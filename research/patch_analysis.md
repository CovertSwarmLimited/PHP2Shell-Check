# Patch analysis

## Commit identification [OFFICIAL]

All four fixed releases contain one security commit titled **"Avoid state corruption via
bailout"**. It is referenced in the php.net ChangeLog under Core, alongside both GHSA IDs.

| Range compared (GitHub compare API) | Fix commit | Other commits in range |
|---|---|---|
| php-8.2.34...php-8.2.35 | `01a40e89fbfc` | CI, Windows SDK, bundled PCRE2 security backport, NEWS, version bump |
| php-8.3.35...php-8.3.36 | `3c832b523ee1` | as above |
| php-8.4.26...php-8.4.27 | `506e87fa7dcd` | as above |
| php-8.5.11...php-8.5.12 | `31c0ea7d7ff1` | plus `a0434fdc2412` "ext/soap: fix use of uninitialized func in do_request() on OOM bailout" |

The 8.2 diff is about 20,000 lines across about 300 files. Most of it is new `oom_*.phpt`
tests and "fallible allocation" conversions.

## Key changes relevant to detection

### 1. New INI directive `memory_hard_limit_percent` (main/main.c)

```c
PHP_INI_ENTRY("memory_hard_limit_percent", NULL, PHP_INI_ALL, OnChangeMemoryHardLimitPercent)
```

- It is registered in the Core INI table, so `phpinfo()` and `php -i` list it, and
  `ini_get_all()` returns it.
- The default (`NULL`, shown as "no value") means 200% of `memory_limit` when that is
  below 1G, or a fixed 1G buffer otherwise.
- Values below 100 (other than -1) produce `E_WARNING "memory_hard_limit_percent must be
  >= 100, or -1"`.
- The directive is present in **all four** branch commits (verified by grepping each
  commit diff).

This is the basis of signature H4. A build either contains the fix commit, and so this
directive, or it does not. The version string does not matter.

### 2. OOM handling (Zend/zend_alloc.c, zend_alloc.h, zend_globals.h)

- New `EG(delayed_oom)` (`zend_oom_info`) and `ZEND_HAS_OOM()`.
- New messages: `"Hard memory limit of %zu bytes exhausted ..."` and
  `"Possible integer overflow in memory allocation ..."`, now routed through
  `zend_mm_delayed_error_or_panic()`.
- The soft OOM still reports "Allowed memory size of %zu bytes exhausted", but it is
  raised at a safe point (`zend_handle_delayed_oom()`), for example after
  `sapi_handle_post()` in main/SAPI.c.

Detection relevance: only observable by inducing OOM. Rejected for remote use (H3).

### 3. Multipart parsing (main/rfc1867.c)

- Duplicate or unused part headers are dropped ("Keep only headers we use, and ignore
  duplicates"). This addresses "unlimited headers per part".
- `SG(read_post_bytes) > SG(post_max_size)` is enforced in the read loop. This addresses
  a missing or unusable content length.
- About 20 `ZEND_HAS_OOM()` checks abort parsing cleanly, marking the upload
  `UPLOAD_ERROR_X` or jumping to `oom:`.

Detection relevance: a patched server would reject oversized multipart bodies sent
without a usable content length differently. Testing that means sending the
attack-shaped request to the target. Not used.

### 4. Session upload progress (ext/session/session.c)

See vulnerability_analysis.md. The observable change (H2): with an invalid session ID
the vulnerable build still forced `session_status = active` and attempted a write
("Failed to write session data" warning). The patched build returns early.

Upstream test `ext/session/tests/rfc1867_sid_invalid.phpt` was changed accordingly:
the two "Failed to write session data" warnings are removed from the expected output,
and `$_SESSION` is now `NULL` in user code.

### 5. setcookie (ext/standard/head.c)

`php_setcookie()` now uses fallible appends and returns `FAILURE` on OOM. This matters
for the memory-disclosure cookie (Wiz bug 2), whose URL-encoded value can be three times
the input size. Observable only on OOM.

## Backport considerations

- RHEL, Alma, Rocky, Oracle and Amazon Linux ship PHP with the upstream version number
  and backport fixes without a suffix, so the version string cannot show patch status.
- Debian and Ubuntu add a package suffix (`-1~deb12u1`, `-1ubuntu2.22`). A newer suffix
  *may* contain the backport, which only the package changelog can confirm.
- deb.sury.org follows upstream point releases, so the base version is meaningful.
- Because the fix commit is large and adds the INI directive in main/main.c, a faithful
  vendor backport would also register the directive. This is an **assumption**, stated
  in every H4-based finding. It will be re-checked once vendor packages are published.
