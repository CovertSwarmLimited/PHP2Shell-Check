# Detection hypotheses and signature validation

Every candidate signature went through the ten-step validation process. The scanner
runs only signatures marked **VALIDATED** that are also remote-safe and passive. The
registry is in `php2shell/behavioural.py`; view it with
`python -m php2shell research --show-signatures`.

Lab results: `results/lab_validation.md` and `results/lab_validation.json`, produced
by `lab/local/validate.py`.

## Lab configuration

- Builds: PHP 8.4.26 (vulnerable), 8.4.27 (patched), 8.5.11 (vulnerable) and 8.5.12
  (patched), compiled from official php.net tarballs with `lab/local/build_php.sh`
  (`--disable-all --enable-session --enable-cli --enable-cgi`).
- SAPIs exercised: CLI (`php -i`), CGI (`php-cgi`) and the built-in web server
  (`php -S`, over real HTTP on 127.0.0.1).
- INI profiles: `-n` defaults, `expose_php=Off`, custom limits (`memory_limit=256M`,
  `post_max_size=2M`, `session.upload_progress.enabled=0`), and `display_errors=On`.
- Repetitions: 5 per cell.
- Additional check: the distribution package on the lab host (Ubuntu PHP 8.5.4, released
  before the fix) lacks the directive, consistent with H4.
- Not run in this environment, because Docker is unavailable: Apache mod_php and
  nginx+FPM. The Docker lab (`lab/docker/`) and `lab/docker/validate_docker.py` exist for
  this and should be run before relying on H4 for those SAPIs. Source analysis says the
  INI table is SAPI-independent (main/main.c), so we expect identical results.

---

## H1: Version disclosure compared with fixed releases (VALIDATED, used)

1. **Hypothesis.** A disclosed PHP version (X-Powered-By, a Server banner with a PHP
   token, or a phpinfo() heading) compared with the branch's first fixed release
   indicates exposure.
2. **Code path.** `expose_php` in main/main.c; the Apache module banner.
3. **Vulnerable.** Base version below 8.2.35, 8.3.36, 8.4.27 or 8.5.12, or any branch ≤ 8.1.
4. **Patched.** Base version at or above the fixed release.
5. **Test.** Lab, headers-only scans with expose_php on (15 runs per build): 8.4.26 and
   8.5.11 gave POTENTIALLY_VULNERABLE 15/15, and 8.4.27 and 8.5.12 gave CONFIRMED_PATCHED
   15/15. With `expose_php=Off` (5 runs per build), every build gave INCONCLUSIVE 5/5, as
   designed.
6. **Reliability.** Deterministic.
7. **Configurations.** Four INI profiles on two branches.
8. **False positives.** Vendor backports make "below fixed" unreliable, so H1 can **never**
   produce CONFIRMED_VULNERABLE, only POTENTIALLY_VULNERABLE. Confidence is MEDIUM when a
   vendor suffix or a backporting platform banner is present. **False negatives.**
   Headers stripped by expose_php=Off or a CDN, or spoofed headers.
9. **Documented.** Here and in the unit tests (`tests/unit/test_detection.py`).
10. **Decision.** Included as a *version-based* method. It is not a behavioural signature.

## H4: `memory_hard_limit_percent` listed in phpinfo() (VALIDATED, used)

1. **Hypothesis.** The fix commit registers a new Core INI directive. phpinfo() prints
   every registered directive, so the directive's presence shows the fix is compiled
   in, independent of the version string.
2. **Code path.** `main/main.c` `PHP_INI_BEGIN()`, entry `memory_hard_limit_percent`
   (`OnChangeMemoryHardLimitPercent`).
3. **Vulnerable.** A complete Core directive table without the directive.
4. **Patched.** The row `memory_hard_limit_percent | no value | no value` (default).
5. **Test.** 4 builds × 4 INI profiles × 3 SAPIs × 5 runs. The HTTP runs go through the
   real `Scanner` code path.
6. **Reliability.** 0 mismatches. Every run of every vulnerable build reports the
   directive absent; every run of every patched build reports it present.
7. **Configurations.** CLI, CGI and built-in server. Defaults, expose_php=Off, custom
   limits, display_errors=On.
8. **False positives.** A partial vendor backport without the directive would read as
   vulnerable; none known. A modified or spoofed phpinfo() page that contradicts its own
   version is reported INCONCLUSIVE. **False negatives.** The phpinfo() page is served by
   a different PHP pool or vhost than the application. A truncated page is detected by
   requiring a complete Core table (`memory_limit`, `max_execution_time`,
   `post_max_size`, `display_errors`); otherwise H4 is not applied.
9. **Documented.** Here, in `results/`, in `tests/unit/test_fingerprint.py` (real
   sanitised phpinfo fixtures from each build) and in `tests/integration/test_lab_builds.py`.
10. **Decision.** Included. It is the only route to CONFIRMED_VULNERABLE and the
    strongest route to CONFIRMED_PATCHED. Purely passive: the scanner only parses
    pages the operator names (`--phpinfo-url`) or, with explicit opt-in, two well-known
    paths (`--check-info-paths`).

## H2: Upload-progress diagnostics with an invalid session ID (LAB_ONLY, not used)

1. **Hypothesis.** The patched `php_session_rfc1867_update()` returns early when session
   initialisation fails, so the "Failed to write session data" warning disappears.
2. **Code path.** `ext/session/session.c` `php_session_rfc1867_update()` and
   `php_session_rfc1867_cleanup()`.
3. **Vulnerable.** Two "Failed to write session data" warnings.
4. **Patched.** None. The "illegal characters" warnings remain.
5. **Test.** php-cgi, multipart body with a `PHP_SESSION_UPLOAD_PROGRESS` field,
   `PHPSESSID=_`, display_errors=On.
6. **Reliability.** 5/5 runs per build: vulnerable builds emit 2 warnings, patched builds 0.
7. **Configurations.** Only display_errors=On makes the difference visible.
8. **FP/FN.** Production hosts run display_errors=Off. The warning also depends on the
   save handler and error_reporting.
9. **Documented.** Here and in `results/`.
10. **Decision. Rejected for remote use.** The difference is real, but observing it
    means sending a multipart POST that drives the vulnerable pre-RINIT upload-progress
    path (the producer side of CVE-2026-109619). It also writes session state on the
    target and is only visible with display_errors=On. That violates the
    non-destructive and "no probing the vulnerable code path" requirements.

## H3: OOM error message wording (REJECTED)

Patched builds raise the soft OOM at a safe point and add a "Hard memory limit ...
exhausted" message. Observing either requires inducing OOM on the target, which is the
exploitation trigger. Not tested remotely or in the lab; the conclusion follows from
source analysis.

## H5: Differences on ordinary requests (REJECTED)

Hypothesis: timing, headers, error pages or worker behaviour differ on benign requests.
Lab: GET `/index.php`, `/session.php` (session_start) and `/missing.php` (404) on each
build. After normalising version strings, dates and session IDs, responses were
**byte-identical** between vulnerable and patched builds of each branch. This matches
the source: the fix only changes allocation-failure, fatal-error and pre-RINIT paths.

## Other ideas considered and not pursued

| Idea | Reason |
|---|---|
| Oversized multipart body without a usable content length (rfc1867 read-loop check) | It is the advisory's attack shape. It drives the target toward OOM. |
| Multipart part with many duplicate headers | Same as above. |
| Fatal-error-then-follow-up request to observe stale state | The exploitation producer/consumer pattern; destabilising. |
| PHPSESSID memory-disclosure cookie | It *is* the memory-disclosure exploit. The scanner only passively flags anomalous PHPSESSID cookies the server sends on its own, as an indicator of compromise, never as vulnerability evidence. |
| OPcache shared-memory behaviour | Requires allocation failure during persist. Not externally observable. |
| `ini_get_all()` / `ini_get('memory_hard_limit_percent')` | Requires code execution on the target. Suitable for host-side checks only (see README). |
