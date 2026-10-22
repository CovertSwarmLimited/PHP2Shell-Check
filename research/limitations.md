# Detection limitations

## The central conclusion

**Neither CVE-2026-109618 nor CVE-2026-109619 can be reliably detected remotely, in the
general case, without exercising the vulnerable code paths.** The fix changes behaviour
only when an allocation fails, a fatal error interrupts the request, or session upload
progress runs before request initialisation. Benign requests behave identically on
vulnerable and patched builds (lab-validated, H5). The one reproducible behavioural
difference we found (H2) needs a multipart request into the vulnerable pre-RINIT session
path plus `display_errors=On`. It is excluded from remote use.

Remote assessment therefore depends on information the server already discloses:

| Available evidence | Best possible result |
|---|---|
| Exposed phpinfo() with a complete Core table | CONFIRMED_VULNERABLE or CONFIRMED_PATCHED (H4) |
| X-Powered-By / Server version ≥ fixed release | CONFIRMED_PATCHED (MEDIUM confidence) |
| X-Powered-By / Server version < fixed release | POTENTIALLY_VULNERABLE (never confirmed) |
| PHP identified, version hidden | INCONCLUSIVE |
| Nothing identified | INCONCLUSIVE |
| Non-PHP runtime positively identified, no PHP signal | NOT_APPLICABLE (for that URL only) |

Most hardened production sites hide their version and do not expose phpinfo(). For
them the expected and correct result is **INCONCLUSIVE**. Patch status must then be
checked from the host:

```sh
php -i | grep -c memory_hard_limit_percent      # CLI binary
# or, through the web SAPI, a temporary internal-only page:
<?php var_dump(array_key_exists('memory_hard_limit_percent', ini_get_all(null, false)));
```

Check through the SAPI that actually serves the site. The CLI binary may be a
different package or version.

## Specific limitations

1. **Vendor backports.** RHEL-family and SUSE packages keep the upstream version. Debian
   and Ubuntu suffixes can only be resolved against the package changelog. No vendor
   update had been published at research time, and the scanner holds no table of fixed
   vendor package versions. A version string alone therefore never confirms
   vulnerability.
2. **H4 assumption.** We assume vendor backports include the upstream
   `memory_hard_limit_percent` directive. It is part of the same commit, but this must be
   re-checked against vendor packages once they ship.
3. **Runtime mismatch.** A phpinfo() page, or a header on one path, may come from a
   different PHP pool, vhost, container or version than the application. When header
   and phpinfo() evidence conflict, findings are downgraded and explained.
4. **CDNs and proxies** can strip, rewrite or cache headers. The scanner records CDN
   indicators as limitations.
5. **Headers can be spoofed.** A deliberately false X-Powered-By defeats H1.
6. **Exploitability preconditions are not assessed.** SAPI, worker persistence,
   `session.upload_progress.enabled`, `fatal_error_backtraces` and OPcache are recorded
   as exposure factors when phpinfo() reveals them. The advisory says mitigations are
   partial, so they never downgrade a classification.
7. **Scope.** Only the requested URLs are assessed. No crawling and no endpoint
   enumeration beyond the opt-in two-path check.
8. **NOT_APPLICABLE is URL-scoped.** A reverse proxy may serve PHP on other paths.
9. **Lab coverage.** H4 was validated on CLI, CGI and the built-in server. Apache mod_php
   and FPM validation (Docker lab) could not be executed in the research environment and
   should be run with `lab/docker/validate_docker.py`. The INI table is SAPI-independent,
   so identical results are expected.
10. **Newer branches.** Versions newer than 8.5 are outside the advisory and are reported
    INCONCLUSIVE.
11. **No third-party metadata.** The scanner is standalone and never queries
    Shodan, BuiltWith or similar services.
