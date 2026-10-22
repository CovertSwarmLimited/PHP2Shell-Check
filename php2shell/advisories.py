"""Authoritative advisory data for the PHP2Shell CVEs.

Everything here is transcribed from the official php-src security advisories
and the php-src git history (see research/patch_analysis.md). Nothing is
inferred.
"""

from __future__ import annotations

from dataclasses import dataclass

CVE_OOM = "CVE-2026-109618"
CVE_STALE_STATE = "CVE-2026-109619"
CVES = (CVE_OOM, CVE_STALE_STATE)

# First fixed release per supported branch. Both CVEs are fixed by the same
# commit ("Avoid state corruption via bailout") on every branch.
FIXED_RELEASES: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
OLDEST_FIXED_BRANCH = (8, 2)
NEWEST_KNOWN_BRANCH = (8, 5)

FIX_COMMITS: dict[str, str] = {
    "PHP-8.2": "01a40e89fbfc",
    "PHP-8.3": "3c832b523ee1",
    "PHP-8.4": "506e87fa7dcd",
    "PHP-8.5": "31c0ea7d7ff1",
}

RELEASE_DATE = "2026-10-21"

# INI directive registered in main/main.c by every fix commit. Its presence in
# phpinfo() output means the build contains the fix (lab-validated, see
# research/detection_hypotheses.md, H4).
PATCH_MARKER_DIRECTIVE = "memory_hard_limit_percent"


@dataclass(frozen=True, slots=True)
class Advisory:
    cve: str
    ghsa: str
    title: str
    cvss: str
    cwe: tuple[str, ...]
    summary: str
    references: tuple[str, ...]
    mitigations: tuple[str, ...]


ADVISORIES: dict[str, Advisory] = {
    CVE_OOM: Advisory(
        cve=CVE_OOM,
        ghsa="GHSA-w8hw-w9fx-j79w",
        title="RCE via OOM corruption",
        cvss="9.2 (CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)",
        cwe=("CWE-416", "CWE-755", "CWE-824", "CWE-1325", "CWE-1419"),
        summary=(
            "PHP leaves the request with longjmp() on out-of-memory errors. Request "
            "memory reachable before it is fully initialised can be left invalid and is "
            "then used during request shutdown. Multipart parsing can reach OOM while "
            "staying within apparent PHP limits. Exploitation was confirmed against "
            "Apache mod_php with default limits. Source analysis suggests PHP-FPM and "
            "FrankenPHP are also susceptible."
        ),
        references=(
            "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
            "https://www.php.net/ChangeLog-8.php",
            "https://www.wiz.io/blog/php2shell-php-rce",
        ),
        mitigations=(
            "Upgrade to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12 or later (the only complete fix).",
            "Enforce decoded request size at the front end and lower post_max_size and max_input_nesting_level.",
            "Bound multipart parts, headers and uploads, or block multipart at the front end if it is unused.",
            "memory_limit=-1 is not a complete mitigation. Avoid RLIMIT_AS and RLIMIT_DATA.",
        ),
    ),
    CVE_STALE_STATE: Advisory(
        cve=CVE_STALE_STATE,
        ghsa="GHSA-6wmf-4rv5-p3rp",
        title="RCE via stale global state",
        cvss="9.2 (CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)",
        cwe=("CWE-416", "CWE-755", "CWE-824", "CWE-1325", "CWE-1419"),
        summary=(
            "Request-owned state (error, session, object and extension state) can survive "
            "in persistent worker globals after the request heap is freed, when a fatal "
            "error interrupts an operation before its reset. A later request on the same "
            "worker consumes the stale state before initialisation (use-after-free). "
            "Named paths include fatal error backtraces (PHP 8.5), session upload "
            "progress and INI diagnostics raised before request initialisation."
        ),
        references=(
            "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
            "https://www.php.net/ChangeLog-8.php",
            "https://www.wiz.io/blog/php2shell-php-rce",
        ),
        mitigations=(
            "Upgrade to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12 or later (the only reliable mitigation).",
            "PHP 8.5: set fatal_error_backtraces=0 and restart workers.",
            "Set session.upload_progress.enabled=0 and restart workers if the feature is unused.",
            "Remove diagnostics from startup and per-request INI configuration. Consider pm.max_requests=1 (FPM).",
        ),
    ),
}


def fixed_release_for(major: int, minor: int) -> tuple[int, int, int] | None:
    return FIXED_RELEASES.get((major, minor))


def format_version(v: tuple[int, ...]) -> str:
    return ".".join(str(p) for p in v)
