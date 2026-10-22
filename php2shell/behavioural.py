"""Behavioural detection research: the signature registry and passive observations.

The registry records every detection hypothesis investigated, its validation
status and whether it is safe to run against remote hosts. The scanner only
executes signatures with ``enabled_in_scanner=True``, and every one of those
is passive: it parses responses to ordinary GET requests.

Hypotheses that need multipart uploads, induced fatal errors or OOM conditions
touch the vulnerable code paths themselves. They are documented here with
their lab results, and they are never sent to remote targets.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import StrEnum

from php2shell.advisories import CVE_OOM, CVE_STALE_STATE, PATCH_MARKER_DIRECTIVE
from php2shell.confidence import Evidence, EvidenceKind
from php2shell.transport import HttpResponse


class SignatureStatus(StrEnum):
    VALIDATED = "VALIDATED"
    """Lab-validated against vulnerable and patched builds. Safe and passive."""
    LAB_ONLY = "LAB_ONLY"
    """Reproducible difference exists, but observing it remotely is unsafe or unreliable."""
    REJECTED = "REJECTED"
    """Investigated and not supported by evidence, or inherently unsafe."""
    UNTESTED = "UNTESTED"


@dataclass(frozen=True, slots=True)
class Signature:
    id: str
    name: str
    cves: tuple[str, ...]
    status: SignatureStatus
    safe_for_remote: bool
    enabled_in_scanner: bool
    hypothesis: str
    code_path: str
    vulnerable_behaviour: str
    patched_behaviour: str
    requirements: str
    false_positive_risk: str
    false_negative_risk: str
    validation: str
    """Summary of lab validation results (details in research/results/)."""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


SIGNATURES: tuple[Signature, ...] = (
    Signature(
        id="H1",
        name="Version disclosure compared with fixed releases",
        cves=(CVE_OOM, CVE_STALE_STATE),
        status=SignatureStatus.VALIDATED,
        safe_for_remote=True,
        enabled_in_scanner=True,
        hypothesis=(
            "A PHP version disclosed in X-Powered-By, the Server banner or phpinfo() can be compared "
            "with the first fixed release of its branch."
        ),
        code_path="main/main.c (expose_php), sapi/apache2handler (Server token)",
        vulnerable_behaviour="Disclosed upstream version below 8.2.35, 8.3.36, 8.4.27 or 8.5.12, or any branch older than 8.2",
        patched_behaviour="Disclosed upstream version at or above the fixed release of its branch",
        requirements="expose_php=On, or a version-bearing Server banner, or an exposed phpinfo() page",
        false_positive_risk=(
            "HIGH for 'vulnerable' verdicts: distributions such as RHEL, SUSE, Debian and Ubuntu backport "
            "fixes without changing the upstream version. A version string alone therefore never yields "
            "CONFIRMED_VULNERABLE."
        ),
        false_negative_risk="Headers can be stripped, rewritten or stale (CDN or proxy cache).",
        validation="Version comparison logic is unit-tested against the advisory's fixed releases.",
    ),
    Signature(
        id="H4",
        name=f"phpinfo() lists the {PATCH_MARKER_DIRECTIVE} INI directive",
        cves=(CVE_OOM, CVE_STALE_STATE),
        status=SignatureStatus.VALIDATED,
        safe_for_remote=True,
        enabled_in_scanner=True,
        hypothesis=(
            f"Every fix commit registers a new INI directive, {PATCH_MARKER_DIRECTIVE}, in main/main.c "
            "for the new hard OOM threshold. phpinfo() lists every registered Core directive, so the "
            "directive's presence or absence shows whether the fix code is compiled in, whatever "
            "version string the build reports. This also covers vendor backports."
        ),
        code_path="main/main.c PHP_INI_BEGIN (OnChangeMemoryHardLimitPercent); Zend/zend_alloc.c",
        vulnerable_behaviour=f"Complete Core directive table without {PATCH_MARKER_DIRECTIVE}",
        patched_behaviour=f"{PATCH_MARKER_DIRECTIVE} row present (default 'no value')",
        requirements=(
            "An already-exposed phpinfo() page, supplied with --phpinfo-url or found with the opt-in "
            "--check-info-paths. The page must be served by the same PHP runtime as the application."
        ),
        false_positive_risk=(
            "Low. A vendor backport that omits the directive would read as unpatched. None is known "
            "(no vendor backports were published at release time)."
        ),
        false_negative_risk=(
            "A phpinfo() page from a different PHP pool or vhost than the application. Truncated pages "
            "are detected: the absence verdict requires a complete Core directive table."
        ),
        validation=(
            "Lab: 8.4.26 and 8.5.11 lack the directive. 8.4.27 and 8.5.12 list it. Checked via CLI, "
            "CGI and the built-in web server over HTTP, through the scanner's own parser, with default "
            "and custom INI. See research/results/."
        ),
    ),
    Signature(
        id="H2",
        name="Session upload-progress diagnostics with an invalid session ID",
        cves=(CVE_STALE_STATE,),
        status=SignatureStatus.LAB_ONLY,
        safe_for_remote=False,
        enabled_in_scanner=False,
        hypothesis=(
            "The patched php_session_rfc1867_update() returns early when php_session_initialize() "
            "fails, so a multipart upload with an invalid PHPSESSID no longer produces the "
            "'Failed to write session data' warning."
        ),
        code_path="ext/session/session.c php_session_rfc1867_update()/php_session_rfc1867_cleanup()",
        vulnerable_behaviour="Startup warnings include 'Failed to write session data' (twice)",
        patched_behaviour="Only 'Session ID is too long or contains illegal characters' and 'Failed to read session data'",
        requirements=(
            "A multipart POST with a PHP_SESSION_UPLOAD_PROGRESS field, session.upload_progress.enabled=1 "
            "and display_errors=On on the target."
        ),
        false_positive_risk="High: depends on display_errors, save handler and error_reporting.",
        false_negative_risk="High: production hosts normally run display_errors=Off.",
        validation=(
            "Reproduced in the lab, but REJECTED for remote use. The probe drives the vulnerable "
            "pre-RINIT upload-progress code path, writes session state on the target, uses POST and "
            "multipart, and is observable only with display_errors=On."
        ),
    ),
    Signature(
        id="H3",
        name="OOM error message wording ('Hard memory limit ... exhausted')",
        cves=(CVE_OOM,),
        status=SignatureStatus.REJECTED,
        safe_for_remote=False,
        enabled_in_scanner=False,
        hypothesis="Patched builds emit new OOM messages when the hard limit is reached.",
        code_path="Zend/zend_alloc.c zend_mm_safe_error()/delayed OOM",
        vulnerable_behaviour="'Allowed memory size ... exhausted' raised via longjmp",
        patched_behaviour="Soft OOM at the next VM safe point; 'Hard memory limit ...' at the hard threshold",
        requirements="Inducing an out-of-memory condition on the target",
        false_positive_risk="n/a",
        false_negative_risk="n/a",
        validation=(
            "REJECTED: needs an induced OOM on the target, which is the exploitation trigger and is "
            "prohibited. Studied only in the patch source."
        ),
    ),
    Signature(
        id="H5",
        name="Timing, worker persistence or error-page differences on ordinary requests",
        cves=(CVE_OOM, CVE_STALE_STATE),
        status=SignatureStatus.REJECTED,
        safe_for_remote=False,
        enabled_in_scanner=False,
        hypothesis="Patched builds behave differently on benign GET requests.",
        code_path="n/a",
        vulnerable_behaviour="n/a",
        patched_behaviour="n/a",
        requirements="n/a",
        false_positive_risk="n/a",
        false_negative_risk="n/a",
        validation=(
            "REJECTED: the fix changes behaviour only on allocation failure, fatal-error and "
            "pre-RINIT paths. Lab comparison of benign GET responses (headers and body) between "
            "vulnerable and patched builds showed no difference beyond the version string."
        ),
    ),
)


def enabled_signatures() -> list[Signature]:
    return [s for s in SIGNATURES if s.enabled_in_scanner and s.safe_for_remote]


# ---------------------------------------------------------------------------
# Passive anomaly observation (indicator of compromise, NOT a vulnerability signature)
# ---------------------------------------------------------------------------

_DEFAULT_SID_RE = re.compile(r"^[A-Za-z0-9,\-]{22,256}$")


def observe_session_cookie_anomalies(resp: HttpResponse) -> list[Evidence]:
    """Flag PHPSESSID values that are unusually large or contain illegal characters.

    Wiz lists oversized or malformed PHPSESSID response cookies as an
    indicator of the session upload-progress memory disclosure. A legitimate
    PHP session ID uses only [A-Za-z0-9,-]. This observes cookies the server
    sent on its own; it never provokes them.
    """
    out: list[Evidence] = []
    for raw in resp.set_cookies:
        name, _, rest = raw.partition("=")
        if name.strip().lower() != "phpsessid":
            continue
        value = rest.split(";", 1)[0].strip()
        if not value or value.lower() == "deleted":
            continue
        if not _DEFAULT_SID_RE.match(value):
            out.append(Evidence(
                EvidenceKind.ANOMALY,
                "behavioural.session-cookie-anomaly",
                "PHPSESSID cookie has an abnormal length or characters (possible memory-disclosure "
                "indicator; also possible with custom session ID handlers)",
                resp.url,
                f"length={len(value)}, sample={value[:24]!r}",
            ))
    return out
