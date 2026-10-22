"""Evidence-based per-CVE classification.

Classification rules (kept deliberately conservative):

* CONFIRMED_VULNERABLE needs a complete phpinfo() Core directive table that
  lacks the fix's INI directive and reports an affected version. A version
  string alone is never enough, because vendors backport fixes silently.
* CONFIRMED_PATCHED needs either the fix's INI directive in phpinfo(), or a
  disclosed upstream version at or above the fixed release.
* POTENTIALLY_VULNERABLE: a disclosed version predates the fix, but the patch
  status cannot be verified remotely.
* NOT_APPLICABLE needs a positively identified non-PHP runtime and no PHP
  signal, and applies only to the assessed URL.
* Everything else is INCONCLUSIVE.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from php2shell.advisories import (
    CVE_OOM,
    CVE_STALE_STATE,
    CVES,
    NEWEST_KNOWN_BRANCH,
    OLDEST_FIXED_BRANCH,
    PATCH_MARKER_DIRECTIVE,
    fixed_release_for,
    format_version,
)
from php2shell.confidence import (
    Classification,
    Confidence,
    Evidence,
    EvidenceKind,
    PhpDetection,
)
from php2shell.fingerprint import PhpInfo, PhpVersion

HOST_CHECK = (
    f"php -i | grep -c {PATCH_MARKER_DIRECTIVE}   # 1 = fix present, 0 = fix absent "
    "(run with the same PHP binary or SAPI that serves the site)"
)


@dataclass(slots=True)
class VersionObservation:
    version: PhpVersion
    method: str
    url: str


class VersionStatus:
    AFFECTED = "affected"
    FIXED = "fixed"
    UNKNOWN = "unknown"


def version_status(v: PhpVersion) -> tuple[str, str]:
    """Compare a version with the advisory's fixed releases. Returns (status, explanation)."""
    if v.branch < OLDEST_FIXED_BRANCH:
        return VersionStatus.AFFECTED, (
            f"PHP {v.major}.{v.minor} is an end-of-life branch older than 8.2. The advisory lists every "
            "release before 8.2.35 as affected, and no upstream fix exists for this branch"
        )
    if v.branch > NEWEST_KNOWN_BRANCH:
        return VersionStatus.UNKNOWN, (
            f"PHP {v.major}.{v.minor} is newer than every branch named in the advisory. Its status is unknown"
        )
    fixed = fixed_release_for(*v.branch)
    if fixed is None:
        return VersionStatus.UNKNOWN, f"No fixed release is recorded for branch {v.major}.{v.minor}"
    if v.patch is None:
        return VersionStatus.UNKNOWN, (
            f"Only the branch {v.major}.{v.minor} was disclosed. The fixed release is "
            f"{format_version(fixed)}, so the patch level cannot be compared"
        )
    if v.base < fixed:
        what = "pre-release of " if v.prerelease else ""
        return VersionStatus.AFFECTED, (
            f"Upstream version {what}{format_version(v.base)} is below the fixed release {format_version(fixed)}"
        )
    return VersionStatus.FIXED, (
        f"Upstream version {format_version(v.base)} is at or above the fixed release {format_version(fixed)}"
    )


@dataclass(slots=True)
class Finding:
    target: str
    cve: str
    classification: Classification
    confidence: Confidence
    rationale: str
    detection_methods: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    exposure_factors: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    independently_validated: bool = False

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "cve": self.cve,
            "classification": self.classification.value,
            "confidence": self.confidence.value,
            "rationale": self.rationale,
            "detection_methods": self.detection_methods,
            "evidence": [e.to_dict() for e in self.evidence],
            "assumptions": self.assumptions,
            "limitations": self.limitations,
            "exposure_factors": self.exposure_factors,
            "next_steps": self.next_steps,
            "independently_validated": self.independently_validated,
        }


GENERAL_LIMITATIONS = [
    "No safe, validated behavioural signature exists for these CVEs. Remote assessment relies on "
    "disclosed version information and exposed phpinfo() output (see research/limitations.md).",
    "The scan covers only the URLs requested. Other paths, virtual hosts or PHP pools on the "
    "same host may run a different PHP build.",
]


def _platform_backport(evidence: list[Evidence]) -> list[Evidence]:
    return [e for e in evidence if e.method == "header.server.platform"]


def _cdn(evidence: list[Evidence]) -> list[Evidence]:
    return [e for e in evidence if e.method == "header.cdn"]


def _exposure_factors(cve: str, infos: list[PhpInfo]) -> list[str]:
    out: list[str] = []
    for info in infos:
        sapi = (info.server_api or "").lower()
        if sapi:
            if "apache 2.0 handler" in sapi:
                note = ("Apache mod_php: the advisory reports a confirmed RCE exploit for this SAPI"
                        if cve == CVE_OOM else
                        "Apache mod_php: the advisory reports a confirmed exploit chain for this SAPI")
            elif "fpm" in sapi:
                note = ("PHP-FPM: susceptible by source analysis; the advisory demonstrated no complete exploit"
                        if cve == CVE_OOM else
                        "PHP-FPM: the advisory validated session-lifecycle RCE against FPM")
            elif "litespeed" in sapi:
                note = "LiteSpeed (LSAPI): likely susceptible to application-specific triggers (unvalidated)"
            elif "frankenphp" in sapi:
                note = "FrankenPHP: likely susceptible according to source analysis"
            else:
                note = f"Server API '{info.server_api}': the advisory does not discuss this SAPI"
            out.append(note)
        if cve == CVE_STALE_STATE:
            up = info.directive("session.upload_progress.enabled")
            if up is not None:
                on = up.strip().lower() in ("on", "1", "true", "yes")
                out.append(
                    f"session.upload_progress.enabled={up}: "
                    + ("the session upload-progress path named in the advisory is enabled"
                       if on else "the session upload-progress path is disabled (partial mitigation only)")
                )
            feb = info.directive("fatal_error_backtraces")
            if feb is not None:
                out.append(f"fatal_error_backtraces={feb} (PHP 8.5 backtrace path; Off is a partial mitigation)")
        if cve == CVE_OOM:
            ml = info.directive("memory_limit")
            if ml is not None and ml.strip() == "-1":
                out.append("memory_limit=-1: the advisory states this is not a complete mitigation")
    return out


def _next_steps(cls: Classification) -> list[str]:
    upgrade = "Upgrade to PHP 8.2.35, 8.3.36, 8.4.27 or 8.5.12 or later, then restart all PHP workers."
    if cls is Classification.CONFIRMED_VULNERABLE:
        return [upgrade, "Until upgraded, apply the advisory mitigations (request-size limits at the front end, "
                "disable unused multipart/upload progress) and watch for repeated HTTP 500s and worker churn.",
                "Disable or restrict the exposed phpinfo() page."]
    if cls is Classification.POTENTIALLY_VULNERABLE:
        return ["Verify patch status on the host: " + HOST_CHECK,
                "For distribution packages, check the package changelog for CVE-2026-109618/109619.",
                upgrade]
    if cls is Classification.CONFIRMED_PATCHED:
        return ["No action needed for these CVEs on the assessed runtime. Confirm that every PHP pool and "
                "vhost on the host runs the same build."]
    if cls is Classification.NOT_APPLICABLE:
        return ["No PHP runtime was identified on the assessed URL. Confirm no PHP application is served "
                "elsewhere on the host."]
    return ["Establish the PHP version and patch status from the host side: " + HOST_CHECK,
            "If an existing phpinfo() page is known, rescan with --phpinfo-url."]


def assess_target(
    target: str,
    detection: PhpDetection,
    evidence: list[Evidence],
    versions: list[VersionObservation],
    phpinfos: list[PhpInfo],
    reachable: bool,
    transport_notes: list[str],
) -> list[Finding]:
    return [
        _assess_cve(cve, target, detection, evidence, versions, phpinfos, reachable, transport_notes)
        for cve in CVES
    ]


def _assess_cve(cve, target, detection, evidence, versions, phpinfos, reachable, transport_notes) -> Finding:
    limitations = [*GENERAL_LIMITATIONS, *transport_notes]
    cdn = _cdn(evidence)
    if cdn:
        limitations.append("A CDN or proxy sits in front of the origin. Headers may be stripped, rewritten or "
                           "served from cache, and may not reflect the origin's PHP build.")
    exposure = _exposure_factors(cve, phpinfos)

    def finding(cls, conf, rationale, methods, ev, assumptions=(), validated=False):
        return Finding(
            target=target, cve=cve, classification=cls, confidence=conf, rationale=rationale,
            detection_methods=sorted(set(methods)), evidence=list(ev), assumptions=list(assumptions),
            limitations=limitations, exposure_factors=exposure, next_steps=_next_steps(cls),
            independently_validated=validated,
        )

    if not reachable:
        return finding(Classification.INCONCLUSIVE, Confidence.LOW,
                       "The target could not be assessed (unreachable, refused or stopped early).",
                       ["transport"], [])

    # 1. phpinfo() with a complete Core table: the patch marker is authoritative.
    complete = [i for i in phpinfos if i.core_table_parsed]
    if complete:
        return _assess_from_phpinfo(complete, versions, evidence, finding)

    # 2. Disclosed versions.
    if versions:
        return _assess_from_versions(versions, evidence, finding)

    # 3. No version information.
    if detection.detected:
        return finding(
            Classification.INCONCLUSIVE, Confidence.LOW,
            f"PHP was identified ({detection.confidence.value} confidence, score {detection.score}), but no "
            "version or patch information is disclosed. Running PHP alone does not establish exposure. "
            "Note that every PHP release before the 2026-10-21 fixes is affected.",
            [e.method for e in detection.evidence], detection.evidence)
    strong_non_php = [e for e in detection.non_php_evidence if e.weight >= 0.8]
    if strong_non_php:
        names = ", ".join(sorted({e.observed for e in strong_non_php}))
        return finding(
            Classification.NOT_APPLICABLE, Confidence.MEDIUM,
            f"The assessed URL is served by a non-PHP runtime ({names}) and no PHP indicator was observed. "
            "This applies only to the assessed URL: a reverse proxy may route other paths to PHP.",
            [e.method for e in strong_non_php], strong_non_php,
            assumptions=["The runtime headers come from the application tier, not from a proxy in front of it."])
    return finding(
        Classification.INCONCLUSIVE, Confidence.LOW,
        "Neither PHP nor another runtime could be identified from passive signals. This is not evidence "
        "that the host is unaffected.", [], [])


def _assess_from_phpinfo(infos: list[PhpInfo], versions, evidence, finding) -> Finding:
    marker_ev = [e for e in evidence if e.kind is EvidenceKind.PATCH_MARKER]
    vuln: list[tuple[PhpInfo, str]] = []
    patched: list[PhpInfo] = []
    contradictory: list[tuple[PhpInfo, str]] = []
    unknown: list[tuple[PhpInfo, str]] = []
    for info in infos:
        if info.has_patch_marker:
            patched.append(info)
            continue
        if info.version is None:
            unknown.append((info, "phpinfo() did not report a parsable version"))
            continue
        status, why = version_status(info.version)
        if status == VersionStatus.AFFECTED:
            vuln.append((info, why))
        elif status == VersionStatus.FIXED:
            contradictory.append((info, why))
        else:
            unknown.append((info, why))

    ev = [*marker_ev, *[e for e in evidence if e.method == "phpinfo"]]
    methods = ["phpinfo.patch-marker", "phpinfo"]
    assumptions = [
        "The phpinfo() page is served by the same PHP runtime (SAPI, pool, binary) as the application.",
        f"Vendor backports include the upstream {PATCH_MARKER_DIRECTIVE} directive. It is part of the fix "
        "commit on every branch.",
    ]
    if vuln:
        info, why = vuln[0]
        return finding(
            Classification.CONFIRMED_VULNERABLE, Confidence.HIGH,
            f"phpinfo() at {info.url} reports PHP {info.version.raw} ({why}), and its complete Core directive "
            f"table lacks {PATCH_MARKER_DIRECTIVE}, which the fix registers. The build does not contain the fix.",
            methods, ev, assumptions, validated=True)
    if patched and not contradictory and not unknown:
        info = patched[0]
        conf = Confidence.HIGH
        rationale = (f"phpinfo() at {info.url} lists {PATCH_MARKER_DIRECTIVE}, which is registered only by "
                     "builds that contain the fix" + (f" (reported version {info.version.raw})." if info.version else "."))
        affected_headers = [o for o in versions if version_status(o.version)[0] == VersionStatus.AFFECTED
                            and o.method != "phpinfo"]
        if affected_headers:
            conf = Confidence.MEDIUM
            rationale += (f" However, {affected_headers[0].method} on {affected_headers[0].url} reports "
                          f"{affected_headers[0].version.raw}, which suggests the application may be served by a "
                          "different runtime than the phpinfo() page.")
        return finding(Classification.CONFIRMED_PATCHED, conf, rationale, methods, ev, assumptions, validated=True)
    if contradictory:
        info, why = contradictory[0]
        return finding(
            Classification.INCONCLUSIVE, Confidence.LOW,
            f"phpinfo() at {info.url} reports {info.version.raw} ({why}), yet {PATCH_MARKER_DIRECTIVE} is "
            "absent. This contradiction (custom build, modified source or spoofed page) prevents a verdict.",
            methods, ev, assumptions)
    info, why = unknown[0]
    return finding(Classification.INCONCLUSIVE, Confidence.LOW,
                   f"phpinfo() at {info.url} could not be classified: {why}.", methods, ev, assumptions)


def _assess_from_versions(versions: list[VersionObservation], evidence, finding) -> Finding:
    platform = _platform_backport(evidence)
    version_ev = [e for e in evidence if e.kind is EvidenceKind.PHP_VERSION]
    methods = [o.method for o in versions]
    distinct = {o.version.raw for o in versions}
    statuses = [(o, *version_status(o.version)) for o in versions]
    affected = [s for s in statuses if s[1] == VersionStatus.AFFECTED]
    fixed = [s for s in statuses if s[1] == VersionStatus.FIXED]

    assumptions = ["The disclosed version string reflects the PHP build that serves the application."]
    conflict_note = ""
    if len(distinct) > 1:
        conflict_note = f" Different version strings were observed ({', '.join(sorted(distinct))})."

    if affected:
        obs, _, why = affected[0]
        v = obs.version
        backport_reasons = []
        if v.backport_possible:
            backport_reasons.append(f"the version suffix '{v.suffix}' indicates a {v.vendor} package")
        if platform:
            backport_reasons.append("the Server banner indicates a distribution that backports PHP fixes")
        if backport_reasons:
            conf = Confidence.MEDIUM
            bp = ("Patch status cannot be confirmed remotely because " + " and ".join(backport_reasons) +
                  ", so the fix may have been backported without a version change.")
        else:
            conf = Confidence.HIGH
            bp = ("The version string looks like an upstream build, but vendor or commercial backports "
                  "cannot be ruled out remotely, so the missing fix is not confirmed.")
        eol = ""
        if v.branch < OLDEST_FIXED_BRANCH:
            eol = " The branch is end-of-life: only vendor or commercial extended-support builds can carry a fix."
        return finding(
            Classification.POTENTIALLY_VULNERABLE, conf,
            f"{obs.method} on {obs.url} discloses PHP {v.raw}. {why}. {bp}{eol}{conflict_note}",
            methods, [*version_ev, *platform],
            assumptions + ["A version below the fixed release with no vendor backport means the fix is absent."])
    if fixed and len(fixed) == len(statuses):
        obs, _, why = fixed[0]
        return finding(
            Classification.CONFIRMED_PATCHED, Confidence.MEDIUM,
            f"{obs.method} on {obs.url} discloses PHP {obs.version.raw}. {why}. The fix shipped in this "
            f"upstream release.{conflict_note}",
            methods, version_ev,
            assumptions + ["The version header is genuine and not spoofed by the operator."])
    obs, _, why = statuses[0]
    return finding(
        Classification.INCONCLUSIVE, Confidence.LOW,
        f"{obs.method} on {obs.url} discloses PHP {obs.version.raw}, but: {why}.{conflict_note}",
        methods, version_ev, assumptions)
