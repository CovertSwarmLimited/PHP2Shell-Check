"""Classification matrix, including false-positive prevention."""

import pytest

from php2shell.advisories import CVES
from php2shell.confidence import Classification as C, Confidence, assess_php_presence
from php2shell.detection import VersionObservation, assess_target
from php2shell.fingerprint import extract_signals, parse_php_version, parse_phpinfo, phpinfo_evidence
from tests.conftest import fixture_text, make_response


def run(headers=None, cookies=None, body="", phpinfo=None, reachable=True):
    resp = make_response(headers=headers, cookies=cookies, body=body)
    ev = extract_signals(resp)
    versions = []
    for e in ev:
        if e.kind.value == "php_version":
            versions.append(VersionObservation(parse_php_version(e.observed), e.method, resp.url))
    infos = []
    if phpinfo:
        info = parse_phpinfo(fixture_text(phpinfo) if phpinfo.endswith(".html") else phpinfo, "https://t.example/i.php")
        infos.append(info)
        ev += phpinfo_evidence(info)
        if info.version:
            versions.append(VersionObservation(info.version, "phpinfo", info.url))
    det = assess_php_presence(ev)
    findings = assess_target("https://t.example/", det, ev, versions, infos, reachable, [])
    assert [f.cve for f in findings] == list(CVES)
    return findings


def classes(findings):
    return {f.classification for f in findings}


def test_upstream_affected_version_is_potential_high():
    f = run(headers={"X-Powered-By": "PHP/8.4.26"})
    assert classes(f) == {C.POTENTIALLY_VULNERABLE}
    assert f[0].confidence is Confidence.HIGH


def test_debian_backport_is_potential_medium():
    f = run(headers={"X-Powered-By": "PHP/8.2.29-1~deb12u1"})
    assert classes(f) == {C.POTENTIALLY_VULNERABLE}
    assert f[0].confidence is Confidence.MEDIUM
    assert "debian" in f[0].rationale


def test_rhel_platform_lowers_confidence():
    f = run(headers={"Server": "Apache/2.4.37 (Red Hat Enterprise Linux)", "X-Powered-By": "PHP/8.0.30"})
    assert classes(f) == {C.POTENTIALLY_VULNERABLE}
    assert f[0].confidence is Confidence.MEDIUM
    assert "end-of-life" in f[0].rationale


def test_fixed_version_is_patched_medium():
    for v in ("8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.4.27-1+deb13u1"):
        f = run(headers={"X-Powered-By": f"PHP/{v}"})
        assert classes(f) == {C.CONFIRMED_PATCHED}, v
        assert f[0].confidence is Confidence.MEDIUM


def test_header_version_never_confirms_vulnerable():
    for v in ("5.4.45", "7.4.33", "8.1.2", "8.2.0", "8.4.26", "8.5.11"):
        assert C.CONFIRMED_VULNERABLE not in classes(run(headers={"X-Powered-By": f"PHP/{v}"}))


def test_phpinfo_vulnerable_confirms():
    f = run(phpinfo="phpinfo_8.4.26.html")
    assert classes(f) == {C.CONFIRMED_VULNERABLE}
    assert all(x.independently_validated and x.confidence is Confidence.HIGH for x in f)


def test_phpinfo_patched_confirms():
    f = run(phpinfo="phpinfo_8.5.12.html")
    assert classes(f) == {C.CONFIRMED_PATCHED}
    assert f[0].confidence is Confidence.HIGH


def test_vendor_backport_detected_by_marker():
    """A distro build reporting an old version but carrying the fix (marker present)."""
    html = fixture_text("phpinfo_8.4.27.html").replace("PHP Version 8.4.27", "PHP Version 8.4.11-1~deb13u2")
    f = run(phpinfo=html)
    assert classes(f) == {C.CONFIRMED_PATCHED}


def test_marker_absent_but_fixed_version_is_inconclusive():
    html = fixture_text("phpinfo_8.4.26.html").replace("PHP Version 8.4.26", "PHP Version 8.4.27")
    assert classes(run(phpinfo=html)) == {C.INCONCLUSIVE}


def test_phpinfo_patched_but_app_header_old_lowers_confidence():
    f = run(headers={"X-Powered-By": "PHP/8.4.26"}, phpinfo="phpinfo_8.4.27.html")
    assert classes(f) == {C.CONFIRMED_PATCHED}
    assert f[0].confidence is Confidence.MEDIUM


def test_php_without_version_is_inconclusive():
    f = run(cookies=["PHPSESSID=abcdefabcdefabcdefabcdef12"])
    assert classes(f) == {C.INCONCLUSIVE}


def test_never_vulnerable_solely_because_php():
    f = run(headers={"X-Powered-By": "PHP"}, cookies=["PHPSESSID=abcdefabcdefabcdefabcdef12"],
            body="<b>Fatal error</b>: boom in <b>/x.php</b> on line <b>1</b>")
    assert classes(f) == {C.INCONCLUSIVE}


def test_non_php_is_not_applicable():
    f = run(headers={"X-Powered-By": "ASP.NET"})
    assert classes(f) == {C.NOT_APPLICABLE}


def test_non_php_with_php_signal_is_not_not_applicable():
    f = run(headers={"X-Powered-By": "ASP.NET"}, cookies=["PHPSESSID=abcdefabcdefabcdefabcdef12"])
    assert C.NOT_APPLICABLE not in classes(f)


def test_nothing_known_is_inconclusive():
    assert classes(run(headers={"Server": "nginx"})) == {C.INCONCLUSIVE}


def test_unreachable_is_inconclusive():
    assert classes(run(reachable=False)) == {C.INCONCLUSIVE}


def test_future_branch_is_inconclusive():
    assert classes(run(headers={"X-Powered-By": "PHP/8.6.0"})) == {C.INCONCLUSIVE}


def test_conflicting_versions_reported():
    f = run(headers={"X-Powered-By": "PHP/8.4.27", "Server": "Apache PHP/8.4.20"})
    assert classes(f) == {C.POTENTIALLY_VULNERABLE}
    assert "Different version strings" in f[0].rationale


@pytest.mark.parametrize("phpinfo", ["phpinfo_8.4.26.html", "phpinfo_8.5.11.html"])
def test_per_cve_exposure_factors(phpinfo):
    oom, stale = run(phpinfo=phpinfo)
    assert any("upload_progress" in x for x in stale.exposure_factors)
    assert not any("upload_progress" in x for x in oom.exposure_factors)


def test_every_finding_has_required_fields():
    for f in run(headers={"X-Powered-By": "PHP/8.3.1"}):
        d = f.to_dict()
        for key in ("target", "cve", "classification", "confidence", "detection_methods", "evidence",
                    "assumptions", "limitations", "independently_validated", "next_steps"):
            assert key in d
        assert d["evidence"] and d["limitations"]
