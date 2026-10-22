from php2shell.advisories import PATCH_MARKER_DIRECTIVE
from php2shell.behavioural import observe_session_cookie_anomalies
from php2shell.confidence import EvidenceKind, assess_php_presence, Confidence
from php2shell.fingerprint import extract_signals, parse_phpinfo, phpinfo_evidence
from tests.conftest import fixture_text, make_response


def methods(ev, kind=None):
    return {e.method for e in ev if kind is None or e.kind is kind}


def test_x_powered_by_php_with_version():
    ev = extract_signals(make_response(headers={"X-Powered-By": "PHP/8.4.26"}))
    assert "header.x-powered-by" in methods(ev, EvidenceKind.PHP_PRESENCE)
    assert "header.x-powered-by" in methods(ev, EvidenceKind.PHP_VERSION)


def test_hidden_version_session_cookie_only():
    ev = extract_signals(make_response(cookies=["PHPSESSID=abcdefabcdefabcdefabcdef12; path=/; HttpOnly"]))
    assert methods(ev, EvidenceKind.PHP_VERSION) == set()
    det = assess_php_presence(ev)
    assert det.detected and det.confidence is Confidence.MEDIUM


def test_cookie_value_not_leaked_into_evidence():
    ev = extract_signals(make_response(cookies=["PHPSESSID=secretsessionvalue1234567; path=/"]))
    assert all("secretsessionvalue" not in e.observed for e in ev)


def test_server_banner_mod_php_and_platform():
    ev = extract_signals(make_response(headers={"Server": "Apache/2.4.37 (Red Hat Enterprise Linux) PHP/8.0.30"}))
    assert "header.server" in methods(ev, EvidenceKind.PHP_VERSION)
    assert "header.server.platform" in methods(ev, EvidenceKind.ENVIRONMENT)


def test_wordpress_markers():
    body = ('<html><head><meta name="generator" content="WordPress 6.6.2" />'
            '<link rel="stylesheet" href="/wp-content/themes/x/style.css"></head></html>')
    ev = extract_signals(make_response(headers={"Content-Type": "text/html", "Link": '<https://t.example/wp-json/>; rel="https://api.w.org/"'}, body=body))
    m = methods(ev, EvidenceKind.PHP_PRESENCE)
    assert {"body.meta-generator", "body.framework-assets", "header.link.wp-json"} <= m
    assert assess_php_presence(ev).confidence is Confidence.HIGH


def test_existing_php_error_in_body():
    body = "<br />\n<b>Warning</b>:  Undefined variable $x in <b>/var/www/html/index.php</b> on line <b>3</b><br />"
    ev = extract_signals(make_response(headers={"Content-Type": "text/html"}, body=body))
    assert "body.php-error" in methods(ev, EvidenceKind.PHP_PRESENCE)


def test_same_host_php_links_only():
    body = '<a href="/login.php">x</a>'
    assert "body.php-links" in methods(extract_signals(make_response(headers={"Content-Type": "text/html"}, body=body)))
    body = '<a href="https://other.example/login.php">x</a>'
    assert "body.php-links" not in methods(extract_signals(make_response(headers={"Content-Type": "text/html"}, body=body)))


def test_non_php_site():
    ev = extract_signals(make_response(headers={"X-Powered-By": "ASP.NET", "X-AspNet-Version": "4.0.30319"},
                                       body="<html>hello</html>"))
    det = assess_php_presence(ev)
    assert not det.detected
    assert det.non_php_evidence


def test_plain_site_has_no_signals():
    ev = extract_signals(make_response(headers={"Server": "nginx", "Content-Type": "text/html"}, body="<html>hi</html>"))
    assert methods(ev, EvidenceKind.PHP_PRESENCE) == set()
    assert not assess_php_presence(ev).detected


def test_binary_content_ignored():
    ev = extract_signals(make_response(headers={"Content-Type": "image/png"}, body="<b>Fatal error</b>: x on line <b>1</b>"))
    assert "body.php-error" not in methods(ev)


def test_cdn_noted():
    ev = extract_signals(make_response(headers={"CF-Ray": "abc-LHR", "X-Powered-By": "PHP/8.3.1"}))
    assert "header.cdn" in methods(ev, EvidenceKind.ENVIRONMENT)


def test_duplicate_signals_do_not_inflate_score():
    ev = extract_signals(make_response(cookies=["PHPSESSID=a" * 1 + "b" * 25, "PHPSESSID=" + "c" * 26]))
    assert assess_php_presence(ev).score == 0.6


def test_phpinfo_vulnerable_fixture():
    info = parse_phpinfo(fixture_text("phpinfo_8.4.26.html"), "https://t.example/phpinfo.php")
    assert info.version.raw == "8.4.26"
    assert info.core_table_parsed
    assert not info.has_patch_marker
    assert info.server_api == "CGI/FastCGI"
    assert info.directive("session.upload_progress.enabled") == "On"


def test_phpinfo_patched_fixtures():
    for ver in ("8.4.27", "8.5.12"):
        info = parse_phpinfo(fixture_text(f"phpinfo_{ver}.html"), "u")
        assert info.version.raw == ver and info.has_patch_marker and info.core_table_parsed
    for ver in ("8.4.26", "8.5.11"):
        assert not parse_phpinfo(fixture_text(f"phpinfo_{ver}.html"), "u").has_patch_marker


def test_truncated_phpinfo_is_not_treated_as_marker_absent():
    html = fixture_text("phpinfo_8.4.26.html")
    cut = html[: html.index("memory_limit") - 200]  # Core table cut before memory_limit
    info = parse_phpinfo(cut, "u")
    assert info is not None and not info.core_table_parsed
    assert not [e for e in phpinfo_evidence(info) if e.kind is EvidenceKind.PATCH_MARKER]


def test_phpinfo_marker_evidence_is_validated():
    info = parse_phpinfo(fixture_text("phpinfo_8.5.12.html"), "u")
    marker = [e for e in phpinfo_evidence(info) if e.kind is EvidenceKind.PATCH_MARKER]
    assert len(marker) == 1 and marker[0].validated and PATCH_MARKER_DIRECTIVE in marker[0].observed


def test_not_phpinfo():
    assert parse_phpinfo("<html>PHP Version mentioned in a blog post</html>", "u") is None
    assert parse_phpinfo("", "u") is None


def test_session_cookie_anomaly():
    normal = make_response(cookies=["PHPSESSID=0123456789abcdefghijklmnop; path=/"])
    assert observe_session_cookie_anomalies(normal) == []
    leak = make_response(cookies=["PHPSESSID=%00%01%7F" + "%41" * 300 + "; path=/"])
    out = observe_session_cookie_anomalies(leak)
    assert len(out) == 1 and out[0].kind is EvidenceKind.ANOMALY
