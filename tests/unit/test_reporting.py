import json

from rich.console import Console

from php2shell.config import ScanConfig
from php2shell.reporting import print_report, print_signatures, to_html, to_json
from php2shell.scanner import Scanner
from tests.conftest import FakeHTTPResponse, fixture_text

T = "https://t.example/"
XSS = '<script>alert("x")</script>'


def scan(routes, fake_factory, **cfg):
    cfg.setdefault("request_interval", 0.2)
    return Scanner(ScanConfig(**cfg), [T], session_factory=fake_factory(routes)).run()


def test_json_report_structure(fake_factory):
    rep = scan({T: FakeHTTPResponse(200, {"X-Powered-By": "PHP/8.4.26"}, "<html></html>")}, fake_factory)
    d = json.loads(to_json(rep))
    r = d["results"][0]
    assert r["php_version"] == "8.4.26"
    assert [f["classification"] for f in r["findings"]] == ["POTENTIALLY_VULNERABLE"] * 2
    assert d["advisories"]["CVE-2026-109618"]["ghsa"] == "GHSA-w8hw-w9fx-j79w"
    assert d["fixed_releases"]["8.4"] == "8.4.27"
    assert "INCONCLUSIVE" in d["classification_definitions"]
    assert set(d["signatures_used"]) == {"H1", "H4"}


def test_html_escapes_untrusted_content(fake_factory):
    body = f'<meta name="generator" content="WordPress {XSS}">'
    rep = scan({T: FakeHTTPResponse(200, {"X-Powered-By": f"PHP/8.4.1 {XSS}", "Content-Type": "text/html"}, body)},
               fake_factory)
    out = to_html(rep)
    assert XSS not in out
    assert "&lt;script&gt;" in out


def test_html_distinguishes_categories(fake_factory):
    routes = {T: FakeHTTPResponse(200, {"X-Powered-By": "PHP/8.4.26"}),
              "https://t.example/phpinfo.php": FakeHTTPResponse(200, {"Content-Type": "text/html"},
                                                                fixture_text("phpinfo_8.4.26.html"))}
    rep = scan(routes, fake_factory, phpinfo_urls=("https://t.example/phpinfo.php",))
    out = to_html(rep)
    for word in ("CONFIRMED_VULNERABLE", "POTENTIALLY_VULNERABLE", "INCONCLUSIVE", "LAB_ONLY", "REJECTED",
                 "GHSA-6wmf-4rv5-p3rp", "independently validated"):
        assert word in out
    assert "<title>PHP2Shell Exposure Assessment</title>" in out


def test_terminal_report_renders_and_is_markup_safe(fake_factory):
    rep = scan({T: FakeHTTPResponse(200, {"X-Powered-By": "PHP/[bold red]8.4.1"})}, fake_factory)
    console = Console(record=True, width=120)
    print_report(rep, console)
    text = console.export_text()
    assert "CVE-2026-109618" in text and "CVE-2026-109619" in text
    assert "Recommended next steps" in text


def test_signature_registry_renders():
    console = Console(record=True, width=140)
    print_signatures(console)
    text = console.export_text()
    for sid in ("H1", "H2", "H3", "H4", "H5"):
        assert sid in text
