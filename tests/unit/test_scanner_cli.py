import pytest

from php2shell.behavioural import SIGNATURES, enabled_signatures
from php2shell.cli import main
from php2shell.config import ScanConfig
from php2shell.confidence import Classification as C
from php2shell.scanner import Scanner
from php2shell.transport import ScopeError
from tests.conftest import FakeHTTPResponse, fixture_text

T = "https://t.example/"


def test_default_scan_is_single_get(fake_factory):
    Scanner(ScanConfig(request_interval=0.2), [T],
            session_factory=fake_factory({T: FakeHTTPResponse(200)})).run()
    calls = fake_factory.sessions[0].calls
    assert [(m, u) for m, u, _ in calls] == [("GET", T)]


def test_info_paths_only_when_opted_in(fake_factory):
    routes = {T: FakeHTTPResponse(200),
              "https://t.example/phpinfo.php": FakeHTTPResponse(200, {"Content-Type": "text/html"},
                                                                fixture_text("phpinfo_8.4.27.html"))}
    rep = Scanner(ScanConfig(request_interval=0.2, check_info_paths=True), [T],
                  session_factory=fake_factory(routes)).run()
    urls = [u for _, u, _ in fake_factory.sessions[0].calls]
    assert urls == [T, "https://t.example/phpinfo.php", "https://t.example/info.php"]
    r = rep.results[0]
    assert "opt-in.info-path" in r.methods_executed
    assert {f.classification for f in r.findings} == {C.CONFIRMED_PATCHED}


def test_target_url_itself_is_phpinfo(fake_factory):
    rep = Scanner(ScanConfig(request_interval=0.2), [T], session_factory=fake_factory(
        {T: FakeHTTPResponse(200, {"Content-Type": "text/html"}, fixture_text("phpinfo_8.5.11.html"))})).run()
    assert {f.classification for f in rep.results[0].findings} == {C.CONFIRMED_VULNERABLE}


def test_phpinfo_url_must_be_in_scope():
    with pytest.raises(ScopeError):
        Scanner(ScanConfig(phpinfo_urls=("https://other.example/phpinfo.php",)), [T])


def test_unstable_target_stops(fake_factory):
    rep = Scanner(ScanConfig(request_interval=0.2, check_info_paths=True, error_threshold=2,
                             phpinfo_urls=("https://t.example/a.php",)), [T],
                  session_factory=fake_factory({T: FakeHTTPResponse(500),
                                                "https://t.example/a.php": FakeHTTPResponse(500)})).run()
    r = rep.results[0]
    assert r.stopped_reason
    assert len(fake_factory.sessions[0].calls) == 2


def test_unreachable_target(fake_factory):
    import requests
    rep = Scanner(ScanConfig(request_interval=0.2), [T],
                  session_factory=fake_factory({T: requests.ConnectionError("refused")})).run()
    r = rep.results[0]
    assert not r.reachable and r.error
    assert {f.classification for f in r.findings} == {C.INCONCLUSIVE}


def test_only_safe_signatures_enabled():
    enabled = enabled_signatures()
    assert {s.id for s in enabled} == {"H1", "H4"}
    for s in SIGNATURES:
        if not s.safe_for_remote:
            assert not s.enabled_in_scanner


def test_cli_refuses_without_authorisation(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["scan", "--url", "https://t.example/"]) == 2


@pytest.mark.parametrize("argv", [
    ["scan"],
    ["scan", "--url", "ftp://x.example/", "--confirm-authorised"],
    ["scan", "--url", "https://x.example/", "--concurrency", "99", "--confirm-authorised"],
    ["scan", "--url", "https://x.example/", "--interval", "0", "--confirm-authorised"],
    ["scan", "--url", "https://x.example/", "-o", "report.txt", "--confirm-authorised"],
    ["scan", "--url", "https://x.example/", "--phpinfo-url", "https://y.example/i.php", "--confirm-authorised"],
])
def test_cli_usage_errors(argv):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_cli_targets_file(tmp_path, monkeypatch):
    f = tmp_path / "t.txt"
    f.write_text("# comment\nhttps://a.example/\n\nhttps://a.example/  # dup\nhttps://b.example/x\n")
    seen = {}

    class Dummy:
        def __init__(self, config, targets):
            seen["targets"] = targets

        def run(self):
            from php2shell.scanner import ScanReport
            return ScanReport("t", "s", "f", {}, [])

    monkeypatch.setattr("php2shell.scanner.Scanner", Dummy)
    assert main(["scan", "--targets", str(f), "--confirm-authorised", "-q"]) == 0
    assert seen["targets"] == ["https://a.example/", "https://b.example/x"]


def test_research_command(capsys):
    assert main(["research", "--show-signatures"]) == 0
    out = capsys.readouterr().out
    assert "memory_hard_limit_percent" in out and "LAB_ONLY" in out


def test_phpinfo_url_matched_by_origin_not_host(fake_factory):
    a, b = "https://t.example/", "https://t.example:8443/"
    routes = {a: FakeHTTPResponse(200), b: FakeHTTPResponse(200),
              "https://t.example:8443/i.php": FakeHTTPResponse(200, {"Content-Type": "text/html"},
                                                               fixture_text("phpinfo_8.4.26.html"))}
    rep = Scanner(ScanConfig(request_interval=0.2, phpinfo_urls=("https://t.example:8443/i.php",)), [a, b],
                  session_factory=fake_factory(routes)).run()
    first, second = rep.results
    assert first.phpinfo_pages == [] and {f.classification for f in first.findings} == {C.INCONCLUSIVE}
    assert {f.classification for f in second.findings} == {C.CONFIRMED_VULNERABLE}
