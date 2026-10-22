"""End-to-end tests against a local HTTP server on 127.0.0.1 (no internet access)."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from php2shell.config import ScanConfig
from php2shell.confidence import Classification as C
from php2shell.reporting import to_html, to_json
from php2shell.scanner import Scanner
from tests.conftest import fixture_text

PHPINFO_VULN = fixture_text("phpinfo_8.4.26.html")
PHPINFO_FIXED = fixture_text("phpinfo_8.4.27.html")


class Handler(BaseHTTPRequestHandler):
    hits: list[tuple[str, str]] = []
    error_count = 0

    def log_message(self, *a):
        pass

    def _send(self, status, headers=(), body=b""):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        Handler.hits.append(("POST", self.path))
        self._send(405)

    def do_GET(self):
        Handler.hits.append((self.command, self.path))
        p = self.path
        html = ("Content-Type", "text/html; charset=UTF-8")
        if p == "/php-old":
            self._send(200, [html, ("X-Powered-By", "PHP/8.3.20"),
                             ("Set-Cookie", "PHPSESSID=abcdefabcdefabcdefabcdef12; path=/")], b"<html>hi</html>")
        elif p == "/php-new":
            self._send(200, [html, ("X-Powered-By", "PHP/8.3.36")], b"<html>hi</html>")
        elif p == "/php-hidden":
            self._send(200, [html, ("Set-Cookie", "PHPSESSID=abcdefabcdefabcdefabcdef12; path=/")],
                       b'<html><a href="/index.php">home</a></html>')
        elif p == "/ubuntu":
            self._send(200, [html, ("X-Powered-By", "PHP/8.1.2-1ubuntu2.22")], b"<html></html>")
        elif p == "/aspnet":
            self._send(200, [html, ("X-Powered-By", "ASP.NET"), ("X-AspNet-Version", "4.0.30319")], b"<html></html>")
        elif p == "/static":
            self._send(200, [html, ("Server", "nginx")], b"<html>static</html>")
        elif p == "/phpinfo-vuln.php":
            self._send(200, [html], PHPINFO_VULN.encode())
        elif p == "/phpinfo-fixed.php":
            self._send(200, [html], PHPINFO_FIXED.encode())
        elif p == "/redirect-internal":
            self._send(302, [("Location", "/php-old")])
        elif p == "/redirect-external":
            self._send(302, [("Location", "http://169.254.169.254/latest/meta-data/")])
        elif p == "/redirect-localhost":
            self._send(302, [("Location", f"http://localhost:{self.server.server_address[1]}/php-old")])
        elif p == "/error":
            self._send(500, [html], b"<html>error</html>")
        elif p == "/slow":
            time.sleep(2.5)
            self._send(200, [html], b"late")
        else:
            self._send(404, [html], b"<html>not found</html>")


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(autouse=True)
def reset_hits():
    Handler.hits = []


def scan(urls, **cfg):
    cfg.setdefault("request_interval", 0.2)
    cfg.setdefault("timeout", 5)
    return Scanner(ScanConfig(**cfg), urls).run()


def classes(result):
    return {f.classification for f in result.findings}


def test_old_php(server):
    r = scan([server + "/php-old"]).results[0]
    assert r.php_version == "8.3.20"
    assert classes(r) == {C.POTENTIALLY_VULNERABLE}


def test_new_php(server):
    assert classes(scan([server + "/php-new"]).results[0]) == {C.CONFIRMED_PATCHED}


def test_hidden_version(server):
    r = scan([server + "/php-hidden"]).results[0]
    assert r.php.detected and r.php_version is None
    assert classes(r) == {C.INCONCLUSIVE}


def test_vendor_backport_possible(server):
    r = scan([server + "/ubuntu"]).results[0]
    assert classes(r) == {C.POTENTIALLY_VULNERABLE}
    assert r.findings[0].confidence.value == "MEDIUM"


def test_non_php(server):
    assert classes(scan([server + "/aspnet"]).results[0]) == {C.NOT_APPLICABLE}


def test_static_site_inconclusive(server):
    r = scan([server + "/static"]).results[0]
    assert not r.php.detected
    assert classes(r) == {C.INCONCLUSIVE}


def test_phpinfo_confirms_vulnerable(server):
    r = scan([server + "/php-old"], phpinfo_urls=(server + "/phpinfo-vuln.php",)).results[0]
    assert classes(r) == {C.CONFIRMED_VULNERABLE}


def test_phpinfo_confirms_patched(server):
    r = scan([server + "/php-hidden"], phpinfo_urls=(server + "/phpinfo-fixed.php",)).results[0]
    assert classes(r) == {C.CONFIRMED_PATCHED}


def test_internal_redirect_followed(server):
    r = scan([server + "/redirect-internal"]).results[0]
    assert r.final_url.endswith("/php-old") and r.php_version == "8.3.20"


def test_external_redirect_not_followed(server):
    r = scan([server + "/redirect-external"]).results[0]
    assert r.http_status == 302
    assert any("not followed" in n for n in r.notes)
    assert [p for _, p in Handler.hits] == ["/redirect-external"]


def test_redirect_to_different_hostname_blocked(server):
    r = scan([server + "/redirect-localhost"]).results[0]
    assert r.http_status == 302
    assert all(p != "/php-old" for _, p in Handler.hits)


def test_server_errors_stop_scan(server):
    r = scan([server + "/error"], check_info_paths=True, error_threshold=1).results[0]
    assert r.stopped_reason
    assert len(Handler.hits) == 1


def test_timeout(server):
    start = time.monotonic()
    r = scan([server + "/slow"], timeout=1).results[0]
    assert time.monotonic() - start < 2.4
    assert not r.reachable and "Timeout" in (r.error or "")
    assert classes(r) == {C.INCONCLUSIVE}


def test_unreachable_target():
    r = scan(["http://127.0.0.1:9/"], timeout=1).results[0]
    assert not r.reachable
    assert classes(r) == {C.INCONCLUSIVE}


def test_only_get_requests_sent(server):
    scan([server + "/php-old", server + "/php-hidden"], check_info_paths=True,
         phpinfo_urls=(server + "/phpinfo-vuln.php",))
    assert Handler.hits and {m for m, _ in Handler.hits} == {"GET"}


def test_rate_limit_across_targets_same_host(server):
    start = time.monotonic()
    scan([server + "/php-old", server + "/php-new", server + "/static"], request_interval=0.3, concurrency=3)
    assert time.monotonic() - start >= 0.55


def test_reports_render(server):
    rep = scan([server + "/php-old"], phpinfo_urls=(server + "/phpinfo-vuln.php",))
    assert '"CONFIRMED_VULNERABLE"' in to_json(rep)
    assert "CONFIRMED_VULNERABLE" in to_html(rep)
