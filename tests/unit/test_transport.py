import time

import pytest
import requests

from php2shell.config import ScanConfig
from php2shell.transport import (
    BudgetExceeded,
    Scope,
    ScopeError,
    TargetUnstable,
    Transport,
    TransportError,
    validate_target_url,
)
from tests.conftest import FakeHTTPResponse

T = "https://t.example/"


def transport(routes, fake_factory, **cfg):
    cfg.setdefault("request_interval", 0.2)
    config = ScanConfig(**cfg)
    return Transport(config, Scope.from_targets([T]), session_factory=fake_factory(routes))


@pytest.mark.parametrize("url", ["ftp://t.example/", "file:///etc/passwd", "gopher://x/", "//t.example/",
                                 "https://user:pw@t.example/", "javascript:alert(1)", "https:///nohost"])
def test_invalid_targets_rejected(url):
    with pytest.raises(ValueError):
        validate_target_url(url)


def test_target_normalised():
    assert validate_target_url(" https://T.example ") == "https://T.example/"


def test_scope_rejects_other_hosts():
    s = Scope.from_targets([T])
    s.check("http://t.example:8080/x")
    for u in ("https://evil.example/", "https://t.example.evil.example/", "https://169.254.169.254/",
              "file:///etc/passwd", "https://a:b@t.example/"):
        with pytest.raises(ScopeError):
            s.check(u)


def test_only_get_and_head(fake_factory):
    ts = transport({}, fake_factory).session_for(T)
    for m in ("POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"):
        with pytest.raises(TransportError):
            ts.request(m, T)
    assert ts.requests_sent == 0


def test_env_proxies_ignored_and_headers_set(fake_factory):
    ts = transport({T: FakeHTTPResponse(200)}, fake_factory).session_for(T)
    ts.get(T)
    s = fake_factory.sessions[0]
    assert s.trust_env is False
    assert "php2shell" in s.headers["User-Agent"]
    method, url, kwargs = s.calls[0]
    assert kwargs["allow_redirects"] is False
    assert kwargs["timeout"] == (10.0, 10.0)


def test_in_scope_redirect_followed(fake_factory):
    routes = {T: FakeHTTPResponse(301, {"Location": "/home"}),
              "https://t.example/home": FakeHTTPResponse(200, {"X-Powered-By": "PHP/8.4.1"}, "ok")}
    r = transport(routes, fake_factory).session_for(T).get(T)
    assert r.status == 200 and r.url == "https://t.example/home"
    assert r.redirect_chain == [T]


def test_out_of_scope_redirect_not_followed(fake_factory):
    routes = {T: FakeHTTPResponse(302, {"Location": "http://169.254.169.254/latest/meta-data/"})}
    ts = transport(routes, fake_factory).session_for(T)
    r = ts.get(T)
    assert r.status == 302
    assert r.blocked_redirect == "http://169.254.169.254/latest/meta-data/"
    assert [c[1] for c in fake_factory.sessions[0].calls] == [T]


def test_redirect_to_other_scheme_blocked(fake_factory):
    routes = {T: FakeHTTPResponse(302, {"Location": "file:///etc/passwd"})}
    r = transport(routes, fake_factory).session_for(T).get(T)
    assert r.blocked_redirect == "file:///etc/passwd"


def test_redirect_loop_limited(fake_factory):
    routes = {T: FakeHTTPResponse(302, {"Location": T})}
    ts = transport(routes, fake_factory, max_redirects=2).session_for(T)
    with pytest.raises(TransportError):
        ts.get(T)
    assert ts.requests_sent == 3


def test_request_budget(fake_factory):
    ts = transport({T: FakeHTTPResponse(200)}, fake_factory, max_requests_per_target=2).session_for(T)
    ts.get(T)
    ts.get(T)
    with pytest.raises(BudgetExceeded):
        ts.get(T)
    assert len(fake_factory.sessions[0].calls) == 2


def test_circuit_breaker_on_5xx(fake_factory):
    ts = transport({T: FakeHTTPResponse(503)}, fake_factory, error_threshold=3).session_for(T)
    for _ in range(3):
        assert ts.get(T).status == 503
    with pytest.raises(TargetUnstable):
        ts.get(T)
    assert len(fake_factory.sessions[0].calls) == 3
    assert "unstable" in ts.stopped_reason


def test_circuit_breaker_resets_on_success(fake_factory):
    seq = iter([FakeHTTPResponse(500), FakeHTTPResponse(500), FakeHTTPResponse(200), FakeHTTPResponse(500)])
    ts = transport({T: lambda: next(seq)}, fake_factory, error_threshold=3).session_for(T)
    for _ in range(4):
        ts.get(T)
    assert ts.stopped_reason is None


def test_timeout_counts_as_failure(fake_factory):
    ts = transport({T: requests.Timeout("read timed out")}, fake_factory, error_threshold=2).session_for(T)
    for _ in range(2):
        with pytest.raises(TransportError):
            ts.get(T)
    with pytest.raises(TargetUnstable):
        ts.get(T)


def test_body_cap(fake_factory):
    big = FakeHTTPResponse(200, {"Content-Type": "text/html"}, b"a" * 100_000)
    ts = transport({T: big}, fake_factory, ).session_for(T)
    ts.config.max_body_bytes = 1000
    r = ts.get(T)
    assert len(r.body) == 1000 and r.truncated


def test_rate_limiting(fake_factory):
    ts = transport({T: FakeHTTPResponse(200)}, fake_factory, request_interval=0.25).session_for(T)
    start = time.monotonic()
    for _ in range(3):
        ts.get(T)
    assert time.monotonic() - start >= 0.45


@pytest.mark.parametrize("kw", [{"timeout": 0}, {"timeout": 1000}, {"concurrency": 50},
                                {"max_requests_per_target": 1000}, {"request_interval": 0.0},
                                {"max_redirects": 50}, {"error_threshold": 0}])
def test_config_ceilings(kw):
    with pytest.raises(ValueError):
        ScanConfig(**kw).validate()


def test_set_cookie_list_preserved(fake_factory):
    r = FakeHTTPResponse(200, {}, b"", cookies=["a=1", "PHPSESSID=x"])
    out = transport({T: r}, fake_factory).session_for(T).get(T)
    assert out.set_cookies == ["a=1", "PHPSESSID=x"]
