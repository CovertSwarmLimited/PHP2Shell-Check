from __future__ import annotations

from pathlib import Path

import pytest
import requests

from php2shell.transport import HttpResponse

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def make_response(url="https://t.example/", status=200, headers=None, cookies=None, body="",
                  method="GET") -> HttpResponse:
    return HttpResponse(
        url=url, method=method, status=status,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        set_cookies=list(cookies or []), body=body, truncated=False, elapsed=0.01,
    )


class _RawHeaders:
    def __init__(self, cookies):
        self._cookies = cookies

    def getlist(self, name):
        return list(self._cookies) if name.lower() == "set-cookie" else []


class FakeHTTPResponse:
    def __init__(self, status=200, headers=None, body=b"", cookies=()):
        self.status_code = status
        self.headers = requests.structures.CaseInsensitiveDict(headers or {})
        self.raw = type("Raw", (), {"headers": _RawHeaders(cookies)})()
        self._body = body if isinstance(body, bytes) else body.encode()
        self.encoding = "utf-8"
        self.closed = False

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    """Offline stand-in for requests.Session. Routes are {url: FakeHTTPResponse | Exception | callable}."""

    def __init__(self, routes):
        self.routes = routes
        self.calls: list[tuple[str, str, dict]] = []
        self.headers = requests.structures.CaseInsensitiveDict()
        self.proxies = {}
        self.trust_env = True

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        r = self.routes.get(url)
        if r is None:
            return FakeHTTPResponse(404, {"Content-Type": "text/html"}, b"not found")
        if callable(r) and not isinstance(r, FakeHTTPResponse):
            r = r()
        if isinstance(r, Exception):
            raise r
        return r

    def close(self):
        pass


@pytest.fixture
def fake_factory():
    """Return (factory, sessions) so tests can inspect the requests made."""
    sessions: list[FakeSession] = []

    def build(routes):
        def factory():
            s = FakeSession(routes)
            sessions.append(s)
            return s
        return factory

    build.sessions = sessions
    return build
