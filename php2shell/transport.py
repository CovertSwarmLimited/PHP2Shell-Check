"""Safety-enforcing HTTP transport.

All network access in the scanner goes through :class:`TargetSession`, which
enforces:

* scope: only explicitly authorised hosts, http/https, no URL credentials;
* redirects are followed manually and every hop is scope-checked (SSRF guard);
* only GET and HEAD;
* per-host rate limiting, per-target request budget and timeouts;
* response body size cap;
* a circuit breaker that stops a target after repeated 5xx or transport errors.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests

from php2shell.config import ScanConfig

ALLOWED_METHODS = frozenset({"GET", "HEAD"})
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class TransportError(Exception):
    """Base class for transport refusals and failures."""


class ScopeError(TransportError):
    """A request or redirect would leave the authorised scope."""


class BudgetExceeded(TransportError):
    """The per-target request budget is exhausted."""


class TargetUnstable(TransportError):
    """The circuit breaker tripped. No further requests are sent to this target."""


def normalise_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def validate_target_url(url: str) -> str:
    """Return a normalised target URL or raise ValueError."""
    url = url.strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme in {url!r}: only http and https are allowed")
    if not parts.hostname:
        raise ValueError(f"no host in {url!r}")
    if parts.username or parts.password:
        raise ValueError(f"credentials embedded in {url!r} are not accepted")
    try:
        parts.port
    except ValueError as exc:
        raise ValueError(f"invalid port in {url!r}") from exc
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{parts.netloc}{path}{query}"


class Scope:
    """The set of hosts the operator has authorised."""

    def __init__(self, hosts: Iterable[str]):
        self._hosts = frozenset(normalise_host(h) for h in hosts)

    @classmethod
    def from_targets(cls, targets: Iterable[str], extra_hosts: Iterable[str] = ()) -> Scope:
        hosts = [urlsplit(t).hostname or "" for t in targets]
        return cls([h for h in [*hosts, *extra_hosts] if h])

    @property
    def hosts(self) -> frozenset[str]:
        return self._hosts

    def check(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ScopeError(f"scheme {parts.scheme!r} is not allowed: {url}")
        if parts.username or parts.password:
            raise ScopeError(f"credentials in URL are not allowed: {url}")
        host = normalise_host(parts.hostname or "")
        if host not in self._hosts:
            raise ScopeError(f"host {host!r} is not an authorised target")


@dataclass(slots=True)
class HttpResponse:
    url: str
    method: str
    status: int
    headers: dict[str, str]
    """Header names are lower-cased. Repeated headers are joined with ', '."""
    set_cookies: list[str]
    body: str
    truncated: bool
    elapsed: float
    redirect_chain: list[str] = field(default_factory=list)
    blocked_redirect: str | None = None
    """Out-of-scope Location that was not followed (the 3xx response is returned)."""

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class _RateLimiter:
    """Enforces a minimum interval between requests to the same host."""

    def __init__(self, interval: float):
        self._interval = interval
        self._lock = threading.Lock()
        self._next_slot: dict[str, float] = {}

    def wait(self, host: str) -> None:
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot.get(host, 0.0))
            self._next_slot[host] = slot + self._interval
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class Transport:
    """Shared transport for a scan; hands out one :class:`TargetSession` per target."""

    def __init__(self, config: ScanConfig, scope: Scope, session_factory=requests.Session):
        config.validate()
        self.config = config
        self.scope = scope
        self._limiter = _RateLimiter(config.request_interval)
        self._session_factory = session_factory

    def session_for(self, target: str) -> TargetSession:
        self.scope.check(target)
        return TargetSession(self, target)

    def _make_session(self) -> requests.Session:
        s = self._session_factory()
        # Never pick up proxies, .netrc credentials or CA overrides from the environment.
        s.trust_env = False
        if self.config.proxy:
            s.proxies = {"http": self.config.proxy, "https": self.config.proxy}
        s.headers.clear()
        s.headers.update({
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        })
        return s


class TargetSession:
    """Budgeted, scope-checked HTTP access to a single target."""

    def __init__(self, transport: Transport, target: str):
        self._t = transport
        self.target = target
        self.requests_sent = 0
        self.consecutive_errors = 0
        self.stopped_reason: str | None = None
        self.log: list[dict] = []
        self._session = transport._make_session()

    @property
    def config(self) -> ScanConfig:
        return self._t.config

    def close(self) -> None:
        self._session.close()

    def get(self, url: str) -> HttpResponse:
        return self.request("GET", url)

    def head(self, url: str) -> HttpResponse:
        return self.request("HEAD", url)

    def request(self, method: str, url: str) -> HttpResponse:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise TransportError(f"method {method} is not permitted by this scanner")
        chain: list[str] = []
        current = url
        for _ in range(self.config.max_redirects + 1):
            resp = self._send_once(method, current)
            if resp.status in REDIRECT_CODES and resp.header("location"):
                nxt = urljoin(current, resp.header("location"))
                chain.append(current)
                try:
                    self._t.scope.check(nxt)
                except ScopeError as exc:
                    self._log(method, nxt, None, f"redirect not followed: {exc}")
                    resp.redirect_chain = chain[:-1]
                    resp.blocked_redirect = nxt
                    return resp
                current = nxt
                if resp.status == 303:
                    method = "GET"
                continue
            resp.redirect_chain = chain
            return resp
        raise TransportError(f"too many redirects (> {self.config.max_redirects}) starting at {url}")

    def _send_once(self, method: str, url: str) -> HttpResponse:
        if self.stopped_reason:
            raise TargetUnstable(self.stopped_reason)
        self._t.scope.check(url)
        if self.requests_sent >= self.config.max_requests_per_target:
            raise BudgetExceeded(f"request budget of {self.config.max_requests_per_target} exhausted")

        host = normalise_host(urlsplit(url).hostname or "")
        self._t._limiter.wait(host)
        self.requests_sent += 1
        started = time.monotonic()
        try:
            r = self._session.request(
                method,
                url,
                allow_redirects=False,
                timeout=(self.config.timeout, self.config.timeout),
                verify=self.config.verify_tls,
                stream=True,
            )
        except requests.RequestException as exc:
            self._log(method, url, None, f"{type(exc).__name__}: {exc}")
            self._record_failure(f"transport error: {type(exc).__name__}")
            raise TransportError(f"{method} {url} failed: {type(exc).__name__}: {exc}") from exc

        try:
            body, truncated = self._read_body(r, method)
        except requests.RequestException as exc:
            r.close()
            self._log(method, url, r.status_code, f"body read failed: {exc}")
            self._record_failure(f"transport error while reading body: {type(exc).__name__}")
            raise TransportError(f"{method} {url} body read failed: {exc}") from exc
        finally:
            r.close()

        elapsed = time.monotonic() - started
        headers: dict[str, str] = {}
        for k, v in r.headers.items():
            headers[k.lower()] = v
        set_cookies = _raw_set_cookies(r)

        if r.status_code >= 500:
            self._record_failure(f"HTTP {r.status_code}")
        else:
            self.consecutive_errors = 0

        self._log(method, url, r.status_code, None, elapsed)
        return HttpResponse(
            url=url,
            method=method,
            status=r.status_code,
            headers=headers,
            set_cookies=set_cookies,
            body=body,
            truncated=truncated,
            elapsed=elapsed,
        )

    def _read_body(self, r: requests.Response, method: str) -> tuple[str, bool]:
        if method == "HEAD":
            return "", False
        cap = self.config.max_body_bytes
        chunks: list[bytes] = []
        size = 0
        truncated = False
        for chunk in r.iter_content(chunk_size=16384):
            chunks.append(chunk)
            size += len(chunk)
            if size >= cap:
                truncated = True
                break
        raw = b"".join(chunks)[:cap]
        encoding = r.encoding or "utf-8"
        try:
            return raw.decode(encoding, errors="replace"), truncated
        except LookupError:
            return raw.decode("utf-8", errors="replace"), truncated

    def _record_failure(self, reason: str) -> None:
        self.consecutive_errors += 1
        if self.consecutive_errors >= self.config.error_threshold:
            self.stopped_reason = (
                f"stopped after {self.consecutive_errors} consecutive errors (last: {reason}); "
                "the target may be unstable, so no further requests were sent"
            )

    def _log(self, method, url, status, error, elapsed=None) -> None:
        self.log.append({
            "method": method,
            "url": url,
            "status": status,
            "error": error,
            "elapsed": round(elapsed, 3) if elapsed is not None else None,
        })


def _raw_set_cookies(r: requests.Response) -> list[str]:
    raw_headers = getattr(getattr(r, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        return list(raw_headers.getlist("Set-Cookie"))
    value = r.headers.get("Set-Cookie")
    return [value] if value else []
