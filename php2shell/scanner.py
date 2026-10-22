"""Scan orchestration: passive collection, then classification."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

from php2shell import __version__
from php2shell.behavioural import enabled_signatures, observe_session_cookie_anomalies
from php2shell.config import COMMON_INFO_PATHS, ScanConfig
from php2shell.confidence import Evidence, EvidenceKind, PhpDetection, assess_php_presence
from php2shell.detection import Finding, VersionObservation, assess_target
from php2shell.fingerprint import (
    PhpInfo,
    extract_signals,
    parse_php_version,
    parse_phpinfo,
    phpinfo_evidence,
)
from php2shell.transport import (
    BudgetExceeded,
    HttpResponse,
    Scope,
    TargetSession,
    TargetUnstable,
    Transport,
    TransportError,
    normalise_host,
)

log = logging.getLogger(__name__)


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, normalise_host(parts.hostname or ""), port


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(slots=True)
class TargetResult:
    target: str
    started: str
    finished: str = ""
    reachable: bool = False
    final_url: str | None = None
    http_status: int | None = None
    error: str | None = None
    php: PhpDetection | None = None
    php_version: str | None = None
    versions: list[VersionObservation] = field(default_factory=list)
    phpinfo_pages: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    anomalies: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    methods_executed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    requests: list[dict] = field(default_factory=list)
    stopped_reason: str | None = None
    phpinfos: list[PhpInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        php = self.php
        return {
            "target": self.target,
            "started": self.started,
            "finished": self.finished,
            "reachable": self.reachable,
            "final_url": self.final_url,
            "http_status": self.http_status,
            "error": self.error,
            "php_detection": {
                "detected": php.detected if php else False,
                "confidence": php.confidence.value if php else "NONE",
                "score": php.score if php else 0.0,
                "evidence": [e.to_dict() for e in php.evidence] if php else [],
                "non_php_evidence": [e.to_dict() for e in php.non_php_evidence] if php else [],
            },
            "php_version": self.php_version,
            "version_observations": [
                {"version": o.version.raw, "method": o.method, "url": o.url,
                 "vendor": o.version.vendor, "backport_possible": o.version.backport_possible}
                for o in self.versions
            ],
            "phpinfo_pages": self.phpinfo_pages,
            "findings": [f.to_dict() for f in self.findings],
            "anomalies": [e.to_dict() for e in self.anomalies],
            "environment_evidence": [e.to_dict() for e in self.evidence
                                     if e.kind in (EvidenceKind.ENVIRONMENT, EvidenceKind.CONFIGURATION)],
            "methods_executed": self.methods_executed,
            "notes": self.notes,
            "requests": self.requests,
            "stopped_reason": self.stopped_reason,
        }


@dataclass(slots=True)
class ScanReport:
    tool_version: str
    started: str
    finished: str
    config: dict
    results: list[TargetResult]

    def to_dict(self) -> dict:
        from php2shell.advisories import ADVISORIES, FIXED_RELEASES, format_version

        return {
            "tool": "php2shell-check",
            "tool_version": self.tool_version,
            "started": self.started,
            "finished": self.finished,
            "config": self.config,
            "advisories": {
                cve: {"ghsa": a.ghsa, "title": a.title, "cvss": a.cvss, "references": list(a.references)}
                for cve, a in ADVISORIES.items()
            },
            "fixed_releases": {f"{k[0]}.{k[1]}": format_version(v) for k, v in FIXED_RELEASES.items()},
            "signatures_used": [s.id for s in enabled_signatures()],
            "results": [r.to_dict() for r in self.results],
        }


class Scanner:
    def __init__(self, config: ScanConfig, targets: list[str], session_factory=None):
        config.validate()
        self.config = config
        self.targets = targets
        self.scope = Scope.from_targets(targets, config.allowed_hosts)
        target_origins = {_origin(t) for t in targets}
        for u in config.phpinfo_urls:
            self.scope.check(u)
            if _origin(u) not in target_origins:
                raise ValueError(f"phpinfo URL {u} does not share an origin (scheme, host, port) with any target")
        kwargs = {"session_factory": session_factory} if session_factory else {}
        self.transport = Transport(config, self.scope, **kwargs)

    def run(self) -> ScanReport:
        started = _now()
        with ThreadPoolExecutor(max_workers=self.config.concurrency) as pool:
            results = list(pool.map(self.scan_target, self.targets))
        return ScanReport(
            tool_version=__version__,
            started=started,
            finished=_now(),
            config={
                "timeout": self.config.timeout,
                "max_requests_per_target": self.config.max_requests_per_target,
                "request_interval": self.config.request_interval,
                "concurrency": self.config.concurrency,
                "max_redirects": self.config.max_redirects,
                "error_threshold": self.config.error_threshold,
                "check_info_paths": self.config.check_info_paths,
                "phpinfo_urls": list(self.config.phpinfo_urls),
                "verify_tls": self.config.verify_tls,
            },
            results=results,
        )

    def scan_target(self, target: str) -> TargetResult:
        result = TargetResult(target=target, started=_now())
        session = self.transport.session_for(target)
        try:
            self._collect(session, target, result)
        finally:
            session.close()
            result.requests = session.log
            result.stopped_reason = session.stopped_reason
            result.finished = _now()

        transport_notes = list(result.notes)
        if result.stopped_reason:
            transport_notes.append(result.stopped_reason)
        result.php = assess_php_presence(result.evidence)
        result.findings = assess_target(
            target, result.php, result.evidence, result.versions,
            result.phpinfos, result.reachable, transport_notes,
        )
        if result.versions:
            result.php_version = result.versions[0].version.raw
        return result

    def _collect(self, session: TargetSession, target: str, result: TargetResult) -> None:
        result.methods_executed.append("passive.get-target")
        resp = self._fetch(session, target, result)
        if resp is None:
            return
        result.reachable = True
        result.final_url = resp.url
        result.http_status = resp.status
        self._analyse(resp, result)

        extra: list[tuple[str, str]] = []
        # phpinfo pages belong to a target only when served from the same origin:
        # another port on the same host is usually a different service.
        origin = _origin(target)
        for u in self.config.phpinfo_urls:
            if _origin(u) == origin:
                extra.append(("operator.phpinfo-url", u))
        if self.config.check_info_paths:
            base = f"{urlsplit(target).scheme}://{urlsplit(target).netloc}"
            for path in COMMON_INFO_PATHS:
                extra.append(("opt-in.info-path", urljoin(base, path)))

        seen = {target, resp.url}
        for method, url in extra:
            if url in seen:
                continue
            seen.add(url)
            if method not in result.methods_executed:
                result.methods_executed.append(method)
            r = self._fetch(session, url, result)
            if r is None:
                if session.stopped_reason:
                    break
                continue
            if r.status == 200:
                self._analyse(r, result)

    def _fetch(self, session: TargetSession, url: str, result: TargetResult) -> HttpResponse | None:
        try:
            resp = session.get(url)
        except (TargetUnstable, BudgetExceeded) as exc:
            result.notes.append(f"{url}: not requested ({exc})")
            return None
        except TransportError as exc:
            if result.error is None and url == result.target:
                result.error = str(exc)
            result.notes.append(f"{url}: {exc}")
            return None
        if resp.blocked_redirect:
            result.notes.append(
                f"{url}: redirect to out-of-scope {resp.blocked_redirect} not followed. "
                "Add the host with --allow-host if it is authorised.")
        return resp

    def _analyse(self, resp: HttpResponse, result: TargetResult) -> None:
        info = parse_phpinfo(resp.body, resp.url)
        if info is not None:
            result.phpinfos.append(info)
            result.phpinfo_pages.append(resp.url)
            result.evidence.extend(phpinfo_evidence(info))
            if info.version:
                result.versions.append(VersionObservation(info.version, "phpinfo", resp.url))
            if not info.core_table_parsed:
                result.notes.append(f"{resp.url}: phpinfo() output is incomplete (no full Core directive "
                                    "table), so the patch-marker check was not applied")
        signals = extract_signals(resp)
        result.evidence.extend(signals)
        for e in signals:
            if e.kind is EvidenceKind.PHP_VERSION:
                v = parse_php_version(e.observed)
                if v:
                    result.versions.append(VersionObservation(v, e.method, resp.url))
        result.anomalies.extend(observe_session_cookie_anomalies(resp))
