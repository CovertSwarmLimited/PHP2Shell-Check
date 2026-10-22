"""Scan configuration and safety limits.

Every limit here is a ceiling enforced by :mod:`php2shell.transport`; the
defaults are deliberately conservative for authorised client assessments.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from php2shell import __version__

DEFAULT_USER_AGENT = f"php2shell-check/{__version__} (authorised security assessment; non-destructive)"

# Small, fixed list of well-known diagnostic pages. Only requested when the
# operator explicitly passes --check-info-paths; never enumerated beyond this.
COMMON_INFO_PATHS: tuple[str, ...] = ("/phpinfo.php", "/info.php")

# Hard ceilings that command-line options cannot exceed.
MAX_CONCURRENCY = 4
MAX_REQUESTS_PER_TARGET = 25
MIN_REQUEST_INTERVAL = 0.2
MAX_TIMEOUT = 60.0


@dataclass(slots=True)
class ScanConfig:
    timeout: float = 10.0
    """Connect and read timeout per request, in seconds."""

    max_requests_per_target: int = 8
    """Request budget per target, including redirect hops."""

    request_interval: float = 1.0
    """Minimum delay between two requests to the same host, in seconds."""

    concurrency: int = 1
    """Number of targets scanned in parallel."""

    max_redirects: int = 3
    max_body_bytes: int = 2 * 1024 * 1024

    error_threshold: int = 3
    """Consecutive 5xx responses or transport failures that stop a target."""

    user_agent: str = DEFAULT_USER_AGENT
    verify_tls: bool = True
    proxy: str | None = None

    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    """Extra hosts that redirects may lead to. Target hosts are always allowed."""

    phpinfo_urls: tuple[str, ...] = ()
    """Operator-supplied phpinfo() pages to parse (explicit, in scope only)."""

    check_info_paths: bool = False
    """Opt-in: request COMMON_INFO_PATHS on each target."""

    def validate(self) -> None:
        if not 0 < self.timeout <= MAX_TIMEOUT:
            raise ValueError(f"timeout must be in (0, {MAX_TIMEOUT}]")
        if not 1 <= self.max_requests_per_target <= MAX_REQUESTS_PER_TARGET:
            raise ValueError(f"max requests per target must be in [1, {MAX_REQUESTS_PER_TARGET}]")
        if self.request_interval < MIN_REQUEST_INTERVAL:
            raise ValueError(f"request interval must be at least {MIN_REQUEST_INTERVAL}s")
        if not 1 <= self.concurrency <= MAX_CONCURRENCY:
            raise ValueError(f"concurrency must be in [1, {MAX_CONCURRENCY}]")
        if not 0 <= self.max_redirects <= 5:
            raise ValueError("max redirects must be in [0, 5]")
        if self.error_threshold < 1:
            raise ValueError("error threshold must be at least 1")
