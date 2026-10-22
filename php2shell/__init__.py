"""PHP2Shell remote exposure assessment for CVE-2026-109618 and CVE-2026-109619.

The scanner is evidence-driven and non-destructive by default. It never sends
exploit payloads, never triggers out-of-memory conditions and never probes the
vulnerable request-parsing code paths on remote hosts.
"""

__version__ = "1.0.0"
