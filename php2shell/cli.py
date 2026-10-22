"""Command-line interface."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from rich.console import Console

from php2shell import __version__
from php2shell.config import (
    COMMON_INFO_PATHS,
    MAX_CONCURRENCY,
    MAX_REQUESTS_PER_TARGET,
    MIN_REQUEST_INTERVAL,
    ScanConfig,
)
from php2shell.transport import validate_target_url


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="php2shell",
        description="Non-destructive remote exposure assessment for CVE-2026-109618 and CVE-2026-109619.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Assess explicitly authorised targets")
    tgt = s.add_argument_group("targets (explicit authorisation required)")
    tgt.add_argument("--url", action="append", default=[], help="Target URL (repeatable)")
    tgt.add_argument("--targets", type=Path, help="File with one target URL per line ('#' comments allowed)")
    tgt.add_argument("--allow-host", action="append", default=[], metavar="HOST",
                     help="Additional authorised host that redirects may lead to (repeatable)")
    tgt.add_argument("--confirm-authorised", action="store_true",
                     help="Confirm you are authorised to test every target (skips the interactive prompt)")

    act = s.add_argument_group("optional checks (all passive GET requests)")
    act.add_argument("--phpinfo-url", action="append", default=[], metavar="URL",
                     help="Known, already-exposed phpinfo() page on a target host to parse (repeatable)")
    act.add_argument("--check-info-paths", action="store_true",
                     help=f"Also request {', '.join(COMMON_INFO_PATHS)} on each target (opt-in)")

    lim = s.add_argument_group("safety limits")
    lim.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default 10)")
    lim.add_argument("--max-requests", type=int, default=8,
                     help=f"Request budget per target (default 8, max {MAX_REQUESTS_PER_TARGET})")
    lim.add_argument("--interval", type=float, default=1.0,
                     help=f"Minimum seconds between requests to one host (default 1.0, min {MIN_REQUEST_INTERVAL})")
    lim.add_argument("--concurrency", type=int, default=1,
                     help=f"Targets scanned in parallel (default 1, max {MAX_CONCURRENCY})")
    lim.add_argument("--max-redirects", type=int, default=3, help="Maximum in-scope redirects (default 3)")
    lim.add_argument("--error-threshold", type=int, default=3,
                     help="Stop a target after this many consecutive 5xx or transport errors (default 3)")

    net = s.add_argument_group("network")
    net.add_argument("--proxy", help="HTTP(S) proxy URL (environment proxies are ignored)")
    net.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    net.add_argument("--user-agent", help="Override the User-Agent header")

    out = s.add_argument_group("output")
    out.add_argument("--output", "-o", action="append", default=[], type=Path,
                     help="Write report; format from extension (.json or .html). Repeatable.")
    out.add_argument("--quiet", "-q", action="store_true", help="No terminal report")
    out.add_argument("--verbose", "-v", action="store_true", help="Show transport notes")

    r = sub.add_parser("research", help="Show research data built into the scanner")
    r.add_argument("--show-signatures", action="store_true", help="Detection signature registry and status")
    r.add_argument("--show-advisories", action="store_true", help="Advisory summary and fixed releases")
    return p


def _load_targets(args, parser) -> list[str]:
    raw: list[str] = list(args.url)
    if args.targets:
        try:
            for line in args.targets.read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    raw.append(line)
        except OSError as exc:
            parser.error(f"cannot read targets file: {exc}")
    if not raw:
        parser.error("no targets: use --url or --targets")
    targets: list[str] = []
    for t in raw:
        try:
            norm = validate_target_url(t)
        except ValueError as exc:
            parser.error(str(exc))
        if norm not in targets:
            targets.append(norm)
    return targets


def _confirm(targets: list[str], args, console: Console) -> bool:
    if args.confirm_authorised:
        return True
    if not sys.stdin.isatty():
        console.print("[red]Refusing to scan: pass --confirm-authorised to confirm authorisation "
                      "for every target.[/red]")
        return False
    console.print("[bold]Targets:[/bold]")
    for t in targets:
        console.print(f"  {t}", markup=False)
    answer = console.input("Are you authorised to assess all of these targets? [y/N] ")
    return answer.strip().lower() in ("y", "yes")


def _scan(args, parser) -> int:
    from php2shell.reporting import print_report, write_html, write_json
    from php2shell.scanner import Scanner

    console = Console(stderr=args.quiet)
    targets = _load_targets(args, parser)
    phpinfo_urls = []
    for u in args.phpinfo_url:
        try:
            phpinfo_urls.append(validate_target_url(u))
        except ValueError as exc:
            parser.error(str(exc))
    for o in args.output:
        if o.suffix.lower() not in (".json", ".html", ".htm"):
            parser.error(f"unsupported output format for {o}: use .json or .html")

    config = ScanConfig(
        timeout=args.timeout,
        max_requests_per_target=args.max_requests,
        request_interval=args.interval,
        concurrency=args.concurrency,
        max_redirects=args.max_redirects,
        error_threshold=args.error_threshold,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        allowed_hosts=frozenset(args.allow_host),
        phpinfo_urls=tuple(phpinfo_urls),
        check_info_paths=args.check_info_paths,
    )
    if args.user_agent:
        config.user_agent = args.user_agent
    try:
        config.validate()
    except ValueError as exc:
        parser.error(str(exc))

    if not _confirm(targets, args, console):
        return 2

    try:
        scanner = Scanner(config, targets)
    except Exception as exc:  # scope errors for phpinfo URLs etc.
        parser.error(str(exc))
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    report = scanner.run()
    if not args.quiet:
        print_report(report, console, verbose=args.verbose)
    for o in args.output:
        if o.suffix.lower() == ".json":
            write_json(report, o)
        else:
            write_html(report, o)
        console.print(f"Report written to {o}", markup=False)
    return 0


def _research(args) -> int:
    from php2shell.reporting import print_advisories, print_signatures

    console = Console()
    if not (args.show_signatures or args.show_advisories):
        args.show_signatures = args.show_advisories = True
    if args.show_advisories:
        print_advisories(console)
    if args.show_signatures:
        print_signatures(console)
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args, parser)
    return _research(args)


if __name__ == "__main__":
    sys.exit(main())
