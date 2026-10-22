#!/usr/bin/env python3
"""Run the scanner against the Docker lab (127.0.0.1 only) and check expectations.

    docker compose -f lab/docker/docker-compose.yml up -d
    python lab/docker/validate_docker.py --repeat 5
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from php2shell.config import ScanConfig  # noqa: E402
from php2shell.confidence import Classification as C  # noqa: E402
from php2shell.scanner import Scanner  # noqa: E402

SERVICES = {
    # port: (label, patched?)
    18101: ("apache mod_php 8.4.26", False),
    18102: ("apache mod_php 8.4.27", True),
    18103: ("apache mod_php 8.5.11", False),
    18104: ("apache mod_php 8.5.12", True),
    18111: ("nginx+fpm 8.4.26", False),
    18112: ("nginx+fpm 8.4.27", True),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=3)
    args = ap.parse_args()
    failures = 0
    for port, (label, patched) in SERVICES.items():
        base = f"http://127.0.0.1:{port}/"
        for _ in range(args.repeat):
            cfg = ScanConfig(request_interval=0.2, timeout=5, phpinfo_urls=(base + "phpinfo.php",))
            r = Scanner(cfg, [base]).run().results[0]
            got = {f.classification for f in r.findings}
            want = {C.CONFIRMED_PATCHED if patched else C.CONFIRMED_VULNERABLE}
            ok = got == want
            failures += not ok
            print(f"{'OK  ' if ok else 'FAIL'} {label:24} version={r.php_version} "
                  f"got={sorted(g.value for g in got)} reachable={r.reachable}")
    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
