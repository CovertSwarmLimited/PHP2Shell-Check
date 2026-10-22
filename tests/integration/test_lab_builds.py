"""Optional: scan real PHP builds served on 127.0.0.1 by `php -S`.

Enable with PHP2SHELL_LAB_BUILDS="8.4.26=/opt/php-8.4.26,8.4.27=/opt/php-8.4.27"
(install prefixes built by lab/local/build_php.sh). Skipped otherwise.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from php2shell.advisories import fixed_release_for
from php2shell.config import ScanConfig
from php2shell.confidence import Classification as C
from php2shell.fingerprint import parse_bare_version
from php2shell.scanner import Scanner

BUILDS = [b.split("=", 1) for b in os.environ.get("PHP2SHELL_LAB_BUILDS", "").split(",") if "=" in b]

pytestmark = [pytest.mark.lab, pytest.mark.skipif(not BUILDS, reason="PHP2SHELL_LAB_BUILDS not set")]


def _port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.parametrize("version,prefix", BUILDS)
@pytest.mark.parametrize("expose", ["1", "0"])
def test_real_build(version, prefix, expose, tmp_path):
    (tmp_path / "index.php").write_text('<?php session_start(); echo "Hello World";')
    (tmp_path / "phpinfo.php").write_text("<?php phpinfo();")
    port = _port()
    proc = subprocess.Popen([Path(prefix) / "bin/php", "-n", "-d", f"expose_php={expose}", "-S",
                             f"127.0.0.1:{port}", "-t", str(tmp_path)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
                break
            except OSError:
                time.sleep(0.05)
        base = f"http://127.0.0.1:{port}/"
        v = parse_bare_version(version)
        patched = v.base >= fixed_release_for(*v.branch)

        r = Scanner(ScanConfig(request_interval=0.2, timeout=5, phpinfo_urls=(base + "phpinfo.php",)),
                    [base]).run().results[0]
        expected = C.CONFIRMED_PATCHED if patched else C.CONFIRMED_VULNERABLE
        assert {f.classification for f in r.findings} == {expected}

        r = Scanner(ScanConfig(request_interval=0.2, timeout=5), [base]).run().results[0]
        if expose == "0":
            assert {f.classification for f in r.findings} == {C.INCONCLUSIVE}
        else:
            assert {f.classification for f in r.findings} == {
                C.CONFIRMED_PATCHED if patched else C.POTENTIALLY_VULNERABLE}
    finally:
        proc.terminate()
        proc.wait(timeout=5)
