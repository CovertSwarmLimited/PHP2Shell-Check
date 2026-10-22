#!/usr/bin/env python3
"""Local signature-validation harness (isolated lab only).

Runs every detection hypothesis against locally built vulnerable and patched
PHP binaries and records the results. Nothing here touches the network beyond
127.0.0.1. Build the binaries with lab/local/build_php.sh first.

    python lab/local/validate.py \
        --build 8.4.26=/path/inst-8.4.26 --build 8.4.27=/path/inst-8.4.27 \
        --repeat 5 --out research/results

H4 (patch-marker directive) is tested through the scanner's own code path:
php -S serves phpinfo() over HTTP and php2shell.scanner.Scanner classifies it.
H2 (upload-progress diagnostics) drives the vulnerable pre-RINIT path through
php-cgi. That is acceptable here only because the target is a local
throwaway process.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from php2shell.advisories import PATCH_MARKER_DIRECTIVE, fixed_release_for  # noqa: E402
from php2shell.config import ScanConfig  # noqa: E402
from php2shell.fingerprint import parse_bare_version, parse_phpinfo  # noqa: E402
from php2shell.scanner import Scanner  # noqa: E402

INI_PROFILES: dict[str, list[str]] = {
    "defaults(-n)": [],
    "expose_php=Off": ["-d", "expose_php=0"],
    "custom-limits": ["-d", "memory_limit=256M", "-d", "post_max_size=2M", "-d", "session.upload_progress.enabled=0"],
    "display_errors=On": ["-d", "display_errors=1", "-d", "error_reporting=-1"],
}

BOUNDARY = "---------------------------20896060251896012921717172737"
H2_BODY = (
    f"--{BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    "lab.php\r\n"
    f"--{BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="file1"; filename="file1.txt"\r\n\r\n'
    "1\r\n"
    f"--{BOUNDARY}--\r\n"
)


def expected_patched(version: str) -> bool:
    v = parse_bare_version(version)
    fixed = fixed_release_for(v.major, v.minor)
    return fixed is not None and v.base >= fixed


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not open")


def make_docroot(tmp: Path) -> Path:
    www = tmp / "www"
    www.mkdir()
    (www / "index.php").write_text('<?php echo "Hello World\\n";\n')
    (www / "session.php").write_text('<?php session_start(); echo "Hello World\\n";\n')
    (www / "phpinfo.php").write_text("<?php phpinfo();\n")
    (www / "lab.php").write_text(
        "<?php\nob_start();\nsession_start();\nvar_dump(session_id());\nvar_dump(isset($_SESSION) ? array_keys($_SESSION) : null);\n"
    )
    return www


def h4_cli(prefix: Path, profile: list[str]) -> dict:
    out = subprocess.run([prefix / "bin/php", "-n", *profile, "-i"], capture_output=True, text=True, timeout=30).stdout
    return {"marker_present": re.search(rf"^{PATCH_MARKER_DIRECTIVE} =>", out, re.M) is not None}


def h4_cgi(prefix: Path, www: Path, profile: list[str]) -> dict:
    env = {"PATH": os.environ.get("PATH", ""), "REDIRECT_STATUS": "1", "REQUEST_METHOD": "GET",
           "SCRIPT_FILENAME": str(www / "phpinfo.php")}
    out = subprocess.run([prefix / "bin/php-cgi", "-n", *profile], capture_output=True, text=True,
                         env=env, timeout=30).stdout
    info = parse_phpinfo(out, "cgi://phpinfo.php")
    return {"parsed": info is not None, "core_table": bool(info and info.core_table_parsed),
            "marker_present": bool(info and info.has_patch_marker),
            "version": info.version.raw if info and info.version else None}


def h4_http_scanner(prefix: Path, www: Path, profile: list[str]) -> dict:
    """Serve over HTTP and run the real scanner (H1 + H4 end to end)."""
    port = free_port()
    proc = subprocess.Popen([prefix / "bin/php", "-n", *profile, "-S", f"127.0.0.1:{port}", "-t", str(www)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_port(port)
        base = f"http://127.0.0.1:{port}/"
        cfg = ScanConfig(request_interval=0.2, timeout=5, phpinfo_urls=(base + "phpinfo.php",))
        with_info = Scanner(cfg, [base]).run().results[0]
        hdr_only = Scanner(ScanConfig(request_interval=0.2, timeout=5), [base]).run().results[0]
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    return {
        "with_phpinfo": {f.cve: f.classification.value for f in with_info.findings},
        "headers_only": {f.cve: f.classification.value for f in hdr_only.findings},
        "headers_only_version": hdr_only.php_version,
    }


def h2_upload_progress(prefix: Path, www: Path, profile: list[str]) -> dict:
    with tempfile.TemporaryDirectory() as sess:
        env = {
            "PATH": os.environ.get("PATH", ""), "REDIRECT_STATUS": "1", "REQUEST_METHOD": "POST",
            "SCRIPT_FILENAME": str(www / "lab.php"), "HTTP_COOKIE": "PHPSESSID=_",
            "CONTENT_TYPE": f"multipart/form-data; boundary={BOUNDARY}",
            "CONTENT_LENGTH": str(len(H2_BODY.encode())),
        }
        ini = ["-d", "display_errors=1", "-d", "error_reporting=-1", "-d", "html_errors=0",
               "-d", "file_uploads=1", "-d", f"session.save_path={sess}", "-d", "session.use_strict_mode=0",
               "-d", "session.upload_progress.enabled=1", "-d", "session.upload_progress.cleanup=0",
               "-d", "session.upload_progress.freq=0"]
        out = subprocess.run([prefix / "bin/php-cgi", "-n", *ini, *profile], input=H2_BODY, capture_output=True,
                             text=True, env=env, timeout=30).stdout
    return {
        "write_failure_warnings": out.count("Failed to write session data"),
        "illegal_sid_warnings": out.count("Session ID is too long or contains illegal characters"),
    }


def h5_benign_get(prefix: Path, www: Path) -> dict:
    """Headers and body of an ordinary GET, with version strings, dates and cookie values normalised."""
    port = free_port()
    proc = subprocess.Popen([prefix / "bin/php", "-n", "-S", f"127.0.0.1:{port}", "-t", str(www)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_port(port)
        res = {}
        for path in ("/index.php", "/session.php", "/missing.php"):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                s.sendall(f"GET {path} HTTP/1.0\r\nHost: lab\r\n\r\n".encode())
                data = b""
                while chunk := s.recv(65536):
                    data += chunk
            text = data.decode("latin-1")
            text = re.sub(r"\d+\.\d+\.\d+", "<ver>", text)
            text = re.sub(r"Date: [^\r\n]+", "Date: <date>", text)
            text = re.sub(r"PHPSESSID=[^;\r\n]+", "PHPSESSID=<sid>", text)
            res[path] = text
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", action="append", required=True, help="VERSION=PREFIX")
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--out", type=Path, default=ROOT / "research" / "results")
    args = ap.parse_args()

    builds = {}
    for b in args.build:
        ver, _, prefix = b.partition("=")
        builds[ver] = Path(prefix)

    results: dict = {"generated": datetime.now(UTC).isoformat(timespec="seconds"), "repeat": args.repeat,
                     "builds": {}, "h5_identical_by_branch": {}}
    with tempfile.TemporaryDirectory() as tmp:
        www = make_docroot(Path(tmp))
        h5 = {}
        for ver, prefix in builds.items():
            r: dict = {"expected_patched": expected_patched(ver), "h4_cli": {}, "h4_cgi": {}, "h4_http": {}, "h2": {}}
            for name, profile in INI_PROFILES.items():
                r["h4_cli"][name] = [h4_cli(prefix, profile) for _ in range(args.repeat)]
                r["h4_cgi"][name] = [h4_cgi(prefix, www, profile) for _ in range(args.repeat)]
                r["h4_http"][name] = [h4_http_scanner(prefix, www, profile) for _ in range(args.repeat)]
            r["h2"]["default"] = [h2_upload_progress(prefix, www, []) for _ in range(args.repeat)]
            h5[ver] = h5_benign_get(prefix, www)
            results["builds"][ver] = r
            print(f"{ver}: done", file=sys.stderr)
        # H5: compare vulnerable vs patched builds of the same branch.
        by_branch: dict[str, list[str]] = {}
        for ver in builds:
            by_branch.setdefault(".".join(ver.split(".")[:2]), []).append(ver)
        for branch, vers in by_branch.items():
            if len(vers) >= 2:
                results["h5_identical_by_branch"][branch] = {
                    path: len({h5[v][path] for v in vers}) == 1 for path in h5[vers[0]]
                }

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "lab_validation.json").write_text(json.dumps(results, indent=2) + "\n")
    (args.out / "lab_validation.md").write_text(summarise(results))
    print(summarise(results))
    return 0


def summarise(res: dict) -> str:
    lines = [f"# Lab validation results\n\nGenerated {res['generated']}, {res['repeat']} repetitions per cell.\n",
             "## H4: phpinfo() patch-marker directive\n",
             "| Build | Expected | INI profile | CLI marker | CGI marker | HTTP scanner (with phpinfo) | HTTP scanner (headers only) |",
             "|---|---|---|---|---|---|---|"]
    mismatches = 0
    for ver, r in res["builds"].items():
        exp = "patched" if r["expected_patched"] else "vulnerable"
        for prof in r["h4_cli"]:
            cli = {x["marker_present"] for x in r["h4_cli"][prof]}
            cgi = {x["marker_present"] for x in r["h4_cgi"][prof]}
            http = {json.dumps(x["with_phpinfo"], sort_keys=True) for x in r["h4_http"][prof]}
            hdr = {json.dumps(x["headers_only"], sort_keys=True) for x in r["h4_http"][prof]}
            ok = cli == {r["expected_patched"]} and cgi == {r["expected_patched"]}
            mismatches += 0 if ok else 1
            lines.append(f"| {ver} | {exp} | {prof} | {sorted(cli)} | {sorted(cgi)} | "
                         f"{'; '.join(sorted(set(v for h in http for v in json.loads(h).values())))} | "
                         f"{'; '.join(sorted(set(v for h in hdr for v in json.loads(h).values())))} |")
    lines.append(f"\nMarker mismatches against expectation: {mismatches}\n")
    lines.append("## H2: upload-progress diagnostics with invalid session ID (php-cgi, display_errors=On)\n")
    lines.append("| Build | Expected | 'Failed to write session data' count (per run) | Illegal-SID warnings |")
    lines.append("|---|---|---|---|")
    for ver, r in res["builds"].items():
        exp = "patched" if r["expected_patched"] else "vulnerable"
        w = sorted({x["write_failure_warnings"] for x in r["h2"]["default"]})
        i = sorted({x["illegal_sid_warnings"] for x in r["h2"]["default"]})
        lines.append(f"| {ver} | {exp} | {w} | {i} |")
    lines.append("\n## H5: ordinary GET responses identical after normalising version, date and SID\n")
    for branch, paths in res["h5_identical_by_branch"].items():
        lines.append(f"- {branch}: " + ", ".join(f"{p}: {'identical' if same else 'DIFFERENT'}"
                                                 for p, same in paths.items()))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
