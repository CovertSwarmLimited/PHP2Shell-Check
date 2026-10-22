"""Terminal (Rich), JSON and HTML reporting."""

from __future__ import annotations

import html
import json
from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from php2shell.advisories import ADVISORIES, CVES, FIXED_RELEASES, format_version
from php2shell.behavioural import SIGNATURES
from php2shell.confidence import CLASSIFICATION_MEANING, Classification, EvidenceKind
from php2shell.scanner import ScanReport

STYLE = {
    Classification.CONFIRMED_VULNERABLE: "bold white on red",
    Classification.POTENTIALLY_VULNERABLE: "bold yellow",
    Classification.INCONCLUSIVE: "cyan",
    Classification.CONFIRMED_PATCHED: "bold green",
    Classification.NOT_APPLICABLE: "dim",
}

DISCLAIMER = (
    "This assessment is evidence-based and non-destructive. No safe, validated behavioural "
    "signature exists for these vulnerabilities, so remote conclusions rest on disclosed version "
    "information and existing phpinfo() output. INCONCLUSIVE does not mean 'not vulnerable'."
)


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------

def print_report(report: ScanReport, console: Console | None = None, verbose: bool = False) -> None:
    console = console or Console()
    for r in report.results:
        php = r.php
        head = Table.grid(padding=(0, 2))
        head.add_column(style="bold")
        head.add_column()
        head.add_row("Target", Text(r.target))
        if r.final_url and r.final_url != r.target:
            head.add_row("Final URL", Text(r.final_url))
        head.add_row("HTTP status", str(r.http_status) if r.http_status else Text(r.error or "n/a", style="red"))
        head.add_row("PHP detected", f"{php.confidence.value} (score {php.score})" if php else "n/a")
        head.add_row("PHP version", Text(r.php_version or "not disclosed"))
        if r.phpinfo_pages:
            head.add_row("phpinfo()", Text(", ".join(r.phpinfo_pages)))
        head.add_row("Requests sent", str(len(r.requests)))
        if r.stopped_reason:
            head.add_row("Stopped", Text(r.stopped_reason, style="red"))

        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("CVE", no_wrap=True)
        table.add_column("Assessment", no_wrap=True)
        table.add_column("Confidence", no_wrap=True)
        table.add_column("Rationale", ratio=1)
        for f in r.findings:
            table.add_row(f.cve, Text(f.classification.value, style=STYLE[f.classification]),
                          f.confidence.value, Text(f.rationale))

        parts = [head, table]
        ev_table = Table(title="Supporting evidence", show_header=True, header_style="bold", expand=True)
        ev_table.add_column("Method", ratio=2, overflow="fold")
        ev_table.add_column("Observation", ratio=4)
        ev_table.add_column("Value", ratio=3, overflow="fold")
        rows = [*(php.evidence if php else []), *(php.non_php_evidence if php else []),
                *(e for e in r.evidence if e.kind not in (EvidenceKind.PHP_PRESENCE, EvidenceKind.NON_PHP))]
        seen_rows = set()
        for e in rows:
            key = (e.method, e.description, e.observed)
            if key in seen_rows:
                continue
            seen_rows.add(key)
            ev_table.add_row(e.method, Text(e.description), Text(e.observed))
        if rows:
            parts.append(ev_table)

        if r.anomalies:
            an = Table(title="Anomalies (indicators, not vulnerability evidence)", expand=True)
            an.add_column("Observation")
            an.add_column("Value")
            for e in r.anomalies:
                an.add_row(Text(e.description), Text(e.observed))
            parts.append(an)

        steps = []
        seen = set()
        for f in r.findings:
            for s in f.next_steps:
                if s not in seen:
                    seen.add(s)
                    steps.append(s)
        if steps:
            parts.append(Text("Recommended next steps", style="bold"))
            for s in steps:
                parts.append(Text("• " + s))

        if verbose:
            notes = [*r.notes]
            if notes:
                parts.append(Text("Notes", style="bold"))
                for n in notes:
                    parts.append(Text("• " + n, style="dim"))

        console.print(Panel(Group(*parts), title=Text(r.target, style="bold"), border_style="blue"))
    console.print(Text(DISCLAIMER, style="dim italic"))


def print_signatures(console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title="Detection signature registry", show_header=True, header_style="bold", expand=True)
    for col in ("ID", "Name", "CVEs", "Status", "Remote-safe", "In scanner"):
        table.add_column(col)
    for s in SIGNATURES:
        table.add_row(s.id, Text(s.name), ", ".join(s.cves), s.status.value,
                      "yes" if s.safe_for_remote else "no", "yes" if s.enabled_in_scanner else "no")
    console.print(table)
    for s in SIGNATURES:
        body = Table.grid(padding=(0, 2))
        body.add_column(style="bold", no_wrap=True)
        body.add_column()
        for label, val in (("Hypothesis", s.hypothesis), ("Code path", s.code_path),
                           ("Vulnerable", s.vulnerable_behaviour), ("Patched", s.patched_behaviour),
                           ("Requires", s.requirements), ("FP risk", s.false_positive_risk),
                           ("FN risk", s.false_negative_risk), ("Validation", s.validation)):
            body.add_row(label, Text(val))
        console.print(Panel(body, title=Text(f"{s.id}: {s.name} [{s.status.value}]")))


def print_advisories(console: Console | None = None) -> None:
    console = console or Console()
    for cve in CVES:
        a = ADVISORIES[cve]
        body = Text()
        body.append(f"{a.ghsa} | {a.title}\nCVSS {a.cvss}\n{', '.join(a.cwe)}\n\n", style="bold")
        body.append(a.summary + "\n\nMitigations:\n")
        for m in a.mitigations:
            body.append(f"  • {m}\n")
        body.append("\nReferences:\n")
        for ref in a.references:
            body.append(f"  {ref}\n")
        console.print(Panel(body, title=cve))
    fixed = ", ".join(format_version(v) for v in FIXED_RELEASES.values())
    console.print(f"Fixed releases: {fixed}. Branches older than 8.2 receive no upstream fix.")


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def to_json(report: ScanReport) -> str:
    d = report.to_dict()
    d["disclaimer"] = DISCLAIMER
    d["classification_definitions"] = {k.value: v for k, v in CLASSIFICATION_MEANING.items()}
    return json.dumps(d, indent=2, ensure_ascii=False)


def write_json(report: ScanReport, path: Path) -> None:
    path.write_text(to_json(report) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def _e(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


_CSS = """
:root{--bg:#fff;--fg:#1c1f24;--muted:#5d6670;--line:#dfe3e8;--card:#f7f8fa;
--vuln:#b42318;--pot:#b54708;--inc:#175cd3;--ok:#067647;--na:#667085}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e6e8eb;--muted:#9aa3ad;--line:#2b3036;
--card:#1a1d21;--vuln:#f97066;--pot:#fdb022;--inc:#84adff;--ok:#47cd89;--na:#98a2b3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:32px 16px}h1{font-size:26px;margin:0 0 4px}
h2{font-size:20px;margin:36px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
h3{font-size:16px;margin:20px 0 8px}.muted{color:var(--muted)}
table{width:100%;border-collapse:collapse;margin:8px 0 16px;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:7px 9px;border-bottom:1px solid var(--line)}
th{font-weight:600;background:var(--card)}code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;
font-size:13px;word-break:break-all}.card{background:var(--card);border:1px solid var(--line);
border-radius:8px;padding:16px;margin:14px 0}.badge{display:inline-block;padding:2px 8px;border-radius:4px;
font-weight:600;font-size:12px;border:1px solid currentColor;white-space:nowrap}
.CONFIRMED_VULNERABLE{color:var(--vuln)}.POTENTIALLY_VULNERABLE{color:var(--pot)}
.INCONCLUSIVE{color:var(--inc)}.CONFIRMED_PATCHED{color:var(--ok)}.NOT_APPLICABLE{color:var(--na)}
.summary td:first-child{width:38%}ul{margin:6px 0 10px;padding-left:20px}
.wrap{overflow-x:auto}details{margin:8px 0}summary{cursor:pointer;color:var(--muted)}
"""


def to_html(report: ScanReport) -> str:
    d = report.to_dict()
    out: list[str] = []
    w = out.append
    w("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    w("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    w("<title>PHP2Shell Exposure Assessment</title>")
    w(f"<style>{_CSS}</style></head><body><main>")
    w("<h1>PHP2Shell Exposure Assessment</h1>")
    w(f"<p class='muted'>CVE-2026-109618 and CVE-2026-109619 | php2shell-check {_e(d['tool_version'])} | "
      f"scan {_e(d['started'])} to {_e(d['finished'])} UTC</p>")
    w(f"<div class='card'>{_e(DISCLAIMER)}</div>")

    # Executive summary
    w("<h2>Summary</h2><div class='wrap'><table><tr><th>Target</th><th>PHP</th><th>Version</th>")
    for cve in CVES:
        w(f"<th>{_e(cve)}</th>")
    w("</tr>")
    for r in d["results"]:
        pd = r["php_detection"]
        w(f"<tr><td class='mono'>{_e(r['target'])}</td><td>{_e(pd['confidence'])}</td>"
          f"<td class='mono'>{_e(r['php_version'] or 'not disclosed')}</td>")
        for f in r["findings"]:
            w(f"<td><span class='badge {_e(f['classification'])}'>{_e(f['classification'])}</span></td>")
        w("</tr>")
    w("</table></div>")

    counts: dict[str, int] = {}
    for r in d["results"]:
        for f in r["findings"]:
            counts[f["classification"]] = counts.get(f["classification"], 0) + 1
    w("<table class='summary'><tr><th>Classification</th><th>Findings</th><th>Meaning</th></tr>")
    for cls, meaning in CLASSIFICATION_MEANING.items():
        w(f"<tr><td><span class='badge {cls.value}'>{cls.value}</span></td>"
          f"<td>{counts.get(cls.value, 0)}</td><td>{_e(meaning)}</td></tr>")
    w("</table>")

    # Per-target details
    w("<h2>Findings by target</h2>")
    for r in d["results"]:
        w(f"<div class='card'><h3 class='mono'>{_e(r['target'])}</h3>")
        meta = [("Final URL", r["final_url"]), ("HTTP status", r["http_status"]), ("Error", r["error"]),
                ("PHP detection", f"{r['php_detection']['confidence']} (score {r['php_detection']['score']})"),
                ("PHP version", r["php_version"] or "not disclosed"),
                ("phpinfo() pages", ", ".join(r["phpinfo_pages"]) or "none"),
                ("Methods executed", ", ".join(r["methods_executed"])),
                ("Requests sent", len(r["requests"])), ("Stopped", r["stopped_reason"])]
        w("<table>")
        for k, v in meta:
            if v not in (None, ""):
                w(f"<tr><th style='width:22%'>{_e(k)}</th><td class='mono'>{_e(v)}</td></tr>")
        w("</table>")
        for f in r["findings"]:
            cls = f["classification"]
            w(f"<h3>{_e(f['cve'])}: <span class='badge {_e(cls)}'>{_e(cls)}</span> "
              f"<span class='muted'>confidence {_e(f['confidence'])}"
              f"{' | independently validated' if f['independently_validated'] else ''}</span></h3>")
            w(f"<p>{_e(f['rationale'])}</p>")
            if f["evidence"]:
                w("<div class='wrap'><table><tr><th>Method</th><th>Evidence</th><th>Observed</th>"
                  "<th>Source</th><th>Lab-validated</th></tr>")
                for e in f["evidence"]:
                    w(f"<tr><td class='mono'>{_e(e['method'])}</td><td>{_e(e['description'])}</td>"
                      f"<td class='mono'>{_e(e['observed'])}</td><td class='mono'>{_e(e['source_url'])}</td>"
                      f"<td>{'yes' if e['validated'] else 'no'}</td></tr>")
                w("</table></div>")
            for title, key in (("Exposure factors", "exposure_factors"), ("Assumptions", "assumptions"),
                               ("Recommended next steps", "next_steps")):
                if f[key]:
                    w(f"<strong>{_e(title)}</strong><ul>" + "".join(f"<li>{_e(x)}</li>" for x in f[key]) + "</ul>")
            w("<details><summary>Limitations</summary><ul>"
              + "".join(f"<li>{_e(x)}</li>" for x in f["limitations"]) + "</ul></details>")
        if r["anomalies"]:
            w("<strong>Anomalies (indicators, not vulnerability evidence)</strong><ul>"
              + "".join(f"<li>{_e(a['description'])}: <code>{_e(a['observed'])}</code></li>" for a in r["anomalies"])
              + "</ul>")
        env = r["environment_evidence"]
        if env:
            w("<details><summary>Environment and configuration observations</summary><ul>"
              + "".join(f"<li>{_e(e['description'])}: <code>{_e(e['observed'])}</code></li>" for e in env)
              + "</ul></details>")
        w("<details><summary>Request log</summary><div class='wrap'><table><tr><th>Method</th><th>URL</th>"
          "<th>Status</th><th>Error</th></tr>"
          + "".join(f"<tr><td>{_e(q['method'])}</td><td class='mono'>{_e(q['url'])}</td>"
                    f"<td>{_e(q['status'])}</td><td>{_e(q['error'])}</td></tr>" for q in r["requests"])
          + "</table></div></details></div>")

    # Signatures
    w("<h2>Detection methods and their validation status</h2><div class='wrap'><table>"
      "<tr><th>ID</th><th>Signature</th><th>Status</th><th>Used remotely</th><th>Validation</th></tr>")
    for s in SIGNATURES:
        w(f"<tr><td>{_e(s.id)}</td><td>{_e(s.name)}</td><td>{_e(s.status.value)}</td>"
          f"<td>{'yes' if s.enabled_in_scanner else 'no'}</td><td>{_e(s.validation)}</td></tr>")
    w("</table></div><p class='muted'>Only passive, lab-validated methods run against remote targets. "
      "LAB_ONLY and REJECTED hypotheses are unverified for remote use or unsafe, and none of them "
      "contributed to any finding.</p>")

    # Advisories
    w("<h2>Advisory references</h2>")
    for cve in CVES:
        a = ADVISORIES[cve]
        w(f"<div class='card'><h3>{_e(cve)} / {_e(a.ghsa)}: {_e(a.title)}</h3>"
          f"<p class='muted'>CVSS {_e(a.cvss)} | {_e(', '.join(a.cwe))}</p><p>{_e(a.summary)}</p>"
          "<strong>Mitigations</strong><ul>" + "".join(f"<li>{_e(m)}</li>" for m in a.mitigations) + "</ul>"
          "<strong>References</strong><ul>"
          + "".join(f"<li><a href='{_e(u)}'>{_e(u)}</a></li>" for u in a.references) + "</ul></div>")
    w("<p>Fixed releases: " + _e(", ".join(format_version(v) for v in FIXED_RELEASES.values()))
      + ". Branches older than 8.2 are end-of-life and receive no upstream fix.</p>")
    w("</main></body></html>")
    return "\n".join(out)


def write_html(report: ScanReport, path: Path) -> None:
    path.write_text(to_html(report), encoding="utf-8")
