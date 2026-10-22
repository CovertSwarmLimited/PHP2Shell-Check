# php2shell-check

A standalone, non-destructive remote exposure assessment for the **PHP2Shell**
vulnerabilities:

| CVE | Advisory | Title | CVSS 4.0 |
|---|---|---|---|
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | RCE via OOM corruption | 9.2 |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | RCE via stale global state | 9.2 |

Fixed in PHP **8.2.35, 8.3.36, 8.4.27 and 8.5.12** (released 2026-10-21). Branches 8.1 and
older are end-of-life and get no upstream fix.

## Read this first: what the scanner can and cannot do

The research (see [`research/`](research/)) found that **no safe behavioural signature
exists for either CVE.** The fix changes PHP behaviour only on allocation failure,
fatal errors and pre-initialisation session upload progress. Benign requests behave
byte-identically on vulnerable and patched builds (lab-validated). Every
code-path-specific difference requires sending the attack-shaped requests the
advisories describe, so the scanner never does that.

The scanner therefore relies on evidence the server already discloses, and grades its
confidence:

| Evidence found | Result |
|---|---|
| Exposed `phpinfo()` with a complete Core table **without** `memory_hard_limit_percent` and an affected version | **CONFIRMED_VULNERABLE** |
| Exposed `phpinfo()` listing `memory_hard_limit_percent` (registered by the fix commit; also detects vendor backports) | **CONFIRMED_PATCHED** (HIGH) |
| Disclosed version at or above the fixed release | **CONFIRMED_PATCHED** (MEDIUM) |
| Disclosed version below the fixed release | **POTENTIALLY_VULNERABLE**. Vendor backports cannot be ruled out remotely. |
| PHP identified, version hidden; or nothing identified | **INCONCLUSIVE**. *Not* the same as "not vulnerable". |
| Non-PHP runtime positively identified, no PHP signal | **NOT_APPLICABLE** (for that URL only) |

On a well-hardened site the honest answer is usually INCONCLUSIVE. In that case, check
from the host (see [Host-side verification](#host-side-verification)).

## Installation

Requires Python 3.12+.

### Quick start: launcher script

`php2shell.sh` finds a suitable Python, checks the dependencies and starts the tool. If
anything is missing it offers to create `.venv` and install it.

```sh
./php2shell.sh check                      # environment report (Python, deps, optional lab tools)
./php2shell.sh setup                      # create .venv with runtime + test dependencies
./php2shell.sh scan --url https://example.com --confirm-authorised
./php2shell.sh research --show-signatures
./php2shell.sh test                       # offline test suite
```

Any arguments other than `check`, `setup` and `test` are passed to `python -m php2shell`.
The working directory is not changed, so relative `--targets` and `-o` paths work.

| Variable | Effect |
|---|---|
| `PHP2SHELL_PYTHON` | Interpreter to use when there is no `.venv` (must be 3.12+) |
| `PHP2SHELL_AUTO_INSTALL=1` | Install missing dependencies without prompting (CI and other non-interactive use) |

In a non-interactive shell without `PHP2SHELL_AUTO_INSTALL=1`, the launcher refuses to
install anything and tells you to run `setup`.

### Manual

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'      # runtime deps: requests, rich; dev: pytest
```

Or run in place without installing: `pip install requests rich` and then
`python -m php2shell ...`.

## Usage

```sh
# Single target (the default is one GET request per target)
python -m php2shell scan --url https://example.com --confirm-authorised

# Targets file: one URL per line, '#' comments allowed
python -m php2shell scan --targets targets.txt --confirm-authorised

# JSON and HTML client reports (format chosen by extension, repeatable)
python -m php2shell scan --url https://example.com -o report.json -o report.html --confirm-authorised

# Parse a phpinfo() page you already know is exposed (must share the target's origin)
python -m php2shell scan --url https://example.com --phpinfo-url https://example.com/info.php --confirm-authorised

# Opt in: also request /phpinfo.php and /info.php (2 extra GETs per target)
python -m php2shell scan --url https://example.com --check-info-paths --confirm-authorised

# Research data: advisories, signature registry and validation status
python -m php2shell research --show-signatures
python -m php2shell research --show-advisories
```

Without `--confirm-authorised` the scanner asks for interactive confirmation, and in
non-interactive mode it refuses to run.

### Options

| Option | Default | Notes |
|---|---|---|
| `--timeout` | 10 s | Connect and read timeout per request (max 60) |
| `--max-requests` | 8 | Request budget per target, including redirects (max 25) |
| `--interval` | 1.0 s | Minimum gap between requests to one host (min 0.2) |
| `--concurrency` | 1 | Targets scanned in parallel (max 4); the per-host interval still applies |
| `--max-redirects` | 3 | Only in-scope redirects are followed |
| `--error-threshold` | 3 | Stop a target after N consecutive 5xx or transport errors |
| `--allow-host` | none | Extra authorised host that redirects may reach (e.g. `www.` variant) |
| `--proxy` | none | Environment proxies, `.netrc` and similar settings are ignored |
| `--insecure` | off | Skip TLS verification |
| `-o/--output` | none | `.json` or `.html`, repeatable |
| `-q`, `-v` | | Quiet or verbose terminal output |

## Safety design

- **Explicit targets only.** http/https URLs; embedded credentials are rejected.
- **No enumeration.** By default one GET per target. phpinfo pages are fetched only when
  named by the operator, or with the explicit two-path `--check-info-paths` opt-in.
- **GET and HEAD only**, enforced in the transport layer. No POST, no multipart, no
  payloads of any kind.
- **SSRF guard.** Redirects are followed manually and every hop is scope-checked.
  Out-of-scope locations (other hosts, IP literals, cloud metadata, non-http schemes)
  are recorded and not followed.
- **Rate limiting** per host, a **request budget** per target, **timeouts**, and a 2 MB
  response cap.
- **Circuit breaker.** Repeated 5xx or transport errors stop all further requests to
  the target, and the report says so.
- **No escalation.** There is no active or behavioural probing mode at all. Hypotheses
  that need one are kept lab-only (see below).
- Cookie values are never written to reports (only their length). Anomalous PHPSESSID
  cookies the server sends on its own are flagged as a possible *indicator of
  compromise* (Wiz IOC), never as vulnerability evidence.

## Output

Each target lists: PHP detection confidence, PHP version (if disclosed), a separate
assessment for each CVE (classification, confidence, rationale), detection methods,
evidence (with source URL and whether it is lab-validated), assumptions, limitations,
exposure factors (SAPI, `session.upload_progress.enabled`, `fatal_error_backtraces`,
`memory_limit`; recorded but never used to downgrade), and recommended next steps.

Examples produced against the local lab: [`examples/`](examples/)
([terminal](examples/example_terminal_output.txt), [JSON](examples/example_report.json),
[HTML](examples/example_report.html)).

## Host-side verification

Use this when the remote result is POTENTIALLY_VULNERABLE or INCONCLUSIVE. Run it with
the PHP that serves the site:

```sh
php -i | grep -c memory_hard_limit_percent     # 1 = fix present, 0 = fix absent
```

For the web SAPI (FPM, mod_php), put this on a temporary, access-restricted page and
remove it afterwards:

```php
<?php var_dump(array_key_exists('memory_hard_limit_percent', ini_get_all(null, false)));
```

## Detection methods and validation

| ID | Signature | Status | Used remotely |
|---|---|---|---|
| H1 | Disclosed version vs fixed releases | VALIDATED | yes (never yields CONFIRMED_VULNERABLE alone) |
| H4 | `memory_hard_limit_percent` in phpinfo() | VALIDATED, 0 mismatches across 4 builds × 4 INI profiles × 3 SAPIs × 5 runs | yes (passive) |
| H2 | Upload-progress warning difference with invalid SID | LAB_ONLY (reproducible, but needs a multipart POST into the vulnerable path plus display_errors=On) | **no** |
| H3 | OOM message wording | REJECTED (needs induced OOM) | **no** |
| H5 | Differences on benign requests | REJECTED (lab: byte-identical) | **no** |

Full write-ups: [`research/detection_hypotheses.md`](research/detection_hypotheses.md).
Raw results: [`research/results/`](research/results/).

## Local validation lab

The lab is optional and independent of the scanner. Never expose it publicly.

**Source builds (no Docker; used for the published results):**

```sh
lab/local/build_php.sh /opt/php2shell-lab 8.4.26 8.4.27 8.5.11 8.5.12
python lab/local/validate.py --repeat 5 \
  --build 8.4.26=/opt/php2shell-lab/inst-8.4.26 --build 8.4.27=/opt/php2shell-lab/inst-8.4.27 \
  --build 8.5.11=/opt/php2shell-lab/inst-8.5.11 --build 8.5.12=/opt/php2shell-lab/inst-8.5.12
```

This runs H4 (CLI, CGI, HTTP through the real scanner), H2 (php-cgi, local only) and H5,
and writes `research/results/lab_validation.{md,json}`.

**Docker (Apache mod_php and nginx + PHP-FPM; ports bound to 127.0.0.1):**

```sh
docker compose -f lab/docker/docker-compose.yml up -d
python lab/docker/validate_docker.py --repeat 3
```

The Docker lab is provided but **was not executed** in the research environment (no
Docker available). Run it before relying on H4 results for mod_php or FPM targets.

## Tests

```sh
python -m pytest                       # unit + local integration, fully offline
PHP2SHELL_LAB_BUILDS="8.4.26=/opt/php2shell-lab/inst-8.4.26,8.4.27=/opt/php2shell-lab/inst-8.4.27" \
  python -m pytest tests/integration/test_lab_builds.py   # optional, against real PHP
```

Coverage includes fingerprinting, hidden versions, version parsing, vendor backports,
the classification matrix, false-positive prevention, timeouts, redirects (including
SSRF attempts), rate limiting, budgets, the circuit breaker, unreachable targets,
non-PHP sites, HTML escaping and report contents. Real phpinfo() fixtures from each lab
build are in `tests/fixtures/`.

## Limitations

See [`research/limitations.md`](research/limitations.md). In short: hidden versions
give INCONCLUSIVE; version strings cannot exclude vendor backports; phpinfo pages may
belong to a different runtime than the application; CDNs can alter headers; and
exploitability preconditions (SAPI, worker model, configuration) are reported but not
assessed.

## Project layout

```
php2shell/       scanner package (cli, scanner, transport, fingerprint, behavioural,
                 detection, confidence, reporting, config, advisories)
research/        vulnerability, patch and detection analysis; limitations; lab results
lab/local/       source-build lab and validation harness
lab/docker/      Docker lab (mod_php, FPM)
tests/           unit/, integration/, fixtures/
examples/        sample terminal, JSON and HTML output
```
