# Lab validation results

Generated 2026-10-21T20:32:09+00:00, 5 repetitions per cell.

## H4: phpinfo() patch-marker directive

| Build | Expected | INI profile | CLI marker | CGI marker | HTTP scanner (with phpinfo) | HTTP scanner (headers only) |
|---|---|---|---|---|---|---|
| 8.4.26 | vulnerable | defaults(-n) | [False] | [False] | CONFIRMED_VULNERABLE | POTENTIALLY_VULNERABLE |
| 8.4.26 | vulnerable | expose_php=Off | [False] | [False] | CONFIRMED_VULNERABLE | INCONCLUSIVE |
| 8.4.26 | vulnerable | custom-limits | [False] | [False] | CONFIRMED_VULNERABLE | POTENTIALLY_VULNERABLE |
| 8.4.26 | vulnerable | display_errors=On | [False] | [False] | CONFIRMED_VULNERABLE | POTENTIALLY_VULNERABLE |
| 8.4.27 | patched | defaults(-n) | [True] | [True] | CONFIRMED_PATCHED | CONFIRMED_PATCHED |
| 8.4.27 | patched | expose_php=Off | [True] | [True] | CONFIRMED_PATCHED | INCONCLUSIVE |
| 8.4.27 | patched | custom-limits | [True] | [True] | CONFIRMED_PATCHED | CONFIRMED_PATCHED |
| 8.4.27 | patched | display_errors=On | [True] | [True] | CONFIRMED_PATCHED | CONFIRMED_PATCHED |
| 8.5.11 | vulnerable | defaults(-n) | [False] | [False] | CONFIRMED_VULNERABLE | POTENTIALLY_VULNERABLE |
| 8.5.11 | vulnerable | expose_php=Off | [False] | [False] | CONFIRMED_VULNERABLE | INCONCLUSIVE |
| 8.5.11 | vulnerable | custom-limits | [False] | [False] | CONFIRMED_VULNERABLE | POTENTIALLY_VULNERABLE |
| 8.5.11 | vulnerable | display_errors=On | [False] | [False] | CONFIRMED_VULNERABLE | POTENTIALLY_VULNERABLE |
| 8.5.12 | patched | defaults(-n) | [True] | [True] | CONFIRMED_PATCHED | CONFIRMED_PATCHED |
| 8.5.12 | patched | expose_php=Off | [True] | [True] | CONFIRMED_PATCHED | INCONCLUSIVE |
| 8.5.12 | patched | custom-limits | [True] | [True] | CONFIRMED_PATCHED | CONFIRMED_PATCHED |
| 8.5.12 | patched | display_errors=On | [True] | [True] | CONFIRMED_PATCHED | CONFIRMED_PATCHED |

Marker mismatches against expectation: 0

## H2: upload-progress diagnostics with invalid session ID (php-cgi, display_errors=On)

| Build | Expected | 'Failed to write session data' count (per run) | Illegal-SID warnings |
|---|---|---|---|
| 8.4.26 | vulnerable | [2] | [2] |
| 8.4.27 | patched | [0] | [2] |
| 8.5.11 | vulnerable | [2] | [2] |
| 8.5.12 | patched | [0] | [2] |

## H5: ordinary GET responses identical after normalising version, date and SID

- 8.4: /index.php: identical, /session.php: identical, /missing.php: identical
- 8.5: /index.php: identical, /session.php: identical, /missing.php: identical
