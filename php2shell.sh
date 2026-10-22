#!/usr/bin/env bash
# Launcher for php2shell-check.
#
#   ./php2shell.sh scan --url https://example.com --confirm-authorised
#   ./php2shell.sh research --show-signatures
#   ./php2shell.sh check        # report environment status only
#   ./php2shell.sh setup        # create .venv and install dependencies
#   ./php2shell.sh test         # run the offline test suite
#
# Finds Python 3.12+, prefers the project's .venv, and checks the runtime
# dependencies. If anything is missing it offers to create .venv and install
# them (in a non-interactive shell set PHP2SHELL_AUTO_INSTALL=1, or run
# "setup" first). All other arguments go straight to "python -m php2shell".
# The working directory is not changed, so relative -o/--targets paths work.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$DIR/.venv"
MIN_PY="3.12"
# Keep in sync with [project.dependencies] / [project.optional-dependencies] in pyproject.toml.
RUNTIME_DEPS=("requests>=2.31" "rich>=13.0")
DEV_DEPS=("pytest>=8")

if [[ -t 2 ]]; then
  RED=$'\e[31m' GREEN=$'\e[32m' YELLOW=$'\e[33m' BOLD=$'\e[1m' RESET=$'\e[0m'
else
  RED="" GREEN="" YELLOW="" BOLD="" RESET=""
fi
ok()   { printf '  %s✔%s %s\n' "$GREEN" "$RESET" "$*" >&2; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
fail() { printf '  %s✘%s %s\n' "$RED" "$RESET" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

py_ok() {  # $1 = interpreter; true if it is Python >= MIN_PY
  "$1" -c "import sys; sys.exit(0 if sys.version_info >= tuple(map(int, '$MIN_PY'.split('.'))) else 1)" 2>/dev/null
}

find_system_python() {
  local c
  for c in "${PHP2SHELL_PYTHON:-}" python3.14 python3.13 python3.12 python3 python; do
    [[ -n "$c" ]] && command -v "$c" >/dev/null 2>&1 && py_ok "$c" && { command -v "$c"; return 0; }
  done
  return 1
}

select_python() {  # prints the interpreter to use: .venv first, then system
  if [[ -x "$VENV/bin/python" ]] && py_ok "$VENV/bin/python"; then
    echo "$VENV/bin/python"
  else
    find_system_python
  fi
}

# Prints one line per missing or too-old package; empty output = all satisfied.
missing_deps() {  # $1 = interpreter, rest = requirement specs (name>=version)
  local py=$1; shift
  "$py" - "$@" <<'EOF'
import sys
from importlib import metadata

def parse(v):
    out = []
    for part in v.split(".")[:3]:
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)

for spec in sys.argv[1:]:
    name, _, minimum = spec.partition(">=")
    try:
        have = metadata.version(name)
    except metadata.PackageNotFoundError:
        print(f"{name} (not installed, need >= {minimum})")
        continue
    if minimum and parse(have) < parse(minimum):
        print(f"{name} {have} (need >= {minimum})")
EOF
}

setup_venv() {  # $1 = "dev" to also install test dependencies
  local base
  base="$(find_system_python)" || die "Python >= $MIN_PY not found. Install it, or set PHP2SHELL_PYTHON=/path/to/python3.12+"
  if [[ ! -x "$VENV/bin/python" ]]; then
    printf '%sCreating virtual environment%s %s (%s)\n' "$BOLD" "$RESET" "$VENV" "$("$base" --version)" >&2
    "$base" -m venv "$VENV" || die "could not create $VENV (on Debian/Ubuntu: apt install python3-venv)"
  fi
  local deps=("${RUNTIME_DEPS[@]}")
  [[ "${1:-}" == "dev" ]] && deps+=("${DEV_DEPS[@]}")
  printf '%sInstalling%s %s\n' "$BOLD" "$RESET" "${deps[*]}" >&2
  "$VENV/bin/python" -m pip install --quiet --upgrade pip >&2 || warn "pip upgrade failed (continuing)"
  "$VENV/bin/python" -m pip install --quiet "${deps[@]}" >&2 || die "dependency installation failed (network or proxy issue?)"
  ok "dependencies installed in $VENV"
}

check_env() {
  local py missing status=0
  printf '%sphp2shell-check environment%s\n' "$BOLD" "$RESET" >&2
  if py="$(select_python)"; then
    ok "Python: $("$py" --version 2>&1) ($py)"
  else
    fail "Python >= $MIN_PY not found"
    return 1
  fi
  [[ "$py" == "$VENV/bin/python" ]] && ok "using project virtualenv" || warn "no .venv; using system Python (./php2shell.sh setup creates one)"

  missing="$(missing_deps "$py" "${RUNTIME_DEPS[@]}")"
  if [[ -z "$missing" ]]; then ok "runtime dependencies: ${RUNTIME_DEPS[*]}"; else
    while IFS= read -r m; do fail "runtime: $m"; done <<<"$missing"; status=1; fi
  missing="$(missing_deps "$py" "${DEV_DEPS[@]}")"
  if [[ -z "$missing" ]]; then ok "test dependencies: ${DEV_DEPS[*]}"; else
    while IFS= read -r m; do warn "tests (optional): $m"; done <<<"$missing"; fi

  [[ -f "$DIR/php2shell/__init__.py" ]] && ok "package found in $DIR" || { fail "php2shell package missing from $DIR"; status=1; }

  # Optional tooling for the local validation lab only; the scanner does not need these.
  local t
  for t in php docker gcc make curl; do
    if command -v "$t" >/dev/null 2>&1; then ok "lab (optional): $t"; else warn "lab (optional): $t not found"; fi
  done
  return $status
}

ensure_ready() {  # prints the interpreter to run with, installing deps if needed and allowed
  local py missing answer
  py="$(select_python)" || die "Python >= $MIN_PY not found. Install it, or set PHP2SHELL_PYTHON=/path/to/python3.12+"
  missing="$(missing_deps "$py" "${RUNTIME_DEPS[@]}")"
  [[ -z "$missing" ]] && { echo "$py"; return 0; }

  printf '%sMissing dependencies for %s:%s\n' "$YELLOW" "$py" "$RESET" >&2
  while IFS= read -r m; do printf '  - %s\n' "$m" >&2; done <<<"$missing"
  if [[ "${PHP2SHELL_AUTO_INSTALL:-0}" == "1" ]]; then
    answer=y
  elif [[ -t 0 && -t 2 ]]; then
    read -r -p "Create $VENV and install them now? [y/N] " answer </dev/tty
  else
    die "run './php2shell.sh setup' first, or set PHP2SHELL_AUTO_INSTALL=1"
  fi
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]] || die "dependencies missing; aborted"
  setup_venv
  echo "$VENV/bin/python"
}

run_tool() {  # $1 = interpreter, rest = args to the module
  local py=$1; shift
  # Run from source without requiring "pip install -e".
  PYTHONPATH="$DIR${PYTHONPATH:+:$PYTHONPATH}" exec "$py" -m php2shell "$@"
}

case "${1:-}" in
  check)
    check_env
    ;;
  setup)
    setup_venv dev
    check_env
    ;;
  test)
    shift
    py="$(ensure_ready)"
    if [[ -n "$(missing_deps "$py" "${DEV_DEPS[@]}")" ]]; then
      [[ "$py" == "$VENV/bin/python" ]] || die "pytest missing; run './php2shell.sh setup' to create .venv with test dependencies"
      "$VENV/bin/python" -m pip install --quiet "${DEV_DEPS[@]}" >&2 || die "could not install pytest"
    fi
    cd "$DIR" && exec "$py" -m pytest "$@"
    ;;
  ""|-h|--help|help)
    sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    echo
    py="$(ensure_ready)"
    run_tool "$py" --help
    ;;
  *)
    py="$(ensure_ready)"
    run_tool "$py" "$@"
    ;;
esac
