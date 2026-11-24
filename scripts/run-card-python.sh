#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REQUIREMENTS="${NURI_CARD_REQUIREMENTS:-$ROOT/requirements-card-v1.txt}"
VENV="${NURI_CARD_VENV:-$ROOT/.build/card-v1-python}"
MARKER="$VENV/.nuri-card-requirements-sha256"

if command -v shasum >/dev/null 2>&1; then
  REQUIREMENTS_HASH="$(shasum -a 256 "$REQUIREMENTS" | awk '{print $1}')"
else
  REQUIREMENTS_HASH="$(sha256sum "$REQUIREMENTS" | awk '{print $1}')"
fi

# Fast path: reuse an already-built Python 3.10+ venv matching requirements.
if [[ -z "${PYTHON_BIN:-}" && -x "$VENV/bin/python" && -f "$MARKER" && "$(<"$MARKER")" == "$REQUIREMENTS_HASH" ]]; then
  if "$VENV/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    exec "$VENV/bin/python" "$@"
  fi
fi

find_python_310() {
  local cand
  for cand in "${PYTHON_BIN:-}" python3.14 python3.13 python3.12 python3.11 python3.10 \
    /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 \
    /opt/homebrew/bin/python3.11 /opt/homebrew/bin/python3.10 /usr/local/bin/python3 python3; do
    [[ -n "$cand" ]] || continue
    local resolved
    resolved="$(command -v "$cand" 2>/dev/null || true)"
    [[ -n "$resolved" && -x "$resolved" ]] || continue
    if "$resolved" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      printf '%s\n' "$resolved"
      return 0
    fi
  done
  return 1
}

PYTHON_BIN="$(find_python_310 || true)"
if [[ -z "$PYTHON_BIN" ]]; then
  echo "Python 3.10 or newer was not found. Set PYTHON_BIN to a Python 3.10+ executable." >&2
  exit 69
fi

if [[ ! -x "$VENV/bin/python" ]] || [[ ! -f "$MARKER" ]] || [[ "$(<"$MARKER")" != "$REQUIREMENTS_HASH" ]]; then
  rm -rf "$VENV"
  "$PYTHON_BIN" -m venv "$VENV"
  "$VENV/bin/python" -m pip install --disable-pip-version-check -r "$REQUIREMENTS"
  printf '%s\n' "$REQUIREMENTS_HASH" >"$MARKER"
fi

exec "$VENV/bin/python" "$@"
