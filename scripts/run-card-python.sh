#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REQUIREMENTS="${NURI_CARD_REQUIREMENTS:-$ROOT/requirements-card-v1.txt}"
VENV="${NURI_CARD_VENV:-$ROOT/.build/card-v1-python}"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || true)}"

if [[ -z "$PYTHON_BIN" || ! -x "$PYTHON_BIN" ]]; then
  echo "Python 3 was not found. Set PYTHON_BIN to a Python 3.10+ executable." >&2
  exit 69
fi

"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
  echo "Python 3.10 or newer is required: $PYTHON_BIN" >&2
  exit 69
}

if command -v shasum >/dev/null 2>&1; then
  REQUIREMENTS_HASH="$(shasum -a 256 "$REQUIREMENTS" | awk '{print $1}')"
else
  REQUIREMENTS_HASH="$(sha256sum "$REQUIREMENTS" | awk '{print $1}')"
fi
MARKER="$VENV/.nuri-card-requirements-sha256"

if [[ ! -x "$VENV/bin/python" ]] || [[ ! -f "$MARKER" ]] || [[ "$(<"$MARKER")" != "$REQUIREMENTS_HASH" ]]; then
  rm -rf "$VENV"
  "$PYTHON_BIN" -m venv "$VENV"
  "$VENV/bin/python" -m pip install --disable-pip-version-check -r "$REQUIREMENTS"
  printf '%s\n' "$REQUIREMENTS_HASH" >"$MARKER"
fi

exec "$VENV/bin/python" "$@"
