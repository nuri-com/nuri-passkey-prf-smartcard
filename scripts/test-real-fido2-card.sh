#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE="${FIDO2_DEST:-$ROOT/.build/fido2-applet}"

if [[ ! -d "$BASELINE" ]]; then
  "$ROOT/scripts/prepare-fido2-baseline.sh"
fi

exec "$ROOT/scripts/run-card-python.sh" "$ROOT/scripts/test-real-fido2-card.py"
