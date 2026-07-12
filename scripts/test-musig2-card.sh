#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MUSIG2_PYTHON="${MUSIG2_PYTHON:-$ROOT/scripts/run-card-python.sh}"

exec "$MUSIG2_PYTHON" "$ROOT/scripts/real-card-cosign-proof.py" --use-existing-card-key
