#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "$ROOT/scripts/run-card-python.sh" "$ROOT/scripts/manage-fido2-pin.py" "$@"
