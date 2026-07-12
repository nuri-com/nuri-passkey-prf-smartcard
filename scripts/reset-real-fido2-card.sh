#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "${FIDO2_RESET_CONFIRM:-}" != "YES" ]]; then
  echo "Refusing to reset without explicit confirmation." >&2
  echo "This erases FIDO2 credentials and PIN/authenticator state on the inserted card." >&2
  echo "Run: FIDO2_RESET_CONFIRM=YES npm run card:reset" >&2
  exit 64
fi

exec "$ROOT/scripts/run-card-python.sh" "$ROOT/scripts/reset-real-fido2-card.py"
