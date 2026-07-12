#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

npm test
npm run musig2:demo
npm run cosign:demo
scripts/run-card-python.sh scripts/card-totp.py --selfcheck
npm run card:release:verify

if [[ "${CARD_REAL_TESTS:-}" != "YES" ]]; then
  echo "HOST_ACCEPTANCE_OK"
  echo "Set CARD_REAL_TESTS=YES with one card inserted to run non-destructive hardware acceptance."
  exit 0
fi

npm run card:test
npm run card:musig2:test
scripts/run-card-python.sh scripts/card-totp.py status
scripts/run-card-python.sh scripts/card-eth-test.py

echo "REAL_CARD_V1_ACCEPTANCE_OK"
