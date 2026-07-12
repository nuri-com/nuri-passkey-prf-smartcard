#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

npm run cli:e2e
npm run card:arkade:signer:sim
npm run fido2:test-prf
scripts/run-card-python.sh scripts/card-totp.py --selfcheck

echo "CARD_V1_VIRTUAL_TESTS_OK"
echo "ETH and Java Card hardware behavior still require a qualified physical card."
