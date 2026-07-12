#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

npm ci
npm run source:audit
if [[ -n "${JAVA17_HOME:-}" ]]; then
  JAVA_HOME="$JAVA17_HOME" npm run test:virtual
else
  npm run test:virtual
fi
npm run card:release:verify

if [[ "${REPRODUCE_EXPO:-YES}" == "YES" ]]; then
  npm run mobile:verify:v1
  echo "NURI_CARD_V1_FULL_SOURCE_REPRODUCED"
else
  echo "NURI_CARD_V1_PUBLIC_CORE_REPRODUCED"
  echo "Expo verification was explicitly skipped with REPRODUCE_EXPO=NO."
fi
