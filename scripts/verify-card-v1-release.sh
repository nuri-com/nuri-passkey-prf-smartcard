#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_ROOT="${CARD_BUILD_ROOT:-$ROOT/.build/card-v1}"
ARTIFACTS="${CARD_RELEASE_OUT:-$BUILD_ROOT/artifacts}"

if [[ "${CARD_SKIP_BUILD:-}" != "YES" ]]; then
  "$ROOT/scripts/build-card-v1-release.sh"
fi

(
  cd "$ROOT/dist"
  shasum -a 256 -c SHA256SUMS
)

for name in FIDO2 FIDO2-up nuri-musig2-v20-keygen nuri-oath-totp nuri-eth-signer; do
  python3 "$ROOT/scripts/compare-cap-components.py" \
    "$ROOT/dist/$name.cap" "$ARTIFACTS/$name.cap"
done

diff -u "$ROOT/dist/SHA256SUMS" "$ARTIFACTS/SHA256SUMS"
echo "CARD_V1_RELEASE_VERIFIED"
