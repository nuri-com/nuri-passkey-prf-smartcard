#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${FIDO2_SOURCE:-$ROOT/third_party/fido2-applet}"
DEST="${FIDO2_DEST:-$ROOT/.build/fido2-applet}"

mkdir -p "$(dirname "$DEST")"

mkdir -p "$DEST"
rsync -a --delete "$SOURCE/" "$DEST/"

# Apply the versioned Nuri patches to the vendored clean snapshot.
for patch in "$ROOT"/patches/*.patch; do
  [[ -e "$patch" ]] || continue
  echo "Applying $(basename "$patch")"
  patch --directory="$DEST" --strip=1 --input="$patch"
done

echo "Prepared clean FIDO2 baseline at $DEST"
echo "Nuri FIDO2 base: 4f318197cc08f316ce784a89bdf29dc73cca7fcf"
