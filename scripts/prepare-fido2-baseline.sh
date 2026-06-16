#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${FIDO2_SOURCE:-https://github.com/BryanJacobs/FIDO2Applet.git}"
DEST="${FIDO2_DEST:-$ROOT/vendor/FIDO2Applet-clean}"
REF="${FIDO2_REF:-fb827954cd091a1810163ce51d2f86d42d0b8e20}"

mkdir -p "$ROOT/vendor"

if [[ -e "$DEST" ]]; then
  echo "Baseline already exists: $DEST"
else
  if [[ -d "$SOURCE/.git" ]]; then
    git clone --no-hardlinks "$SOURCE" "$DEST"
  else
    git clone "$SOURCE" "$DEST"
  fi
fi

git -C "$DEST" fetch --all --tags --prune >/dev/null 2>&1 || true
git -C "$DEST" checkout --detach "$REF"
git -C "$DEST" submodule update --init --recursive
git -C "$DEST" clean -fdx
git -C "$DEST" reset --hard

# Apply Nuri patches (kept here because vendor/ is gitignored and re-cloned).
for patch in "$ROOT"/patches/*.patch; do
  [[ -e "$patch" ]] || continue
  echo "Applying $(basename "$patch")"
  git -C "$DEST" apply "$patch"
done

echo "Prepared clean FIDO2 baseline at $DEST"
git -C "$DEST" log --oneline -1
