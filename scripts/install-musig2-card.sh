#!/usr/bin/env bash
set -euo pipefail

GP_READER="${GP_READER:-2}"
MUSIG2_CAP="${MUSIG2_CAP:-dist/nuri-musig2-v20-keygen.cap}"
MUSIG2_PACKAGE_AID="${MUSIG2_PACKAGE_AID:-4E5552494D5547}"
MUSIG2_APPLET_AID="${MUSIG2_APPLET_AID:-4E5552494D554701}"

if [[ ! -f "$MUSIG2_CAP" ]]; then
  echo "MuSig2 CAP not found: $MUSIG2_CAP" >&2
  echo "Set MUSIG2_CAP=/path/to/nuri-musig2-v20-keygen.cap or build/copy the MuSig2 CAP into dist/." >&2
  exit 1
fi

registry="$(gp -r "$GP_READER" -l 2>&1 || true)"

if grep -q "APP: $MUSIG2_APPLET_AID" <<<"$registry"; then
  if [[ "${MUSIG2_REINSTALL:-}" != "YES" ]]; then
    echo "MuSig2 applet already installed: $MUSIG2_APPLET_AID"
    echo "Set MUSIG2_REINSTALL=YES to delete/reinstall it."
    exit 0
  fi

  echo "Deleting existing MuSig2 applet/package before reinstall..."
  gp -r "$GP_READER" -f --delete "$MUSIG2_APPLET_AID" || true
  gp -r "$GP_READER" -f --delete "$MUSIG2_PACKAGE_AID" || true
  registry="$(gp -r "$GP_READER" -l 2>&1 || true)"
fi

if grep -q "PKG: $MUSIG2_PACKAGE_AID" <<<"$registry"; then
  echo "MuSig2 package already loaded: $MUSIG2_PACKAGE_AID"
else
  gp -r "$GP_READER" --load "$MUSIG2_CAP"
fi

gp -r "$GP_READER" --package "$MUSIG2_PACKAGE_AID" --applet "$MUSIG2_APPLET_AID" --create "$MUSIG2_APPLET_AID"
gp -r "$GP_READER" -l
