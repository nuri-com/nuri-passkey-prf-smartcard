#!/usr/bin/env bash
set -euo pipefail

GP_READER="${GP_READER:-2}"
TOTP_CAP="${TOTP_CAP:-dist/nuri-oath-totp.cap}"
TOTP_PACKAGE_AID="${TOTP_PACKAGE_AID:-4E555249544F50}"
TOTP_APPLET_AID="${TOTP_APPLET_AID:-4E555249544F5450}"

if [[ ! -f "$TOTP_CAP" ]]; then
  echo "TOTP CAP not found: $TOTP_CAP" >&2
  echo "Build it first: (cd card && JAVA_HOME=\$(/usr/libexec/java_home -v 1.8) ant build)" >&2
  exit 1
fi

registry="$(gp -r "$GP_READER" -l 2>&1 || true)"

if grep -q "APP: $TOTP_APPLET_AID" <<<"$registry"; then
  if [[ "${TOTP_REINSTALL:-}" != "YES" ]]; then
    echo "TOTP applet already installed: $TOTP_APPLET_AID"
    echo "Set TOTP_REINSTALL=YES to delete/reinstall it."
    exit 0
  fi
  echo "Deleting existing TOTP applet/package before reinstall..."
  gp -r "$GP_READER" -f --delete "$TOTP_APPLET_AID" || true
  gp -r "$GP_READER" -f --delete "$TOTP_PACKAGE_AID" || true
  registry="$(gp -r "$GP_READER" -l 2>&1 || true)"
fi

if grep -q "PKG: $TOTP_PACKAGE_AID" <<<"$registry"; then
  echo "TOTP package already loaded: $TOTP_PACKAGE_AID"
else
  gp -r "$GP_READER" --load "$TOTP_CAP"
fi

gp -r "$GP_READER" --package "$TOTP_PACKAGE_AID" --applet "$TOTP_APPLET_AID" --create "$TOTP_APPLET_AID"
gp -r "$GP_READER" -l
