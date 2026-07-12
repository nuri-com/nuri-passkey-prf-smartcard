#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CAP="${CAP:-$ROOT/dist/FIDO2-up.cap}"
GP_BIN="${GP_BIN:-gp}"

if [[ "${FIDO2_REINSTALL_CONFIRM:-}" != "YES" ]]; then
  echo "Refusing to reinstall without explicit confirmation." >&2
  echo "This deletes the installed FIDO2 applet/package and installs $CAP." >&2
  echo "Run: FIDO2_REINSTALL_CONFIRM=YES GP_READER_INDEX=2 npm run card:reinstall" >&2
  exit 64
fi

if [[ ! -f "$CAP" ]]; then
  echo "CAP not found: $CAP" >&2
  echo "Run npm run card:build first." >&2
  exit 1
fi

if ! command -v "$GP_BIN" >/dev/null 2>&1; then
  echo "GlobalPlatformPro 'gp' was not found. Install it or set GP_BIN." >&2
  exit 1
fi

GP_ARGS=()
if [[ -n "${GP_READER_INDEX:-}" ]]; then
  GP_ARGS+=("-r${GP_READER_INDEX}")
elif [[ -n "${GP_READER:-}" ]]; then
  GP_ARGS+=("-r" "$GP_READER")
fi
if [[ -n "${GP_KEY:-}" ]]; then
  GP_ARGS+=("-k" "$GP_KEY")
fi
KEY_ENC="${GP_KEY_ENC:-${SCP03_ENC:-}}"
KEY_MAC="${GP_KEY_MAC:-${SCP03_MAC:-}}"
KEY_DEK="${GP_KEY_DEK:-${SCP03_DEK:-}}"
if [[ -n "$KEY_ENC" ]]; then
  GP_ARGS+=("--key-enc" "$KEY_ENC")
fi
if [[ -n "$KEY_MAC" ]]; then
  GP_ARGS+=("--key-mac" "$KEY_MAC")
fi
if [[ -n "$KEY_DEK" ]]; then
  GP_ARGS+=("--key-dek" "$KEY_DEK")
fi

delete_if_present() {
  local aid="$1"
  if "$GP_BIN" "${GP_ARGS[@]}" -l 2>/dev/null | grep -qE "^(APP|PKG): ${aid}( |$)"; then
    echo "Deleting $aid"
    "$GP_BIN" "${GP_ARGS[@]}" --force --delete "$aid"
  else
    echo "Not present: $aid"
  fi
}

echo "Readers visible to GlobalPlatformPro:"
"$GP_BIN" -list || true

# Older BryanJacobs-derived builds used package AID A0000006472F; the clean CAP
# in this repo uses package AID A000000647 and applet AID A0000006472F0001.
delete_if_present A0000006472F
delete_if_present A000000647

echo "Installing $CAP"
"$GP_BIN" "${GP_ARGS[@]}" -install "$CAP"

echo "Installed registry entry:"
"$GP_BIN" "${GP_ARGS[@]}" -l | grep -E '^(APP|PKG): A000000647'
