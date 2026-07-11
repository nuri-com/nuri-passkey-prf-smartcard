#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/mobile/expo-nfc-prf-probe"
PROFILE="${NURI_PRF_PROFILE:?Set NURI_PRF_PROFILE to the exact credential profile for this account}"
COMMAND="${1:-android}"
SALT="${NURI_PRF_SALT:-nuri-offline-backup-v1}"
DEFAULT_ANDROID_HOME="/opt/homebrew/share/android-commandlinetools"

if [[ $# -gt 0 ]]; then
  shift
fi

if [[ ! -f "$PROFILE" ]]; then
  echo "Missing PRF profile: $PROFILE" >&2
  echo "Create it first with: npm run card:prf:selftest" >&2
  exit 2
fi

eval "$(
  node - "$PROFILE" "$SALT" <<'NODE'
const fs = require('fs');
const [profilePath, salt] = process.argv.slice(2);
const profile = JSON.parse(fs.readFileSync(profilePath, 'utf8'));

function exportLine(name, value) {
  if (!value) throw new Error(`${name} is missing in ${profilePath}`);
  console.log(`export ${name}=${JSON.stringify(String(value))};`);
}

exportLine('EXPO_PUBLIC_NURI_RP_ID', profile.rp_id);
exportLine('EXPO_PUBLIC_NURI_ORIGIN', profile.origin);
exportLine('EXPO_PUBLIC_NURI_CREDENTIAL_ID', profile.credential_id);
exportLine('EXPO_PUBLIC_NURI_CREDENTIAL_PUBLIC_KEY', profile.credential_public_key_spki_b64u);
exportLine('EXPO_PUBLIC_NURI_PRF_SALT', salt);
NODE
)"

: "${EXPO_PUBLIC_ASP_BASE:?Set EXPO_PUBLIC_ASP_BASE to the live Arkade v4 base URL}"
: "${EXPO_PUBLIC_NODE_URL:?Set EXPO_PUBLIC_NODE_URL to the live Ark node URL}"

if [[ -z "${ANDROID_HOME:-}" && -d "$DEFAULT_ANDROID_HOME" ]]; then
  export ANDROID_HOME="$DEFAULT_ANDROID_HOME"
fi

if [[ -z "${ANDROID_SDK_ROOT:-}" && -n "${ANDROID_HOME:-}" ]]; then
  export ANDROID_SDK_ROOT="$ANDROID_HOME"
fi

if command -v /usr/libexec/java_home >/dev/null 2>&1; then
  JAVA_17_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"
  if [[ -n "$JAVA_17_HOME" ]]; then
    export JAVA_HOME="$JAVA_17_HOME"
    export PATH="$JAVA_HOME/bin:$PATH"
  fi
fi

echo "Using PRF profile: $PROFILE"
echo "EXPO_PUBLIC_NURI_RP_ID=$EXPO_PUBLIC_NURI_RP_ID"
echo "EXPO_PUBLIC_NURI_ORIGIN=$EXPO_PUBLIC_NURI_ORIGIN"
echo "EXPO_PUBLIC_NURI_CREDENTIAL_ID length=${#EXPO_PUBLIC_NURI_CREDENTIAL_ID}"
echo "EXPO_PUBLIC_NURI_CREDENTIAL_PUBLIC_KEY length=${#EXPO_PUBLIC_NURI_CREDENTIAL_PUBLIC_KEY}"
echo "EXPO_PUBLIC_NURI_PRF_SALT=$EXPO_PUBLIC_NURI_PRF_SALT"
echo "ANDROID_HOME=${ANDROID_HOME:-}"
echo "JAVA_HOME=${JAVA_HOME:-}"

cd "$APP"
exec npm run "$COMMAND" -- "$@"
