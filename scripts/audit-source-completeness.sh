#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

required_files=(
  third_party/fido2-applet/src/main/java/us/q3q/fido2/FIDO2Applet.java
  third_party/ant-javacard/src/main/java/pro/javacard/ant/JavaCard.java
  third_party/ant-javacard/LICENSE
  third_party/ant-javacard/UPSTREAM.md
  patches/0001-prf-on-by-default.patch
  patches/0002-advertise-user-presence.patch
  card/musig2/NuriMuSig2v019.java
  card/totp/NuriOathTotp.java
  card/eth/NuriEcdsaSigner.java
  mobile/expo-nfc-prf-probe/App.tsx
  mobile/expo-nfc-prf-probe/TerminalScreen.tsx
  mobile/expo-nfc-prf-probe/ProfileScreen.tsx
  mobile/expo-nfc-prf-probe/ApproveScreen.tsx
  dist/FIDO2.cap
  dist/FIDO2-up.cap
  dist/nuri-musig2-v20-keygen.cap
  dist/nuri-oath-totp.cap
  dist/nuri-eth-signer.cap
  dist/SHA256SUMS
  LICENSES/GPL-2.0-or-later.txt
  THIRD_PARTY_NOTICES.md
  tools/ant-javacard-proven.jar
)

for file in "${required_files[@]}"; do
  [[ -f "$file" ]] || {
    echo "Missing required source/release file: $file" >&2
    exit 1
  }
done

tracked_generated="$(git ls-files 'card/**/3.0.4' 'card/3.0.4')"
if [[ -n "$tracked_generated" ]]; then
  echo "Generated Java Card converter output must not be tracked:" >&2
  echo "$tracked_generated" >&2
  exit 1
fi

if rg -n 'org\.gradle\.java\.home=|/Users/[^/]+/|/private/tmp/nuri-fido2-real-card-venv' \
  package.json scripts card third_party mobile/expo-nfc-prf-probe \
  --glob '!scripts/audit-source-completeness.sh' \
  --glob '!**/node_modules/**' --glob '!**/build/**' --glob '!**/.gradle/**'; then
  echo "Active source contains a developer-machine path." >&2
  exit 1
fi

(
  cd dist
  shasum -a 256 -c SHA256SUMS
)

echo "SOURCE_COMPLETENESS_OK"
