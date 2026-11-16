#!/usr/bin/env bash
# JC 3.0.4 + JDK 8, same pinned toolchain and ZIP normalization as card/totp.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${CARD_BUILD_ROOT:-$ROOT/.build/card-v1}"
OUT="${VAULT_BUILD_OUT:-$ROOT/.build/vault-artifacts}"
if [[ -z "${JAVA8_HOME:-}" && -d /Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home ]]; then
  JAVA8_HOME=/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home
fi
[[ -x "${JAVA8_HOME:-}/bin/java" ]] || { printf 'Set JAVA8_HOME to JDK 8\n' >&2; exit 1; }
SDK="$(CARD_BUILD_ROOT="$BUILD" "$ROOT/scripts/prepare-card-build-toolchain.sh")"
mkdir -p "$OUT/raw"
JAVA_HOME="$JAVA8_HOME" PATH="$JAVA8_HOME/bin:$PATH" ant -f "$ROOT/card/vault/build.xml" \
  -Djckit.path="$SDK/jc304_kit" -Dcap.output="$OUT/raw/nuri-vault.cap" build
python3 "$ROOT/scripts/normalize-cap.py" "$OUT/raw/nuri-vault.cap" "$OUT/nuri-vault.cap"
(cd "$OUT" && shasum -a 256 nuri-vault.cap > SHA256SUMS)
printf 'VAULT_CAP_BUILD_OK %s\n' "$OUT"
