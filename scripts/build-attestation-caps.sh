#!/usr/bin/env bash
# Build the three W25 applets twice, verify CAPs and compare normalized bytes.
# Does not connect to a reader or overwrite committed dist artifacts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${CARD_BUILD_ROOT:-$ROOT/.build/card-v1}"
OUT="${ATTESTATION_CAP_OUT:-$ROOT/.build/attestation-caps}"
PYTHON="${PYTHON_BIN:-python3}"
JAVA8_HOME="${JAVA8_HOME:-/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home}"
[[ -x "$JAVA8_HOME/bin/java" ]] || { printf 'Set JAVA8_HOME to JDK8\n' >&2; exit 1; }
"$PYTHON" "$ROOT/scripts/generate-attestation.py" --check
SDK="$(CARD_BUILD_ROOT="$BUILD" "$ROOT/scripts/prepare-card-build-toolchain.sh")"
export JAVA_HOME="$JAVA8_HOME" PATH="$JAVA8_HOME/bin:$PATH"
mkdir -p "$OUT/java-tmp"
export ANT_OPTS="${ANT_OPTS:-} -Djava.io.tmpdir=$OUT/java-tmp"
for pass in 1 2; do
  mkdir -p "$OUT/$pass/raw"
  for name in eth2 musig2 vault; do
    case "$name" in
      eth2) cap=nuri-eth2-signer.cap ;;
      musig2) cap=nuri-musig2-v20-keygen.cap ;;
      vault) cap=nuri-vault.cap ;;
    esac
    ant -f "$ROOT/card/$name/build.xml" -Djckit.path="$SDK/jc304_kit" \
      -Dcap.output="$OUT/$pass/raw/$cap" build
    "$PYTHON" "$ROOT/scripts/normalize-cap.py" "$OUT/$pass/raw/$cap" "$OUT/$pass/$cap"
  done
done
for cap in nuri-eth2-signer.cap nuri-musig2-v20-keygen.cap nuri-vault.cap; do
  cmp "$OUT/1/$cap" "$OUT/2/$cap"
done
(cd "$OUT/1" && shasum -a 256 nuri-eth2-signer.cap nuri-musig2-v20-keygen.cap nuri-vault.cap)
printf 'ATTESTATION_CAP_REPRODUCIBLE_OK %s\n' "$OUT/1"
