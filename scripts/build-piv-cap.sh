#!/usr/bin/env bash
# JC 3.0.4 + JDK 8 reproducible build for NuriPivApplet (dist/nuri-piv.cap).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${CARD_BUILD_ROOT:-$ROOT/.build/card-v1}"
OUT="${PIV_BUILD_OUT:-$ROOT/.build/piv-artifacts}"
if [[ -z "${JAVA8_HOME:-}" && -d /Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home ]]; then
  JAVA8_HOME=/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home
fi
[[ -x "${JAVA8_HOME:-}/bin/java" ]] || { printf 'Set JAVA8_HOME to JDK 8\n' >&2; exit 1; }
SDK="$(CARD_BUILD_ROOT="$BUILD" "$ROOT/scripts/prepare-card-build-toolchain.sh")"
mkdir -p "$OUT/raw"
JAVA_HOME="$JAVA8_HOME" PATH="$JAVA8_HOME/bin:$PATH" ant -f "$ROOT/card/piv/build.xml" \
  -Djckit.path="$SDK/jc304_kit" -Dcap.output="$OUT/raw/nuri-piv.cap" build
python3 "$ROOT/scripts/normalize-cap.py" "$OUT/raw/nuri-piv.cap" "$OUT/nuri-piv.cap"
(cd "$OUT" && shasum -a 256 nuri-piv.cap > SHA256SUMS)
printf 'PIV_CAP_BUILD_OK %s\n' "$OUT"
