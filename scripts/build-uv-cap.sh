#!/usr/bin/env bash
# Build the vendor-neutral PIN-only NuriUV CAP; private backends override uv.matcher.dir.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${CARD_BUILD_ROOT:-$ROOT/.build/card-v1}"
OUT="${UV_BUILD_OUT:-$ROOT/.build/uv-artifacts}"
if [[ -z "${JAVA8_HOME:-}" && -d /Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home ]]; then
  JAVA8_HOME=/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home
fi
[[ -x "${JAVA8_HOME:-}/bin/java" ]] || { printf 'Set JAVA8_HOME to JDK 8\n' >&2; exit 1; }
SDK="$(CARD_BUILD_ROOT="$BUILD" "$ROOT/scripts/prepare-card-build-toolchain.sh")"
mkdir -p "$OUT"
JAVA_HOME="$JAVA8_HOME" PATH="$JAVA8_HOME/bin:$PATH" ant -f "$ROOT/card/uv/build.xml" \
  -Djckit.path="$SDK/jc304_kit" -Dcap.output="$OUT/nuri-uv.cap" \
  -Duv.matcher.dir="${UV_MATCHER_DIR:-matcher-none}" build
printf 'UV_CAP_BUILD_OK %s\n' "$OUT/nuri-uv.cap"
