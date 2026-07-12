#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_ROOT="${CARD_BUILD_ROOT:-$ROOT/.build/card-v1}"
WORK="$BUILD_ROOT/work"
OUT="${CARD_RELEASE_OUT:-$BUILD_ROOT/artifacts}"
JAVA8_HOME="${JAVA8_HOME:-}"

if [[ -z "$JAVA8_HOME" ]] && [[ -x "${JAVA_HOME:-}/bin/java" ]] && \
   "$JAVA_HOME/bin/java" -version 2>&1 | head -1 | grep -Eq 'version "1\.8\.'; then
  JAVA8_HOME="$JAVA_HOME"
fi

if [[ -z "$JAVA8_HOME" ]] && [[ -x /Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home/bin/java ]]; then
  JAVA8_HOME=/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home
fi
if [[ -z "$JAVA8_HOME" ]] && command -v /usr/libexec/java_home >/dev/null 2>&1; then
  JAVA8_HOME="$(/usr/libexec/java_home -v 1.8 2>/dev/null || true)"
fi
if [[ -z "$JAVA8_HOME" ]] || [[ ! -x "$JAVA8_HOME/bin/java" ]]; then
  echo "JDK 8 is required. Set JAVA8_HOME to a JDK 8 installation." >&2
  exit 1
fi
if ! "$JAVA8_HOME/bin/java" -version 2>&1 | head -1 | grep -Eq '(version "1\.8\.|openjdk version "1\.8\.)'; then
  echo "JAVA8_HOME does not point to JDK 8: $JAVA8_HOME" >&2
  exit 1
fi

for command_name in ant git patch python3 rsync shasum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Missing required command: $command_name" >&2
    exit 1
  }
done

SDK_DIR="$($ROOT/scripts/prepare-card-build-toolchain.sh)"
JC304="$SDK_DIR/jc304_kit"
JC305="$SDK_DIR/jc305u3_kit"
export JAVA_HOME="$JAVA8_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

mkdir -p "$WORK" "$OUT/raw"

build_fido() {
  local name="$1"
  shift
  local build_dir="$WORK/$name"
  mkdir -p "$build_dir"
  rsync -a --delete --exclude sdks/ "$ROOT/third_party/fido2-applet/" "$build_dir/"
  for patch_file in "$@"; do
    patch --directory="$build_dir" --strip=1 --input="$patch_file"
  done
  (
    cd "$build_dir"
    JC_HOME="$JC305" ./gradlew clean buildJavaCard --no-daemon
  )
  cp "$build_dir/build/javacard/FIDO2.cap" "$OUT/raw/$name.cap"
}

build_fido FIDO2 "$ROOT/patches/0001-prf-on-by-default.patch"
build_fido FIDO2-up \
  "$ROOT/patches/0001-prf-on-by-default.patch" \
  "$ROOT/patches/0002-advertise-user-presence.patch"

ant -f "$ROOT/card/musig2/build.xml" \
  -Djckit.path="$JC304" \
  -Dcap.output="$OUT/raw/nuri-musig2-v20-keygen.cap" build
ant -f "$ROOT/card/totp/build.xml" \
  -Djckit.path="$JC304" \
  -Dcap.output="$OUT/raw/nuri-oath-totp.cap" build
ant -f "$ROOT/card/eth/build.xml" \
  -Djckit.path="$JC304" \
  -Dcap.output="$OUT/raw/nuri-eth-signer.cap" build

for cap in "$OUT"/raw/*.cap; do
  name="$(basename "$cap")"
  python3 "$ROOT/scripts/normalize-cap.py" "$cap" "$OUT/$name"
done

(
  cd "$OUT"
  shasum -a 256 FIDO2.cap FIDO2-up.cap nuri-musig2-v20-keygen.cap \
    nuri-oath-totp.cap nuri-eth-signer.cap >SHA256SUMS
)

{
  printf '%s\n' "Nuri card release build"
  printf 'source_commit=%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
  printf 'source_dirty=%s\n' "$(git -C "$ROOT" status --porcelain | wc -l | tr -d ' ')"
  printf '%s\n' "fido2_nuri_ref=4f318197cc08f316ce784a89bdf29dc73cca7fcf"
  printf '%s\n' "javacard_sdk_ref=e2df471e04d86f33de69a947f44766fbef1d9d69"
  printf '%s\n' "ant_javacard_sha256=def557393fd20dbe478a4581c3273222805b9e494836aa8465dfbe0fb9d64cf2"
  printf 'java=%s\n' "$($JAVA_HOME/bin/java -version 2>&1 | head -1)"
} >"$OUT/BUILD-PROVENANCE.txt"

cat "$OUT/SHA256SUMS"
echo "CARD_V1_BUILD_OK $OUT"
