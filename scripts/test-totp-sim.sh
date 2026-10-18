#!/usr/bin/env bash
# Run card/totp/NuriOathTotp.java under jCardSim: RFC 6238 vectors on the native
# HMAC engine and on the software RFC 2104 fallback, plus PUT/PIN protection.
#
#   scripts/test-totp-sim.sh
#
# Needs JDK 17 (jCardSim 3.0.5.11, same artifact the FIDO2 sim tests use) and
# network once to fetch the jar from Maven Central into .build/ (hash pinned).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${TOTP_SIM_BUILD:-$ROOT/.build/totp-sim}"
JCARDSIM_VERSION=3.0.5.11
JCARDSIM_SHA256=f6c3b6b8140401a47cf39d7b9dbfc052e381474c6c3b22018051024be1fca97c
JCARDSIM_URL="https://repo1.maven.org/maven2/com/klinec/jcardsim/$JCARDSIM_VERSION/jcardsim-$JCARDSIM_VERSION.jar"
JAR="$BUILD/jcardsim-$JCARDSIM_VERSION.jar"

if [[ -n "${JAVA17_HOME:-}" ]]; then
  export JAVA_HOME="$JAVA17_HOME"
elif [[ -d /Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home ]]; then
  export JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home
fi
if [[ -n "${JAVA_HOME:-}" ]]; then
  export PATH="$JAVA_HOME/bin:$PATH"
fi
command -v javac >/dev/null 2>&1 || { echo "javac not found (need JDK 17)" >&2; exit 1; }

mkdir -p "$BUILD/classes"

if [[ ! -f "$JAR" ]]; then
  gradle_copy="$(find "$HOME/.gradle/caches/modules-2/files-2.1/com.klinec/jcardsim/$JCARDSIM_VERSION" \
    -name "jcardsim-$JCARDSIM_VERSION.jar" 2>/dev/null | head -1 || true)"
  if [[ -n "$gradle_copy" ]]; then
    cp "$gradle_copy" "$JAR"
  else
    curl -fsSL -o "$JAR" "$JCARDSIM_URL"
  fi
fi
actual="$(shasum -a 256 "$JAR" | awk '{print $1}')"
if [[ "$actual" != "$JCARDSIM_SHA256" ]]; then
  echo "jcardsim jar hash mismatch: $actual" >&2
  exit 1
fi

# jCardSim ships its own javacard.* API classes; compiling the applet against
# them is enough for the simulator (the CAP build uses jc304_kit separately).
javac -nowarn -d "$BUILD/classes" -cp "$JAR" \
  "$ROOT/card/totp/NuriOathTotp.java" \
  "$ROOT/test/totp/NuriOathTotpSimTest.java"

java -cp "$BUILD/classes:$JAR" test.totp.NuriOathTotpSimTest
