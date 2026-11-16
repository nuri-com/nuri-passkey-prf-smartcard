#!/usr/bin/env bash
# jCardSim regression test for the MuSig2 applet nonce-lifetime fix (audit A1).
# Simulator only; never touches a reader or a card.
#
# Usage: scripts/test-musig2-jcardsim.sh [path/to/applet/source/dir]
# Env:   JAVA17_HOME (default: Zulu 17 on macOS), JCARDSIM_JAR (default: ~/.m2 /
#        ~/.gradle cache, else download of the pinned Maven artifact)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APPLET_SRC="${1:-$ROOT/card/musig2}"
BUILD_ROOT="${CARD_BUILD_ROOT:-$ROOT/.build/card-v1}"
WORK="$BUILD_ROOT/musig2-jcardsim"
JCARDSIM_VERSION="3.0.5.11"
JCARDSIM_SHA1="87d0049bd958e674d7aa92ddacd3662d1133074e"
JCARDSIM_SHA256="f6c3b6b8140401a47cf39d7b9dbfc052e381474c6c3b22018051024be1fca97c"

if [[ -n "${JAVA17_HOME:-}" ]]; then
  export JAVA_HOME="$JAVA17_HOME"
elif [[ -d /Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home ]]; then
  export JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home
elif [[ -z "${JAVA_HOME:-}" ]] && command -v /usr/libexec/java_home >/dev/null 2>&1; then
  export JAVA_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || /usr/libexec/java_home)"
fi
if [[ -n "${JAVA_HOME:-}" ]]; then
  export PATH="$JAVA_HOME/bin:$PATH"
fi
command -v javac >/dev/null 2>&1 || { echo "javac not found; set JAVA17_HOME" >&2; exit 1; }

mkdir -p "$WORK"

# Locate the pinned jCardSim jar (same artifact the vendored FIDO2 tests use:
# third_party/fido2-applet/build.gradle -> com.klinec:jcardsim:3.0.5.11).
JAR="${JCARDSIM_JAR:-}"
if [[ -z "$JAR" ]]; then
  for candidate in \
    "$WORK/jcardsim-$JCARDSIM_VERSION.jar" \
    "$HOME/.m2/repository/com/klinec/jcardsim/$JCARDSIM_VERSION/jcardsim-$JCARDSIM_VERSION.jar" \
    "$HOME/.gradle/caches/modules-2/files-2.1/com.klinec/jcardsim/$JCARDSIM_VERSION/$JCARDSIM_SHA1/jcardsim-$JCARDSIM_VERSION.jar"; do
    if [[ -f "$candidate" ]]; then JAR="$candidate"; break; fi
  done
fi
if [[ -z "$JAR" ]]; then
  JAR="$WORK/jcardsim-$JCARDSIM_VERSION.jar"
  curl -fsSL -o "$JAR" \
    "https://repo1.maven.org/maven2/com/klinec/jcardsim/$JCARDSIM_VERSION/jcardsim-$JCARDSIM_VERSION.jar"
fi
actual="$(shasum -a 256 "$JAR" | awk '{print $1}')"
if [[ "$actual" != "$JCARDSIM_SHA256" ]]; then
  echo "Unexpected jCardSim jar hash: $actual ($JAR)" >&2
  exit 1
fi

CLASSES="$WORK/classes"
rm -rf "$CLASSES"
mkdir -p "$CLASSES"
# jCardSim ships its own javacard.* API classes, so no JC SDK is needed here.
javac -nowarn -source 8 -target 8 -cp "$JAR" -d "$CLASSES" \
  "$APPLET_SRC"/*.java \
  "$ROOT/test/musig2-jcardsim/NonceLifetimeTest.java" \
  "$ROOT/test/musig2-jcardsim/Scalar256Test.java" \
  "$ROOT/test/musig2-jcardsim/RsaMultiplyTest.java" \
  "$ROOT/test/musig2-jcardsim/PinHardeningTest.java"

java -cp "$CLASSES:$JAR" nuri.musig2.RsaMultiplyTest
java -cp "$CLASSES:$JAR" Scalar256Test
java -cp "$CLASSES:$JAR" NonceLifetimeTest
java -cp "$CLASSES:$JAR" PinHardeningTest
