#!/usr/bin/env bash
# Actual ETH2, MuSig2 and vault applets in jCardSim; independent Java and Python
# signature verification. No reader access, hardware, private fixture keys or installs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/.build/attestation"
JCARDSIM_SHA256="f6c3b6b8140401a47cf39d7b9dbfc052e381474c6c3b22018051024be1fca97c"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ -n "${JAVA17_HOME:-}" ]]; then
  export JAVA_HOME="$JAVA17_HOME"
elif [[ -d /Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home ]]; then
  export JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home
fi
JAVA="${JAVA_HOME:+$JAVA_HOME/bin/}java"
JAVAC="${JAVA_HOME:+$JAVA_HOME/bin/}javac"
"$JAVAC" -version
"$PYTHON_BIN" -c 'import ecdsa' || {
  printf '%s\n' 'python-ecdsa missing: set PYTHON_BIN to an existing test venv.' >&2
  exit 1
}
if [[ -z "${JCARDSIM_JAR:-}" ]]; then
  for cached in "$HOME"/.gradle/caches/modules-2/files-2.1/com.klinec/jcardsim/3.0.5.11/*/jcardsim-3.0.5.11.jar; do
    if [[ -f "$cached" ]]; then JCARDSIM_JAR="$cached"; break; fi
  done
fi
if [[ -z "${JCARDSIM_JAR:-}" || ! -f "$JCARDSIM_JAR" ]]; then
  printf '%s\n' 'Pinned jcardsim-3.0.5.11.jar missing: set JCARDSIM_JAR (no automatic downloads).' >&2
  exit 1
fi
actual="$(shasum -a 256 "$JCARDSIM_JAR")"
actual="${actual%% *}"
if [[ "$actual" != "$JCARDSIM_SHA256" ]]; then
  printf 'jCardSim hash mismatch: %s (expected %s)\n' "$actual" "$JCARDSIM_SHA256" >&2
  exit 1
fi
mkdir -p "$BUILD/classes"
"$JAVAC" -nowarn -d "$BUILD/classes" -cp "$JCARDSIM_JAR" \
  "$ROOT"/card/eth2/*.java \
  "$ROOT"/card/musig2/*.java \
  "$ROOT"/card/vault/*.java \
  "$ROOT"/test/attestation/AttestationSimTest.java
"$JAVA" -cp "$BUILD/classes:$JCARDSIM_JAR" \
  com.nuri.attestation.test.AttestationSimTest "$BUILD"
"$PYTHON_BIN" -B "$ROOT/test/attestation/verify_fixtures.py" "$BUILD"
printf '%s\n' 'ATTESTATION_SIM_TESTS_OK' 'Simulator only; no real-card claim.'
