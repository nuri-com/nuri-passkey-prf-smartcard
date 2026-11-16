#!/usr/bin/env bash
# Reader-free jCardSim tests of the actual vault applet, pinned as for TOTP.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${VAULT_SIM_BUILD:-$ROOT/.build/vault-sim}"
VERSION=3.0.5.11
SHA256=f6c3b6b8140401a47cf39d7b9dbfc052e381474c6c3b22018051024be1fca97c
JAR="$BUILD/jcardsim-$VERSION.jar"
if [[ -n "${JAVA17_HOME:-}" ]]; then
  export JAVA_HOME="$JAVA17_HOME"
elif [[ -d /Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home ]]; then
  export JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home
fi
if [[ -n "${JAVA_HOME:-}" ]]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
mkdir -p "$BUILD/classes"
if [[ ! -f "$JAR" ]]; then
  curl --retry 3 -fsSL -o "$JAR" "https://repo.maven.apache.org/maven2/com/klinec/jcardsim/$VERSION/jcardsim-$VERSION.jar"
fi
actual="$(shasum -a 256 "$JAR")"
[[ "${actual%% *}" == "$SHA256" ]] || { printf 'jcardsim hash mismatch: %s\n' "$actual" >&2; exit 1; }
javac -nowarn -d "$BUILD/classes" -cp "$JAR" \
  "$ROOT"/card/vault/*.java "$ROOT/test/vault/NuriVaultSimTest.java" \
  "$ROOT/test/vault/VaultApduBridge.java"
java -cp "$BUILD/classes:$JAR" test.vault.NuriVaultSimTest
