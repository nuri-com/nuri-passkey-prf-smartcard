#!/usr/bin/env bash
# Reader-free NuriUV PIN/OR/AND policy and cross-applet gate tests.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${UV_SIM_BUILD:-$ROOT/.build/uv-sim}"
VERSION=3.0.5.11
SHA256=f6c3b6b8140401a47cf39d7b9dbfc052e381474c6c3b22018051024be1fca97c
JAR="$BUILD/jcardsim-$VERSION.jar"
if [[ -d /Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home ]]; then
  export JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home
  export PATH="$JAVA_HOME/bin:$PATH"
fi
mkdir -p "$BUILD/classes"
if [[ ! -f "$JAR" ]]; then
  cp "$ROOT/.build/piv-sim/jcardsim-$VERSION.jar" "$JAR"
fi
actual="$(shasum -a 256 "$JAR")"
[[ "${actual%% *}" == "$SHA256" ]] || { printf 'jcardsim hash mismatch\n' >&2; exit 1; }
javac -nowarn -d "$BUILD/classes" -cp "$JAR" \
  "$ROOT"/card/uv/com/nuri/uv/*.java "$ROOT"/test/uv/src/com/nuri/uv/*.java "$ROOT/test/uv/NuriUvSimTest.java"
java -cp "$BUILD/classes:$JAR" com.nuri.uv.NuriUvSimTest
