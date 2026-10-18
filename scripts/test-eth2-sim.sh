#!/usr/bin/env bash
# ETH signer v2 simulator test: jCardSim (SW/PIN/keygen paths) + python-ecdsa
# verification of every signature + host/test_host.py. No reader, no card.
#
# Needs: JDK 17 (zulu-17 or JAVA17_HOME), jcardsim-3.0.5.11.jar (gradle cache
# from the FIDO2 build, or set JCARDSIM_JAR, or it is fetched from Maven Central
# and pinned by sha256), python3 with python-ecdsa + pycryptodome (venv created
# under .build/eth2-python).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${ETH2_BUILD_DIR:-$ROOT/.build/eth2}"
SIGN_COUNT="${ETH2_SIGN_COUNT:-20}"
JCARDSIM_SHA256="f6c3b6b8140401a47cf39d7b9dbfc052e381474c6c3b22018051024be1fca97c"
JCARDSIM_URL="https://repo1.maven.org/maven2/com/klinec/jcardsim/3.0.5.11/jcardsim-3.0.5.11.jar"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
VENV="${ETH2_TEST_VENV:-$ROOT/.build/eth2-python}"

# --- JDK 17 ------------------------------------------------------------------
if [[ -n "${JAVA17_HOME:-}" ]]; then
  export JAVA_HOME="$JAVA17_HOME"
elif [[ -d /Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home ]]; then
  export JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home
fi
JAVA="${JAVA_HOME:+$JAVA_HOME/bin/}java"
JAVAC="${JAVA_HOME:+$JAVA_HOME/bin/}javac"
"$JAVAC" -version >/dev/null 2>&1 || { echo "javac not found (set JAVA17_HOME)" >&2; exit 1; }

# --- jCardSim ----------------------------------------------------------------
JCARDSIM_JAR="${JCARDSIM_JAR:-}"
if [[ -z "$JCARDSIM_JAR" ]]; then
  cached="$(find "$HOME/.gradle/caches/modules-2/files-2.1/com.klinec/jcardsim/3.0.5.11" -name 'jcardsim-3.0.5.11.jar' 2>/dev/null | head -1 || true)"
  if [[ -n "$cached" ]]; then
    JCARDSIM_JAR="$cached"
  else
    mkdir -p "$BUILD"
    JCARDSIM_JAR="$BUILD/jcardsim-3.0.5.11.jar"
    [[ -f "$JCARDSIM_JAR" ]] || curl -fsSL -o "$JCARDSIM_JAR" "$JCARDSIM_URL"
  fi
fi
actual="$(shasum -a 256 "$JCARDSIM_JAR" | awk '{print $1}')"
if [[ "$actual" != "$JCARDSIM_SHA256" ]]; then
  echo "jcardsim jar hash mismatch: $actual (expected $JCARDSIM_SHA256) at $JCARDSIM_JAR" >&2
  exit 1
fi

# --- python venv -------------------------------------------------------------
if [[ ! -x "$VENV/bin/python" ]] || ! "$VENV/bin/python" -c 'import ecdsa, Crypto' 2>/dev/null; then
  rm -rf "$VENV"
  "$PYTHON_BIN" -m venv "$VENV"
  "$VENV/bin/pip" install -q --disable-pip-version-check 'ecdsa>=0.19' 'pycryptodome>=3.20'
fi

# --- compile applet + v1 (coexistence) + driver against jCardSim's API ---------
rm -rf "$BUILD/classes"
mkdir -p "$BUILD/classes"
"$JAVAC" -nowarn -d "$BUILD/classes" -cp "$JCARDSIM_JAR" \
  "$ROOT"/card/eth2/NuriEthSignerV2.java \
  "$ROOT"/card/eth/*.java \
  "$ROOT"/test/eth2/Eth2SimTest.java

# --- run ------------------------------------------------------------------------
"$JAVA" -cp "$BUILD/classes:$JCARDSIM_JAR" com.nuri.eth2.test.Eth2SimTest "$BUILD/sigs.json" "$SIGN_COUNT" with-v1
"$VENV/bin/python" "$ROOT/test/eth2/verify_eth2_sigs.py" "$BUILD/sigs.json" "$SIGN_COUNT"
"$VENV/bin/python" -m unittest discover -s "$ROOT/host" -p 'test_host.py' -v 2>&1 | tail -4

echo "ETH2_SIM_TESTS_OK"
echo "Simulator only. Real-card behaviour of ALG_ECDSA_SHA_256 on secp256k1 still needs the physical J3R180/SecID card."
