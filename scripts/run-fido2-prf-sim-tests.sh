#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE="${FIDO2_DEST:-$ROOT/.build/fido2-applet}"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"
VENV="${FIDO2_TEST_VENV:-/tmp/nuri-fido2-prf-venv}"

if [[ ! -d "$BASELINE" ]]; then
  "$ROOT/scripts/prepare-fido2-baseline.sh"
fi

if [[ -z "${JC_HOME:-}" ]]; then
  SDK_DIR="${JAVACARD_SDK_DIR:-$ROOT/.build/card-v1/toolchain/oracle-javacard-sdks}"
  if [[ ! -d "$SDK_DIR/jc305u3_kit/lib" ]]; then
    SDK_DIR="$("$ROOT/scripts/prepare-card-build-toolchain.sh")"
  fi
  export JC_HOME="$SDK_DIR/jc305u3_kit"
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi

if [[ -n "${JAVA17_HOME:-}" ]]; then
  export JAVA_HOME="$JAVA17_HOME"
  export PATH="$JAVA_HOME/bin:$PATH"
elif [[ -d /Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home ]]; then
  export JAVA_HOME="${JAVA_HOME:-/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home}"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

if [[ ! -d "$JC_HOME/lib" ]]; then
  echo "JC_HOME does not look usable: $JC_HOME" >&2
  echo "Set JC_HOME to a Java Card SDK with a lib directory." >&2
  exit 1
fi

if [[ -f "$BASELINE/requirements.txt" ]]; then
  REQ_ID="pyscard-2.0.7:$(shasum -a 256 "$BASELINE/requirements.txt" | awk '{print $1}')"
else
  REQ_ID="fallback-fido2-1.1.2"
fi

if [[ ! -x "$VENV/bin/python" ]] || [[ ! -f "$VENV/.nuri-requirements" ]] || [[ "$(cat "$VENV/.nuri-requirements")" != "$REQ_ID" ]]; then
  rm -rf "$VENV"
  "$PYTHON_BIN" -m venv "$VENV"
  if [[ -f "$BASELINE/requirements.txt" ]]; then
    "$VENV/bin/pip" install -r "$BASELINE/requirements.txt"
    "$VENV/bin/pip" install 'pyscard==2.0.7'
  else
    "$VENV/bin/pip" install \
      'fido2[pcsc]==1.1.2' \
      'pyscard==2.0.7' \
      'JPype1==1.5.0' \
      'parameterized==0.9.0' \
      'uhid==0.0.1'
  fi
  echo "$REQ_ID" >"$VENV/.nuri-requirements"
fi

cd "$BASELINE"
./gradlew jar testJar test --no-daemon
"$VENV/bin/python" -m unittest python_tests.ctap.test_hmac_secret.HMACSecretTestCase
cd "$ROOT"
FIDO2_BASELINE="$BASELINE" "$VENV/bin/python" test/fido2_prf_e2e.py
echo "FIDO2_JCARDSIM_PRF_OK"
