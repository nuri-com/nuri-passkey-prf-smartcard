#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE="${FIDO2_DEST:-$ROOT/vendor/FIDO2Applet-clean}"
PYTHON_BIN="${PYTHON_BIN:-/opt/homebrew/bin/python3.10}"
VENV="${FIDO2_TEST_VENV:-/tmp/nuri-fido2-prf-venv}"

if [[ ! -d "$BASELINE" ]]; then
  "$ROOT/scripts/prepare-fido2-baseline.sh"
fi

if [[ -z "${JC_HOME:-}" ]]; then
  if [[ -d "$BASELINE/sdks/jc305u3_kit/lib" ]]; then
    export JC_HOME="$BASELINE/sdks/jc305u3_kit"
  elif [[ -d "$ROOT/../FIDO2Applet/sdks/jc305u3_kit/lib" ]]; then
    export JC_HOME="$ROOT/../FIDO2Applet/sdks/jc305u3_kit"
  else
    export JC_HOME="$BASELINE/sdks/jc305u3_kit"
  fi
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi

if [[ -d /Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home ]]; then
  export JAVA_HOME="${JAVA_HOME:-/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home}"
  export PATH="$JAVA_HOME/bin:$PATH"
fi

if [[ ! -d "$JC_HOME/lib" ]]; then
  echo "JC_HOME does not look usable: $JC_HOME" >&2
  echo "Set JC_HOME to a Java Card SDK with a lib directory." >&2
  exit 1
fi

if [[ -f "$BASELINE/requirements.txt" ]]; then
  REQ_ID="$(shasum -a 256 "$BASELINE/requirements.txt" | awk '{print $1}')"
else
  REQ_ID="fallback-fido2-1.1.2"
fi

if [[ ! -x "$VENV/bin/python" ]] || [[ ! -f "$VENV/.nuri-requirements" ]] || [[ "$(cat "$VENV/.nuri-requirements")" != "$REQ_ID" ]]; then
  rm -rf "$VENV"
  "$PYTHON_BIN" -m venv "$VENV"
  if [[ -f "$BASELINE/requirements.txt" ]]; then
    "$VENV/bin/pip" install -r "$BASELINE/requirements.txt"
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
