#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_ROOT="${CARD_BUILD_ROOT:-$ROOT/.build/card-v1}"
SDK_REPO="${JAVACARD_SDK_REPO:-https://github.com/martinpaljak/oracle_javacard_sdks.git}"
SDK_REF="${JAVACARD_SDK_REF:-e2df471e04d86f33de69a947f44766fbef1d9d69}"
SDK_DIR="${JAVACARD_SDK_DIR:-$BUILD_ROOT/toolchain/oracle-javacard-sdks}"
PROVEN_ANT_JAR="$ROOT/tools/ant-javacard-proven.jar"
PROVEN_ANT_SHA256="def557393fd20dbe478a4581c3273222805b9e494836aa8465dfbe0fb9d64cf2"

for command_name in git shasum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Missing required command: $command_name" >&2
    exit 1
  }
done

actual_ant_sha="$(shasum -a 256 "$PROVEN_ANT_JAR" | awk '{print $1}')"
if [[ "$actual_ant_sha" != "$PROVEN_ANT_SHA256" ]]; then
  echo "Unexpected ant-javacard tool hash: $actual_ant_sha" >&2
  exit 1
fi

mkdir -p "$(dirname "$SDK_DIR")"
if [[ ! -d "$SDK_DIR/.git" ]]; then
  local_sdk="$ROOT/vendor/FIDO2Applet-clean/sdks"
  if [[ -d "$local_sdk/.git" ]]; then
    git clone --no-hardlinks "$local_sdk" "$SDK_DIR"
  else
    git clone "$SDK_REPO" "$SDK_DIR"
  fi
fi

if ! git -C "$SDK_DIR" cat-file -e "$SDK_REF^{commit}" 2>/dev/null; then
  git -C "$SDK_DIR" fetch --all --tags --prune
fi
git -C "$SDK_DIR" checkout --detach "$SDK_REF"
if [[ "$(git -C "$SDK_DIR" rev-parse HEAD)" != "$SDK_REF" ]]; then
  echo "Java Card SDK checkout did not resolve to $SDK_REF" >&2
  exit 1
fi

for kit in jc304_kit jc305u3_kit; do
  if [[ ! -d "$SDK_DIR/$kit" ]]; then
    echo "Pinned SDK checkout is missing $kit" >&2
    exit 1
  fi
done

printf '%s\n' "$SDK_DIR"
