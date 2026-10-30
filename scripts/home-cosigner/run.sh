#!/usr/bin/env bash
# Nuri home cosigner: long-lived card service for a local agent.
#
# Started by launchd (macOS) or by a systemd --user unit (Linux), never by hand
# in normal use. The card stays in the reader; the PIN comes from the OS keystore
# and reaches the server through the environment only (never argv, never logged).
# There is no spending limit and no allowlist here: the calling agent owns policy.
#
#   run.sh            (installers set the PIN source)
#
# Environment:
#   NURI_HOME_COSIGNER_PIN_SOURCE  keychain (default) | file
#   NURI_HOME_COSIGNER_PIN_FILE    file source path, default ~/.nuri-card/pin
#   NURI_HOME_COSIGNER_SERVICE     keychain service, default nuri-card-pin
#   NURI_HOME_COSIGNER_PORT        loopback port, default 8787
#   NURI_HOME_COSIGNER_PYTHON      Python >= 3.10 for the card drivers
#   NURI_HOME_COSIGNER_NODE        node >= 22
#   NURI_HOME_COSIGNER_PRINT_CMD=1 resolve everything, print the command, exit
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
STATE_DIR="${NURI_CARD_STATE_DIR:-$HOME/.nuri-card}"
LOG_DIR="$STATE_DIR/logs"
LOG_FILE="$LOG_DIR/home-cosigner.log"
PORT="${NURI_HOME_COSIGNER_PORT:-8787}"
SERVICE="${NURI_HOME_COSIGNER_SERVICE:-nuri-card-pin}"
SECURITY="${NURI_HOME_COSIGNER_SECURITY:-security}"
PIN_FILE="${NURI_HOME_COSIGNER_PIN_FILE:-$STATE_DIR/pin}"
PIN_SOURCE="${NURI_HOME_COSIGNER_PIN_SOURCE:-keychain}"
# Homebrew first: launchd starts us with a bare PATH where python3 is macOS 3.9
# without pyscard, and no node at all.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

die() { printf 'nuri home-cosigner: %s\n' "$*" >&2; exit 78; }

mkdir -p "$LOG_DIR"
chmod 700 "$STATE_DIR" "$LOG_DIR" 2>/dev/null || true
: >>"$LOG_FILE"
chmod 600 "$LOG_FILE" 2>/dev/null || true

# --- PIN ---------------------------------------------------------------------
# The value only ever lives in a shell variable, then in the child environment.
if [[ -n "${NURI_CARD_PIN:-}" ]]; then
  pin="$NURI_CARD_PIN" # already exported (tests, manual runs)
elif [[ "$PIN_SOURCE" == file ]]; then
  [[ -f "$PIN_FILE" ]] || die "no PIN file at $PIN_FILE — write the card PIN there once, chmod 600:
  ( umask 077; read -rs -p 'card PIN: ' p; printf '%s\n' \"\$p\" > '$PIN_FILE' )"
  if [[ "$(uname -s)" == Darwin ]]; then pin_mode="$(stat -f '%Lp' "$PIN_FILE")"; else pin_mode="$(stat -c '%a' "$PIN_FILE")"; fi
  [[ "$pin_mode" == 600 ]] || die "$PIN_FILE must be mode 600 (is $pin_mode)"
  pin="$(tr -d '\r\n' <"$PIN_FILE")"
else
  command -v "$SECURITY" >/dev/null 2>&1 || die "security(1) not found; set NURI_HOME_COSIGNER_PIN_SOURCE=file"
  pin="$("$SECURITY" find-generic-password -s "$SERVICE" -a "$USER" -w 2>/dev/null || true)"
  [[ -n "$pin" ]] || die "no card PIN in the login keychain (service '$SERVICE', account '$USER').
Store it yourself once, so it never lands in shell history:
  security add-generic-password -s $SERVICE -a \"\$USER\" -w"
fi
[[ "$pin" =~ ^[0-9]{4,12}$ ]] || die "card PIN is not 4-12 digits (value not shown)"
export NURI_CARD_PIN="$pin"
export NURI_FIDO_PIN="$pin"

# --- reader ------------------------------------------------------------------
# ~/.nuri-card-host/bitcoin.env is the existing per-machine card config. Read
# only the reader key; the file may hold other values we must not override.
HOST_ENV="$HOME/.nuri-card-host/bitcoin.env"
if [[ -f "$HOST_ENV" ]]; then
  reader="$(sed -n 's/^[[:space:]]*NURI_READER=//p' "$HOST_ENV" | tail -1 | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
  [[ -n "$reader" ]] && export NURI_READER="$reader"
fi

# --- interpreters ------------------------------------------------------------
PYTHON="${NURI_HOME_COSIGNER_PYTHON:-/opt/homebrew/bin/python3.13}"
[[ -x "$PYTHON" ]] || PYTHON="$(command -v python3 || true)"
[[ -n "$PYTHON" && -x "$PYTHON" ]] || die "no Python found; install Python 3.10+ (brew install python@3.13) or set NURI_HOME_COSIGNER_PYTHON"
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
  || die "$PYTHON is older than 3.10"
export PYTHON_BIN="$PYTHON"

NODE_BIN="${NURI_HOME_COSIGNER_NODE:-$(command -v node || true)}"
[[ -n "$NODE_BIN" ]] || die "node not found (need Node 22+)"
"$NODE_BIN" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' \
  || die "$NODE_BIN is older than Node 22"
# A fresh clone without dependencies fails deep inside the send path with a bare
# ERR_MODULE_NOT_FOUND; refuse early and name the fix.
[[ -d "$REPO/node_modules/@arkade-os" ]] || die "dependencies missing in $REPO — run: ( cd $REPO && npm ci )"

cd "$REPO"
unset COSIGN_BACKEND
set -- "$NODE_BIN" scripts/local-card-cosign-server.mjs "--host=127.0.0.1" "--port=$PORT" "--backend=real-card"

if [[ "${NURI_HOME_COSIGNER_PRINT_CMD:-}" == 1 ]]; then
  printf '%s\n' "$*"
  exit 0
fi
echo "starting $(date -u +%FT%TZ): $*" >>"$LOG_FILE"
exec "$@"
