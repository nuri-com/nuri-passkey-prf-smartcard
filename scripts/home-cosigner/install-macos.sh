#!/usr/bin/env bash
# Install the Nuri home cosigner as a macOS LaunchAgent: the card stays in the
# reader and signs for a local agent until you remove it. No spending limit and
# no allowlist live here — the calling agent owns policy.
#
#   scripts/home-cosigner/install-macos.sh [--port 8787] [--python <3.10+>] [--node <22+>] [--no-load]
#   scripts/home-cosigner/install-macos.sh --uninstall
#
# The PIN is never asked for and never printed. It lives in your login keychain
# and is read by the wrapper at every start. Store it yourself, once:
#
#   security add-generic-password -s nuri-card-pin -a "$USER" -w
#
# Details and the agent one-liner: docs/home-cosigner.md
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/run.sh"
LABEL="com.nuri.home-cosigner"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
STATE_DIR="${NURI_CARD_STATE_DIR:-$HOME/.nuri-card}"
LOG_DIR="$STATE_DIR/logs"
LOG_FILE="$LOG_DIR/home-cosigner.log"
PORT="${NURI_HOME_COSIGNER_PORT:-8787}"
PYTHON="${NURI_HOME_COSIGNER_PYTHON:-/opt/homebrew/bin/python3.13}"
NODE_BIN="${NURI_HOME_COSIGNER_NODE:-$(command -v node || true)}"
LOAD=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift ;;
    --python) PYTHON="$2"; shift ;;
    --node) NODE_BIN="$2"; shift ;;
    --print-plist) ;;
    --no-load) LOAD=0 ;;
    -h|--help) sed -n 2,17p "$0"; exit 0 ;;
    --uninstall)
      launchctl bootout "gui/$UID/$LABEL" 2>/dev/null || launchctl unload -w "$PLIST" 2>/dev/null || true
      rm -f "$PLIST"
      echo "removed $PLIST (state and logs stay in $STATE_DIR)"
      exit 0 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
  shift
done

[[ -x "$PYTHON" ]] || PYTHON="$(command -v python3 || true)"
[[ -n "$PYTHON" && -x "$PYTHON" ]] || { echo "python not found at ${PYTHON:-<none>} (brew install python@3.13 or pass --python)" >&2; exit 1; }
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || { echo "python 3.10+ required: $PYTHON" >&2; exit 1; }
[[ -n "$NODE_BIN" && -x "$NODE_BIN" ]] || { echo "node not found (need Node 22+); pass --node" >&2; exit 1; }
"$NODE_BIN" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' || { echo "node 22+ required: $NODE_BIN" >&2; exit 1; }

# 0700 state, 0700 logs, 0600 log file. launchd would create the log 0644 if we
# let it; the wrapper re-chmods on every start as a second line of defence.
mkdir -p "$LOG_DIR"
chmod 700 "$STATE_DIR" "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

mkdir -p "$(dirname "$PLIST")"
cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$RUN</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>NURI_HOME_COSIGNER_PORT</key>
    <string>$PORT</string>
    <key>NURI_HOME_COSIGNER_PYTHON</key>
    <string>$PYTHON</string>
    <key>NURI_HOME_COSIGNER_NODE</key>
    <string>$NODE_BIN</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key>
  <string>$LOG_FILE</string>
  <key>StandardErrorPath</key>
  <string>$LOG_FILE</string>
</dict>
</plist>
EOF
if command -v plutil >/dev/null 2>&1; then plutil -lint "$PLIST" >/dev/null; fi

echo "wrote $PLIST (loopback 127.0.0.1:$PORT, card stays in the reader, no limits)"
echo "log:  $LOG_FILE (0600)"
echo "token file: ${NURI_CARD_STATE_DIR:-$HOME/.nuri-card}/cosign.token (0600, created at first start)"

if [[ -f "$HOME/.nuri-card-host/bitcoin.env" ]]; then
  echo "reader: NURI_READER is read from $HOME/.nuri-card-host/bitcoin.env"
else
  echo "reader: no ~/.nuri-card-host/bitcoin.env — the default reader selection is used"
fi

echo
echo "One-time PIN step (quiet prompt, nothing in shell history):"
echo "  security add-generic-password -s nuri-card-pin -a \"\$USER\" -w"
echo "Then: launchctl kickstart -k gui/$UID/$LABEL && tail -n 20 \"$LOG_FILE\""
echo

if [[ "$LOAD" == 1 ]]; then
  launchctl bootout "gui/$UID/$LABEL" 2>/dev/null || true
  launchctl bootstrap "gui/$UID" "$PLIST"
  launchctl enable "gui/$UID/$LABEL"
  launchctl kickstart -k "gui/$UID/$LABEL" 2>/dev/null || true
  echo "loaded $LABEL"
else
  echo "not loaded (--no-load): launchctl bootstrap gui/\$UID \"$PLIST\""
fi
