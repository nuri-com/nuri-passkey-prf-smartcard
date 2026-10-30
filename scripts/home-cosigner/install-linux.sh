#!/usr/bin/env bash
# Install the Nuri home cosigner as a systemd --user unit (Linux, e.g. a Pi).
# UNVERIFIED on hardware: written against the macOS twin (run.sh is shared), but
# no Linux box has run it yet.
#
#   scripts/home-cosigner/install-linux.sh [--port 8787] [--python /usr/bin/python3] [--node /usr/bin/node] [--no-load]
#   scripts/home-cosigner/install-linux.sh --uninstall
#
# The PIN is never asked for and never printed. Linux has no login keychain here,
# so it lives in a mode-600 file that the wrapper re-checks at every start:
#
#   mkdir -p ~/.nuri-card && chmod 700 ~/.nuri-card
#   ( umask 077; read -rs -p 'card PIN: ' p; printf '%s\n' "$p" > ~/.nuri-card/pin )
#
# Details and the agent one-liner: docs/home-cosigner.md
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUN="$HERE/run.sh"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/nuri-home-cosigner.service"
STATE_DIR="${NURI_CARD_STATE_DIR:-$HOME/.nuri-card}"
LOG_DIR="$STATE_DIR/logs"
LOG_FILE="$LOG_DIR/home-cosigner.log"
PIN_FILE="$STATE_DIR/pin"
PORT="${NURI_HOME_COSIGNER_PORT:-8787}"
PYTHON="${NURI_HOME_COSIGNER_PYTHON:-$(command -v python3 || true)}"
NODE_BIN="${NURI_HOME_COSIGNER_NODE:-$(command -v node || true)}"
LOAD=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift ;;
    --python) PYTHON="$2"; shift ;;
    --node) NODE_BIN="$2"; shift ;;
    --no-load) LOAD=0 ;;
    -h|--help) sed -n 2,19p "$0"; exit 0 ;;
    --uninstall)
      systemctl --user disable --now nuri-home-cosigner.service 2>/dev/null || true
      rm -f "$UNIT"
      systemctl --user daemon-reload 2>/dev/null || true
      echo "removed $UNIT (state and logs stay in $STATE_DIR)"
      exit 0 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
  shift
done

[[ -x "$PYTHON" ]] || { echo "python not found: ${PYTHON:-<none>} (need 3.10+); pass --python" >&2; exit 1; }
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || { echo "python 3.10+ required: $PYTHON" >&2; exit 1; }
[[ -n "$NODE_BIN" && -x "$NODE_BIN" ]] || { echo "node not found (need Node 22+); pass --node" >&2; exit 1; }
"$NODE_BIN" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' || { echo "node 22+ required: $NODE_BIN" >&2; exit 1; }

mkdir -p "$LOG_DIR"
chmod 700 "$STATE_DIR" "$LOG_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

mkdir -p "$UNIT_DIR"
cat >"$UNIT" <<EOF
[Unit]
Description=Nuri card home cosigner (card in reader, no spending limits)
Documentation=file:$REPO/docs/home-cosigner.md
After=pcscd.service pcscd.socket

[Service]
Type=simple
Environment=NURI_HOME_COSIGNER_PIN_SOURCE=file
Environment=NURI_HOME_COSIGNER_PIN_FILE=$PIN_FILE
Environment=NURI_HOME_COSIGNER_PORT=$PORT
Environment=NURI_HOME_COSIGNER_PYTHON=$PYTHON
Environment=NURI_HOME_COSIGNER_NODE=$NODE_BIN
Environment=NURI_CARD_STATE_DIR=$STATE_DIR
ExecStart=/bin/bash $RUN
Restart=always
RestartSec=5
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE
# The card is the only hardware; keep the service off the network-cleanup path.
KillMode=mixed
[Install]
WantedBy=default.target
EOF

echo "wrote $UNIT (loopback 127.0.0.1:$PORT, card stays in the reader, no limits)"
echo "log:  $LOG_FILE (0600)"
[[ -f "$PIN_FILE" ]] || { echo; echo "No PIN file yet. Store it once, quiet and outside shell history:"; \
  echo "  ( umask 077; read -rs -p 'card PIN: ' p; printf '%s\\n' \"\$p\" > \"$PIN_FILE\" )"; }
echo

if [[ "$LOAD" == 1 ]]; then
  systemctl --user daemon-reload
  systemctl --user enable --now nuri-home-cosigner.service
  loginctl enable-linger "$USER" 2>/dev/null || echo "note: loginctl enable-linger $USER failed; the unit only runs while you are logged in"
  echo "started nuri-home-cosigner.service — journalctl --user -u nuri-home-cosigner -f"
else
  echo "not loaded (--no-load): systemctl --user daemon-reload && systemctl --user enable --now nuri-home-cosigner"
fi
