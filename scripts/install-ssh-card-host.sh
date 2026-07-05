#!/usr/bin/env bash
#
# install-ssh-card-host.sh — one-command setup for using the Nuri smartcard
# as an SSH hardware key on THIS machine (the card is the key; the private
# key never leaves the secure element).
#
# What this does:
#   1. Builds dist/nuri-pcsc-sk-provider.so (the OpenSSH FIDO provider bridge).
#   2. Sets up a Python venv with the `fido2` library (the provider calls it).
#   3. Installs the SSH key + ssh_config snippet into ~/.ssh.
#
# Requirements:
#   - macOS: Xcode CLI (clang), Python 3.10+, a PC/SC reader + the card inserted.
#   - Linux: gcc, Python 3.10+, pcscd running, a PC/SC reader + the card inserted.
#
# After running this, you can:
#   ssh nuri-card-host   (alias configured below — edit the HostName/User)
#
# To enroll a NEW SSH key on the card (first time, or on a new card):
#   ssh-keygen -t ecdsa-sk -w dist/nuri-pcsc-sk-provider.so -f ~/.ssh/id_nuri_pcsc_sk -C "nuri-card"
#
# Re-run this script any time on a new machine — it is idempotent.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROVIDER="$ROOT/dist/nuri-pcsc-sk-provider.so"
HELPER="$ROOT/scripts/ssh-pcsc-sk-helper.py"
VENV="${NURI_PCSC_VENV:-/tmp/nuri-fido2-real-card-venv}"
SSH_DIR="$HOME/.ssh"
KEY_FILE="$SSH_DIR/id_nuri_pcsc_sk"

echo "=== Nuri smartcard SSH host setup ==="
echo "repo:   $ROOT"
echo "venv:   $VENV"
echo "key:    $KEY_FILE"
echo

# --- 1. Build the provider .so -------------------------------------------------
echo "[1/4] Building nuri-pcsc-sk-provider.so ..."
if [[ ! -f "$PROVIDER" ]] || [[ "${FORCE_BUILD:-}" == "yes" ]]; then
  CC=cc
  if command -v clang >/dev/null 2>&1; then CC=clang; fi
  $CC -dynamiclib -fvisibility=hidden -Wall -O2 -o "$PROVIDER" scripts/ssh-pcsc-sk-provider.c
  echo "  built: $PROVIDER"
else
  echo "  exists: $PROVIDER (set FORCE_BUILD=yes to rebuild)"
fi

# --- 2. Python venv with fido2 ------------------------------------------------
echo "[2/4] Setting up Python venv with fido2 ..."
if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi
# fido2 may already be installed (existing venv). Only install if missing.
if ! "$VENV/bin/python" -c 'import fido2' 2>/dev/null; then
  "$VENV/bin/python" -m pip install --quiet 'fido2>=1.1' pyscard 2>/dev/null || \
    "$VENV/bin/python" -m pip install --quiet --break-system-packages 'fido2>=1.1' pyscard 2>/dev/null || true
fi
if ! "$VENV/bin/python" -c 'import fido2, smartcard' 2>/dev/null; then
  echo "  installing fido2 + pyscard ..." >&2
  "$VENV/bin/python" -m pip install --quiet 'fido2>=1.1' pyscard 2>/dev/null || \
    "$VENV/bin/python" -m pip install --quiet --break-system-packages 'fido2>=1.1' pyscard 2>/dev/null || true
fi
echo "  venv ready: $VENV/bin/python"

# --- 3. SSH config snippet ----------------------------------------------------
echo "[3/4] Writing ssh_config snippet ..."
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

CONFIG_MARKER_BEGIN="# === Nuri smartcard SSH (auto-managed by install-ssh-card-host.sh) ==="
CONFIG_MARKER_END="# === End Nuri smartcard SSH ==="

# Remove any previous auto-managed block
if [[ -f "$SSH_DIR/config" ]]; then
  python3 - "$SSH_DIR/config" "$CONFIG_MARKER_BEGIN" "$CONFIG_MARKER_END" <<'PYEOF'
import sys
path, begin, end = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path).read().splitlines(keepends=True)
out, skip = [], False
for line in lines:
    if begin in line: skip = True; continue
    if skip and end in line: skip = False; continue
    if not skip: out.append(line)
open(path, 'w').writelines(out)
PYEOF
fi

SNIPPET="$CONFIG_MARKER_BEGIN
# The card is the SSH key. Private key never leaves the secure element.
# Each sign requires the card in the reader + a tap (user presence).
# Edit HostName/User below for your server.
Host nuri-card-host
  HostName REPLACE_ME.example.com
  User root
  IdentityFile $KEY_FILE
  SecurityKeyProvider $PROVIDER
  IdentitiesOnly yes
$CONFIG_MARKER_END
"

echo "$SNIPPET" >> "$SSH_DIR/config"
chmod 600 "$SSH_DIR/config"
echo "  config written: $SSH_DIR/config (edit HostName/User for your server)"

# --- 4. Check for existing key ------------------------------------------------
echo "[4/4] Checking for SSH key on card ..."
if [[ -f "$KEY_FILE" ]]; then
  echo "  key exists: $KEY_FILE"
  FP=$(/opt/homebrew/bin/ssh-keygen -l -f "$KEY_FILE.pub" 2>/dev/null || ssh-keygen -l -f "$KEY_FILE.pub" 2>/dev/null || echo "unknown")
  echo "  fingerprint: $FP"
  echo
  echo "=== Done. Test with: ssh nuri-card-host ==="
  echo "(edit $SSH_DIR/config → replace REPLACE_ME.example.com with your server)"
else
  echo
  echo "=== No key file yet. To create one on the card: ==="
  echo
  SSHGEN=ssh-keygen
  command -v /opt/homebrew/bin/ssh-keygen >/dev/null 2>&1 && SSHGEN=/opt/homebrew/bin/ssh-keygen
  echo "  $SSHGEN -t ecdsa-sk -w $PROVIDER -f $KEY_FILE -C nuri-card"
  echo
  echo "Then copy the public key to your server's ~/.ssh/authorized_keys:"
  echo "  cat $KEY_FILE.pub"
fi