#!/usr/bin/env bash
# DIY one-command admin (GP) key change for a provisioned Nuri card.
# Wraps scripts/card_lock.py: all card logic lives there, this file only sets up
# tools, explains what happens and forwards the exact reader name.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="lock"
READER=""
ESCROW=""
PASSPHRASE_FD=""
ASSUME_YES=0
JAVA_MIN=11
GP_SHA256_DEFAULT="a68eca9ab9be84a0560b2d312ca6a18cd2dbcd223bb7b30525e0e0f85a372696"
GP_SIZE_DEFAULT="14668599"
GP_URL_DEFAULT="https://github.com/martinpaljak/GlobalPlatformPro/releases/download/v24.10.15/gp.jar"

usage() {
    cat <<'EOF'
Usage: bash scripts/diy-key.sh            # guided lock: change the card's admin key
       bash scripts/diy-key.sh unlock     # guided restore of the default admin key
       bash scripts/diy-key.sh --help

Options:
  --reader NAME         use this exact PC/SC reader, skip the picker
  --escrow PATH         escrow file (backup of the card keys)
  --passphrase-fd N     read the escrow passphrase from inherited descriptor N
  --yes                 skip the wizard's own y/N prompt (card_lock still asks)
  --help                show this help
EOF
}

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        unlock|lock)
            ACTION="$1"; shift ;;
        --reader)
            [ "$#" -ge 2 ] || die "--reader needs a value"
            READER="$2"; shift 2 ;;
        --escrow)
            [ "$#" -ge 2 ] || die "--escrow needs a value"
            ESCROW="$2"; shift 2 ;;
        --passphrase-fd)
            [ "$#" -ge 2 ] || die "--passphrase-fd needs a number"
            case "$2" in ''|*[!0-9]*) die "--passphrase-fd needs a number" ;; esac
            PASSPHRASE_FD="$2"; shift 2 ;;
        --yes)
            ASSUME_YES=1; shift ;;
        --help|-h)
            usage; exit 0 ;;
        *)
            die "unknown argument: $1 (see --help)" ;;
    esac
done

# ---------------------------------------------------------------- preflight
OS="$(uname -s)"
DEBIAN=0
[ -r /etc/debian_version ] && DEBIAN=1
if [ -r /etc/os-release ]; then
    ID_LIKE="$(sed -n 's/^ID_LIKE=//p' /etc/os-release | tr -d '"')"
    case "$ID_LIKE" in *debian*|*ubuntu*) DEBIAN=1 ;; esac
fi

print_fix() {
    case "$OS" in
        Darwin)
            say "Install Java 21 from https://adoptium.net and Python 3 from https://www.python.org" >&2
            say "  (or: brew install --cask temurin   and   brew install python)" >&2 ;;
        *)
            if [ "$DEBIAN" = 1 ]; then
                say "Debian/Ubuntu: sudo apt install default-jre-headless python3-venv pcscd" >&2
            else
                say "Install a Java 11+ runtime (openjdk-21-jre-headless), python3 3.9+, python3-venv and pcscd from your package manager" >&2
            fi ;;
    esac
}

BASE_PY="${PYTHON_BIN:-}"
if [ -z "$BASE_PY" ]; then
    BASE_PY="$(command -v python3 2>/dev/null || true)"
fi
if [ -z "$BASE_PY" ]; then
    say "python3 was not found." >&2
    print_fix
    exit 1
fi
if ! "$BASE_PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    say "python3 3.9 or newer is required ($BASE_PY is older or unusable)." >&2
    print_fix
    exit 1
fi

if ! command -v java >/dev/null 2>&1; then
    say "java was not found. GlobalPlatformPro needs Java 11 or newer." >&2
    print_fix
    exit 1
fi
JAVA_NUM="$(java -version 2>&1 | sed -n 's/.*version "\([0-9][0-9]*\).*/\1/p' | head -n 1 || true)"
if [ -z "$JAVA_NUM" ] || [ "$JAVA_NUM" -lt "$JAVA_MIN" ]; then
    say "Java ${JAVA_NUM:-unknown} is too old; Java ${JAVA_MIN} or newer is required." >&2
    print_fix
    exit 1
fi

if [ "$OS" = Linux ] && command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet pcscd 2>/dev/null; then
        say "Warning: the smartcard daemon 'pcscd' is not active. Start it with:" >&2
        say "  sudo systemctl start pcscd   (Debian/Ubuntu: sudo apt install pcscd)" >&2
    fi
fi

# ------------------------------------------------------------ private state
umask 077
NURI_DIR="$HOME/.nuri-card"
TOOLS="$NURI_DIR/tools"
mkdir -p "$NURI_DIR" "$TOOLS"
chmod 700 "$NURI_DIR" "$TOOLS"
ESCROW_DIR="$NURI_DIR/escrow"

# ------------------------------------------------------------------ gp tool
if [ -n "${GP_BIN:-}" ]; then
    GP="$GP_BIN"
else
    JAR="$TOOLS/gp-24.10.15.jar"
    GP="$TOOLS/gp-24.10.15"
    EXPECTED_SHA="${NURI_GP_SHA256:-$GP_SHA256_DEFAULT}"
    EXPECTED_SIZE="${NURI_GP_SIZE:-$GP_SIZE_DEFAULT}"

    file_sha() {
        if command -v shasum >/dev/null 2>&1; then
            shasum -a 256 "$1" | awk '{print $1}'
        elif command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$1" | awk '{print $1}'
        else
            die "neither shasum nor sha256sum is available"
        fi
    }

    verify_jar() {
        local actual_size actual_sha
        actual_size="$(wc -c < "$1" | tr -d ' ')"
        if [ "$actual_size" != "$EXPECTED_SIZE" ]; then
            say "Unexpected download size: expected $EXPECTED_SIZE bytes, got $actual_size" >&2
            return 1
        fi
        actual_sha="$(file_sha "$1")"
        if [ "$actual_sha" != "$EXPECTED_SHA" ]; then
            say "Unexpected download checksum: expected $EXPECTED_SHA, got $actual_sha" >&2
            return 1
        fi
        return 0
    }

    if [ ! -f "$JAR" ]; then
        TMP_JAR="$(mktemp "$TOOLS/.gp-download.XXXXXXXXXX")"
        say "Downloading GlobalPlatformPro 24.10.15 ..."
        if ! curl -fL --proto '=https,file' --proto-redir '=https,file' --silent --show-error \
                -o "$TMP_JAR" "${NURI_GP_URL:-$GP_URL_DEFAULT}"; then
            rm -f "$TMP_JAR"
            die "download failed; check the network and run again"
        fi
        if ! verify_jar "$TMP_JAR"; then
            rm -f "$TMP_JAR"
            die "refusing an unverified gp.jar; nothing was installed"
        fi
        mv "$TMP_JAR" "$JAR"
        chmod 600 "$JAR"
    elif ! verify_jar "$JAR"; then
        die "the installed gp.jar no longer matches the pinned checksum; delete it and run again"
    fi

    printf '#!/bin/sh\nexec java -jar "%s" "$@"\n' "$JAR" > "$GP"
    chmod 700 "$GP"
fi
export GP_BIN="$GP"

# ------------------------------------------------------------------- python
if [ -n "${PYTHON_BIN:-}" ]; then
    PY="$PYTHON_BIN"
else
    VENV="$NURI_DIR/venv"
    PY="$VENV/bin/python"
    if [ ! -x "$PY" ]; then
        say "Preparing a private Python environment ..."
        "$BASE_PY" -m venv "$VENV" || { say "could not create $VENV" >&2; print_fix; exit 1; }
    fi
    if ! "$PY" -c 'import Crypto' >/dev/null 2>&1; then
        say "Installing the card-lock Python requirements ..."
        "$PY" -m pip install --quiet --disable-pip-version-check \
            --requirement "$ROOT/scripts/requirements-card-lock.txt" ||
            die "pip install failed; run again or check the network"
    fi
fi

# ---------------------------------------------------------------- deny list
DENY="$NURI_DIR/no-lock-cplc.txt"
if [ ! -f "$DENY" ]; then
    say "This file lists cards the wizard must never touch (owner reserves, demo cards)."
    say "It does not exist yet, so it will be created now."
    DENY_VALUE=""
    DENY_OK=0
    for attempt in 1 2 3; do
        printf 'Serial of a card that must NEVER be changed (8 hex), Enter = none: '
        read -r DENY_VALUE || DENY_VALUE=""
        DENY_VALUE="$(printf '%s' "$DENY_VALUE" | tr -d ' \t\r' | tr '[:lower:]' '[:upper:]')"
        if [ -z "$DENY_VALUE" ]; then
            DENY_OK=1
            break
        fi
        case "${#DENY_VALUE}" in
            8|84) ;;
            *) say "  expected 8 or 84 hex characters, got ${#DENY_VALUE}"; DENY_VALUE=""; continue ;;
        esac
        case "$DENY_VALUE" in
            *[!0-9A-F]*) say "  only hex characters 0-9 A-F are allowed"; DENY_VALUE=""; continue ;;
        esac
        DENY_OK=1
        break
    done
    if [ "$DENY_OK" != 1 ]; then
        die "no valid deny-list value after 3 attempts; nothing was created"
    fi
    {
        printf '# Cards listed here are never touched by the DIY wizard.\n'
        printf '# One 8-hex serial or one complete 84-hex CPLC per line.\n'
        [ -n "$DENY_VALUE" ] && printf '%s\n' "$DENY_VALUE"
    } > "$DENY"
    chmod 600 "$DENY"
fi

# ------------------------------------------------------------------ readers
# Inherited GP_* values must not steer the listing or the later card calls.
clean_gp_env() {
    local v
    for v in $(compgen -e); do
        if [ "${v#GP_}" != "$v" ]; then unset "$v"; fi
    done
    "$GP" --reader
}

if [ -z "$READER" ]; then
    set +e
    READER_OUT="$(clean_gp_env)"
    READER_RC=$?
    set -e
    case "$READER_RC" in
        0|1) ;;
        *) die "could not list the readers; is the card reader connected?" ;;
    esac
    READERS=()
    seen_header=0
    while IFS= read -r line; do
        if [ "$seen_header" = 0 ]; then
            [ "$line" = "Available readers:" ] && seen_header=1
            continue
        fi
        case "$line" in
            "- "*) READERS[${#READERS[@]}]="${line#- }" ;;
        esac
    done <<< "$READER_OUT"

    if [ "${#READERS[@]}" -eq 0 ]; then
        say "No card reader with a card was found."
        say "Plug the USB reader in, insert the Nuri card, wait for the LED and run this again."
        if [ "$OS" = Linux ]; then
            say "On Linux the 'pcscd' daemon must run: sudo systemctl start pcscd"
        fi
        exit 1
    fi
    say ""
    say "Readers holding a card:"
    i=0
    while [ "$i" -lt "${#READERS[@]}" ]; do
        say "  $((i + 1))) ${READERS[$i]}"
        i=$((i + 1))
    done
    PICK_OK=0
    for attempt in 1 2 3; do
        printf 'Select the reader by number: '
        read -r choice || choice=""
        choice="$(printf '%s' "$choice" | tr -d ' \t\r')"
        case "$choice" in
            ''|*[!0-9]*) say "  not a number"; continue ;;
        esac
        if [ "$choice" -ge 1 ] && [ "$choice" -le "${#READERS[@]}" ]; then
            READER="${READERS[$((choice - 1))]}"
            PICK_OK=1
            break
        fi
        say "  choose 1 to ${#READERS[@]}"
    done
    [ "$PICK_OK" = 1 ] || die "no valid reader selected"
fi

# -------------------------------------------------------------- unlock file
if [ "$ACTION" = unlock ] && [ -z "$ESCROW" ]; then
    ESCROWS=()
    for candidate in "$ESCROW_DIR"/*.json; do
        [ -e "$candidate" ] || continue
        ESCROWS[${#ESCROWS[@]}]="$candidate"
    done
    if [ "${#ESCROWS[@]}" -eq 0 ]; then
        say "No escrow file in $ESCROW_DIR; pass one with --escrow." >&2
        exit 1
    fi
    say ""
    say "Escrow backups found:"
    i=0
    while [ "$i" -lt "${#ESCROWS[@]}" ]; do
        say "  $((i + 1))) ${ESCROWS[$i]}"
        i=$((i + 1))
    done
    PICK_OK=0
    for attempt in 1 2 3; do
        printf 'Select the escrow by number: '
        read -r choice || choice=""
        choice="$(printf '%s' "$choice" | tr -d ' \t\r')"
        case "$choice" in
            ''|*[!0-9]*) say "  not a number"; continue ;;
        esac
        if [ "$choice" -ge 1 ] && [ "$choice" -le "${#ESCROWS[@]}" ]; then
            ESCROW="${ESCROWS[$((choice - 1))]}"
            PICK_OK=1
            break
        fi
        say "  choose 1 to ${#ESCROWS[@]}"
    done
    [ "$PICK_OK" = 1 ] || die "no escrow file selected"
fi

# ---------------------------------------------------------------- summary
say ""
if [ "$ACTION" = lock ]; then
    say "About to change the card's admin (GP) key. It is used to install or remove apps."
else
    say "About to restore the card's factory-default admin (GP) key from the escrow backup."
fi
say "Unchanged: your passkeys, wallet keys, card PINs and the installed applets."
say "The card's serial number is shown and must be typed back before anything is sent."
say "Choose escrow passphrase (16+ characters); it is never printed and never stored."
say "Keep the escrow file AND the passphrase, in two separate places."
if [ "$ASSUME_YES" = 0 ]; then
    printf 'Continue? [y/N] '
    read -r answer || answer=""
    case "$answer" in
        y|Y|yes|YES|Yes) ;;
        *) say "Aborted; the card was not touched."; exit 0 ;;
    esac
fi

# ------------------------------------------------------------ card_lock run
RUN_ARGS=("$ROOT/scripts/card_lock.py" "$ACTION" --execute --reader "$READER")
if [ -n "$ESCROW" ]; then
    RUN_ARGS+=(--escrow "$ESCROW")
fi
if [ -n "$PASSPHRASE_FD" ]; then
    RUN_ARGS+=(--passphrase-fd "$PASSPHRASE_FD")
fi

LOG="$(mktemp)"
set +e
"$PY" "${RUN_ARGS[@]}" 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}
set -e

if [ "$RC" -eq 0 ]; then
    say ""
    if [ "$ACTION" = lock ]; then
        SHOWN="$(sed -n 's/^Encrypted escrow durably published: //p' "$LOG" | tail -n 1 || true)"
        [ -n "$SHOWN" ] && ESCROW="$SHOWN"
        say "Escrow backup: $ESCROW"
        say "Copy that file to a USB stick or a second place NOW."
        say "Keep the passphrase somewhere else (password manager, paper safe)."
        say "Without both, a lost key cannot be recovered."
    else
        say "Default admin key restored. The escrow file $ESCROW is kept for reuse."
    fi
fi
rm -f "$LOG"
exit "$RC"
