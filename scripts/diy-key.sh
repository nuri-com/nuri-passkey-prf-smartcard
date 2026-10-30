#!/usr/bin/env bash
# DIY one-command admin (GP) key change for a provisioned Nuri card.
# Wraps scripts/card_lock.py: all card logic lives there, this file only sets up
# tools, explains what happens and forwards the exact reader name.
# Preflight, pinned gp, venv, deny-list and reader choice are shared with
# scripts/card-setup.sh through scripts/lib/card-common.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/card-common.sh
. "$ROOT/scripts/lib/card-common.sh"

ACTION="lock"
READER=""
ESCROW=""
PASSPHRASE_FD=""
ASSUME_YES=0

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

card_common_init_env
card_common_state
card_common_gp
export GP_BIN="$GP"
card_common_python
card_common_denylist

if [ -z "$READER" ]; then
    card_common_list_readers
    if [ "${#READERS[@]}" -eq 0 ]; then
        say "No card reader with a card was found."
        say "Plug the USB reader in, insert the Nuri card, wait for the LED and run this again."
        if [ "$OS" = Linux ]; then
            say "On Linux the 'pcscd' daemon must run: sudo systemctl start pcscd"
        fi
        exit 1
    fi
    card_common_pick_reader
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
        SHOWN="$(sed -n 's/.*Encrypted escrow durably published: //p' "$LOG" | tail -n 1 || true)"
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
