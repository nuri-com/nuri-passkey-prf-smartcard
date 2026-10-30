#!/usr/bin/env bash
# One command from a blank Nuri card to a working card.
#
# Installs the seven applets of release v1.2.0 in the proven order, checks the
# result, and writes everything to a private log. ETH2 signs with a PIN and
# replaces the legacy PIN-less ETH1, which is only kept for the demo card. It
# never deletes anything, so a wrong run costs time, not a card.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/card-common.sh
. "$ROOT/scripts/lib/card-common.sh"

DEFAULT_KEY="404142434445464748494A4B4C4D4E4F"
READER=""
EXPECT_SERIAL=""
DRY_RUN=0
RESUME=0
ASSUME_YES=0

AIDS=(
    A0000006472F0001
    4E5552494D554701
    4E555249544F5450
    4E5552494554483201
    4E5552494D55473201
    4E5552494D55473301
    4E555249564C5401
)

usage() {
    cat <<'EOF'
Usage: bash scripts/card-setup.sh [options]

Takes a blank Nuri card to a working card in eight numbered steps.

Options:
  --reader NAME    use this exact PC/SC reader, skip the picker
  --serial 8HEX    expect this card serial and skip the typed confirmation
  --dry-run        run every read-only step, print the plan, write nothing
  --resume         install only what is missing, never delete
  --yes            accepted for scripts; without --serial it still asks
  --help           show this help
EOF
}

step() { printf '\n[%s/8] %s\n' "$1" "$2"; }
say() { printf '%s\n' "$*"; }
die() {
    printf '\nERROR: %s\n' "$*" >&2
    [ -n "${LOG:-}" ] && printf 'Full log: %s\n' "$LOG" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --reader)
            [ "$#" -ge 2 ] || { usage >&2; die "--reader needs a value"; }
            READER="$2"; shift 2 ;;
        --serial)
            [ "$#" -ge 2 ] || { usage >&2; die "--serial needs a value"; }
            EXPECT_SERIAL="$(printf '%s' "$2" | tr -d ' \t\r' | tr '[:lower:]' '[:upper:]')"
            case "$EXPECT_SERIAL" in
                *[!0-9A-F]*|'') die "--serial needs 8 hex characters" ;;
            esac
            [ "${#EXPECT_SERIAL}" -eq 8 ] || die "--serial needs exactly 8 hex characters"
            shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --resume) RESUME=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) { usage >&2; die "unknown argument: $1"; } ;;
    esac
done

# An inherited value must not silently turn a step into a delete.
unset MUSIG2_REINSTALL

if [ "$ASSUME_YES" = 1 ] && [ -z "$EXPECT_SERIAL" ]; then
    say "Note: --yes alone does not skip the confirmation; pass --serial <8 hex> for that."
fi

# ---------------------------------------------------------------- 1 preflight
step 1 "Check the machine and install the tools"
card_common_init_env
card_common_state
card_common_gp
# install-musig2-card.sh calls a bare `gp`; a pinned shim must win in PATH.
GP_REAL="$GP"
case "$GP_REAL" in
    */*) ;;
    *) GP_REAL="$(command -v -- "$GP_REAL" || true)" ;;
esac
[ -n "$GP_REAL" ] || die "no usable gp found"
mkdir -p "$TOOLS/bin"
chmod 700 "$TOOLS/bin"
printf '#!/bin/sh\nexec "%s" "$@"\n' "$GP_REAL" > "$TOOLS/bin/gp"
chmod 700 "$TOOLS/bin/gp"
export GP_BIN="$GP_REAL"
PATH="$TOOLS/bin:$PATH"; export PATH
card_common_python
card_common_python_pcsc
card_common_denylist
say "Tools ready. gp: $GP"

# ------------------------------------------------------------------- 2 reader
step 2 "Find the card and read it (no write)"
if [ -z "$READER" ]; then
    card_common_list_readers
    if [ "${#READERS[@]}" -eq 0 ]; then
        say "No card reader with a card was found."
        say "Plug the USB reader in, insert the blank card, wait for the LED and run again."
        exit 1
    fi
    card_common_pick_reader
else
    card_common_list_readers
    card_common_reader_exists "$READER" ||
        die "reader not found: $READER (listed: ${READERS[*]:-none})"
fi
card_common_set_ignores

INFO_OUT="$("$PY" "$ROOT/scripts/card-setup-card.py" info --reader "$READER")" ||
    die "could not read the card; is it in the reader and a contact card?"
SERIAL=""; CPLC=""; ATR=""; CHIP=""; OS_DATE=""
while IFS='=' read -r key value; do
    case "$key" in
        SERIAL) SERIAL="$value" ;;
        CPLC) CPLC="$value" ;;
        ATR) ATR="$value" ;;
        CHIP) CHIP="$value" ;;
        OS_DATE) OS_DATE="$value" ;;
    esac
done <<< "$INFO_OUT"
[ -n "$SERIAL" ] && [ -n "$CPLC" ] || die "could not parse the card serial"
say "Chip: $CHIP"
say "Serial: $SERIAL   OS date: $OS_DATE"
say "ATR: $ATR"

if [ -n "$EXPECT_SERIAL" ] && [ "$EXPECT_SERIAL" != "$SERIAL" ]; then
    die "this is card $SERIAL but --serial says $EXPECT_SERIAL; nothing was written"
fi
if card_common_denylisted "$SERIAL" "$CPLC"; then
    say "Card $SERIAL is on the deny-list ($NURI_DIR/no-lock-cplc.txt)."
    say "It belongs to a card that keeps its keys; setup would still work, but this guard stops here."
    exit 1
fi

LOG_DIR="$NURI_DIR/logs"
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"
LOG="$LOG_DIR/setup-$SERIAL-$(date +%Y%m%d-%H%M%S).log"
: > "$LOG"
chmod 600 "$LOG"
exec > >(tee -a "$LOG") 2>&1
say "Log: $LOG"

# --------------------------------------------------------------------- 3 auth
step 3 "Check that the public default admin key opens the card"
# A card whose admin key was changed on this machine (scripts/diy-key.sh) has an
# escrow named after its CPLC. Never try the default key on it: a wrong try
# counts toward locking the card for good.
ESCROW_DIR="${NURI_ESCROW_DIR:-$HOME/.nuri-card/escrow}"
ESCROW="$ESCROW_DIR/$CPLC.json"
if [ -n "$CPLC" ] && [ -f "$ESCROW" ]; then
    say "Card $SERIAL: its admin key was changed on this machine (escrow $ESCROW)."
    say "The public default key is not tried; a wrong try counts toward locking the card."
    say ""
    say "This card is not blank. Nothing was written."
    exit 0
fi
set +e
REGISTRY="$("$GP" -r "$READER" -k "$DEFAULT_KEY" -l 2>&1)"
AUTH_RC=$?
set -e
printf '%s\n' "$REGISTRY"
if [ "$AUTH_RC" -ne 0 ]; then
    say ""
    say "This card does not use the public default admin key. Ask the seller for the keys."
    say "Do not retry: cards lock after a few wrong tries."
    exit 1
fi

has_app() { grep -Eq "^[[:space:]]*APP:[[:space:]]+$1([[:space:]]|$)" <<< "$REGISTRY"; }
gp_run() { "$GP" -r "$READER" -k "$DEFAULT_KEY" "$@"; }

# ------------------------------------------------------------ 4 blank check
step 4 "Check that the card is blank"
present=(); missing=()
for aid in "${AIDS[@]}"; do
    if has_app "$aid"; then present+=("$aid"); else missing+=("$aid"); fi
done
if [ "${#present[@]}" -gt 0 ]; then
    say "Found on the card: ${present[*]}"
    if [ "$RESUME" = 0 ]; then
        say ""
        say "This card is not blank. Nothing was written."
        say "Use --resume to install only the missing applets; nothing is ever deleted."
        exit 0
    fi
    say "Resume: only the missing applets are installed (${#missing[@]} of ${#AIDS[@]})."
else
    say "Blank card, none of the seven applets present."
fi
if [ "$RESUME" = 1 ] && [ "${#missing[@]}" -eq 0 ]; then
    say "All seven applets are already installed. Nothing to do."
    exit 0
fi

# --------------------------------------------------------------------- 5 plan
step 5 "Confirm the plan"
say "Target: card $SERIAL on reader $READER"
say ""
say "  1) FIDO2, MuSig2 AID1, TOTP           scripts/provision-card-v1.sh"
say "  2) ETH2                              scripts/install-eth2-card.sh"
say "  3) MuSig2 AID2                       scripts/install-musig2-card.sh"
say "  4) MuSig2 AID3                       scripts/install-musig2-card.sh"
say "  5) vault                             scripts/install-vault-card.sh"
say ""
say "Legacy PIN-less ETH1 is not installed (ETH2 does the same with a PIN)."
say "Then FIDO2/ETH2/MuSig2/vault are checked with a read-only SELECT."
say "No PIN is set here and no key is generated here. No existing applet is deleted."
say "Time: about 10 minutes. The card must stay in the reader."
if [ -n "$EXPECT_SERIAL" ]; then
    say "Serial confirmed with --serial."
else
    card_common_confirm_serial "$SERIAL"
fi

if [ "$DRY_RUN" = 1 ]; then
    say ""
    say "DRY RUN: nothing was written to the card."
    exit 0
fi

# ------------------------------------------------------------------ 6 install
step 6 "Install the applets (log: $LOG)"
( cd "$ROOT/dist" && shasum -a 256 -c SHA256SUMS ) || die "dist checksums do not match; nothing was installed"

install_bundle() {
    if [ "$RESUME" = 0 ]; then
        env CARD_PROVISION_CONFIRM=YES PROVISION_SKIP_ETH1=YES GP_KEY="$DEFAULT_KEY" GP_READER="$READER" \
            bash "$ROOT/scripts/provision-card-v1.sh"
        return
    fi
    local caps=(FIDO2-up.cap nuri-musig2-v20-keygen.cap nuri-oath-totp.cap)
    local i
    for i in 0 1 2; do
        if has_app "${AIDS[$i]}"; then
            say "  skip ${caps[$i]}: ${AIDS[$i]} already present"
            continue
        fi
        say "  install ${caps[$i]}"
        gp_run --install "$ROOT/dist/${caps[$i]}" || return 1
    done
}

install_eth2() {
    env GP_KEY="$DEFAULT_KEY" GP_READER="$READER" bash "$ROOT/scripts/install-eth2-card.sh"
}

install_musig2() {
    env GP_KEY="$DEFAULT_KEY" GP_READER="$READER" \
        MUSIG2_CAP="$ROOT/dist/$1" MUSIG2_PACKAGE_AID="$2" MUSIG2_APPLET_AID="$3" \
        bash "$ROOT/scripts/install-musig2-card.sh"
}

install_vault() {
    env GP_KEY="$DEFAULT_KEY" GP_READER="$READER" bash "$ROOT/scripts/install-vault-card.sh"
}

say "Step 1 of 5"
install_bundle || die "step 1 of 5 failed (bundle); the card keeps what is installed"
say "Step 2 of 5"
install_eth2 || die "step 2 of 5 failed (ETH2); the card keeps what is installed"
say "Step 3 of 5"
install_musig2 nuri-musig2-v20-keygen-aid2.cap 4E5552494D554732 4E5552494D55473201 ||
    die "step 3 of 5 failed (MuSig2 AID2); the card keeps what is installed"
say "Step 4 of 5"
install_musig2 nuri-musig2-v20-keygen-aid3.cap 4E5552494D554733 4E5552494D55473301 ||
    die "step 4 of 5 failed (MuSig2 AID3); the card keeps what is installed"
say "Step 5 of 5"
install_vault || die "step 5 of 5 failed (vault); the card keeps what is installed"

# ------------------------------------------------------------------ 7 verify
step 7 "Verify the result (read-only)"
set +e
REGISTRY="$("$GP" -r "$READER" -k "$DEFAULT_KEY" -l 2>&1)"
AUTH_RC=$?
set -e
printf '%s\n' "$REGISTRY"
[ "$AUTH_RC" -eq 0 ] || die "the registry could not be read back"

absent=()
for aid in "${AIDS[@]}"; do
    has_app "$aid" || absent+=("$aid")
done
if [ "${#absent[@]}" -gt 0 ]; then
    say "Missing from the registry: ${absent[*]}"
    die "the card is incomplete; re-run with --resume"
fi
say "All seven applets are listed."

"$PY" "$ROOT/scripts/card-setup-card.py" verify --reader "$READER" || die "at least one applet did not answer SELECT"
say "Every applet answered SELECT (9000, or 61xx on T=0-only readers)."
say ""
say "CARD_SETUP_VERIFIED $SERIAL"

# ------------------------------------------------------------- 8 next steps
step 8 "Next steps"
say "1. Set the FIDO2 PIN:        npm run card:pin:set"
say "2. Set the other PINs (each asks twice, one AID per run):"
say "   python3 scripts/attest-card.py init-key --aid 4E5552494554483201 --execute   # ETH2"
say "   python3 scripts/attest-card.py init-key --aid 4E5552494D554701 --execute"
say "   python3 scripts/attest-card.py init-key --aid 4E5552494D55473201 --execute"
say "   python3 scripts/attest-card.py init-key --aid 4E5552494D55473301 --execute"
say "   python3 scripts/attest-card.py init-key --aid 4E555249564C5401 --execute"
say "3. SSH key:   bash scripts/install-ssh-card-host.sh"
say "              ssh-keygen -t ecdsa-sk -w \"\$PWD/dist/nuri-pcsc-sk-provider.so\" -f \"\$HOME/.ssh/id_nuri_pcsc_sk\" -C nuri-card"
say "4. Chrome:    bash host/install-macos.sh ; see host/bitcoin.env.example"
say "5. Seal last: bash scripts/diy-key.sh"
say ""
say "Full guide: docs/diy-card.md"
say "Log: $LOG"

# Process substitution (tee) may still be flushing when the script returns.
sleep 0.1
exit 0
