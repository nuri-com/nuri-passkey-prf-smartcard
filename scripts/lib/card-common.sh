# Shared setup for the DIY scripts: preflight, pinned gp, private venv,
# deny-list and reader selection. Sourced by scripts/diy-key.sh and
# scripts/card-setup.sh. Everything here is a function; sourcing has no side
# effects, so `--help` still touches nothing.
#
# The caller defines say() and die() before calling anything below.

CARD_COMMON_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JAVA_MIN=11
GP_SHA256_DEFAULT="a68eca9ab9be84a0560b2d312ca6a18cd2dbcd223bb7b30525e0e0f85a372696"
GP_SIZE_DEFAULT="14668599"
GP_URL_DEFAULT="https://github.com/martinpaljak/GlobalPlatformPro/releases/download/v24.10.15/gp.jar"

# ---------------------------------------------------------------- preflight
card_common_init_env() {
    OS="$(uname -s)"
    DEBIAN=0
    [ -r /etc/debian_version ] && DEBIAN=1
    if [ -r /etc/os-release ]; then
        ID_LIKE="$(sed -n 's/^ID_LIKE=//p' /etc/os-release | tr -d '"')"
        case "$ID_LIKE" in *debian*|*ubuntu*) DEBIAN=1 ;; esac
    fi

    BASE_PY="${PYTHON_BIN:-}"
    if [ -z "$BASE_PY" ]; then
        BASE_PY="$(command -v python3 2>/dev/null || true)"
    fi
    if [ -z "$BASE_PY" ]; then
        say "python3 was not found." >&2
        card_common_print_fix
        exit 1
    fi
    if ! "$BASE_PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
        say "python3 3.9 or newer is required ($BASE_PY is older or unusable)." >&2
        card_common_print_fix
        exit 1
    fi

    if ! command -v java >/dev/null 2>&1; then
        say "java was not found. GlobalPlatformPro needs Java 11 or newer." >&2
        card_common_print_fix
        exit 1
    fi
    JAVA_NUM="$(java -version 2>&1 | sed -n 's/.*version "\([0-9][0-9]*\).*/\1/p' | head -n 1 || true)"
    if [ -z "$JAVA_NUM" ] || [ "$JAVA_NUM" -lt "$JAVA_MIN" ]; then
        say "Java ${JAVA_NUM:-unknown} is too old; Java ${JAVA_MIN} or newer is required." >&2
        card_common_print_fix
        exit 1
    fi

    if [ "$OS" = Linux ] && command -v systemctl >/dev/null 2>&1; then
        if ! systemctl is-active --quiet pcscd 2>/dev/null; then
            say "Warning: the smartcard daemon 'pcscd' is not active. Start it with:" >&2
            say "  sudo systemctl start pcscd   (Debian/Ubuntu: sudo apt install pcscd)" >&2
        fi
    fi
}

card_common_print_fix() {
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

# ------------------------------------------------------------ private state
card_common_state() {
    umask 077
    NURI_DIR="$HOME/.nuri-card"
    TOOLS="$NURI_DIR/tools"
    mkdir -p "$NURI_DIR" "$TOOLS"
    chmod 700 "$NURI_DIR" "$TOOLS"
    ESCROW_DIR="$NURI_DIR/escrow"
}

# ------------------------------------------------------------------ gp tool
# GP_BIN wins when set. Otherwise a pinned jar is downloaded, hash-checked and
# wrapped. The wrapper is the only way the pinned version is guaranteed.
card_common_gp() {
    if [ -n "${GP_BIN:-}" ]; then
        GP="$GP_BIN"
        return 0
    fi
    local jar="$TOOLS/gp-24.10.15.jar"
    local gp="$TOOLS/gp-24.10.15"
    local expected_sha="${NURI_GP_SHA256:-$GP_SHA256_DEFAULT}"
    local expected_size="${NURI_GP_SIZE:-$GP_SIZE_DEFAULT}"
    local tmp_jar actual_size actual_sha

    if [ ! -f "$jar" ]; then
        tmp_jar="$(mktemp "$TOOLS/.gp-download.XXXXXXXXXX")"
        say "Downloading GlobalPlatformPro 24.10.15 ..."
        if ! curl -fL --proto '=https,file' --proto-redir '=https,file' --silent --show-error \
                -o "$tmp_jar" "${NURI_GP_URL:-$GP_URL_DEFAULT}"; then
            rm -f "$tmp_jar"
            die "download failed; check the network and run again"
        fi
        actual_size="$(wc -c < "$tmp_jar" | tr -d ' ')"
        if [ "$actual_size" != "$expected_size" ]; then
            rm -f "$tmp_jar"
            say "Unexpected download size: expected $expected_size bytes, got $actual_size" >&2
            die "refusing an unverified gp.jar; nothing was installed"
        fi
        actual_sha="$(card_common_file_sha "$tmp_jar")"
        if [ "$actual_sha" != "$expected_sha" ]; then
            rm -f "$tmp_jar"
            say "Unexpected download checksum: expected $expected_sha, got $actual_sha" >&2
            die "refusing an unverified gp.jar; nothing was installed"
        fi
        mv "$tmp_jar" "$jar"
        chmod 600 "$jar"
    else
        actual_size="$(wc -c < "$jar" | tr -d ' ')"
        actual_sha="$(card_common_file_sha "$jar")"
        if [ "$actual_size" != "$expected_size" ] || [ "$actual_sha" != "$expected_sha" ]; then
            die "the installed gp.jar no longer matches the pinned checksum; delete it and run again"
        fi
    fi

    printf '#!/bin/sh\nexec java -jar "%s" "$@"\n' "$jar" > "$gp"
    chmod 700 "$gp"
    GP="$gp"
}

card_common_file_sha() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        die "neither shasum nor sha256sum is available"
    fi
}

# ------------------------------------------------------------------- python
card_common_python() {
    if [ -n "${PYTHON_BIN:-}" ]; then
        PY="$PYTHON_BIN"
        return 0
    fi
    local venv="$NURI_DIR/venv"
    PY="$venv/bin/python"
    if [ ! -x "$PY" ]; then
        say "Preparing a private Python environment ..."
        "$BASE_PY" -m venv "$venv" || { say "could not create $venv" >&2; card_common_print_fix; exit 1; }
    fi
    if ! "$PY" -c 'import Crypto' >/dev/null 2>&1; then
        say "Installing the card-lock Python requirements ..."
        "$PY" -m pip install --quiet --disable-pip-version-check \
            --requirement "$CARD_COMMON_ROOT/scripts/requirements-card-lock.txt" ||
            die "pip install failed; run again or check the network"
    fi
}

# pyscard for the read-only card probe. Skipped when the interpreter already
# imports it (tests inject a fake module through PYTHONPATH).
card_common_python_pcsc() {
    "$PY" -c 'import smartcard' >/dev/null 2>&1 && return 0
    say "Installing the PC/SC Python module ..."
    "$PY" -m pip install --quiet --disable-pip-version-check \
        --requirement "$CARD_COMMON_ROOT/scripts/requirements-card-setup.txt" ||
        die "pyscard install failed; run again or check the network"
    "$PY" -c 'import smartcard' >/dev/null 2>&1 ||
        die "pyscard still does not import in $PY; install it with pip and run again"
}

# ---------------------------------------------------------------- deny list
card_common_denylist() {
    DENY="$NURI_DIR/no-lock-cplc.txt"
    [ -f "$DENY" ] && return 0
    say "This file lists cards the wizard must never touch (owner reserves, demo cards)."
    say "It does not exist yet, so it will be created now."
    local deny_value="" ok=0 attempt
    for attempt in 1 2 3; do
        printf 'Serial of a card that must NEVER be changed (8 hex), Enter = none: '
        read -r deny_value || deny_value=""
        deny_value="$(printf '%s' "$deny_value" | tr -d ' \t\r' | tr '[:lower:]' '[:upper:]')"
        if [ -z "$deny_value" ]; then
            ok=1
            break
        fi
        case "${#deny_value}" in
            8|84) ;;
            *) say "  expected 8 or 84 hex characters, got ${#deny_value}"; deny_value=""; continue ;;
        esac
        case "$deny_value" in
            *[!0-9A-F]*) say "  only hex characters 0-9 A-F are allowed"; deny_value=""; continue ;;
        esac
        ok=1
        break
    done
    if [ "$ok" != 1 ]; then
        die "no valid deny-list value after 3 attempts; nothing was created"
    fi
    {
        printf '# Cards listed here are never touched by the DIY wizard.\n'
        printf '# One 8-hex serial or one complete 84-hex CPLC per line.\n'
        [ -n "$deny_value" ] && printf '%s\n' "$deny_value"
    } > "$DENY"
    chmod 600 "$DENY"
}

# 0 when the serial or the full CPLC appears in the deny-list.
card_common_denylisted() {
    local serial="$1" cplc="${2:-}"
    [ -f "$DENY" ] || return 1
    grep -qxF "$serial" "$DENY" && return 0
    [ -n "$cplc" ] && grep -qxF "$cplc" "$DENY" && return 0
    return 1
}

# ------------------------------------------------------------------ readers
# Inherited GP_* values must not steer the listing. GP_BIN is ours and is kept.
card_common_list_readers() {
    local v out rc line keep_gp_bin="${GP_BIN:-}"
    for v in $(compgen -e); do
        if [ "${v#GP_}" != "$v" ]; then unset "$v"; fi
    done
    set +e
    out="$("$GP" --reader)"
    rc=$?
    set -e
    [ -n "$keep_gp_bin" ] && export GP_BIN="$keep_gp_bin"
    case "$rc" in
        0|1) ;;
        *) die "could not list the readers; is the card reader connected?" ;;
    esac
    READERS=()
    local seen_header=0
    while IFS= read -r line; do
        if [ "$seen_header" = 0 ]; then
            [ "$line" = "Available readers:" ] && seen_header=1
            continue
        fi
        case "$line" in
            "- "*) READERS[${#READERS[@]}]="${line#- }" ;;
        esac
    done <<< "$out"
}

# 0 when the requested reader exists in READERS; 1 when it does not.
card_common_reader_exists() {
    local wanted="$1" name
    for name in ${READERS[@]+"${READERS[@]}"}; do
        [ "$name" = "$wanted" ] && return 0
    done
    return 1
}

card_common_pick_reader() {
    local i=0 choice ok=0 attempt
    say ""
    say "Readers holding a card:"
    while [ "$i" -lt "${#READERS[@]}" ]; do
        say "  $((i + 1))) ${READERS[$i]}"
        i=$((i + 1))
    done
    for attempt in 1 2 3; do
        printf 'Select the reader by number: '
        read -r choice || choice=""
        choice="$(printf '%s' "$choice" | tr -d ' \t\r')"
        case "$choice" in
            ''|*[!0-9]*) say "  not a number"; continue ;;
        esac
        if [ "$choice" -ge 1 ] && [ "$choice" -le "${#READERS[@]}" ]; then
            READER="${READERS[$((choice - 1))]}"
            ok=1
            break
        fi
        say "  choose 1 to ${#READERS[@]}"
    done
    [ "$ok" = 1 ] || die "no valid reader selected"
}

# gp matches reader names as substrings. Any other listed reader would also
# match, so ignore all of them for every later call.
card_common_set_ignores() {
    local name others=()
    for name in ${READERS[@]+"${READERS[@]}"}; do
        [ "$name" = "$READER" ] || others[${#others[@]}]="$name"
    done
    if [ "${#others[@]}" -gt 0 ]; then
        local joined
        joined="$(IFS=';'; printf '%s' "${others[*]}")"
        export GP_READER_IGNORE="$joined"
    fi
}

# ---------------------------------------------------------------- confirm
# The human types the 8-hex serial back. Three tries, then stop.
card_common_confirm_serial() {
    local serial="$1" typed attempt
    for attempt in 1 2 3; do
        printf 'Type the card serial %s to install: ' "$serial"
        read -r typed || typed=""
        typed="$(printf '%s' "$typed" | tr -d ' \t\r' | tr '[:lower:]' '[:upper:]')"
        if [ "$typed" = "$serial" ]; then
            return 0
        fi
        say "  serials differ"
    done
    die "serial not confirmed; nothing was installed"
}
