#!/usr/bin/env bash
# Install ONLY: never deletes/replaces any package, applet or FIDO2 credential.
# No script argv or arbitrary GP flags accepted. Set GP_BIN/GP_READER explicitly.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GP_BIN="${GP_BIN:-gp}"
VAULT_CAP="${VAULT_CAP:-$ROOT/dist/nuri-vault.cap}"
PACKAGE_AID=4E555249564C54
APPLET_AID=4E555249564C5401
FIDO2_AID=A0000006472F0001
[[ $# == 0 ]] || { printf 'Refusing script arguments (install-only)\n' >&2; exit 1; }
for var in GP_EXTRA_ARGS GP_ARGS_EXTRA; do
  [[ -z "${!var:-}" ]] || { printf 'Refusing %s: arbitrary GP flags are not supported\n' "$var" >&2; exit 1; }
done
[[ -f "$VAULT_CAP" ]] || { printf 'Missing vault CAP: %s\n' "$VAULT_CAP" >&2; exit 1; }
expected="$(python3 -c 'import pathlib,sys; rows=[r.split()[0] for r in pathlib.Path(sys.argv[1]).read_text().splitlines() if r.split() and r.split()[-1]=="nuri-vault.cap"]; assert len(rows)==1 and len(rows[0])==64, "missing/duplicate vault checksum"; print(rows[0])' "$ROOT/dist/SHA256SUMS")"
actual="$(shasum -a 256 "$VAULT_CAP")"
[[ "${actual%% *}" == "$expected" ]] || { printf 'Refusing vault CAP checksum mismatch\n' >&2; exit 1; }
command -v "$GP_BIN" >/dev/null || { printf 'GlobalPlatformPro not found: %s\n' "$GP_BIN" >&2; exit 1; }
GP_ARGS=()
if [[ -n "${GP_READER_INDEX:-}" ]]; then
  [[ "$GP_READER_INDEX" =~ ^[0-9]+$ ]] || { printf 'Invalid GP_READER_INDEX\n' >&2; exit 1; }
  GP_ARGS+=("-r$GP_READER_INDEX")
elif [[ -n "${GP_READER:-}" ]]; then
  GP_ARGS+=("-r" "$GP_READER")
fi
[[ -z "${GP_KEY:-}" ]] || GP_ARGS+=("-k" "$GP_KEY")
[[ -z "${GP_KEY_ENC:-}" ]] || GP_ARGS+=("--key-enc" "$GP_KEY_ENC")
[[ -z "${GP_KEY_MAC:-}" ]] || GP_ARGS+=("--key-mac" "$GP_KEY_MAC")
[[ -z "${GP_KEY_DEK:-}" ]] || GP_ARGS+=("--key-dek" "$GP_KEY_DEK")
gp_run() { "$GP_BIN" ${GP_ARGS[@]+"${GP_ARGS[@]}"} "$@"; }
has_app() { grep -Eq "^[[:space:]]*APP:[[:space:]]+$1([[:space:]]|$)" <<<"$2"; }
has_pkg() { grep -Eq "^[[:space:]]*PKG:[[:space:]]+$1([[:space:]]|$)" <<<"$2"; }
printf '== registry BEFORE ==\n'
before="$(gp_run -l)"
printf '%s\n' "$before"
has_app "$FIDO2_AID" "$before" || { printf 'Refusing: FIDO2 %s not listed before install\n' "$FIDO2_AID" >&2; exit 1; }
if has_app "$APPLET_AID" "$before"; then
  printf 'Vault already installed; nothing changed. This script never deletes.\n'
  exit 0
fi
if [[ "${VAULT_DRY_RUN:-}" == 1 ]]; then
  printf 'DRY RUN: vault install/create only; no write performed\n'
  exit 0
fi
if has_pkg "$PACKAGE_AID" "$before"; then
  gp_run --package "$PACKAGE_AID" --applet "$APPLET_AID" --create "$APPLET_AID"
else
  gp_run --install "$VAULT_CAP"
fi
printf '== registry AFTER ==\n'
after="$(gp_run -l)"
printf '%s\n' "$after"
has_app "$FIDO2_AID" "$after" || { printf 'ASSERT FAILED: FIDO2 missing AFTER install\n' >&2; exit 1; }
has_app "$APPLET_AID" "$after" || { printf 'ASSERT FAILED: vault missing AFTER install\n' >&2; exit 1; }
while read -r aid; do
  [[ -z "$aid" ]] && continue
  grep -Eq "^[[:space:]]*(APP|PKG):[[:space:]]+$aid([[:space:]]|$)" <<<"$after" || {
    printf 'ASSERT FAILED: existing AID vanished: %s\n' "$aid" >&2; exit 1;
  }
done < <(grep -oE '(APP|PKG):[[:space:]]+[0-9A-F]+' <<<"$before" | while read -r label aid; do printf '%s\n' "$aid"; done | sort -u)
printf 'VAULT_INSTALLED_ALONGSIDE_FIDO2 package=%s applet=%s fido2=%s\n' "$PACKAGE_AID" "$APPLET_AID" "$FIDO2_AID"
printf 'Next: owner runs scripts/card-secrets.py --backend card init (mandatory PIN).\n'
