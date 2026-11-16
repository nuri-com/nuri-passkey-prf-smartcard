#!/usr/bin/env bash
# Install ONLY the ETH signer v2 applet (card/eth2, package 4E55524945544832,
# applet 4E5552494554483201) next to whatever is already on the card.
#
# Guarantees:
#   * never issues a GlobalPlatform DELETE (no `--delete`, `--uninstall`, `-f`
#     or `--force`): v1 ETH, MuSig2, TOTP and FIDO2 are left exactly as found;
#   * prints `gp -l` before and after;
#   * asserts the FIDO2 applet A0000006472F0001 is listed before AND after;
#   * refuses to run if v2 is already present (nothing to do, nothing to delete).
#
# Env: GP_BIN (default gp), GP_READER (reader name) or GP_READER_INDEX,
#      GP_KEY / GP_KEY_ENC / GP_KEY_MAC / GP_KEY_DEK for SCP03 after key rotation,
#      ETH2_CAP (default dist/nuri-eth2-signer.cap), ETH2_DRY_RUN=1 to print only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GP_BIN="${GP_BIN:-gp}"
ETH2_CAP="${ETH2_CAP:-$ROOT/dist/nuri-eth2-signer.cap}"
ETH2_PACKAGE_AID="4E55524945544832"
ETH2_APPLET_AID="4E5552494554483201"
FIDO2_AID="A0000006472F0001"
ETH2_SHA256="$(grep ' nuri-eth2-signer.cap$' "$ROOT/dist/SHA256SUMS" | awk '{print $1}')"

[[ -f "$ETH2_CAP" ]] || { echo "ETH2 CAP not found: $ETH2_CAP" >&2; exit 1; }
actual="$(shasum -a 256 "$ETH2_CAP" | awk '{print $1}')"
if [[ -n "$ETH2_SHA256" && "$actual" != "$ETH2_SHA256" ]]; then
  echo "Refusing: $ETH2_CAP sha256 $actual != dist/SHA256SUMS $ETH2_SHA256" >&2
  exit 1
fi

# Any delete flag in the environment is a bug in the caller: fail closed.
for v in GP_EXTRA_ARGS GP_ARGS_EXTRA; do
  if [[ "${!v:-}" == *delete* || "${!v:-}" == *uninstall* || "${!v:-}" == *force* ]]; then
    echo "Refusing: $v contains a delete/uninstall/force flag: ${!v}" >&2
    exit 1
  fi
done

command -v "$GP_BIN" >/dev/null 2>&1 || { echo "GlobalPlatformPro not found: $GP_BIN" >&2; exit 1; }

GP_ARGS=()
if [[ -n "${GP_READER_INDEX:-}" ]]; then
  GP_ARGS+=("-r${GP_READER_INDEX}")
elif [[ -n "${GP_READER:-}" ]]; then
  GP_ARGS+=("-r" "$GP_READER")
fi
[[ -z "${GP_KEY:-}" ]] || GP_ARGS+=("-k" "$GP_KEY")
[[ -z "${GP_KEY_ENC:-}" ]] || GP_ARGS+=("--key-enc" "$GP_KEY_ENC")
[[ -z "${GP_KEY_MAC:-}" ]] || GP_ARGS+=("--key-mac" "$GP_KEY_MAC")
[[ -z "${GP_KEY_DEK:-}" ]] || GP_ARGS+=("--key-dek" "$GP_KEY_DEK")

gp_list() { "$GP_BIN" ${GP_ARGS[@]+"${GP_ARGS[@]}"} -l; }
gp_run()  { "$GP_BIN" ${GP_ARGS[@]+"${GP_ARGS[@]}"} "$@"; }

echo "== registry BEFORE =="
before="$(gp_list)"
printf '%s\n' "$before"

grep -q "$FIDO2_AID" <<<"$before" || {
  echo "Refusing: FIDO2 applet $FIDO2_AID not listed before install; this is not a provisioned Nuri card." >&2
  exit 1
}
if grep -q "$ETH2_APPLET_AID" <<<"$before"; then
  echo "ETH2 applet $ETH2_APPLET_AID already installed. This script never deletes; nothing to do."
  exit 0
fi

if [[ "${ETH2_DRY_RUN:-}" == "1" ]]; then
  echo "DRY RUN: would run: $GP_BIN ${GP_ARGS[*]:-} --install $ETH2_CAP"
  exit 0
fi

echo "== installing ETH2 (load + create only) =="
if grep -q "$ETH2_PACKAGE_AID" <<<"$before"; then
  # package present without an instance: only create
  gp_run --package "$ETH2_PACKAGE_AID" --applet "$ETH2_APPLET_AID" --create "$ETH2_APPLET_AID"
else
  gp_run --install "$ETH2_CAP"
fi

echo "== registry AFTER =="
after="$(gp_list)"
printf '%s\n' "$after"

grep -q "$FIDO2_AID" <<<"$after" || { echo "ASSERT FAILED: FIDO2 $FIDO2_AID missing after install" >&2; exit 1; }
grep -q "$ETH2_APPLET_AID" <<<"$after" || { echo "ASSERT FAILED: ETH2 $ETH2_APPLET_AID not listed after install" >&2; exit 1; }
# Every AID that was there before must still be there.
while read -r aid; do
  [[ -z "$aid" ]] && continue
  grep -q "$aid" <<<"$after" || { echo "ASSERT FAILED: $aid vanished during install" >&2; exit 1; }
done < <(grep -oE '(APP|PKG): [0-9A-F]+' <<<"$before" | awk '{print $2}' | sort -u)

echo "ETH2_INSTALLED_ALONGSIDE_V1 package=$ETH2_PACKAGE_AID applet=$ETH2_APPLET_AID fido2=$FIDO2_AID"
echo "Next: SET_PIN (80 21), VERIFY (80 20), then one-shot KEYGEN (80 03), all in a trusted provisioning session. PIN is mandatory by default. See docs/attestation.md."
