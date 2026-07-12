#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GP_BIN="${GP_BIN:-gp}"

if [[ "${CARD_PROVISION_CONFIRM:-}" != "YES" ]]; then
  echo "Provisioning changes a physical card." >&2
  echo "Re-run with CARD_PROVISION_CONFIRM=YES and an explicit GP_READER or GP_READER_INDEX." >&2
  exit 1
fi
if [[ -z "${GP_READER:-}" ]] && [[ -z "${GP_READER_INDEX:-}" ]]; then
  echo "Set GP_READER or GP_READER_INDEX explicitly." >&2
  exit 1
fi
if [[ -z "${GP_KEY:-}" ]] && {
  [[ -z "${GP_KEY_ENC:-${SCP03_ENC:-}}" ]] ||
  [[ -z "${GP_KEY_MAC:-${SCP03_MAC:-}}" ]] ||
  [[ -z "${GP_KEY_DEK:-${SCP03_DEK:-}}" ]];
}; then
  echo "Provide GP_KEY or all of GP_KEY_ENC, GP_KEY_MAC, and GP_KEY_DEK." >&2
  exit 1
fi

command -v "$GP_BIN" >/dev/null 2>&1 || {
  echo "GlobalPlatformPro not found: $GP_BIN" >&2
  exit 1
}

(
  cd "$ROOT/dist"
  shasum -a 256 -c SHA256SUMS
)

GP_ARGS=()
if [[ -n "${GP_READER_INDEX:-}" ]]; then
  GP_ARGS+=("-r${GP_READER_INDEX}")
else
  GP_ARGS+=("-r" "$GP_READER")
fi
if [[ -n "${GP_KEY:-}" ]]; then
  GP_ARGS+=("-k" "$GP_KEY")
fi
[[ -z "${GP_KEY_ENC:-${SCP03_ENC:-}}" ]] || GP_ARGS+=("--key-enc" "${GP_KEY_ENC:-${SCP03_ENC}}")
[[ -z "${GP_KEY_MAC:-${SCP03_MAC:-}}" ]] || GP_ARGS+=("--key-mac" "${GP_KEY_MAC:-${SCP03_MAC}}")
[[ -z "${GP_KEY_DEK:-${SCP03_DEK:-}}" ]] || GP_ARGS+=("--key-dek" "${GP_KEY_DEK:-${SCP03_DEK}}")

registry="$($GP_BIN "${GP_ARGS[@]}" --list 2>&1)"
for aid in A0000006472F0001 4E5552494D554701 4E555249544F5450 4E55524945544801; do
  if grep -q "$aid" <<<"$registry"; then
    echo "Refusing to provision a non-blank target: applet $aid is already present." >&2
    exit 1
  fi
done

for cap in \
  FIDO2-up.cap \
  nuri-musig2-v20-keygen.cap \
  nuri-oath-totp.cap \
  nuri-eth-signer.cap; do
  echo "Installing $cap"
  "$GP_BIN" "${GP_ARGS[@]}" --install "$ROOT/dist/$cap"
done

"$GP_BIN" "${GP_ARGS[@]}" --list
echo "CARD_V1_APPLETS_INSTALLED"
echo "Next: generate card keys, set the owner's PIN, run scripts/accept-card-v1.sh, then rotate GP keys."
