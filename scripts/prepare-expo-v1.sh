#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DS_REF="${NURI_DESIGN_SYSTEM_REF:-73c64a07e85cf086d750629a82af2b8a7527b43a}"
DS_URL="${NURI_DESIGN_SYSTEM_URL:-https://github.com/nuri-com/nuri-design-system.git}"
DS_DIR="${NURI_DESIGN_SYSTEM_DIR:-$ROOT/.build/nuri-design-system}"

mkdir -p "$(dirname "$DS_DIR")"
if [[ ! -d "$DS_DIR/.git" ]]; then
  local_checkout="$ROOT/../nuri-design-system-official"
  if [[ -d "$local_checkout/.git" ]]; then
    git clone --no-hardlinks "$local_checkout" "$DS_DIR"
  else
    git clone "$DS_URL" "$DS_DIR"
  fi
fi

if ! git -C "$DS_DIR" cat-file -e "$DS_REF^{commit}" 2>/dev/null; then
  git -C "$DS_DIR" fetch --all --tags --prune
fi
git -C "$DS_DIR" checkout --detach "$DS_REF"
if [[ "$(git -C "$DS_DIR" rev-parse HEAD)" != "$DS_REF" ]]; then
  echo "Design-system checkout did not resolve to $DS_REF" >&2
  exit 1
fi
if [[ -n "$(git -C "$DS_DIR" status --porcelain)" ]]; then
  echo "Design-system checkout is dirty: $DS_DIR" >&2
  exit 1
fi
for package in rn spec; do
  [[ -f "$DS_DIR/packages/$package/package.json" ]] || {
    echo "Pinned design system is missing packages/$package" >&2
    exit 1
  }
done

echo "NURI_DESIGN_SYSTEM_READY $DS_REF"
