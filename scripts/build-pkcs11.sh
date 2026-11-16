#!/usr/bin/env bash
# Build dist/pkcs11-nuri.so from scripts/pkcs11-nuri.c (one clang command).
#
#   bash scripts/build-pkcs11.sh            # macOS arm64 (what dist/ ships)
#   bash scripts/build-pkcs11.sh --check    # rebuild to a temp file and compare its hash
#
# Linux (x86_64/arm64) build line, not run here:
#   cc -shared -fPIC -fvisibility=hidden -Wall -O2 -o dist/pkcs11-nuri.so scripts/pkcs11-nuri.c -ldl
#
# Reproducible on one toolchain: the LC_UUID is derived from the file content
# (ld64 -Wl,-random_uuid is the default; -Wl,-no_uuid makes dyld refuse to load
# the library, so it is NOT used), the install_name is fixed, so two builds give
# the same SHA-256 (verified with Apple clang on macOS 15.5 arm64). Other clang
# versions differ; use --check to see whether yours matches dist/SHA256SUMS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/pkcs11-nuri.so"
if [[ "${1:-}" == "--check" ]]; then
  OUT="$(mktemp "${TMPDIR:-/tmp}/pkcs11-nuri.XXXXXX")"
  trap 'rm -f "$OUT"' EXIT
fi

clang -dynamiclib -fvisibility=hidden -Wall -Wextra -O2 \
  -Wl,-install_name,pkcs11-nuri.so \
  -o "$OUT" "$ROOT/scripts/pkcs11-nuri.c"

shasum -a 256 "$OUT"
if [[ "${1:-}" == "--check" ]]; then
  grep pkcs11-nuri.so "$ROOT/dist/SHA256SUMS"
  diff <(shasum -a 256 "$OUT" | cut -d' ' -f1) <(grep pkcs11-nuri.so "$ROOT/dist/SHA256SUMS" | cut -d' ' -f1) \
    && echo "PKCS11_BUILD_MATCHES_SHA256SUMS" || { echo "PKCS11_BUILD_DIFFERS (toolchain or source changed)"; exit 1; }
  rm -f "$OUT"
fi
