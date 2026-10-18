#!/usr/bin/env bash
# Build the OpenSSL 3 provider locally, never into Homebrew's modules directory.
# stdout: installed provider path. Build logs go to stderr.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${1:-$ROOT/.build/pkcs11-provider}"
PYTHON="${NURI_PKCS11_PYTHON:-python3}"
OPENSSL="${NURI_OPENSSL:-/opt/homebrew/bin/openssl}"
VERSION=1.3.0
SHA256=b8bbc30cfb7865603fff1dd0fb516cce90437d8ddb267e331cd89d6121960538
URL="https://github.com/openssl-projects/pkcs11-provider/releases/download/v$VERSION/pkcs11-provider-$VERSION.tar.xz"
[[ "$(uname -s)" == Darwin ]] || { echo 'This build recipe is verified only on macOS.' >&2; exit 69; }
[[ "$($OPENSSL version)" == 'OpenSSL 3.'* ]] || { echo 'NURI_OPENSSL must select OpenSSL 3 (not LibreSSL).' >&2; exit 69; }
command -v pkg-config >/dev/null
# Homebrew's OpenSSL is keg-only. Override this for another OpenSSL 3 prefix.
export PKG_CONFIG_PATH="${NURI_OPENSSL_PKGCONFIG:-/opt/homebrew/opt/openssl@3/lib/pkgconfig}${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
mkdir -p "$ROOT/.build" "$PREFIX/lib/ossl-modules"
PREFIX="$(cd "$PREFIX" && pwd)"
WORK="$(mktemp -d "$ROOT/.build/pkcs11-provider-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
exec 3>&1
exec 1>&2
curl --fail --location --silent --show-error "$URL" -o "$WORK/source.tar.xz"
"$PYTHON" - "$WORK" "$SHA256" <<'PY'
import hashlib
import pathlib
import sys
import tarfile
root = pathlib.Path(sys.argv[1])
archive = root / 'source.tar.xz'
actual = hashlib.sha256(archive.read_bytes()).hexdigest()
if actual != sys.argv[2]:
    raise SystemExit(f'Provider source SHA-256 mismatch: {actual}')
print(f'pkcs11-provider source SHA-256: {actual}')
with tarfile.open(archive) as source:
    source.extractall(root, filter='data')
PY
# Build-only dependencies; private target avoids modifying the selected Python.
"$PYTHON" -m pip install --disable-pip-version-check --target "$WORK/tools" meson==1.12.1 ninja==1.13.2
export PYTHONPATH="$WORK/tools${PYTHONPATH:+:$PYTHONPATH}"
export PATH="$WORK/tools/bin:$PATH"
"$PYTHON" -m mesonbuild.mesonmain setup "$WORK/build" "$WORK/pkcs11-provider-$VERSION" \
  --prefix="$PREFIX" --libdir=lib --buildtype=release
"$PYTHON" -m mesonbuild.mesonmain compile -C "$WORK/build" -j 2
# Upstream install_dir follows libcrypto's modulesdir, NOT --prefix. Do not run
# un-staged `meson install`: that would write into the Homebrew OpenSSL keg.
install -m 755 "$WORK/build/src/pkcs11.dylib" "$PREFIX/lib/ossl-modules/pkcs11.dylib"
printf '%s\n' "$PREFIX/lib/ossl-modules/pkcs11.dylib" >&3
