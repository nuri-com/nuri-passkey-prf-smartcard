#!/usr/bin/env bash
# OpenSSL 3 -> pkcs11-provider -> Nuri module. Exact mode=sim is required for sim.
# Hardware is opt-in with BOTH NURI_PKCS11_MODE=card and --card.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OPENSSL="${NURI_OPENSSL:-/opt/homebrew/bin/openssl}"
export NURI_PKCS11_PYTHON="${NURI_PKCS11_PYTHON:-python3}"
export NURI_PKCS11_HELPER="$ROOT/scripts/pkcs11-helper.py"
case "${1:-}" in
  '')
    [[ "${NURI_PKCS11_MODE:-}" == sim ]] || {
      echo 'Software selftest requires exact NURI_PKCS11_MODE=sim; hardware requires --card and mode=card.' >&2; exit 64;
    }
    MODE=sim
    ;;
  --card)
    [[ "${NURI_PKCS11_MODE:-}" == card ]] || {
      echo '--card requires NURI_PKCS11_MODE=card; refusing silent simulation.' >&2; exit 64;
    }
    MODE=card
    ;;
  *) echo "Usage: $0 [--card]" >&2; exit 64 ;;
esac
[[ $# -le 1 ]] || { echo 'Too many arguments.' >&2; exit 64; }
# Upstream's environment override takes precedence over pkcs11-module-path.
unset PKCS11_PROVIDER_MODULE
[[ "$(OPENSSL_CONF=/dev/null "$OPENSSL" version)" == 'OpenSSL 3.'* ]] || { echo 'Select OpenSSL 3 with NURI_OPENSSL (not LibreSSL).' >&2; exit 69; }
"$NURI_PKCS11_PYTHON" -c 'import ecdsa'
command -v "${PKCS11_TOOL:-pkcs11-tool}" >/dev/null
mkdir -p "$ROOT/.build"
WORK="$(mktemp -d "$ROOT/.build/hsm-openssl.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
# Test/build scratch is task-owned; the C module honors TMPDIR.
export TMPDIR="$WORK"
PROVIDER="${NURI_PKCS11_PROVIDER:-}"
if [[ -z "$PROVIDER" ]]; then
  PROVIDER="$(bash "$ROOT/scripts/build-pkcs11-provider.sh" "$WORK/provider")"
fi
[[ -f "$PROVIDER" ]] || { echo "Provider missing: $PROVIDER" >&2; exit 66; }
[[ -f "$ROOT/dist/pkcs11-nuri.so" ]] || bash "$ROOT/scripts/build-pkcs11.sh"
export NURI_PKCS11_MODULE="$ROOT/dist/pkcs11-nuri.so"
# Explicit configuration prevents a host openssl.cnf from selecting another token.
"$NURI_PKCS11_PYTHON" - "$WORK" "$PROVIDER" "$NURI_PKCS11_MODULE" <<'PY'
import pathlib
import sys
work = pathlib.Path(sys.argv[1])
provider, module = (str(pathlib.Path(p).resolve()) for p in sys.argv[2:])
for path in (provider, module):
    if any(c in path for c in '\n\r"$'):
        raise SystemExit('Unsupported OpenSSL configuration path characters')
(work / 'openssl.cnf').write_text(f'''openssl_conf = openssl_init
[openssl_init]
providers = providers
[providers]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = "{provider}"
pkcs11-module-path = "{module}"
pkcs11-module-cache-keys = false
pkcs11-module-cache-sessions = 0
pkcs11-module-login-behavior = never
pkcs11-module-quirks = no-operation-state
activate = 1
''')
(work / 'message.txt').write_bytes(b'Nuri OpenSSL PKCS#11 signing selftest\n')
(work / 'short31.bin').write_bytes(bytes(31))
PY
export OPENSSL_CONF="$WORK/openssl.cnf"
LABEL='Nuri%20ETH%20Key'
[[ "$MODE" != sim ]] || LABEL='Nuri%20SIMULATOR%20ETH%20Key'
PRIVATE_URI="pkcs11:object=$LABEL;id=%01;type=private"
PUBLIC_URI="pkcs11:object=$LABEL;id=%01;type=public"
printf 'Nuri OpenSSL selftest mode=%s\n' "$MODE"
"$OPENSSL" version
"$OPENSSL" list -providers
"$OPENSSL" pkey -pubin -in "$PUBLIC_URI" -out "$WORK/public.pem"
# Check identity before asking any key to sign, especially in parent card mode.
"$NURI_PKCS11_PYTHON" - "$WORK/public.pem" "$MODE" <<'PY'
import os
import pathlib
import sys
from ecdsa import SECP256k1, VerifyingKey
key = VerifyingKey.from_pem(pathlib.Path(sys.argv[1]).read_bytes())
assert key.curve == SECP256k1
public_key = key.to_string('compressed').hex()
sim_public_key = '03bcd83232b6276e8856605cfd877f7795536a5099555684422fe82f2b6adb95e2'
if sys.argv[2] == 'card' and public_key == sim_public_key:
    raise SystemExit('FAIL: card mode returned the known simulation key')
if sys.argv[2] == 'sim' and public_key != sim_public_key:
    raise SystemExit('FAIL: sim mode returned an unexpected public key')
expected_key = os.environ.get('NURI_PKCS11_EXPECTED_PUBKEY')
if expected_key and public_key != expected_key:
    raise SystemExit(f'FAIL: unexpected key: {public_key}; expected {expected_key}')
print('public_key=' + public_key)
PY
"$OPENSSL" dgst -sha256 -binary "$WORK/message.txt" > "$WORK/hash32.bin"
# No -rawin: this input is ALREADY a digest. -rawin would hash it again.
"$OPENSSL" pkeyutl -sign -inkey "$PRIVATE_URI" -in "$WORK/hash32.bin" -out "$WORK/signature.der"
"$OPENSSL" pkeyutl -verify -pubin -inkey "$WORK/public.pem" \
  -in "$WORK/hash32.bin" -sigfile "$WORK/signature.der"
# Also prove message hashing in the provider/OpenSSL, not CKM_ECDSA_SHA256.
"$OPENSSL" dgst -sha256 -sign "$PRIVATE_URI" -out "$WORK/message-signature.der" "$WORK/message.txt"
"$OPENSSL" dgst -sha256 -verify "$WORK/public.pem" \
  -signature "$WORK/message-signature.der" "$WORK/message.txt"
"$NURI_PKCS11_PYTHON" - "$WORK" <<'PY'
import hashlib
import pathlib
import sys
from ecdsa import BadSignatureError, SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der
work = pathlib.Path(sys.argv[1])
key = VerifyingKey.from_pem((work / 'public.pem').read_bytes())
assert key.curve == SECP256k1
message = (work / 'message.txt').read_bytes()
digest = (work / 'hash32.bin').read_bytes()
assert digest == hashlib.sha256(message).digest() and len(digest) == 32
for filename in ('signature.der', 'message-signature.der'):
    signature = (work / filename).read_bytes()
    assert key.verify_digest(signature, digest, sigdecode=sigdecode_der)
    try:
        key.verify_digest(signature, hashlib.sha256(digest).digest(), sigdecode=sigdecode_der)
    except BadSignatureError:
        pass
    else:
        raise SystemExit('Unexpected double-hashed signature')
    print(f'PYTHON_ECDSA_VERIFIED {filename} (DER; exactly one SHA-256)')
wrong = bytes([digest[0] ^ 1]) + digest[1:]
(work / 'wrong32.bin').write_bytes(wrong)
PY
if "$OPENSSL" pkeyutl -verify -pubin -inkey "$WORK/public.pem" \
    -in "$WORK/wrong32.bin" -sigfile "$WORK/signature.der"; then
  echo 'FAIL: modified digest accepted.' >&2; exit 1
fi
echo 'PASS: modified digest rejected by OpenSSL'
if "$OPENSSL" pkeyutl -sign -inkey "$PRIVATE_URI" -in "$WORK/short31.bin" -out "$WORK/rejected.der"; then
  echo 'FAIL: 31-byte digest accepted.' >&2; exit 1
fi
[[ ! -s "$WORK/rejected.der" ]] || { echo 'FAIL: invalid-length signing emitted a signature.' >&2; exit 1; }
echo 'PASS: 31-byte digest rejected without a signature'
if "$OPENSSL" pkeyutl -sign -inkey 'pkcs11:object=Missing%20Nuri%20Key;type=private' \
    -in "$WORK/hash32.bin" -out "$WORK/missing.der"; then
  echo 'FAIL: missing key label accepted.' >&2; exit 1
fi
echo 'PASS: wrong object label rejected'
# This test also proves the module still returns PKCS#11 raw r||s, not DER.
"$NURI_PKCS11_PYTHON" "$ROOT/scripts/test-pkcs11-e2e.py"
printf 'HSM_OPENSSL_SELFTEST_OK mode=%s (OpenSSL + python-ecdsa + pkcs11-tool)\n' "$MODE"
