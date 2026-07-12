#!/usr/bin/env bash
# Full real-card proof of the Nuri 2-of-2 round. Every step hits the physical
# card (FIDO2 PRF for the client key, MuSig2 applet for the cosigner partial).
# Nothing is simulated. One card command at a time.
#
# Chain of evidence:
#   1. PRF derive from card TWICE  -> identical client key (stable, card-bound)
#   2. card MuSig2 cosign with that client key -> real partial signature
#   3. host aggregate + Taproot tweak (BIP327) -> final BIP340 signature
#   4. cross-check output key / address against @scure/btc-signer (nuri derivation)
#   5. schnorr.verify(sig, msg, outputKey) -> true
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${REAL_CARD_COSIGN_PYTHON:-scripts/run-card-python.sh}"
PROFILE="${NURI_WALLET_PRF_PROFILE:-wallet-client}"
SALT="${NURI_WALLET_PRF_SALT:-nuri-wallet-client-key-v1}"

say(){ printf '\n── %s ──\n' "$1"; }

say "1. Derive client key from card FIDO2 PRF (tap 1)"
PRF_A=$("$PY" scripts/card-prf-backup.py derive --profile "$PROFILE" --salt "$SALT" --raw 2>/dev/null | tail -1)
echo "   prf seed (A) = $PRF_A"

say "2. Derive AGAIN (tap 2) -> must be identical (proves stable, card-bound client key)"
PRF_B=$("$PY" scripts/card-prf-backup.py derive --profile "$PROFILE" --salt "$SALT" --raw 2>/dev/null | tail -1)
echo "   prf seed (B) = $PRF_B"
[ "$PRF_A" = "$PRF_B" ] || { echo "FAIL: PRF not stable"; exit 1; }
echo "   PRF_STABLE_OK"

say "3. card MuSig2 cosign with PRF client key (tap 3) + host Taproot tweak aggregate"
"$PY" scripts/card-cosign-tweaked.py --client-secret-hex "$PRF_A" --msg32 "$(openssl rand -hex 32)" 2>/dev/null > /tmp/card-proof.json
echo "   status        : $(grep -o '"status": "[^"]*"' /tmp/card-proof.json)"
echo "   card_pk33     : $(grep -o '"card_pk33": "[^"]*"' /tmp/card-proof.json)"
echo "   client_pk33   : $(grep -o '"client_pk33": "[^"]*"' /tmp/card-proof.json)"
echo "   output_xonly  : $(grep -o '"tweaked_output_xonly32": "[^"]*"' /tmp/card-proof.json)"
echo "   card_verified : $(grep -o '"final_signature_verified_against_output_key": [a-z]*' /tmp/card-proof.json)"

say "4. Cross-check against @scure/btc-signer (the exact Nuri derivation) + BIP340 verify"
cat /tmp/card-proof.json | node scripts/verify-tweaked-cosign.mjs 2>/dev/null | tee /tmp/card-verify.json | grep -E "internal_key_matches|output_key_matches|signature_valid_bip340|nuri_taproot_address|status"

say "5. Final assertion"
if grep -q 'CARD_TWEAKED_COSIGN_MATCHES_NURI_SCURE' /tmp/card-verify.json && \
   grep -q 'REAL_CARD_TWEAKED_COSIGN_OK' /tmp/card-proof.json && \
   grep -q '"signature_valid_bip340": true' /tmp/card-verify.json; then
  echo "CARD_FULL_ROUND_PROOF_OK"
  echo "  - client key   : derived from card FIDO2 PRF (stable, re-derived every op)"
  echo "  - cosigner     : card MuSig2 applet (non-exportable on-card key)"
  echo "  - wallet       : musig2(client,card) + CSV Taproot, byte-compatible with Nuri/scure"
  echo "  - signature    : real-card BIP340, verified against the Nuri Taproot output key"
else
  echo "CARD_FULL_ROUND_PROOF_FAILED"; exit 1
fi
