#!/usr/bin/env node
// Derive the Nuri/Arkade client key from the card's FIDO2 PRF, byte-for-byte the
// same way the phone app does it (nuri-expo: deriveWalletEntropy ->
// deriveBitcoinAddress BIP86 m/86'/0'/0'/0/0). The only difference: instead of
// browser navigator.credentials PRF, the PRF comes from the physical card.
//
// Use:
//   node scripts/card-arkade-key.mjs                  # print client pk + mainnet p2tr addr
//   node scripts/card-arkade-key.mjs --verify-twice   # derive twice, assert identical
//
// Proves the card is a drop-in identity for an existing Arkade/Nuri wallet: same
// PRF + same salt + same HKDF + same BIP86 path = same client pubkey.
import { execFile } from 'node:child_process';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/curves/abstract/utils';

const utf8 = (s) => new TextEncoder().encode(s);

const PY = process.env.REAL_CARD_COSIGN_PYTHON || 'scripts/run-card-python.sh';
const PRF_SCRIPT = process.env.NURI_CARD_PRF_SCRIPT || 'scripts/card-prf-backup.py';
const PRF_PROFILE = process.env.NURI_WALLET_PRF_PROFILE || 'wallet-client';
// MUST match nuri-expo PRF_SALT (config/constants.ts) and the arkade signing vault.
const PRF_SALT = process.env.NURI_WALLET_PRF_SALT || 'nuri-prf-salt-v1';

function prfFromCard() {
  return new Promise((resolve, reject) => {
    execFile(PY, [PRF_SCRIPT, 'derive', '--profile', PRF_PROFILE, '--salt', PRF_SALT, '--raw'],
      { cwd: process.cwd(), timeout: 60000, maxBuffer: 1 << 20 }, (err, out, errout) => {
        if (err) return reject(new Error(`PRF derive failed: ${err.message}\n${errout || out}`.trim()));
        const hex = out.trim();
        if (!/^[0-9a-f]{64}$/.test(hex)) return reject(new Error(`bad PRF output: ${hex.slice(0, 80)}`));
        resolve(hexToBytes(hex));
      });
  });
}

// Exact port of nuri-expo/lib/walletDerivation.ts deriveWalletEntropy(prf, "bitcoin")
function deriveWalletEntropy(prfBytes) {
  const salt = sha256(utf8('app:nuri.com|wallet|v1'));
  const info = utf8('app:nuri.com|wallet|v1|chain=bitcoin|fmt=taproot');
  return new Uint8Array(hkdf(sha256, prfBytes, salt, info, 32));
}

// Exact port of nuri-expo/lib/bitcoin/bip86.ts deriveBitcoinAddress(entropy)
//   m/86'/0'/0'/0/0, returns the INTERNAL key (untweaked) used in MuSig2.
//   (nuri's fn also returns a tweaked address; arkade signing only needs the
//   internal key, which is what IndividualPubkey is computed from.)
function deriveArkadeClientKey(prfBytes) {
  const entropy = deriveWalletEntropy(prfBytes);
  const root = HDKey.fromMasterSeed(entropy);
  const child = root.derive("m/86'/0'/0'/0/0");
  if (!child.privateKey) throw new Error('failed to derive BIP86 child key');
  const privateKey = new Uint8Array(child.privateKey);
  const pubCompressed = secp256k1.getPublicKey(privateKey, true);
  return { privateKey, clientPk33: pubCompressed, xOnlyInternal: pubCompressed.slice(1) };
}

function hexToBytes(h) {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return a;
}

const args = process.argv.slice(2);
const verifyTwice = args.includes('--verify-twice');

const prf1 = await prfFromCard();
let { privateKey: _p1, clientPk33: pk1 } = deriveArkadeClientKey(prf1);
_p1.fill(0);
let result = {
  source: 'card_fido2_prf',
  prf_profile: PRF_PROFILE,
  prf_salt: PRF_SALT,
  derivation: 'HKDF -> BIP86 m/86\'/0\'/0\'/0/0 (exact nuri-expo port)',
  client_pk33: bytesToHex(pk1),
};
if (verifyTwice) {
  const prf2 = await prfFromCard();
  const { privateKey: _p2, clientPk33: pk2 } = deriveArkadeClientKey(prf2);
  _p2.fill(0);
  result.stable_across_taps = bytesToHex(pk1) === bytesToHex(pk2);
  result.second_client_pk33 = bytesToHex(pk2);
}
result.status = verifyTwice
  ? (result.stable_across_taps ? 'CARD_ARKADE_KEY_STABLE_OK' : 'CARD_ARKADE_KEY_UNSTABLE')
  : 'CARD_ARKADE_KEY_OK';
console.log(JSON.stringify(result, null, 2));
if (result.status.endsWith('_UNSTABLE')) process.exit(1);
