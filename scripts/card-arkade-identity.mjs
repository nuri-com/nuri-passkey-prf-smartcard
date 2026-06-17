#!/usr/bin/env node
// Card-backed Arkade/Nuri wallet identity.
//
// This is the importable SEAM: it exposes the same identity surface the nuri-expo
// phone app derives from a browser passkey PRF, but the PRF comes from the
// physical card. A nuri-expo SigningKeyVault pointed at this module would make
// the card the wallet identity root — no browser prompt, no phone.
//
// Exported:
//   getPublicKey()       -> Uint8Array clientPk33 (the arkade internal key)
//   getSigningKey()      -> Uint8Array clientPrivateKey (BIP86 m/86'/0'/0'/0/0)
//   prfProfile / prfSalt -> the PRF inputs (so nuri-expo can reuse its own credId)
//
// Derivation is a byte-for-byte port of:
//   nuri-expo/lib/walletDerivation.ts  deriveWalletEntropy(prf, "bitcoin")
//   nuri-expo/lib/bitcoin/bip86.ts     deriveBitcoinAddress(entropy)
//   nuri-expo/lib/bitcoin/BitcoinPasskeySigningKey.ts
import { execFile } from 'node:child_process';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/curves/abstract/utils';

const PY = process.env.REAL_CARD_COSIGN_PYTHON || '/tmp/nuri-fido2-real-card-venv/bin/python';
const PRF_SCRIPT = process.env.NURI_CARD_PRF_SCRIPT || 'scripts/card-prf-backup.py';
export const prfProfile = process.env.NURI_WALLET_PRF_PROFILE || 'wallet-client';
// MUST match nuri-expo config/constants.ts PRF_SALT.
export const prfSalt = process.env.NURI_WALLET_PRF_SALT || 'nuri-prf-salt-v1';
const utf8 = (s) => new TextEncoder().encode(s);

export function prfFromCard() {
  return new Promise((resolve, reject) => {
    execFile(PY, [PRF_SCRIPT, 'derive', '--profile', prfProfile, '--salt', prfSalt, '--raw'],
      { cwd: process.cwd(), timeout: 60000, maxBuffer: 1 << 20 }, (err, out, errout) => {
        if (err) return reject(new Error(`PRF derive failed: ${err.message}\n${errout || out}`.trim()));
        const hex = out.trim();
        if (!/^[0-9a-f]{64}$/.test(hex)) return reject(new Error(`bad PRF output: ${hex.slice(0, 80)}`));
        const a = new Uint8Array(32);
        for (let i = 0; i < 32; i++) a[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        resolve(a);
      });
  });
}

// Port of nuri-expo deriveWalletEntropy(prf, "bitcoin")
function deriveWalletEntropy(prfBytes) {
  const salt = sha256(utf8('app:nuri.com|wallet|v1'));
  const info = utf8('app:nuri.com|wallet|v1|chain=bitcoin|fmt=taproot');
  return new Uint8Array(hkdf(sha256, prfBytes, salt, info, 32));
}

// Port of nuri-expo deriveBitcoinAddress(entropy) -> returns the internal key
// used by MuSig2 (arkade signs with the untweaked internal key).
export function deriveArkadeClientKey(prfBytes) {
  const entropy = deriveWalletEntropy(prfBytes);
  const root = HDKey.fromMasterSeed(entropy);
  const child = root.derive("m/86'/0'/0'/0/0");
  if (!child.privateKey) throw new Error('failed to derive BIP86 child key');
  const privateKey = new Uint8Array(child.privateKey);
  root.wipePrivateData();
  entropy.fill(0);
  return { privateKey, clientPk33: secp256k1.getPublicKey(privateKey, true) };
}

export async function getPublicKey() {
  const prf = await prfFromCard();
  try { return deriveArkadeClientKey(prf).clientPk33; } finally { prf.fill(0); }
}
export async function getSigningKey() {
  const prf = await prfFromCard();
  try { return deriveArkadeClientKey(prf).privateKey; } finally { prf.fill(0); }
}

// ---- self-test when run directly ----
const isMain = process.argv[1] && import.meta.url === new URL('file://' + process.argv[1]).href
  || process.argv[1]?.endsWith('card-arkade-identity.mjs');
if (isMain) {
  const pk1 = await getPublicKey();
  // derive again -> must be stable (second tap)
  const pk2 = await getPublicKey();
  const stable = bytesToHex(pk1) === bytesToHex(pk2);
  console.log(JSON.stringify({
    status: stable ? 'CARD_ARKADE_IDENTITY_STABLE_OK' : 'CARD_ARKADE_IDENTITY_UNSTABLE',
    source: 'card_fido2_prf',
    prf_profile: prfProfile,
    prf_salt: prfSalt,
    derivation: "HKDF -> BIP86 m/86'/0'/0'/0/0 (nuri-expo port)",
    client_pk33: bytesToHex(pk1),
    stable_across_taps: stable,
    note: 'Drop-in for nuri-expo SigningKeyVault: same client key the phone derives from its browser passkey PRF.',
  }, null, 2));
  if (!stable) process.exit(1);
}
