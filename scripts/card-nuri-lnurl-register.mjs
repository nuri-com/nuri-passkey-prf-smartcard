// Claim a Nuri Lightning-address username for the card's Arkade owner.
//
// Flow (mirrors server-arkade-v4 request-auth):
//   1. POST /v4/arkade/auth {cred_id_b64u, cred_pubkey_b64u, client_signer_pubkey}
//        -> { token, challenge, rp_id, origin }
//   2. card FIDO2 UV assertion over `challenge` (one PIN tap)
//   3. POST /v4/arkade/lnurl/register {token, username, client_signer_pubkey,
//        client_data_b64u, auth_data_b64u, sig_b64u}
//        -> { lightning_address, callback_url, ... }
//
// The card's secp256k1 key never leaves the card; this is a presence+PIN proof.
// Usage:
//   node scripts/card-nuri-lnurl-register.mjs <username> \
//     --profile <profile-name> \
//     --profile-path <profile-json> \
//     --arkade-url <v4-url>

import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';

const PYTHON = process.env.REAL_CARD_COSIGN_PYTHON || 'scripts/run-card-python.sh';
const PRF_SCRIPT = process.env.NURI_CARD_PRF_SCRIPT || 'scripts/card-prf-backup.py';
const CARD_KEY_SCRIPT = process.env.NURI_MUSIG2_CARD_KEY_SCRIPT || 'scripts/read-musig2-card-key.py';

function arg(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : '';
}

function postJson(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }).then(async (res) => {
    const text = await res.text();
    let data = null;
    try { data = JSON.parse(text); } catch { /* keep raw */ }
    if (!res.ok) throw new Error(`${url} HTTP ${res.status}: ${data?.error || text.slice(0, 200)}`);
    return data;
  });
}

function execFileJson(cmd, args) {
  return new Promise((resolvePromise, reject) => {
    execFile(cmd, args, { maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      try { resolvePromise(JSON.parse(stdout)); }
      catch { reject(new Error(stderr || err?.message || 'card assert produced no JSON')); }
    });
  });
}

async function main() {
  const username = (process.argv[2] || '').trim();
  const profileName = arg('--profile');
  const profilePath = arg('--profile-path');
  const arkadeUrl = arg('--arkade-url').replace(/\/+$/, '');
  const pin = arg('--pin');
  if (!username || username.startsWith('--') || !profileName || !profilePath || !arkadeUrl) {
    throw new Error('usage: card-nuri-lnurl-register.mjs <username> --profile <name> --profile-path <json> --arkade-url <v4-url> [--pin <pin>]');
  }

  const profile = JSON.parse(await readFile(profilePath, 'utf8'));
  const credId = String(profile.credential_id || '').trim();
  const credPubkeyB64u = String(profile.credential_public_key_spki_b64u || '').trim();
  const rpId = String(profile.rp_id || '').trim();
  const origin = String(profile.origin || '').trim();
  if (!credId || !credPubkeyB64u || !rpId || !origin) {
    throw new Error(`profile ${profilePath} missing credential id, SPKI public key, RP ID, or origin`);
  }

  const card = await execFileJson(PYTHON, [CARD_KEY_SCRIPT]);
  const cardPk33 = String(card.card_pk33 || '').trim().toLowerCase();
  if (!/^(02|03)[0-9a-f]{64}$/.test(cardPk33)) {
    throw new Error('physical card did not return a valid MuSig2 public key');
  }

  // 1. request-auth challenge
  const auth = await postJson(`${arkadeUrl}/arkade/auth`, {
    cred_id_b64u: credId,
    cred_pubkey_b64u: credPubkeyB64u,
    client_signer_pubkey: cardPk33,
  });
  if (!auth.token || !auth.challenge) throw new Error(`/arkade/auth failed: ${JSON.stringify(auth)}`);

  // 2. card UV assertion over the challenge
  const assertionArgs = [
    PRF_SCRIPT, 'webauthn-assert',
    '--profile', profileName,
    '--profile-path', profilePath,
    `--challenge-b64u=${auth.challenge}`,
    '--rp-id', rpId,
    '--origin', origin,
    `--credential-id=${credId}`,
    '--user-verification', 'required',
  ];
  if (pin) assertionArgs.push('--pin', pin);
  const assertion = await execFileJson(PYTHON, assertionArgs);

  // 3. claim the username
  const result = await postJson(`${arkadeUrl}/arkade/lnurl/register`, {
    token: auth.token,
    username,
    client_signer_pubkey: cardPk33,
    client_data_b64u: assertion.client_data_b64u,
    auth_data_b64u: assertion.auth_data_b64u,
    sig_b64u: assertion.sig_b64u,
  });
  return { ...result, card_client_pk33: cardPk33 };
}

main().then((out) => {
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  process.exit(0);
}).catch((err) => {
  process.stdout.write(JSON.stringify({ status: 'NURI_LNURL_REGISTER_FAILED', error: err.message }) + '\n');
  process.exit(1);
});
