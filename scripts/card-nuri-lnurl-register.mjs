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
// Usage: node scripts/card-nuri-lnurl-register.mjs <username> [--pin 1996]

import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';

const PYTHON = process.env.REAL_CARD_COSIGN_PYTHON || '/private/tmp/nuri-fido2-real-card-venv/bin/python';
const PRF_SCRIPT = process.env.NURI_CARD_PRF_SCRIPT || 'scripts/card-prf-backup.py';
const V4 = (process.env.NURI_ARKADE_SIGNER_URL || 'https://arkade.nuri.com/v4').replace(/\/+$/, '');
const PROFILE = process.env.NURI_CARD_RECEIVE_PROFILE || 'nuri-card-arkade-receive';
const PROFILE_PATH = process.env.NURI_CARD_RECEIVE_PROFILE_PATH || `.nuri-card-prf/${PROFILE}.json`;
const CARD_PK33 = process.env.NURI_CARD_PK33 || '022589ad2c011a9002a0e2f7ef885541aa79560752dae155c916239831ce9aea9e';

function arg(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
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
  if (!username || username.startsWith('--')) throw new Error('usage: card-nuri-lnurl-register.mjs <username> [--pin 1996]');
  const pin = arg('--pin', process.env.FIDO2_BACKUP_PIN || '');
  if (!pin) throw new Error('PIN required (--pin or FIDO2_BACKUP_PIN)');

  const profile = JSON.parse(await readFile(PROFILE_PATH, 'utf8'));
  const credId = profile.credential_id || profile.credential_id_b64u || profile.cred_id_b64u;
  const credPubkeyB64u = String(profile.credential_public_key_spki_b64u || '').trim();
  if (!credId || !credPubkeyB64u) throw new Error(`profile ${PROFILE_PATH} missing credential id / spki pubkey`);

  // 1. request-auth challenge
  const auth = await postJson(`${V4}/arkade/auth`, {
    cred_id_b64u: credId,
    cred_pubkey_b64u: credPubkeyB64u,
    client_signer_pubkey: CARD_PK33,
  });
  if (!auth.token || !auth.challenge) throw new Error(`/arkade/auth failed: ${JSON.stringify(auth)}`);

  // 2. card UV assertion over the challenge
  const assertion = await execFileJson(PYTHON, [
    PRF_SCRIPT, 'webauthn-assert',
    '--profile', PROFILE,
    `--challenge-b64u=${auth.challenge}`,
    '--rp-id', profile.rp_id || auth.rp_id,
    '--origin', profile.origin || String(auth.origin || '').split(',')[0].trim(),
    `--credential-id=${credId}`,
    '--user-verification', 'required',
    '--pin', pin,
  ]);

  // 3. claim the username
  const result = await postJson(`${V4}/arkade/lnurl/register`, {
    token: auth.token,
    username,
    client_signer_pubkey: CARD_PK33,
    client_data_b64u: assertion.client_data_b64u,
    auth_data_b64u: assertion.auth_data_b64u,
    sig_b64u: assertion.sig_b64u,
  });
  return result;
}

main().then((out) => {
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  process.exit(0);
}).catch((err) => {
  process.stdout.write(JSON.stringify({ status: 'NURI_LNURL_REGISTER_FAILED', error: err.message }) + '\n');
  process.exit(1);
});
