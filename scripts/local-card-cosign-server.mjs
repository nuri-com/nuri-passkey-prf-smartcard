#!/usr/bin/env node
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import process from 'node:process';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { HDKey } from '@scure/bip32';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bech32m } from '@scure/base';
import { createOnCardGeneratedCard, runCardCosignFlow } from '../src/musig2/cosign-flow.js';
import { provisionAddress, fetchUtxos, buildAndSignSpend, loadProfile } from './nuri-card-wallet.mjs';

const card = createOnCardGeneratedCard();
const REAL_CARD_PYTHON = process.env.REAL_CARD_COSIGN_PYTHON || '/private/tmp/nuri-fido2-real-card-venv/bin/python';
const REAL_CARD_SCRIPT = process.env.REAL_CARD_COSIGN_SCRIPT || 'scripts/real-card-cosign-proof.py';
const REAL_CARD_TWEAKED_SCRIPT = process.env.REAL_CARD_TWEAKED_SCRIPT || 'scripts/card-cosign-tweaked.py';
const REAL_CARD_PROFILE = process.env.REAL_CARD_COSIGN_PROFILE || '.nuri-card-musig2/browser-real-card.json';

const utf8 = (s) => new TextEncoder().encode(s);

// Exact port of nuri-expo lib/walletDerivation.ts + lib/bitcoin/bip86.ts:
// browser passkey PRF -> HKDF entropy -> BIP86 m/86'/0'/0'/0/0 client key.
// Same salt/info/path as the PWA, so a passkey derives the PWA-identical wallet.
function deriveClientKeyFromPrf(prfBytes) {
  const salt = sha256(utf8('app:nuri.com|wallet|v1'));
  const info = utf8('app:nuri.com|wallet|v1|chain=bitcoin|fmt=taproot');
  const entropy = new Uint8Array(hkdf(sha256, prfBytes, salt, info, 32));
  const child = HDKey.fromMasterSeed(entropy).derive("m/86'/0'/0'/0/0");
  if (!child.privateKey) throw new Error('failed to derive BIP86 child key');
  const privateKey = new Uint8Array(child.privateKey);
  return { privateKey, clientPk33: secp256k1.getPublicKey(privateKey, true) };
}

function taprootAddress(outputXonlyHex, network) {
  const hrp = network === 'mainnet' ? 'bc' : 'tb';
  const words = [1, ...bech32m.toWords(hexToBytes(outputXonlyHex))];
  return bech32m.encode(hrp, words);
}

function parseArgs(argv) {
  const args = {
    host: '127.0.0.1',
    port: 8787,
    selftest: false,
    backend: process.env.COSIGN_BACKEND || 'simulated',
  };
  for (const arg of argv) {
    if (arg === '--selftest') args.selftest = true;
    else if (arg.startsWith('--host=')) args.host = arg.slice('--host='.length);
    else if (arg.startsWith('--port=')) args.port = Number(arg.slice('--port='.length));
    else if (arg.startsWith('--backend=')) args.backend = arg.slice('--backend='.length);
    else if (arg === '--help' || arg === '-h') {
      console.log('Usage: node scripts/local-card-cosign-server.mjs [--host=127.0.0.1] [--port=8787] [--backend=simulated|real-card] [--selftest]');
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!Number.isInteger(args.port) || args.port <= 0 || args.port > 65535) {
    throw new Error('port must be 1..65535');
  }
  if (!['simulated', 'real-card'].includes(args.backend)) {
    throw new Error('backend must be simulated or real-card');
  }
  return args;
}

function json(res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(body);
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  return JSON.parse(raw);
}

async function serveStatic(res, path, contentType) {
  const body = await readFile(path);
  res.writeHead(200, {
    'content-type': contentType,
    'cache-control': 'no-store',
  });
  res.end(body);
}

function handleInfo(res) {
  json(res, 200, {
    status: 'NURI_CARD_COSIGN_SERVER_READY',
    backend: args.backend === 'real-card' ? 'real-card-pcsc-apdu' : 'simulated-on-card-keygen',
    key_origin: args.backend === 'real-card' ? 'on-card-or-existing-non-exportable' : 'card-generated-non-exportable-in-backend',
    card_pk33: args.backend === 'real-card' ? undefined : bytesToHex(card.getIndividualPubkey()),
    profile: args.backend === 'real-card' ? REAL_CARD_PROFILE : undefined,
    endpoints: {
      sign: 'POST /api/cosign/sign',
    },
    real_card_proof:
      'The installed NuriMuSig2 v1.10/KGEN applet has a real INS_KEYGEN path. Run npm run cosign:real-card to prove on-card keygen, card partial verification, and final aggregate BIP340 verification.',
  });
}

function execFileJson(file, fileArgs) {
  return new Promise((resolvePromise, reject) => {
    execFile(file, fileArgs, {
      cwd: process.cwd(),
      timeout: 60000,
      maxBuffer: 1024 * 1024,
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`${error.message}\n${stderr || stdout}`.trim()));
        return;
      }
      try {
        resolvePromise(JSON.parse(stdout));
      } catch (parseError) {
        reject(new Error(`could not parse JSON from real-card script: ${parseError.message}\n${stdout}\n${stderr}`.trim()));
      }
    });
  });
}

async function loadRealCardProfile() {
  try {
    return JSON.parse(await readFile(REAL_CARD_PROFILE, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function saveRealCardProfile(profile) {
  await mkdir(dirname(resolve(REAL_CARD_PROFILE)), { recursive: true });
  await writeFile(REAL_CARD_PROFILE, `${JSON.stringify(profile, null, 2)}\n`);
}

function realCardArgs(body, profile) {
  const out = [REAL_CARD_SCRIPT];
  if (body.msg32) out.push('--msg32', String(body.msg32));
  else out.push('--message', body.message ? String(body.message) : 'nuri real card browser cosign proof');
  if (profile?.client_secret_hex) out.push('--client-secret-hex', profile.client_secret_hex);
  if (profile?.card_pk33) out.push('--use-existing-card-key');
  else out.push('--include-demo-client-secret');
  return out;
}

async function handleRealCardSign(body) {
  const existingProfile = await loadRealCardProfile();
  const profile = existingProfile || {
    created_at: new Date().toISOString(),
    warning: 'Demo-only local browser profile. Production client keys should come from the Nuri client/passkey wallet, not this file.',
  };
  const result = await execFileJson(REAL_CARD_PYTHON, realCardArgs(body, profile));
  if (!result.final_signature_verified || !result.card_partial_verified) {
    throw new Error(`real-card signature verification failed: ${JSON.stringify(result)}`);
  }
  if (existingProfile) {
    if (result.card_pk33 !== existingProfile.card_pk33) {
      throw new Error(`real card key changed: expected ${existingProfile.card_pk33}, got ${result.card_pk33}. Delete ${REAL_CARD_PROFILE} only if you intentionally reprovision.`);
    }
    if (result.aggregate_xonly32 !== existingProfile.aggregate_xonly32) {
      throw new Error(`aggregate key changed: expected ${existingProfile.aggregate_xonly32}, got ${result.aggregate_xonly32}`);
    }
  } else {
    if (!result.demo_client_secret32) {
      throw new Error('real-card provisioning did not return a demo client secret');
    }
    await saveRealCardProfile({
      ...profile,
      client_secret_hex: result.demo_client_secret32,
      card_aid: result.card_aid,
      card_version: result.card_version,
      card_pk33: result.card_pk33,
      client_pk33: result.client_pk33,
      aggregate_xonly32: result.aggregate_xonly32,
      first_signature64: result.final_signature64,
    });
  }
  const { demo_client_secret32: _demoClientSecret32, ...publicResult } = result;
  return {
    ...publicResult,
    backend: 'real-card-pcsc-apdu',
    stable_profile: REAL_CARD_PROFILE,
    profile_created: !existingProfile,
  };
}

// Localhost passkey -> PWA-identical wallet, cosigned by the physical card.
// Body: { prfHex (32-byte browser PRF output), message?, network? }
async function handlePasskeySign(req, res) {
  const body = await readJson(req);
  const prfHex = String(body.prfHex || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(prfHex)) {
    json(res, 400, { error: 'prfHex must be the 32-byte hex WebAuthn PRF output from the browser passkey' });
    return;
  }
  const network = body.network === 'mainnet' ? 'mainnet' : 'signet';
  const message = body.message ? String(body.message) : 'nuri localhost passkey wallet demo';
  const { privateKey, clientPk33 } = deriveClientKeyFromPrf(hexToBytes(prfHex));
  const r = await execFileJson(REAL_CARD_PYTHON, [
    REAL_CARD_TWEAKED_SCRIPT,
    '--client-secret-hex', bytesToHex(privateKey),
    '--message', message,
  ]);
  if (r.status !== 'REAL_CARD_TWEAKED_COSIGN_OK') {
    throw new Error(`card tweaked cosign failed: ${JSON.stringify(r)}`);
  }
  // Independently re-verify the card's signature against the wallet output key.
  const sigValid = schnorr.verify(
    hexToBytes(r.final_signature64),
    hexToBytes(r.msg32),
    hexToBytes(r.tweaked_output_xonly32),
  );
  json(res, 200, {
    status: sigValid ? 'NURI_LOCALHOST_PASSKEY_WALLET_OK' : 'SIGNATURE_INVALID',
    derivation: "browser passkey PRF -> HKDF(app:nuri.com|wallet|v1) -> BIP86 m/86'/0'/0'/0/0 (identical to nuri-expo PWA)",
    cosigner: 'physical card MuSig2 applet — musig2(client, card) key-path + client CSV recovery leaf',
    client_pk33: bytesToHex(clientPk33),
    card_pk33: r.card_pk33,
    network,
    nuri_address: taprootAddress(r.tweaked_output_xonly32, network),
    output_key_xonly32: r.tweaked_output_xonly32,
    csv_blocks: r.csv_blocks,
    msg32: r.msg32,
    final_signature64: r.final_signature64,
    signature_valid_bip340: sigValid,
  });
}

// Full card-does-both wallet over the browser passkey PRF.
// client key = browser passkey PRF -> HKDF+BIP86 (PWA-identical); cosigner = card.
const PRF_SCRIPT = process.env.NURI_CARD_PRF_SCRIPT || 'scripts/card-prf-backup.py';
const READER_PRF_PROFILE = process.env.NURI_WALLET_PRF_PROFILE || 'wallet-client';
const READER_PRF_SALT = process.env.NURI_WALLET_PRF_SALT || 'nuri-prf-salt-v1';

function clientSeedFromPrf(prfHex) {
  const { privateKey } = deriveClientKeyFromPrf(hexToBytes(prfHex));
  return bytesToHex(privateKey);
}

// This card can't complete browser WebAuthn (it reports up:false), so read the
// card's FIDO2 PRF directly over the PC/SC reader and run the SAME HKDF+BIP86
// derivation — identical wallet to the browser path, just a reliable transport.
function readerClientSeed() {
  return new Promise((resolvePromise, reject) => {
    execFile(REAL_CARD_PYTHON, [PRF_SCRIPT, 'derive', '--profile', READER_PRF_PROFILE, '--salt', READER_PRF_SALT, '--raw'],
      { cwd: process.cwd(), timeout: 60000, maxBuffer: 1 << 20 }, (err, out, errout) => {
        if (err) return reject(new Error(`card PRF over reader failed: ${err.message}\n${errout || out}`.trim()));
        const h = out.trim();
        if (!/^[0-9a-f]{64}$/.test(h)) return reject(new Error(`bad card PRF output: ${h.slice(0, 80)}`));
        resolvePromise(clientSeedFromPrf(h));
      });
  });
}

async function clientSeed(body) {
  return body.prfHex ? clientSeedFromPrf(requirePrf(body)) : await readerClientSeed();
}
function requirePrf(body) {
  const prfHex = String(body.prfHex || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(prfHex)) throw new Error('prfHex must be the 32-byte hex WebAuthn PRF output');
  return prfHex;
}
function pickNetwork(body) { return body.network === 'mainnet' ? 'mainnet' : 'signet'; }

async function handleWalletAddress(req, res) {
  const body = await readJson(req);
  const network = pickNetwork(body);
  const profile = await provisionAddress(network, { clientSeedHex: await clientSeed(body) });
  json(res, 200, profile);
}

async function handleWalletUtxos(req, res) {
  const body = await readJson(req);
  const network = pickNetwork(body);
  const profile = await loadProfile(network);
  if (!profile) { json(res, 400, { error: `no ${network} wallet yet — get a receive address first` }); return; }
  const utxos = await fetchUtxos(profile.address, network);
  const confirmed = utxos.filter((u) => u.status?.confirmed);
  json(res, 200, {
    address: profile.address,
    network,
    utxos,
    confirmed_sats: confirmed.reduce((s, u) => s + u.value, 0),
    pending_sats: utxos.filter((u) => !u.status?.confirmed).reduce((s, u) => s + u.value, 0),
  });
}

async function handleWalletSpend(req, res) {
  const body = await readJson(req);
  const network = pickNetwork(body);
  if (!body.to) { json(res, 400, { error: 'to (address or "self") is required' }); return; }
  const result = await buildAndSignSpend(network, {
    to: String(body.to),
    amountSats: body.amountSats == null ? null : Number(body.amountSats),
    feeSats: body.feeSats == null ? 500 : Number(body.feeSats),
    broadcast: body.broadcast === true,
    includeUnconfirmed: body.includeUnconfirmed === true,
    clientSeedHex: await clientSeed(body),
  });
  json(res, 200, result);
}

async function handleSign(req, res) {
  const body = await readJson(req);
  const result = args.backend === 'real-card'
    ? await handleRealCardSign(body)
    : runCardCosignFlow({
      card,
      msg32: body.msg32,
      message: body.message,
    });
  json(res, 200, result);
}

async function requestHandler(req, res) {
  try {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/cosign-demo.html')) {
      await serveStatic(res, resolve('web/cosign-demo.html'), 'text/html; charset=utf-8');
      return;
    }
    if (req.method === 'GET' && url.pathname === '/passkey-wallet.html') {
      await serveStatic(res, resolve('web/passkey-wallet.html'), 'text/html; charset=utf-8');
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/wallet' || url.pathname === '/card-wallet.html')) {
      await serveStatic(res, resolve('web/card-wallet.html'), 'text/html; charset=utf-8');
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/wallet/address') { await handleWalletAddress(req, res); return; }
    if (req.method === 'POST' && url.pathname === '/api/wallet/utxos') { await handleWalletUtxos(req, res); return; }
    if (req.method === 'POST' && url.pathname === '/api/wallet/spend') { await handleWalletSpend(req, res); return; }
    if (req.method === 'GET' && url.pathname === '/api/cosign/info') {
      handleInfo(res);
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/cosign/passkey-sign') {
      await handlePasskeySign(req, res);
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/cosign/sign') {
      await handleSign(req, res);
      return;
    }
    json(res, 404, { error: 'not found' });
  } catch (error) {
    json(res, 500, {
      error: error?.message || String(error),
    });
  }
}

const args = parseArgs(process.argv.slice(2));

if (args.selftest) {
  const result = args.backend === 'real-card'
    ? await handleRealCardSign({})
    : runCardCosignFlow({ card });
  console.log(JSON.stringify(result, null, 2));
  process.exit(0);
}

const server = createServer(requestHandler);
server.listen(args.port, args.host, () => {
  console.log(`Nuri card cosign demo server at http://${args.host}:${args.port}/cosign-demo.html`);
  if (args.backend === 'real-card') {
    console.log(`Real-card backend enabled; profile: ${REAL_CARD_PROFILE}`);
  } else {
    console.log(`Simulated cosigner card pubkey: ${bytesToHex(card.getIndividualPubkey())}`);
  }
});
