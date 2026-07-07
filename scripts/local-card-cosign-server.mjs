#!/usr/bin/env node
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import process from 'node:process';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { HDKey } from '@scure/bip32';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bech32, bech32m } from '@scure/base';
import { createOnCardGeneratedCard, runCardCosignFlow } from '../src/musig2/cosign-flow.js';
import { provisionAddress, fetchUtxos, buildAndSignSpend, loadProfile } from './nuri-card-wallet.mjs';

const card = createOnCardGeneratedCard();
const REAL_CARD_PYTHON = process.env.REAL_CARD_COSIGN_PYTHON || '/private/tmp/nuri-fido2-real-card-venv/bin/python';
const REAL_CARD_SCRIPT = process.env.REAL_CARD_COSIGN_SCRIPT || 'scripts/real-card-cosign-proof.py';
const REAL_CARD_TWEAKED_SCRIPT = process.env.REAL_CARD_TWEAKED_SCRIPT || 'scripts/card-cosign-tweaked.py';
const REAL_CARD_ARKADE_SCRIPT = process.env.REAL_CARD_ARKADE_SCRIPT || 'scripts/real-card-arkade-signer-proof.py';
const REAL_CARD_PROFILE = process.env.REAL_CARD_COSIGN_PROFILE || '.nuri-card-musig2/browser-real-card.json';
const ARKADE_SIGNER_URL = process.env.NURI_ARKADE_SIGNER_URL || process.env.EXPO_PUBLIC_ARKADE_SIGNER_URL || 'https://arkade.nuri.com/v4';
const PROFILE_LIGHTNING_TARGET = process.env.NURI_PROFILE_LIGHTNING_TARGET || process.env.NURI_LIGHTNING_ADDRESS || '';
const CARD_IDENTITY_CACHE_MS = Number(process.env.NURI_CARD_IDENTITY_CACHE_MS || 300000);
const checkoutSessions = new Map();
let cachedCardAccountIdentity = null;

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

function sha256Hex(value) {
  return bytesToHex(sha256(utf8(value)));
}

const LOCAL_DEMO_ASP_SECRET32 = process.env.NURI_LOCAL_DEMO_ASP_SECRET32 || sha256Hex('nuri local demo arkade asp signer v1');

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function wordsToNumber(words) {
  const value = words.reduce((acc, word) => (acc * 32n) + BigInt(word), 0n);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('BOLT11 numeric field is too large');
  return Number(value);
}

function bolt11AmountToSats(digits, multiplier) {
  if (!digits) return null;
  const units = BigInt(digits);
  let msats;
  if (!multiplier) msats = units * 100_000_000_000n;
  else if (multiplier === 'm') msats = units * 100_000_000n;
  else if (multiplier === 'u') msats = units * 100_000n;
  else if (multiplier === 'n') msats = units * 100n;
  else if (multiplier === 'p') {
    if (units % 10n !== 0n) throw new Error('BOLT11 amount is below millisat precision');
    msats = units / 10n;
  } else {
    throw new Error(`unsupported BOLT11 amount multiplier: ${multiplier}`);
  }
  if (msats % 1000n !== 0n) throw new Error('BOLT11 invoice amount is not a whole-sat amount');
  const sats = msats / 1000n;
  if (sats > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('BOLT11 invoice amount is too large');
  return Number(sats);
}

function parseCheckoutInvoice(invoice) {
  const lower = invoice.toLowerCase();
  const separator = lower.lastIndexOf('1');
  if (!lower.startsWith('ln') || separator <= 2) {
    throw new Error('invoice must be a BOLT11 Lightning invoice');
  }
  const hrp = lower.slice(0, separator);
  const match = hrp.match(/^(lnbc|lntbs|lntb|lnbcrt)([0-9]*)([munp]?)$/);
  if (!match) throw new Error('could not parse BOLT11 invoice amount/network');
  const prefixNetwork = {
    lnbc: 'mainnet',
    lntb: 'signet',
    lntbs: 'signet',
    lnbcrt: 'regtest',
  }[match[1]];
  const decoded = bech32.decode(lower, 4096);
  if (decoded.prefix !== hrp) throw new Error('BOLT11 prefix mismatch');
  const words = decoded.words;
  if (words.length < 7 + 104) throw new Error('BOLT11 invoice is too short');
  const timestamp = wordsToNumber(words.slice(0, 7));
  const tagsEnd = words.length - 104;
  let index = 7;
  let paymentHash = null;
  let expirySeconds = 3600;
  while (index < tagsEnd) {
    if (index + 3 > tagsEnd) throw new Error('BOLT11 tagged field is truncated');
    const type = words[index];
    const length = (words[index + 1] * 32) + words[index + 2];
    const data = words.slice(index + 3, index + 3 + length);
    if (data.length !== length || index + 3 + length > tagsEnd) {
      throw new Error('BOLT11 tagged field length exceeds invoice data');
    }
    if (type === 1) {
      const bytes = bech32.fromWords(data);
      if (bytes.length !== 32) throw new Error('BOLT11 payment hash tag must be 32 bytes');
      paymentHash = bytesToHex(bytes);
    } else if (type === 6) {
      expirySeconds = wordsToNumber(data);
    }
    index += 3 + length;
  }
  if (!paymentHash) throw new Error('BOLT11 invoice is missing payment hash tag');
  const expiresAtMs = (timestamp + expirySeconds) * 1000;
  if (expiresAtMs <= Date.now()) throw new Error('BOLT11 invoice is expired');
  return {
    kind: 'bolt11',
    network: prefixNetwork,
    amount_sats: bolt11AmountToSats(match[2], match[3]),
    payment_hash: paymentHash,
    created_at_unix: timestamp,
    expires_at: new Date(expiresAtMs).toISOString(),
    invoice_hash32: sha256Hex(lower),
  };
}

function validateCheckoutInvoice(invoice, expectedAmountSats, expectedNetwork) {
  const parsed = parseCheckoutInvoice(invoice);
  if (parsed.network !== expectedNetwork) {
    throw new Error(`invoice network ${parsed.network} does not match checkout network ${expectedNetwork}`);
  }
  if (parsed.amount_sats == null) {
    throw new Error('invoice must include an amount for this checkout');
  }
  if (parsed.amount_sats !== expectedAmountSats) {
    throw new Error(`invoice amount ${parsed.amount_sats} sats does not match checkout amount ${expectedAmountSats} sats`);
  }
  return parsed;
}

function decodeLnurl(raw) {
  const value = String(raw || '').trim();
  if (!value) throw new Error('Lightning address, LNURL, or BOLT11 invoice is required');
  if (/^https:\/\//i.test(value)) return value;
  if (/^lnurl/i.test(value)) {
    const decoded = bech32.decode(value.toLowerCase(), 4096);
    return new TextDecoder().decode(Uint8Array.from(bech32.fromWords(decoded.words)));
  }
  const lightningAddress = value.match(/^([^@\s]+)@([^@\s]+)$/);
  if (lightningAddress) {
    const name = encodeURIComponent(lightningAddress[1]);
    const domain = lightningAddress[2].toLowerCase();
    return `https://${domain}/.well-known/lnurlp/${name}`;
  }
  throw new Error('target must be a Lightning address, LNURL-pay string, or HTTPS LNURL-pay endpoint');
}

async function fetchJsonUrl(url, label) {
  return fetchJsonRequest(url, label, { method: 'GET' });
}

async function fetchJsonRequest(url, label, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(url, {
      cache: 'no-store',
      ...init,
      headers: {
        accept: 'application/json',
        ...(init.headers || {}),
      },
      signal: controller.signal,
    });
    const text = await response.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error(`${label} returned non-JSON response`);
    }
    if (!response.ok) throw new Error(`${label} HTTP ${response.status}: ${body.reason || text.slice(0, 160)}`);
    if (body.status && String(body.status).toUpperCase() === 'ERROR') {
      throw new Error(`${label} error: ${body.reason || 'unknown error'}`);
    }
    return body;
  } finally {
    clearTimeout(timer);
  }
}

async function resolveLightningInvoice({ target, amountSats, comment = '' }) {
  const invoiceTarget = String(target || '').trim();
  if (/^ln/i.test(invoiceTarget) && !/^lnurl/i.test(invoiceTarget)) {
    const info = validateCheckoutInvoice(invoiceTarget, amountSats, 'mainnet');
    return { invoice: invoiceTarget, invoice_info: info, source: { kind: 'bolt11' } };
  }

  const amountMsats = Number(amountSats) * 1000;
  if (!Number.isInteger(amountMsats) || amountMsats <= 0) throw new Error('amountSats must be a positive integer');
  const lnurl = decodeLnurl(invoiceTarget);
  const metadata = await fetchJsonUrl(lnurl, 'LNURL-pay metadata');
  if (metadata.tag !== 'payRequest') throw new Error('LNURL target is not a payRequest endpoint');
  if (amountMsats < Number(metadata.minSendable) || amountMsats > Number(metadata.maxSendable)) {
    throw new Error(`amount must be between ${Math.ceil(Number(metadata.minSendable) / 1000)} and ${Math.floor(Number(metadata.maxSendable) / 1000)} sats for this LNURL`);
  }
  const callback = new URL(metadata.callback);
  callback.searchParams.set('amount', String(amountMsats));
  const trimmedComment = String(comment || '').trim();
  if (trimmedComment && Number(metadata.commentAllowed || 0) > 0) {
    callback.searchParams.set('comment', trimmedComment.slice(0, Number(metadata.commentAllowed)));
  }
  const invoiceResponse = await fetchJsonUrl(callback.toString(), 'LNURL-pay callback');
  if (!invoiceResponse.pr) throw new Error('LNURL-pay callback did not return a BOLT11 invoice');
  const invoiceInfo = validateCheckoutInvoice(invoiceResponse.pr, amountSats, 'mainnet');
  return {
    invoice: invoiceResponse.pr,
    invoice_info: invoiceInfo,
    source: {
      kind: 'lnurl-pay',
      target: invoiceTarget,
      lnurl,
      min_sendable_msat: Number(metadata.minSendable),
      max_sendable_msat: Number(metadata.maxSendable),
      metadata: metadata.metadata,
      success_action: invoiceResponse.successAction || null,
    },
  };
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
    network: 'mainnet',
    card_pk33: args.backend === 'real-card' ? undefined : bytesToHex(card.getIndividualPubkey()),
    profile: args.backend === 'real-card' ? REAL_CARD_PROFILE : undefined,
    endpoints: {
      sign: 'POST /api/cosign/sign',
      cardAccount: 'GET /api/card/account',
      cardReceiveRegister: 'POST /api/card/register-receive-owner',
      cardLightningSync: 'POST /api/card/lightning-sync',
      resolveLightningInvoice: 'POST /api/lightning/resolve-invoice',
      merchantCreateCheckout: 'POST /api/merchant/checkout',
      checkoutSession: 'GET /api/checkout/session?id=<session_id>',
      checkoutConfirm: 'POST /api/checkout/confirm',
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
const CARD_RECEIVE_PROFILE = process.env.NURI_CARD_RECEIVE_PROFILE || 'nuri-card-arkade-receive';
const CARD_RECEIVE_PROFILE_PATH = process.env.NURI_CARD_RECEIVE_PROFILE_PATH || '';
const CARD_RECEIVE_RP_ID = process.env.NURI_CARD_RECEIVE_RP_ID || 'nuri.com';
const CARD_RECEIVE_ORIGIN = process.env.NURI_CARD_RECEIVE_ORIGIN || 'https://nuri.com';
const CARD_RECEIVE_RP_NAME = process.env.NURI_CARD_RECEIVE_RP_NAME || 'Nuri Wallet';
const CARD_RECEIVE_USER_NAME = process.env.NURI_CARD_RECEIVE_USER_NAME || 'nuri-card-receive';
const CARD_CLAIM_RUNNER = process.env.NURI_CARD_CLAIM_RUNNER || 'scripts/card-arkade-claim.mjs';
const CARD_CLAIM_SIGNER = process.env.NURI_CARD_CLAIM_SIGNER || 'scripts/card-arkade-claim-signer.py';
// ponytail: PIN in server env so receive-claims (pulling your own funds in) auto-run.
// Fine for a receive; a per-action tap would matter for spends, not top-ups.
const CARD_PIN = process.env.FIDO2_BACKUP_PIN || process.env.NURI_CARD_PIN || '';

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

function assertArkadeProof(proof, msg32) {
  if (proof.status !== 'REAL_CARD_ARKADE_CLIENT_SIGNER_PROOF_OK') {
    throw new Error(`card Arkade proof failed: ${JSON.stringify(proof)}`);
  }
  if (!proof.cases?.every((c) => c.msg32 === msg32 && c.card_client_partial_verified && c.asp_partial_verified && c.final_signature_verified)) {
    throw new Error('card Arkade proof did not verify the requested message');
  }
}

async function runArkadeProof(msg32) {
  const proof = await execFileJson(REAL_CARD_PYTHON, [
    REAL_CARD_ARKADE_SCRIPT,
    '--case', 'all',
    '--msg32', msg32,
    '--asp-secret-hex', LOCAL_DEMO_ASP_SECRET32,
  ]);
  assertArkadeProof(proof, msg32);
  return proof;
}

async function cardAccountIdentity({ fresh = false } = {}) {
  const now = Date.now();
  if (
    !fresh &&
    cachedCardAccountIdentity &&
    now - cachedCardAccountIdentity.cached_at_ms < CARD_IDENTITY_CACHE_MS
  ) {
    return cachedCardAccountIdentity;
  }
  const identityMsg32 = sha256Hex('nuri-local-card-account-v1');
  const proof = await runArkadeProof(identityMsg32);
  const identity = arkadeIdentityFromProof(proof);
  cachedCardAccountIdentity = {
    identity,
    proof,
    msg32: identityMsg32,
    cached_at_ms: now,
  };
  return cachedCardAccountIdentity;
}

function arkadeIdentityFromProof(proof) {
  const untweaked = proof.cases?.find((c) => c.case === 'untweaked');
  const tweaked = proof.cases?.find((c) => c.case === 'tweaked');
  if (!untweaked || !tweaked) throw new Error('Arkade proof did not include both untweaked and tweaked cases');
  if (untweaked.card_client_pk33 !== tweaked.card_client_pk33 || untweaked.asp_pk33 !== tweaked.asp_pk33) {
    throw new Error('Arkade proof returned inconsistent signer keys');
  }
  return {
    reader: proof.reader,
    card_version: proof.card_version,
    card_client_pk33: untweaked.card_client_pk33,
    asp_pk33: untweaked.asp_pk33,
    sorted_pubkeys33: untweaked.sorted_pubkeys33,
    internal_aggregate_xonly32: untweaked.internal_aggregate_xonly32,
    untweaked_signing_xonly32: untweaked.signing_xonly32,
    script_root32: tweaked.script_root32,
    tweak32: tweaked.tweak32,
    tweaked_signing_xonly32: tweaked.signing_xonly32,
  };
}

async function addressBalance(address, network) {
  try {
    const utxos = await fetchUtxos(address, network);
    const confirmed = utxos.filter((u) => u.status?.confirmed);
    const pending = utxos.filter((u) => !u.status?.confirmed);
    return {
      utxos,
      confirmed_sats: confirmed.reduce((sum, u) => sum + u.value, 0),
      pending_sats: pending.reduce((sum, u) => sum + u.value, 0),
    };
  } catch (error) {
    return {
      utxos: [],
      confirmed_sats: 0,
      pending_sats: 0,
      balance_error: error?.message || String(error),
    };
  }
}

function signerOriginUrl() {
  return String(ARKADE_SIGNER_URL || '').replace(/\/+$/, '').replace(/\/v4$/i, '');
}

function signerV4Url() {
  return String(ARKADE_SIGNER_URL || '').replace(/\/+$/, '');
}

function cardReceiveProfilePath() {
  if (CARD_RECEIVE_PROFILE_PATH) return CARD_RECEIVE_PROFILE_PATH;
  const safeProfile = CARD_RECEIVE_PROFILE.replace(/[\\/]/g, '_');
  return `.nuri-card-prf/${safeProfile}.json`;
}

async function readCardReceiveProfile() {
  try {
    const raw = await readFile(cardReceiveProfilePath(), 'utf8');
    const profile = JSON.parse(raw);
    if (profile?.schema !== 'nuri-card-prf-profile-v1') {
      throw new Error(`${cardReceiveProfilePath()} is not a nuri-card-prf-profile-v1 profile`);
    }
    return profile;
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

function profileNeedsReceiveEnroll(profile) {
  if (!profile) return true;
  if (profile.rp_id !== CARD_RECEIVE_RP_ID) return true;
  if (profile.origin !== CARD_RECEIVE_ORIGIN) return true;
  if (!String(profile.credential_id || '').trim()) return true;
  if (!String(profile.credential_public_key_spki_b64u || '').trim()) return true;
  return false;
}

async function enrollCardReceiveProfile({ force = false } = {}) {
  const args = [
    PRF_SCRIPT,
    'enroll',
    '--profile', CARD_RECEIVE_PROFILE,
    '--rp-id', CARD_RECEIVE_RP_ID,
    '--origin', CARD_RECEIVE_ORIGIN,
    '--rp-name', CARD_RECEIVE_RP_NAME,
    '--user-name', CARD_RECEIVE_USER_NAME,
    '--resident-key', 'discouraged',
    '--user-verification', 'discouraged',
    '--registration-prf', 'disabled',
  ];
  if (CARD_RECEIVE_PROFILE_PATH) args.push('--profile-path', CARD_RECEIVE_PROFILE_PATH);
  if (force) args.push('--force');
  await execFileJson(REAL_CARD_PYTHON, args);
  const profile = await readCardReceiveProfile();
  if (profileNeedsReceiveEnroll(profile)) {
    throw new Error('card receive enrollment did not write credential id and SPKI public key');
  }
  return profile;
}

async function ensureCardReceiveProfile() {
  const existing = await readCardReceiveProfile();
  if (!profileNeedsReceiveEnroll(existing)) return { profile: existing, enrolled: false };
  return { profile: await enrollCardReceiveProfile({ force: Boolean(existing) }), enrolled: true };
}

function cardReceiveOwnerFromProfile(identity, profile) {
  if (!profile || profileNeedsReceiveEnroll(profile)) return null;
  return {
    cred_id_b64u: String(profile.credential_id || '').trim(),
    client_public_key_33_hex: identity.card_client_pk33,
    cred_pubkey_b64u: String(profile.credential_public_key_spki_b64u || '').trim(),
    profile: CARD_RECEIVE_PROFILE,
    rp_id: profile.rp_id,
    origin: profile.origin,
  };
}

async function fetchArkadeInfo(identity, owner = null) {
  const url = new URL(`${signerV4Url()}/arkade/info`);
  url.searchParams.set('client_pk33', identity.card_client_pk33);
  if (owner?.cred_id_b64u) url.searchParams.set('cred_id_b64u', owner.cred_id_b64u);
  return fetchJsonUrl(url.toString(), 'Nuri Arkade info');
}

async function describeLiveReceive(identity) {
  const profile = await readCardReceiveProfile();
  const owner = cardReceiveOwnerFromProfile(identity, profile);
  let info = null;
  let infoError = null;
  try {
    info = await fetchArkadeInfo(identity, owner);
  } catch (error) {
    infoError = error?.message || String(error);
  }
  return {
    receive_owner: owner ? {
      cred_id_b64u: owner.cred_id_b64u,
      client_public_key_33_hex: owner.client_public_key_33_hex,
      rp_id: owner.rp_id,
      origin: owner.origin,
      profile: owner.profile,
    } : null,
    registration_required: !owner || info?.recovery?.registered !== true,
    profile_present: Boolean(profile),
    profile_has_spki_public_key: Boolean(profile?.credential_public_key_spki_b64u),
    arkade_signer_url: ARKADE_SIGNER_URL,
    live_server_pubkey: info?.server_pubkey || null,
    recovery: info?.recovery || null,
    info_error: infoError,
  };
}

async function ensureLiveReceiveRegistration(identity) {
  const { profile, enrolled } = await ensureCardReceiveProfile();
  const owner = cardReceiveOwnerFromProfile(identity, profile);
  if (!owner) throw new Error('card receive owner profile is incomplete');
  const registered = await fetchJsonRequest(`${signerV4Url()}/arkade/auth`, 'Nuri Arkade receive owner registration', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-arkade-client': 'nuri-card-browser-demo',
      'x-arkade-sdk': 'nuri-card-browser-demo',
    },
    body: JSON.stringify({
      cred_id_b64u: owner.cred_id_b64u,
      cred_pubkey_b64u: owner.cred_pubkey_b64u,
      client_signer_pubkey: identity.card_client_pk33,
    }),
  });
  return {
    enrolled,
    registered,
    receive_owner: {
      cred_id_b64u: owner.cred_id_b64u,
      client_public_key_33_hex: owner.client_public_key_33_hex,
      rp_id: owner.rp_id,
      origin: owner.origin,
      profile: owner.profile,
    },
  };
}

async function cardAccountView({ includeLive = true } = {}) {
  const {
    identity,
    proof,
    msg32: identityMsg32,
    cached_at_ms: identityCachedAtMs,
  } = await cardAccountIdentity();
  const liveReceive = includeLive ? await describeLiveReceive(identity) : null;
  const addresses = {};
  for (const network of ['mainnet']) {
    const address = taprootAddress(identity.tweaked_signing_xonly32, network);
    addresses[network] = {
      network,
      address,
      internal_address: taprootAddress(identity.untweaked_signing_xonly32, network),
      output_xonly32: identity.tweaked_signing_xonly32,
      internal_xonly32: identity.untweaked_signing_xonly32,
      ...(await addressBalance(address, network)),
    };
  }
  return {
    status: 'NURI_CARD_ARKADE_ACCOUNT_READY',
    model: 'card MuSig2 key is the Arkade client signer; live Nuri Arkade signs as the second signer after receive-owner registration',
    demo_only: true,
    identity_cached_at_ms: identityCachedAtMs,
    identity_cache_ms: CARD_IDENTITY_CACHE_MS,
    ...identity,
    lightning: {
      receive_target: PROFILE_LIGHTNING_TARGET || null,
      receive_configured: Boolean(PROFILE_LIGHTNING_TARGET),
      ...(liveReceive || {
        arkade_signer_url: ARKADE_SIGNER_URL,
        receive_owner: null,
        registration_required: true,
      }),
    },
    addresses,
    proof: {
      msg32: identityMsg32,
      final_signature_verified: proof.cases.every((c) => c.final_signature_verified === true),
      cases: proof.cases.map((c) => ({
        case: c.case,
        signing_xonly32: c.signing_xonly32,
        tweak32: c.tweak32,
        final_signature64: c.final_signature64,
      })),
    },
  };
}

async function handleCardAccount(req, res) {
  json(res, 200, await cardAccountView());
}

async function handleCardReceiveRegistration(req, res) {
  try {
    const account = await cardAccountView({ includeLive: false });
    const identity = {
      card_client_pk33: account.card_client_pk33,
    };
    const registration = await ensureLiveReceiveRegistration(identity);
    const live = await describeLiveReceive(identity);
    json(res, 200, {
      status: 'NURI_CARD_RECEIVE_OWNER_REGISTERED',
      enrolled_new_credential: registration.enrolled,
      receive_owner: registration.receive_owner,
      live_server_pubkey: registration.registered.server_pubkey || live.live_server_pubkey || null,
      recovery: registration.registered.recovery || live.recovery || null,
    });
  } catch (error) {
    json(res, 400, { error: error?.message || String(error) });
  }
}

async function handleResolveLightningInvoice(req, res) {
  const body = await readJson(req);
  const amountSats = Number(body.amountSats);
  if (!Number.isInteger(amountSats) || amountSats <= 0) {
    json(res, 400, { error: 'amountSats must be a positive integer' });
    return;
  }
  try {
    const result = await resolveLightningInvoice({
      target: body.target || body.invoice,
      amountSats,
      comment: body.comment || body.memo || '',
    });
    json(res, 200, {
      status: 'NURI_LIGHTNING_INVOICE_RESOLVED',
      amount_sats: amountSats,
      network: 'mainnet',
      ...result,
    });
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}

async function handleCardLightningInvoice(req, res) {
  const body = await readJson(req);
  const amountSats = Number(body.amountSats);
  if (!Number.isInteger(amountSats) || amountSats <= 0) {
    json(res, 400, { error: 'amountSats must be a positive integer' });
    return;
  }
  try {
    const account = await cardAccountView({ includeLive: false });
    const identity = {
      card_client_pk33: account.card_client_pk33,
    };
    const registration = await ensureLiveReceiveRegistration(identity);
    const receiveOwner = registration.receive_owner;
    const receiveUrl = `${signerOriginUrl()}/api/arkade/receive/invoice`;
    const created = await fetchJsonRequest(receiveUrl, 'Nuri Arkade receive invoice', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-arkade-client': 'nuri-card-browser-demo',
        'x-arkade-sdk': 'nuri-card-browser-demo',
      },
      body: JSON.stringify({
        ...receiveOwner,
        amount_sats: amountSats,
        memo: String(body.memo || 'Nuri card Lightning receive').trim() || undefined,
      }),
    });
    if (created.ok !== true || !created.invoice) {
      throw new Error(`Nuri Arkade receive invoice returned malformed response: ${JSON.stringify(created)}`);
    }
    json(res, 200, {
      status: 'NURI_CARD_LIGHTNING_INVOICE_CREATED',
      amount_sats: amountSats,
      network: 'mainnet',
      account: {
        card_client_pk33: account.card_client_pk33,
        local_demo_asp_pk33: account.asp_pk33,
        live_server_pubkey: registration.registered.server_pubkey || null,
        receive_owner: receiveOwner,
      },
      invoice: created.invoice,
      payment_hash_hex: created.payment_hash_hex || null,
      swap_id: created.swap_id || null,
      expires_at_ms: created.expires_at_ms || null,
      source: created.source || 'app_invoice',
      restore: created.restore || null,
    });
  } catch (error) {
    const message = error.message || String(error);
    if (/owner not found/i.test(message)) {
      json(res, 409, {
        error: 'card account is not registered on the Nuri Arkade receive server yet',
        next_step: 'register the card-backed Arkade owner pair before creating payable Lightning funding invoices',
      });
      return;
    }
    json(res, 400, { error: message });
  }
}

function spawnClaimRunner(cfg) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      process.execPath,
      [CARD_CLAIM_RUNNER],
      { maxBuffer: 8 * 1024 * 1024, timeout: 240000 },
      (err, stdout, stderr) => {
        let parsed = null;
        try { parsed = JSON.parse(stdout); } catch { /* fall through */ }
        if (parsed) { resolve(parsed); return; }
        reject(new Error(stderr || err?.message || 'claim runner produced no JSON output'));
      },
    );
    child.stdin.end(JSON.stringify(cfg));
  });
}

// Build the cfg that scripts/card-arkade-claim.mjs expects, for a single receive swap.
function buildClaimCfg(identity, receiveOwner, profile, serverPk33, r) {
  const v4 = signerV4Url();
  const base = signerOriginUrl();
  return {
    cardPk33: identity.card_client_pk33,
    serverPk33,
    restore: {
      swap_id: r.swap_id,
      status: r.status,
      created_at_unix: Math.floor((r.restore.createdAt || 1000) / 1000),
      preimage: r.restore.preimage,
      request: r.restore.request,
      response: r.restore.response,
    },
    signUrl: `${v4}/arkade/sign`,
    authUrl: `${v4}/arkade/auth`,
    approveUrl: `${base}/api/arkade/receive/claim/approve`,
    credId: receiveOwner.cred_id_b64u,
    credPubkeyB64u: profile.credential_public_key_spki_b64u,
    credProfile: CARD_RECEIVE_PROFILE,
    rpId: profile.rp_id || CARD_RECEIVE_RP_ID,
    origin: profile.origin || CARD_RECEIVE_ORIGIN,
    pin: CARD_PIN,
    python: REAL_CARD_PYTHON,
    prfScript: PRF_SCRIPT,
    claimSigner: CARD_CLAIM_SIGNER,
    nodeUrl: 'https://arkade.computer',
    boltzNetwork: 'bitcoin',
  };
}

async function claimReceiveVHTLCs() {
  if (!CARD_PIN) {
    return { skipped: 'pin-not-set', claims: [] };
  }
  const { identity } = await cardAccountIdentity();
  const registration = await ensureLiveReceiveRegistration(identity);
  const receiveOwner = registration.receive_owner;
  const serverPk33 = registration.registered.server_pubkey;
  const profile = await readCardReceiveProfile();
  if (!profile) throw new Error('card receive profile missing');
  if (!serverPk33) throw new Error('live server public key unavailable');

  const synced = await fetchJsonRequest(`${signerOriginUrl()}/api/arkade/receive/sync`, 'Nuri Arkade receive sync', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-arkade-client': 'nuri-card-browser-demo', 'x-arkade-sdk': 'nuri-card-browser-demo' },
    body: JSON.stringify({ cred_id_b64u: receiveOwner.cred_id_b64u, client_public_key_33_hex: receiveOwner.client_public_key_33_hex }),
  });
  const claimable = (Array.isArray(synced.lightning) ? synced.lightning : [])
    .filter((r) => r.status === 'claimable' && r.restore);

  const claims = [];
  for (const r of claimable) {
    const cfg = buildClaimCfg(identity, receiveOwner, profile, serverPk33, r);
    try {
      const result = await spawnClaimRunner(cfg);
      claims.push({ swap_id: r.swap_id, ...result });
    } catch (error) {
      claims.push({ swap_id: r.swap_id, status: 'NURI_CARD_ARKADE_CLAIM_FAILED', error: error?.message || String(error) });
    }
  }
  return { claims, claimable_count: claimable.length };
}

// Send: Ark -> Lightning submarine swap. Pays a BOLT11 merchant invoice from
// the card's settled Ark VTXO balance. Same card+ASP MuSig2 round as claim,
// just swaps.sendLightningPayment instead of swaps.claimVHTLC.
async function payMerchantInvoice(invoice, pinOverride) {
  const pin = pinOverride || CARD_PIN;
  if (!pin) {
    return { skipped: 'pin-not-set' };
  }
  const { identity } = await cardAccountIdentity();
  const registration = await ensureLiveReceiveRegistration(identity);
  const serverPk33 = registration.registered.server_pubkey;
  if (!serverPk33) throw new Error('live server public key unavailable');
  const profile = await readCardReceiveProfile();
  if (!profile) throw new Error('card receive profile missing');
  const receiveOwner = cardReceiveOwnerFromProfile(identity, profile);

  const v4 = signerV4Url();
  const base = signerOriginUrl();
  const cfg = {
    mode: 'send',
    cardPk33: identity.card_client_pk33,
    serverPk33,
    invoice,
    pin,
    python: REAL_CARD_PYTHON,
    prfScript: PRF_SCRIPT,
    claimSigner: CARD_CLAIM_SIGNER,
    credId: receiveOwner.cred_id_b64u,
    credProfile: CARD_RECEIVE_PROFILE,
    rpId: profile.rp_id || CARD_RECEIVE_RP_ID,
    origin: profile.origin || CARD_RECEIVE_ORIGIN,
    // Nuri native send: swap-intent -> prepare -> card WebAuthn -> cosign -> complete.
    intentUrl: `${v4}/arkade/swap-intent/create`,
    prepareUrl: `${base}/api/arkade/send/prepare`,
    cosignUrl: `${base}/api/arkade/send/cosign`,
    completeUrl: `${base}/api/arkade/send/complete`,
    nodeUrl: 'https://arkade.computer',
    boltzNetwork: 'bitcoin',
  };
  return await spawnClaimRunner(cfg);
}

// Pure-Arkade send: card + a locally-held key (LOCAL_DEMO_ASP_SECRET32), no Nuri.
async function payMerchantInvoicePureArkade(invoice, pinOverride) {
  const pin = pinOverride || CARD_PIN;
  if (!pin) return { skipped: 'pin-not-set' };
  const { identity } = await cardAccountIdentity();
  const cfg = {
    mode: 'send',
    cardPk33: identity.card_client_pk33,
    serverPk33: identity.asp_pk33, // local demo ASP pubkey (we hold the secret)
    localAspSecret: LOCAL_DEMO_ASP_SECRET32,
    invoice,
    python: REAL_CARD_PYTHON,
    prfScript: PRF_SCRIPT,
    claimSigner: CARD_CLAIM_SIGNER,
    nodeUrl: 'https://arkade.computer',
    boltzNetwork: 'bitcoin',
  };
  return await spawnClaimRunner(cfg);
}

async function handleCardLightningClaim(req, res) {
  try {
    const { claims, claimable_count, skipped } = await claimReceiveVHTLCs();
    if (skipped) {
      json(res, 400, {
        error: 'card PIN not configured',
        next_step: 'start the server with FIDO2_BACKUP_PIN=<card pin> to enable auto-claim',
      });
      return;
    }
    json(res, 200, {
      status: 'NURI_CARD_LIGHTNING_CLAIM_DONE',
      claimable_count,
      claimed_ok: claims.filter((c) => c.status === 'NURI_CARD_ARKADE_CLAIM_OK').length,
      claims,
    });
  } catch (error) {
    json(res, 400, { error: error?.message || String(error) });
  }
}

async function handleCardWalletBalance(req, res, url) {
  try {
    const account = url?.searchParams.get('account') === 'pure' ? 'pure' : 'nuri';
    const { identity } = await cardAccountIdentity();
    let serverPk33;
    if (account === 'pure') {
      serverPk33 = identity.asp_pk33; // local demo ASP pubkey (we hold the secret)
    } else {
      const live = await describeLiveReceive(identity);
      serverPk33 = live.live_server_pubkey;
      if (!serverPk33) throw new Error('live server public key unavailable');
    }
    const result = await spawnClaimRunner({
      mode: 'balance',
      cardPk33: identity.card_client_pk33,
      serverPk33,
      nodeUrl: 'https://arkade.computer',
    });
    json(res, 200, { status: 'NURI_CARD_WALLET_BALANCE_OK', account, ...result });
  } catch (error) {
    json(res, 400, { error: error?.message || String(error) });
  }
}

async function handleCardLightningSync(req, res) {
  try {
    const { identity, cached_at_ms: identityCachedAtMs } = await cardAccountIdentity();
    const registration = await ensureLiveReceiveRegistration(identity);
    const receiveOwner = registration.receive_owner;
    const syncUrl = `${signerOriginUrl()}/api/arkade/receive/sync`;
    const synced = await fetchJsonRequest(syncUrl, 'Nuri Arkade receive sync', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-arkade-client': 'nuri-card-browser-demo',
        'x-arkade-sdk': 'nuri-card-browser-demo',
      },
      body: JSON.stringify({
        cred_id_b64u: receiveOwner.cred_id_b64u,
        client_public_key_33_hex: receiveOwner.client_public_key_33_hex,
      }),
    });
    json(res, 200, {
      status: 'NURI_CARD_LIGHTNING_RECEIVES_SYNCED',
      account: {
        card_client_pk33: identity.card_client_pk33,
        identity_cached_at_ms: identityCachedAtMs,
        identity_cache_ms: CARD_IDENTITY_CACHE_MS,
        live_server_pubkey: registration.registered.server_pubkey || null,
        receive_owner: receiveOwner,
      },
      receives: Array.isArray(synced.receives) ? synced.receives : [],
      lightning: Array.isArray(synced.lightning) ? synced.lightning : [],
      boarding: Array.isArray(synced.boarding) ? synced.boarding : [],
      boarding_address: synced.boarding_address || null,
      server: {
        nuri_server_api: synced.nuri_server_api || null,
        nuri_server_version: synced.nuri_server_version || null,
        arkade_sdk_version: synced.arkade_sdk_version || null,
      },
    });
  } catch (error) {
    json(res, 400, { error: error?.message || String(error) });
  }
}

function sessionPublicView(session) {
  const { proof, paymentPackage, broadcast, ...publicSession } = session;
  return {
    ...publicSession,
    payment_package_hash32: paymentPackage ? sha256Hex(canonicalJson(paymentPackage)) : undefined,
    broadcast: broadcast || undefined,
    proof: proof ? {
      status: proof.status,
      card_client_pk33: proof.cases?.[0]?.card_client_pk33,
      asp_pk33: proof.cases?.[0]?.asp_pk33,
      final_signature_verified: proof.cases?.every((c) => c.final_signature_verified === true),
      cases: proof.cases?.map((c) => ({
        case: c.case,
        signing_xonly32: c.signing_xonly32,
        msg32: c.msg32,
        card_client_partial_verified: c.card_client_partial_verified,
        asp_partial_verified: c.asp_partial_verified,
        final_signature_verified: c.final_signature_verified,
        final_signature64: c.final_signature64,
      })),
    } : undefined,
  };
}

async function handleMerchantCheckout(req, res) {
  const body = await readJson(req);
  const amountSats = Number(body.amountSats);
  if (!Number.isInteger(amountSats) || amountSats <= 0) {
    json(res, 400, { error: 'amountSats must be a positive integer' });
    return;
  }
  const merchantName = String(body.merchantName || 'Demo merchant').trim().slice(0, 80);
  const memo = String(body.memo || 'Local Nuri checkout demo').trim().slice(0, 160);
  const requestedNetwork = String(body.network || 'mainnet').trim().toLowerCase();
  if (requestedNetwork !== 'mainnet') {
    json(res, 400, { error: 'this checkout demo is mainnet-only' });
    return;
  }
  const network = 'mainnet';
  const sessionId = randomUUID();
  let invoice = String(body.invoice || '').trim();
  let invoiceInfo;
  let invoiceSource = null;
  try {
    if (!invoice && body.lightningTarget) {
      const resolved = await resolveLightningInvoice({
        target: body.lightningTarget,
        amountSats,
        comment: memo,
      });
      invoice = resolved.invoice;
      invoiceSource = resolved.source;
    }
    if (!invoice) throw new Error('paste a mainnet BOLT11 invoice, or provide a Lightning address/LNURL-pay target');
    invoiceInfo = validateCheckoutInvoice(invoice, amountSats, network);
  } catch (error) {
    json(res, 400, { error: error.message });
    return;
  }
  const paymentHash = invoiceInfo.payment_hash || invoiceInfo.invoice_hash32;
  const now = Date.now();
  const session = {
    id: sessionId,
    status: 'created',
    merchant_name: merchantName,
    network,
    amount_sats: amountSats,
    memo,
    invoice,
    invoice_kind: invoiceInfo.kind,
    invoice_expires_at: invoiceInfo.expires_at,
    invoice_source: invoiceSource,
    payment_hash: paymentHash,
    checkout_url: `/checkout?id=${encodeURIComponent(sessionId)}`,
    created_at: new Date(now).toISOString(),
    expires_at: new Date(now + 15 * 60 * 1000).toISOString(),
  };
  checkoutSessions.set(sessionId, session);
  json(res, 200, sessionPublicView(session));
}

function loadCheckoutSession(id) {
  const session = checkoutSessions.get(id);
  if (!session) throw new Error('checkout session not found');
  if (Date.now() > Date.parse(session.expires_at)) {
    session.status = session.status === 'created' ? 'expired' : session.status;
  }
  return session;
}

async function handleCheckoutSession(req, res, url) {
  const id = url.searchParams.get('id') || '';
  try {
    json(res, 200, sessionPublicView(loadCheckoutSession(id)));
  } catch (error) {
    json(res, 404, { error: error.message });
  }
}

async function handleCheckoutConfirm(req, res) {
  const body = await readJson(req);
  const session = loadCheckoutSession(String(body.sessionId || ''));
  if (session.status === 'expired') {
    json(res, 400, { error: 'checkout session expired' });
    return;
  }
  if (session.status === 'paid_demo') {
    json(res, 200, sessionPublicView(session));
    return;
  }
  const identity = arkadeIdentityFromProof(await runArkadeProof(sha256Hex(`nuri-local-checkout-identity:${session.id}`)));
  const paymentPackage = {
    version: 'nuri-local-checkout-v1',
    session_id: session.id,
    merchant_name: session.merchant_name,
    network: session.network,
    amount_sats: session.amount_sats,
    invoice: session.invoice,
    payment_hash: session.payment_hash,
    invoice_kind: session.invoice_kind,
    invoice_expires_at: session.invoice_expires_at,
    invoice_source: session.invoice_source,
    memo: session.memo,
    client_pk33: identity.card_client_pk33,
    asp_pk33: identity.asp_pk33,
    sorted_pubkeys33: identity.sorted_pubkeys33,
    internal_aggregate_xonly32: identity.internal_aggregate_xonly32,
    script_root32: identity.script_root32,
    tweak32: identity.tweak32,
    signing_xonly32: identity.tweaked_signing_xonly32,
    created_at: session.created_at,
    expires_at: session.expires_at,
    approval_scope: 'demo-local-card-arkade-client-signer',
  };
  const msg32 = sha256Hex(canonicalJson(paymentPackage));
  const proof = await runArkadeProof(msg32);
  if (!proof.cases?.every((c) =>
    c.card_client_pk33 === identity.card_client_pk33
    && c.asp_pk33 === identity.asp_pk33
    && (c.case !== 'tweaked' || c.tweak32 === identity.tweak32)
  )) {
    throw new Error('checkout proof signer identity did not match the bound payment package');
  }
  session.status = 'paid_demo';
  session.paid_at = new Date().toISOString();
  session.paymentPackage = paymentPackage;
  session.proof = proof;

  // Real swap-out: pay the merchant BOLT11 invoice from the card's Ark
  // VTXO balance via a Boltz submarine swap. The card signs the VTXO
  // forfeit leaves (same MuSig2 card+ASP round as the claim path), the
  // SDK builds the offchain tx, sends it to the ASP, and Boltz pays the
  // Lightning invoice. This is a real payment, not a demo.
  let broadcast = { attempted: false };
  try {
    const account = body.account === 'pure' ? 'pure' : 'nuri';
    const send = account === 'pure'
      ? await payMerchantInvoicePureArkade(session.invoice, body.pin || '')
      : await payMerchantInvoice(session.invoice, body.pin || '');
    if (send.skipped) {
      broadcast = { attempted: false, account, skipped: send.skipped };
    } else {
      broadcast = {
        attempted: true,
        account,
        status: send.status,
        funding_amount_sats: send.funding_amount_sats,
        final_amount_sats: send.final_amount_sats,
        ark_txid: send.ark_txid,
        ark_address: send.ark_address,
        error: send.error,
      };
    }
  } catch (error) {
    broadcast = { attempted: true, error: error?.message || String(error) };
  }
  session.broadcast = broadcast;
  json(res, 200, sessionPublicView(session));
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
    if (req.method === 'GET' && (url.pathname === '/terminal' || url.pathname === '/merchant-terminal.html')) {
      await serveStatic(res, resolve('web/merchant-terminal.html'), 'text/html; charset=utf-8');
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/checkout' || url.pathname === '/nuri-checkout.html')) {
      await serveStatic(res, resolve('web/nuri-checkout.html'), 'text/html; charset=utf-8');
      return;
    }
    if (req.method === 'GET' && url.pathname === '/vendor/qrcode.js') {
      await serveStatic(res, resolve('node_modules/qrcode-generator/dist/qrcode.js'), 'application/javascript; charset=utf-8');
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/profile' || url.pathname === '/nuri-profile.html')) {
      await serveStatic(res, resolve('web/nuri-profile.html'), 'text/html; charset=utf-8');
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/wallet/address') { await handleWalletAddress(req, res); return; }
    if (req.method === 'POST' && url.pathname === '/api/wallet/utxos') { await handleWalletUtxos(req, res); return; }
    if (req.method === 'POST' && url.pathname === '/api/wallet/spend') { await handleWalletSpend(req, res); return; }
    if (req.method === 'GET' && url.pathname === '/api/card/account') { await handleCardAccount(req, res); return; }
    if (req.method === 'POST' && url.pathname === '/api/card/register-receive-owner') { await handleCardReceiveRegistration(req, res); return; }
    if (req.method === 'POST' && url.pathname === '/api/card/lightning-invoice') { await handleCardLightningInvoice(req, res); return; }
    if (req.method === 'POST' && url.pathname === '/api/card/lightning-sync') { await handleCardLightningSync(req, res); return; }
    if (req.method === 'POST' && url.pathname === '/api/card/lightning-claim') { await handleCardLightningClaim(req, res); return; }
    if (req.method === 'GET' && url.pathname === '/api/card/wallet-balance') { await handleCardWalletBalance(req, res, url); return; }
    if (req.method === 'POST' && url.pathname === '/api/lightning/resolve-invoice') { await handleResolveLightningInvoice(req, res); return; }
    if (req.method === 'POST' && url.pathname === '/api/merchant/checkout') { await handleMerchantCheckout(req, res); return; }
    if (req.method === 'GET' && url.pathname === '/api/checkout/session') { await handleCheckoutSession(req, res, url); return; }
    if (req.method === 'POST' && url.pathname === '/api/checkout/confirm') { await handleCheckoutConfirm(req, res); return; }
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
  console.log(`Merchant terminal: http://${args.host}:${args.port}/terminal`);
  console.log(`Card profile: http://${args.host}:${args.port}/profile`);
  if (args.backend === 'real-card') {
    console.log(`Real-card backend enabled; profile: ${REAL_CARD_PROFILE}`);
  } else {
    console.log(`Simulated cosigner card pubkey: ${bytesToHex(card.getIndividualPubkey())}`);
  }
});
