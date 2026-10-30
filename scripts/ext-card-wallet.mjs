#!/usr/bin/env node
/**
 * Chrome-extension bridge for the card's Bitcoin wallet (Arkade + Lightning).
 *
 * The extension cannot reach PC/SC or the Arkade SDK, so the native messaging
 * host (host/nuri_card_host.py) spawns this script. Everything card-related stays
 * in the proven Python drivers (scripts/musig2-card-status.py read-only,
 * scripts/card-arkade-claim-signer.py for the MuSig2 partial round).
 *
 * Protocol: config JSON on stdin (one line). Responses are JSON LINES on stdout.
 * A `send` run is two-phase so a human can approve the exact transaction:
 *   {"phase":"preview","summary":{...},"digest":"0x.."}   <- card untouched
 *   ...caller writes {"approved":true,"digest":"0x..","pin":".."} on stdin
 *   {"phase":"result","status":...,"ark_txid":...}
 * Cancellation is killing the process; nothing was signed at that point.
 *
 * Modes: info | balance | invoice | send
 */
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Buffer } from 'node:buffer';
import * as btc from '@scure/btc-signer';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { hexToBytes, bytesToHex } from '@noble/curves/utils.js';
import { bech32m } from '@scure/base';
import {
  Wallet,
  InMemoryWalletRepository,
  InMemoryContractRepository,
  RestArkProvider,
  RestIndexerProvider,
  ArkAddress,
} from '@arkade-os/sdk';
import {
  ArkadeSwaps,
  BoltzSwapProvider,
  InMemorySwapRepository,
  getInvoicePaymentHash,
  getInvoiceSatoshis,
} from '@arkade-os/boltz-swap';
import {
  CardBackedAggregateIdentity,
  PreviewSignal,
  execFileJson,
  obtainApprovalToken,
  postJson,
  prepareNuriSend,
  pythonSendCosign,
  sendSession,
} from './lib/card-arkade-identity.mjs';

if (!globalThis.EventSource) {
  try { globalThis.EventSource = (await import('eventsource')).EventSource; } catch { /* offchain only */ }
}

const CSV_BLOCKS = 52500;
const NETWORKS = {
  mainnet: { hrp: 'ark', btc: btc.NETWORK },
  signet: { hrp: 'tark', btc: btc.TEST_NETWORK },
};

function env(name, fallback = '') {
  const value = String(process.env[name] || '').trim();
  return value || fallback;
}

function signerOrigin() {
  const url = env('NURI_ARKADE_SIGNER_URL').replace(/\/+$/, '');
  if (!url) throw new Error('NURI_ARKADE_SIGNER_URL is required for the Bitcoin wallet');
  return url.replace(/\/v4$/i, '');
}
function signerV4() { return `${signerOrigin()}/v4`; }
function nodeUrl() { return env('NURI_ARKADE_NODE_URL', 'https://arkade.computer').replace(/\/+$/, ''); }
function python() { return env('REAL_CARD_COSIGN_PYTHON', 'scripts/run-card-python.sh'); }
function claimSigner() { return env('NURI_CARD_CLAIM_SIGNER', 'scripts/card-arkade-claim-signer.py'); }
function statusScript() { return env('NURI_CARD_STATUS_SCRIPT', 'scripts/musig2-card-status.py'); }
function prfScript() { return env('NURI_CARD_PRF_SCRIPT', 'scripts/card-prf-backup.py'); }

// Profile names the card's FIDO2 credential + rp/origin used for approval.
async function receiveProfile() {
  const name = env('NURI_CARD_RECEIVE_PROFILE');
  const path = env('NURI_CARD_RECEIVE_PROFILE_PATH');
  if (!name) throw new Error('NURI_CARD_RECEIVE_PROFILE is required');
  if (!path) throw new Error('NURI_CARD_RECEIVE_PROFILE_PATH is required');
  const profile = JSON.parse(await readFile(path, 'utf8'));
  if (profile?.schema !== 'nuri-card-prf-profile-v1') throw new Error(`${path} is not a nuri-card-prf-profile-v1 profile`);
  for (const field of ['credential_id', 'credential_public_key_spki_b64u', 'rp_id', 'origin']) {
    if (!String(profile[field] || '').trim()) throw new Error(`card receive profile has no ${field}`);
  }
  return { name, profile };
}

function readCardStatus() {
  return execFileJson(python(), [statusScript()]);
}

async function readCardPk33() {
  const status = await readCardStatus();
  const pk = String(status.card_pk33 || '').toLowerCase();
  if (!/^0[23][0-9a-f]{64}$/.test(pk)) throw new Error('card returned an invalid MuSig2 public key');
  return pk;
}

// 2-of-2 aggregate -> Arkade address (version 0 || server pk || tweaked vtxo key)
function arkAddressFor(vtxoTaprootKey32, serverPk32, hrp) {
  const data = new Uint8Array(1 + 32 + 32);
  data.set(serverPk32, 1);
  data.set(vtxoTaprootKey32, 33);
  return bech32m.encode(hrp, bech32m.toWords(data), 1023);
}

// Onchain fallback: p2tr(internal = musig2(client, server), leaf = client CSV).
// Same shape as scripts/nuri-card-wallet.mjs:nuriDerive, client = the card.
function onchainAddress(cardPk33, serverPk33, network) {
  const sorted = musig2.sortKeys([hexToBytes(cardPk33), hexToBytes(serverPk33)]);
  const aggComp = musig2.keyAggExport(musig2.keyAggregate(sorted));
  const Px = aggComp.length === 33 ? aggComp.slice(1) : aggComp;
  const cardXOnly = hexToBytes(cardPk33).slice(1);
  const leaf = { script: btc.Script.encode([cardXOnly, 'CHECKSIGVERIFY', CSV_BLOCKS, 'CHECKSEQUENCEVERIFY']), leafVersion: 0xc0 };
  return btc.p2tr(Px, [leaf], network.btc, true).address;
}

function digestOf(summary) {
  return '0x' + createHash('sha256').update(JSON.stringify(summary)).digest('hex');
}

async function serverPubkey(cardPk33) {
  const url = new URL(`${signerV4()}/arkade/info`);
  url.searchParams.set('client_pk33', cardPk33);
  const res = await fetch(url, { cache: 'no-store' });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Nuri Arkade info HTTP ${res.status}`);
  const pk = body?.server_pubkey || body?.server_pubkey33;
  if (!/^0[23][0-9a-f]{64}$/i.test(String(pk || ''))) throw new Error('Nuri Arkade info returned no usable server public key');
  return String(pk).toLowerCase();
}

async function openWallet(cfg, identity) {
  return Wallet.create({
    identity,
    arkProvider: new RestArkProvider(cfg.nodeUrl),
    indexerProvider: new RestIndexerProvider(cfg.nodeUrl),
    storage: {
      walletRepository: new InMemoryWalletRepository(),
      contractRepository: new InMemoryContractRepository(),
    },
    settlementConfig: false,
  });
}

// stdin carries newline-delimited JSON: the config first, the approval decision
// later. The caller keeps the pipe open across both, so we must not wait for EOF.
let stdinBuffer = '';
let stdinWaiter = null;
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  stdinBuffer += chunk;
  if (stdinWaiter && stdinBuffer.includes('\n')) {
    const waiter = stdinWaiter;
    stdinWaiter = null;
    waiter();
  }
});
function readJsonLine(what) {
  return new Promise((resolve, reject) => {
    const take = () => {
      const nl = stdinBuffer.indexOf('\n');
      if (nl === -1) return false;
      const line = stdinBuffer.slice(0, nl);
      stdinBuffer = stdinBuffer.slice(nl + 1);
      try { resolve(JSON.parse(line)); } catch (error) { reject(new Error(`bad ${what} line: ${error.message}`)); }
      return true;
    };
    if (take()) return;
    stdinWaiter = take;
  });
}
const readDecision = () => readJsonLine('decision');

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

// --- modes -------------------------------------------------------------------
async function modeInfo(cfg) {
  const status = await readCardStatus();
  const cardPk33 = String(status.card_pk33 || '').toLowerCase();
  if (!/^0[23][0-9a-f]{64}$/.test(cardPk33)) throw new Error('card returned an invalid MuSig2 public key');
  const serverPk33 = await serverPubkey(cardPk33);
  const net = NETWORKS[cfg.network];
  if (!net) throw new Error(`unknown network ${cfg.network}`);
  const identity = readOnlyIdentity(cardPk33, serverPk33);
  const wallet = await openWallet(cfg, identity);
  const [arkAddress, boardingAddress] = await Promise.all([wallet.getAddress(), wallet.getBoardingAddress()]);
  const aggregate33 = bytesToHex(identity.aggregatedPk33);
  return {
    status: 'NURI_CARD_BITCOIN_INFO_OK',
    network: cfg.network,
    card_pubkey33: cardPk33,
    server_pubkey33: serverPk33,
    aggregate_pubkey33: aggregate33,
    ark_address: arkAddress,
    boarding_address: boardingAddress,
    onchain_address: onchainAddress(cardPk33, serverPk33, net),
    card_applet: status.version,
    card_capabilities: status.capabilities,
    card_pin_required: status.pin_required,
    pin_set: status.pin_set,
    pin_tries_left: status.pin_tries_left,
    reader: status.reader,
  };
}

// Read-only identity: no card session is needed to derive addresses or balances.
function readOnlyIdentity(cardPk33, serverPk33) {
  return new CardBackedAggregateIdentity({
    cardPk33,
    serverPk33,
    cardSign: () => { throw new Error('read-only'); },
    approve: () => { throw new Error('read-only'); },
  });
}

async function modeBalance(cfg, ctx) {
  const status = await readCardStatus();
  const cardPk33 = String(status.card_pk33 || '').toLowerCase();
  if (!/^0[23][0-9a-f]{64}$/.test(cardPk33)) throw new Error('card returned an invalid MuSig2 public key');
  const serverPk33 = await serverPubkey(cardPk33);
  const identity = readOnlyIdentity(cardPk33, serverPk33);
  const wallet = await openWallet(cfg, identity);
  const [arkAddress, boardingAddress, balance] = await Promise.all([
    wallet.getAddress(),
    wallet.getBoardingAddress(),
    wallet.getBalance(),
  ]);
  return {
    status: 'NURI_CARD_BITCOIN_BALANCE_OK',
    network: cfg.network,
    aggregate_pubkey33: bytesToHex(identity.aggregatedPk33),
    ark_address: arkAddress,
    boarding_address: boardingAddress,
    // Every rail, so the caller can lead with the total: VTXOs + boarding + onchain.
    vtxo_sats: Number(balance?.available ?? 0),
    settled_sats: Number(balance?.settled ?? 0),
    boarding_sats: Number(balance?.boarding?.total ?? 0),
    onchain_address: onchainAddress(cardPk33, serverPk33, NETWORKS[cfg.network]),
    total_ark_and_boarding_sats: Number(balance?.available ?? 0) + Number(balance?.boarding?.total ?? 0),
  };
}

async function modeInvoice(cfg, ctx) {
  if (!Number.isInteger(cfg.amount_sats) || cfg.amount_sats <= 0) throw new Error('amount_sats must be a positive integer');
  if (!cfg.memo) throw new Error('memo is required');
  const { profile, name } = await receiveProfile();
  const owner = {
    cred_id_b64u: profile.credential_id,
    cred_pubkey_b64u: profile.credential_public_key_spki_b64u,
    client_public_key_33_hex: cfg.cardPk33,
    rp_id: profile.rp_id,
    origin: profile.origin,
    profile: name,
  };
  const auth = await postJson(`${signerV4()}/arkade/auth`, {
    cred_id_b64u: owner.cred_id_b64u,
    cred_pubkey_b64u: owner.cred_pubkey_b64u,
    client_signer_pubkey: cfg.cardPk33,
  });
  const created = await postJson(`${signerOrigin()}/api/arkade/receive/invoice`, {
    ...owner,
    amount_sats: cfg.amount_sats,
    memo: cfg.memo,
  });
  if (created.ok !== true || !created.invoice) throw new Error(`receive invoice returned malformed response: ${JSON.stringify(created).slice(0, 300)}`);
  return {
    status: 'NURI_CARD_LIGHTNING_INVOICE_CREATED',
    invoice: created.invoice,
    payment_hash: created.payment_hash_hex || null,
    swap_id: created.swap_id || null,
    expires_at_ms: created.expires_at_ms || null,
    amount_sats: cfg.amount_sats,
    server_pubkey33: auth?.registered?.server_pubkey || cfg.serverPk33,
  };
}

// Lightning: Ark -> Lightning submarine swap (lockup funded by the card spend).
async function fundLightning(cfg, wallet, swaps) {
  const pending = await swaps.createSubmarineSwap({ invoice: cfg.target });
  const lockup = pending.response.address;
  const fundingAmount = pending.response.expectedAmount;
  if (!lockup || !fundingAmount) throw new Error(`submarine swap missing lockup/amount: ${JSON.stringify(pending.response)}`);
  const decoded = ArkAddress.decode(lockup);
  const lockupPkScript = typeof decoded.pkScript === 'function' ? decoded.pkScript() : decoded.pkScript;
  const paymentHash = getInvoicePaymentHash(cfg.target);
  const finalAmount = getInvoiceSatoshis(cfg.target);
  const intent = await postJson(`${signerV4()}/arkade/swap-intent/create`, {
    kind: 'lightning_invoice',
    cred_id_b64u: cfg.credId,
    client_signer_pubkey: cfg.cardPk33,
    final_recipient: cfg.target,
    final_amount_sats: finalAmount,
    funding_address: lockup,
    funding_script_hex: bytesToHex(lockupPkScript),
    funding_amount_sats: fundingAmount,
    payment_hash: paymentHash,
    invoice: cfg.target,
  });
  const intentId = intent?.intent?.id;
  if (!intentId) throw new Error(`swap-intent/create failed: ${JSON.stringify(intent).slice(0, 300)}`);
  cfg.sendState = {
    kind: 'lightning_invoice',
    send_intent_id: intentId,
    final_recipient: cfg.target,
    final_amount_sats: finalAmount,
    funding_address: lockup,
    funding_script_hex: bytesToHex(lockupPkScript),
    funding_amount_sats: fundingAmount,
    payment_hash: paymentHash,
    invoice: cfg.target,
  };
  return { address: lockup, amount: fundingAmount, swap: pending, finalAmount, paymentHash, intentId };
}

async function modeSend(cfg, ctx) {
  const kind = String(cfg.kind || '');
  if (!['lightning', 'ark'].includes(kind)) throw new Error(`unsupported send kind ${kind}`);
  if (cfg.kind === 'ark') {
    if (!cfg.amount_sats || !Number.isInteger(cfg.amount_sats) || cfg.amount_sats <= 0) throw new Error('amount_sats must be a positive integer');
    const decoded = ArkAddress.decode(cfg.target);
    const pkScript = typeof decoded.pkScript === 'function' ? decoded.pkScript() : decoded.pkScript;
    cfg.sendState = undefined;
    cfg.destinationScriptHex = bytesToHex(pkScript);
  }

  const wallet = await openWallet(cfg, ctx.identity);
  let swaps = null;
  let funding = null;
  if (kind === 'lightning') {
    if (cfg.boltzNetwork !== 'bitcoin') throw new Error('boltzNetwork must be bitcoin');
    swaps = await ArkadeSwaps.create({
      wallet,
      swapProvider: new BoltzSwapProvider({ network: cfg.boltzNetwork }),
      swapRepository: new InMemorySwapRepository(),
      swapManager: false,
    });
    funding = await fundLightning(cfg, wallet, swaps);
  }

  const destination = kind === 'lightning' ? funding.address : cfg.target;
  const amount = kind === 'lightning' ? funding.amount : cfg.amount_sats;

  let previewed = null;
  const identity = ctx.identity;
  identity._onPlan = async (plan) => {
    previewed = plan;
    emit({ phase: 'preview', summary: ctx.summary, digest: ctx.digest, psbt_b64: plan.psbtB64 });
    const decision = await readDecision();
    if (decision?.digest && decision.digest !== ctx.digest) throw new Error(`approval digest ${decision.digest} != preview ${ctx.digest}`);
    ctx.approved = decision?.approved === true;
    if (ctx.approved) {
      // PIN reaches the card drivers through the child env only, never argv.
      if (!decision?.pin) throw new Error('card PIN is required to spend');
      cfg.pin = decision.pin;
    }
    return { proceed: ctx.approved };
  };

  const funded = kind === 'lightning'
    ? swaps.waitForSwapFunded(funding.swap).then(() => ({ ok: true }), (error) => ({ ok: false, error }))
    : Promise.resolve({ ok: true });

  let txid;
  try {
    txid = await wallet.send({ address: destination, amount });
  } catch (error) {
    if (error instanceof PreviewSignal) return { phase: 'cancelled', digest: ctx.digest, summary: ctx.summary };
    throw error;
  }

  if (kind === 'lightning') {
    const complete = await postJson(`${signerOrigin()}/api/arkade/send/complete`, {
      challenge_token: ctx.session()?.challenge_token,
      send_intent_id: funding.intentId,
      txid,
    });
    const settled = await funded;
    if (!settled.ok) throw new Error(`swap funding monitor failed: ${settled.error?.message || settled.error}`);
    return {
      status: 'NURI_CARD_BITCOIN_SEND_OK',
      kind,
      ark_txid: txid,
      swap_id: funding.swap.id,
      funding_sats: funding.amount,
      final_sats: funding.finalAmount,
      payment_hash: funding.paymentHash,
      ark_address: await wallet.getAddress(),
      complete,
      approved_digest: ctx.digest,
      sign_requests: previewed?.signRequests?.length ?? 0,
    };
  }
  return {
    status: 'NURI_CARD_BITCOIN_SEND_OK',
    kind,
    ark_txid: txid,
    destination: cfg.target,
    amount_sats: amount,
    ark_address: await wallet.getAddress(),
    approved_digest: ctx.digest,
    sign_requests: previewed?.signRequests?.length ?? 0,
  };
}

// --- entry -------------------------------------------------------------------
async function main() {
  const cfg = await readJsonLine('config');
  cfg.network = cfg.network || 'mainnet';
  cfg.nodeUrl = nodeUrl();

  if (cfg.mode === 'info') return modeInfo(cfg);
  if (cfg.mode === 'balance') return modeBalance(cfg, {});
  if (cfg.mode === 'invoice') {
    // The receive owner is identified by the card's own MuSig2 key.
    cfg.cardPk33 = await readCardPk33();
    return modeInvoice(cfg, {});
  }

  // send: the card pubkey and live server key must exist before anything else.
  const cardPk33 = cfg.cardPk33 ? String(cfg.cardPk33).toLowerCase() : await readCardPk33();
  const serverPk33 = cfg.serverPk33 || await serverPubkey(cardPk33);
  const identity = new CardBackedAggregateIdentity({
    cardPk33,
    serverPk33,
    cardSign: (msg32, session, index) => pythonSendCosign(cfg, msg32, session, index),
    approve: (plan) => prepareNuriSend(cfg, plan),
  });
  const aggregate33 = bytesToHex(identity.aggregatedPk33);
  if (cfg.aggregate_pubkey33 && cfg.aggregate_pubkey33.toLowerCase() !== aggregate33) {
    throw new Error(`aggregate ${aggregate33} does not match the displayed wallet ${cfg.aggregate_pubkey33}`);
  }
  if (cfg.kind === 'lightning') {
    const summary = {
      kind: 'lightning',
      destination: cfg.target,
      amount_sats: cfg.amount_sats ?? null,
      payment_hash: getInvoicePaymentHash(cfg.target),
      aggregate_pubkey33: aggregate33,
      network: cfg.network,
    };
    const digest = digestOf(summary);
    return modeSend(cfg, { identity, summary, digest, session: sendSession });
  }
  const summary = {
    kind: 'ark',
    destination: cfg.target,
    amount_sats: cfg.amount_sats,
    aggregate_pubkey33: aggregate33,
    network: cfg.network,
  };
  const digest = digestOf(summary);
  return modeSend(cfg, { identity, summary, digest, session: sendSession });
}

main().then((out) => {
  if (out?.phase === 'cancelled') { emit(out); process.exit(0); }
  emit({ phase: 'result', ...out });
  process.exit(0);
}).catch((error) => {
  emit({ phase: 'error', error: error.message });
  process.exit(1);
});
