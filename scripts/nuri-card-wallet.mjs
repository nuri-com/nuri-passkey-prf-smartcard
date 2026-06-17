#!/usr/bin/env node
// Nuri smartcard wallet: stable musig2(client,card)+CSV Taproot address backed
// by the physical card. Real addresses, real UTXOs, real key-path spend.
//
// CLI:
//   nuri-card-wallet.mjs address  [--network=signet|mainnet]
//   nuri-card-wallet.mjs utxos    [--network=signet|mainnet]
//   nuri-card-wallet.mjs spend    --network=signet --to=<addr|self> --amount-sats=N --fee-sats=N [--broadcast]
//
// The exported functions are also imported by scripts/card-mcp-server.mjs so the
// MCP exposes the same wallet operations (single source of truth for tx building).
import { randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';
import { execFile } from 'node:child_process';
import { SigHash, Transaction } from '@scure/btc-signer';
import * as btc from '@scure/btc-signer';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils';
import { bech32m } from '@scure/base';

export const PY = process.env.REAL_CARD_COSIGN_PYTHON || '/private/tmp/nuri-fido2-real-card-venv/bin/python';
export const TWEAKED = process.env.REAL_CARD_TWEAKED_SCRIPT || 'scripts/card-cosign-tweaked.py';
export const PRF_SCRIPT = process.env.NURI_CARD_PRF_SCRIPT || 'scripts/card-prf-backup.py';
export const CSV_BLOCKS = 52500;
const WALLET_DIR = '.nuri-card-wallet';
// The client key is derived from the card's FIDO2 PRF — nothing secret is stored.
// These name+salt pick WHICH passkey credential and salt feed into HKDF->secp256k1.
export const DEFAULT_PRF_PROFILE = process.env.NURI_WALLET_PRF_PROFILE || 'wallet-client';
export const DEFAULT_PRF_SALT = process.env.NURI_WALLET_PRF_SALT || 'nuri-wallet-client-key-v1';

export const NETWORKS = {
  signet: { hrp: 'tb', btc: btc.TEST_NETWORK, explorer: 'https://mempool.space/signet/api' },
  mainnet: { hrp: 'bc', btc: btc.NETWORK, explorer: 'https://mempool.space/api' },
};

// Nuri Taproot derivation: internal = musig2(client,card); one client CSV leaf.
export function nuriDerive(clientPk33Hex, cardPk33Hex, network) {
  const sorted = musig2.sortKeys([hexToBytes(clientPk33Hex), hexToBytes(cardPk33Hex)]);
  const aggComp = musig2.keyAggExport(musig2.keyAggregate(sorted));
  const Px = aggComp.length === 33 ? aggComp.slice(1) : aggComp;
  const userXOnly = hexToBytes(clientPk33Hex).slice(1);
  const leaf = { script: btc.Script.encode([userXOnly, 'CHECKSIGVERIFY', CSV_BLOCKS, 'CHECKSEQUENCEVERIFY']), leafVersion: 0xc0 };
  const p2tr = btc.p2tr(Px, [leaf], network.btc, true);
  const outputXOnly = bytesToHex(p2tr.script.slice(2));
  const words = bech32m.toWords(hexToBytes(outputXOnly));
  words.unshift(0x01);
  const address = bech32m.encode(network.hrp, words);
  return { outputXOnly, address, scriptPubKey: bytesToHex(p2tr.script) };
}

export function execPy(args) {
  return new Promise((res, rej) => {
    execFile(PY, args, { cwd: process.cwd(), timeout: 120000, maxBuffer: 1 << 20 }, (err, out, errout) => {
      if (err) return rej(new Error(`${err.message}\n${errout || out}`.trim()));
      try { res(JSON.parse(out)); } catch (e) { rej(new Error(`bad JSON: ${e.message}\n${out}`)); }
    });
  });
}

// Derive the CLIENT private-key seed from the card's FIDO2 passkey PRF.
// Nothing secret is stored: the PRF output is recomputed from the card every
// call, HKDF-stretched to 32 bytes, and used as the secp256k1 client secret.
// card-cosign-tweaked.py normalizes it to even-y internally, so the raw seed is fine.
export function derivePrfSeed(prfProfile = DEFAULT_PRF_PROFILE, salt = DEFAULT_PRF_SALT) {
  return new Promise((res, rej) => {
    execFile(PY, [PRF_SCRIPT, 'derive', '--profile', prfProfile, '--salt', salt, '--raw'],
      { cwd: process.cwd(), timeout: 60000, maxBuffer: 1 << 20 }, (err, out, errout) => {
      if (err) return rej(new Error(`PRF derive failed: ${err.message}\n${errout || out}`.trim()));
      const hex = out.trim();
      if (!/^[0-9a-f]{64}$/.test(hex)) return rej(new Error(`PRF derive returned bad output: ${hex.slice(0, 80)}`));
      res(hex);
    });
  });
}

export function profilePath(network) { return resolve(WALLET_DIR, `${network}.json`); }
export async function loadProfile(network) {
  try { return JSON.parse(await readFile(profilePath(network), 'utf8')); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}
export async function saveProfile(network, p) {
  await mkdir(dirname(resolve(profilePath(network))), { recursive: true });
  await writeFile(profilePath(network), JSON.stringify(p, null, 2) + '\n');
}

export async function fetchJson(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(`HTTP ${r.status} for ${url}`);
  return r.json();
}
export async function fetchUtxos(address, networkName) {
  const net = NETWORKS[networkName];
  return fetchJson(`${net.explorer}/address/${address}/utxo`);
}

// Tap the card with a client key to read authoritative pubkeys + output key and
// persist a stable wallet profile for the network.
// persist a stable wallet profile for the network. The CLIENT key is derived
// from the card's FIDO2 PRF every call; nothing secret is stored.
export async function provisionAddress(networkName, opts = {}) {
  const net = NETWORKS[networkName];
  if (!net) throw new Error(`unknown network: ${networkName}`);
  const existing = await loadProfile(networkName);
  const prfProfile = opts.prfProfile || existing?.client_prf_profile || DEFAULT_PRF_PROFILE;
  const prfSalt = opts.prfSalt || existing?.client_prf_salt || DEFAULT_PRF_SALT;
  const seedHex = await derivePrfSeed(prfProfile, prfSalt);
  const r = await execPy([TWEAKED, '--client-secret-hex', seedHex, '--msg32', bytesToHex(randomBytes(32))]);
  if (r.status !== 'REAL_CARD_TWEAKED_COSIGN_OK') throw new Error(`card cosign failed: ${JSON.stringify(r)}`);
  const nuri = nuriDerive(r.client_pk33, r.card_pk33, net);
  if (nuri.outputXOnly !== r.tweaked_output_xonly32) {
    throw new Error(`output key mismatch: node ${nuri.outputXOnly} vs card ${r.tweaked_output_xonly32}`);
  }
  const profile = {
    network: networkName,
    key_origin: 'client=card_fido2_prf__cosigner=card_musig2',
    client_prf_profile: prfProfile,
    client_prf_salt: prfSalt,
    client_pk33: r.client_pk33,
    card_pk33: r.card_pk33,
    output_xonly32: r.tweaked_output_xonly32,
    address: nuri.address,
    scriptPubKey: nuri.scriptPubKey,
    csv_blocks: CSV_BLOCKS,
    created_at: existing?.created_at || new Date().toISOString(),
    note: 'Client key is re-derived from the card FIDO2 PRF on every spend. No secret is stored. Losing the card (or its PRF credential) locks funds until the CSV window (52500 blocks).',
  };
  await saveProfile(networkName, profile);
  return profile;
}

export function parseUtxo(s) {
  const [txid, vout, value] = s.split(':');
  if (!txid || vout === undefined || value === undefined) throw new Error('--utxo=<txid:vout:value>');
  return { txid, vout: Number(vout), value: Number(value) };
}

// Build + sign a real key-path Taproot spend with the physical card.
// Defaults to DRY-RUN (no broadcast). Returns the tx + status.
export async function buildAndSignSpend(networkName, opts) {
  const { to, amountSats = null, feeSats = 500, broadcast = false, utxo: utxoArg = null, includeUnconfirmed = false } = opts;
  const profile = await loadProfile(networkName);
  if (!profile) throw new Error(`no wallet profile for ${networkName}; provision an address first`);
  const net = NETWORKS[networkName];
  const sourceScript = hexToBytes(profile.scriptPubKey);

  let utxo = utxoArg ? parseUtxo(utxoArg) : null;
  if (!utxo) {
    const list = await fetchUtxos(profile.address, networkName);
    const avail = list.filter((u) => includeUnconfirmed || u.status?.confirmed).sort((a, b) => b.value - a.value);
    if (!avail.length) throw new Error(`no confirmed UTXO for ${profile.address}; fund it first (or includeUnconfirmed)`);
    utxo = avail[0];
  }
  const inputValue = BigInt(utxo.value);
  if (inputValue <= feeSats) throw new Error(`UTXO value ${inputValue} <= fee ${feeSats}`);
  const toAddress = to === 'self' ? profile.address : to;
  const sendValue = amountSats === null ? inputValue - BigInt(feeSats) : BigInt(amountSats);
  const changeValue = inputValue - BigInt(feeSats) - sendValue;
  if (sendValue <= 0n) throw new Error('send value must be positive');
  if (changeValue < 0n) throw new Error(`insufficient: have ${inputValue}, need ${sendValue + BigInt(feeSats)}`);

  const tx = new Transaction({ version: 2, allowUnknownOutputs: true });
  tx.addInput({ txid: utxo.txid, index: utxo.vout, witnessUtxo: { amount: inputValue, script: sourceScript } });
  tx.addOutputAddress(toAddress, sendValue, net.btc);
  if (changeValue >= 330n) tx.addOutputAddress(profile.address, changeValue, net.btc);

  const msg32 = bytesToHex(tx.preimageWitnessV1(0, [sourceScript], SigHash.DEFAULT, [inputValue]));
  const seedHex = await derivePrfSeed(profile.client_prf_profile, profile.client_prf_salt);
  const r = await execPy([TWEAKED, '--client-secret-hex', seedHex, '--msg32', msg32]);
  if (r.status !== 'REAL_CARD_TWEAKED_COSIGN_OK') throw new Error(`card sign failed: ${JSON.stringify(r)}`);
  const sig = hexToBytes(r.final_signature64);
  if (!schnorr.verify(sig, hexToBytes(msg32), hexToBytes(profile.output_xonly32))) {
    throw new Error('local BIP340 verification failed');
  }
  tx.updateInput(0, { tapKeySig: sig }, true);
  tx.finalize();

  const result = {
    status: broadcast ? 'NURI_CARD_TX_BROADCAST' : 'NURI_CARD_TX_READY',
    network: networkName,
    source_address: profile.address,
    destination_address: toAddress,
    utxo: `${utxo.txid}:${utxo.vout}`,
    input_sats: Number(inputValue),
    send_sats: Number(sendValue),
    change_sats: Number(changeValue),
    fee_sats: feeSats,
    raw_tx_hex: tx.hex,
    signature_verified_bip340: true,
  };
  if (!broadcast) {
    result.next_step = 'Review raw_tx_hex, then re-run with broadcast: true';
    return result;
  }
  const resp = await fetch(`${net.explorer}/tx`, { method: 'POST', body: tx.hex });
  const text = await resp.text();
  result.broadcast = resp.ok ? { txid: text.trim() } : { http_status: resp.status, body: text };
  return result;
}

// ---- CLI (only when invoked directly, not when imported by the MCP server) ----
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (isMain) {
  function parseArgs(argv) {
    const a = { network: 'signet', command: '', to: null, amountSats: null, feeSats: 500, utxo: null, includeUnconfirmed: false, broadcast: false };
    for (const arg of argv) {
      if (arg.startsWith('--network=')) a.network = arg.slice(10);
      else if (arg.startsWith('--to=')) a.to = arg.slice(5);
      else if (arg.startsWith('--amount-sats=')) a.amountSats = Number(arg.slice(13));
      else if (arg.startsWith('--fee-sats=')) a.feeSats = Number(arg.slice(11));
      else if (arg.startsWith('--utxo=')) a.utxo = arg.slice(7);
      else if (arg === '--include-unconfirmed') a.includeUnconfirmed = true;
      else if (arg === '--broadcast') a.broadcast = true;
      else if (!arg.startsWith('-') && !a.command) a.command = arg;
    }
    if (!NETWORKS[a.network]) throw new Error(`unknown network: ${a.network}`);
    return a;
  }

  try {
    const args = parseArgs(process.argv.slice(2));
    if (!['address', 'utxos', 'spend'].includes(args.command)) {
      console.error('Usage: nuri-card-wallet.mjs <address|utxos|spend> [--network=signet|mainnet] [--to=] [--amount-sats=] [--fee-sats=] [--broadcast] [--include-unconfirmed] [--utxo=txid:vout:value]');
      process.exit(1);
    }
    if (args.command === 'spend' && !args.to) { console.error('spend needs --to=<address|self>'); process.exit(1); }
    if (args.command === 'address') {
      console.log(JSON.stringify(await provisionAddress(args.network), null, 2));
    } else if (args.command === 'utxos') {
      const profile = await loadProfile(args.network);
      if (!profile) throw new Error(`no wallet profile for ${args.network}; run "address" first`);
      console.log(JSON.stringify({ ...profile, utxos: await fetchUtxos(profile.address, args.network) }, null, 2));
    } else if (args.command === 'spend') {
      console.log(JSON.stringify(await buildAndSignSpend(args.network, {
        to: args.to, amountSats: args.amountSats, feeSats: args.feeSats,
        broadcast: args.broadcast, utxo: args.utxo, includeUnconfirmed: args.includeUnconfirmed,
      }), null, 2));
    }
  } catch (e) {
    console.error(`error: ${e.message}`);
    process.exit(1);
  }
}
