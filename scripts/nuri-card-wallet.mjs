#!/usr/bin/env node
// Nuri smartcard wallet: stable musig2(client,card)+CSV Taproot address backed
// by the physical card. Real addresses, real UTXOs, real key-path spend.
//
//   nuri-card-wallet.mjs address  [--network=signet|mainnet]
//   nuri-card-wallet.mjs utxos    [--network=signet]
//   nuri-card-wallet.mjs spend    --network=signet --to=<addr|self> --amount-sats=N --fee-sats=N [--broadcast]
//
// Default network is signet (free, safe). Switch to mainnet once the flow is proven.
import { randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import process from 'node:process';
import { execFile } from 'node:child_process';
import { SigHash, Transaction } from '@scure/btc-signer';
import * as btc from '@scure/btc-signer';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils';
import { bech32m } from '@scure/base';

const PY = process.env.REAL_CARD_COSIGN_PYTHON || '/private/tmp/nuri-fido2-real-card-venv/bin/python';
const TWEAKED = process.env.REAL_CARD_TWEAKED_SCRIPT || 'scripts/card-cosign-tweaked.py';
const CSV_BLOCKS = 52500;
const WALLET_DIR = '.nuri-card-wallet';

const NETWORKS = {
  signet: { hrp: 'tb', btc: btc.TEST_NETWORK, explorer: 'https://mempool.space/signet/api' },
  mainnet: { hrp: 'bc', btc: btc.NETWORK, explorer: 'https://mempool.space/api' },
};

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

// Nuri Taproot derivation: internal = musig2(client,card); one client CSV leaf.
function nuriDerive(clientPk33Hex, cardPk33Hex, network) {
  const sorted = musig2.sortKeys([hexToBytes(clientPk33Hex), hexToBytes(cardPk33Hex)]);
  const aggComp = musig2.keyAggExport(musig2.keyAggregate(sorted));
  const Px = aggComp.length === 33 ? aggComp.slice(1) : aggComp;
  const userXOnly = hexToBytes(clientPk33Hex).slice(1);
  const leaf = { script: btc.Script.encode([userXOnly, 'CHECKSIGVERIFY', CSV_BLOCKS, 'CHECKSEQUENCEVERIFY']), leafVersion: 0xc0 };
  const p2tr = btc.p2tr(Px, [leaf], network.btc, true);
  const outputXOnly = bytesToHex(p2tr.script.slice(2));
  const words = bech32m.toWords(hexToBytes(outputXOnly));
  words.unshift(0x01); // witness v0
  const address = bech32m.encode(network.hrp, words);
  return { outputXOnly, address, scriptPubKey: bytesToHex(p2tr.script) };
}

async function execPy(args) {
  return new Promise((res, rej) => {
    execFile(PY, args, { cwd: process.cwd(), timeout: 120000, maxBuffer: 1 << 20 }, (err, out, errout) => {
      if (err) return rej(new Error(`${err.message}\n${errout || out}`.trim()));
      try { res(JSON.parse(out)); } catch (e) { rej(new Error(`bad JSON: ${e.message}\n${out}`)); }
    });
  });
}

function profilePath(network) { return resolve(WALLET_DIR, `${network}.json`); }

async function loadProfile(network) {
  try { return JSON.parse(await readFile(profilePath(network), 'utf8')); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}
async function saveProfile(network, p) {
  await mkdir(dirname(resolve(profilePath(network))), { recursive: true });
  await writeFile(profilePath(network), JSON.stringify(p, null, 2) + '\n');
}

async function fetchJson(url) {
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error(`HTTP ${r.status} for ${url}`);
  return r.json();
}

// Provision a stable Nuri wallet identity for this network: stable client key,
// tap the card once to read client/card pubkeys + tweaked output key.
async function commandAddress(args) {
  const net = NETWORKS[args.network];
  let profile = await loadProfile(args.network);
  let clientSecretHex = profile?.client_secret_hex || bytesToHex(randomBytes(32));
  // Tap the card to get the authoritative pubkeys + output key for this client key.
  const r = await execPy([TWEAKED, '--client-secret-hex', clientSecretHex, '--msg32', bytesToHex(randomBytes(32))]);
  if (r.status !== 'REAL_CARD_TWEAKED_COSIGN_OK') throw new Error(`card cosign failed: ${JSON.stringify(r)}`);
  const nuri = nuriDerive(r.client_pk33, r.card_pk33, net);
  if (nuri.outputXOnly !== r.tweaked_output_xonly32) {
    throw new Error(`output key mismatch: node ${nuri.outputXOnly} vs card ${r.tweaked_output_xonly32}`);
  }
  profile = {
    network: args.network,
    client_secret_hex: clientSecretHex,
    client_pk33: r.client_pk33,
    card_pk33: r.card_pk33,
    output_xonly32: r.tweaked_output_xonly32,
    address: nuri.address,
    scriptPubKey: nuri.scriptPubKey,
    csv_blocks: CSV_BLOCKS,
    created_at: profile?.created_at || new Date().toISOString(),
    warning: 'Demo client key in a local file. Production client keys should come from the Nuri passkey PRF, not this file.',
  };
  await saveProfile(args.network, profile);
  console.log(JSON.stringify(profile, null, 2));
}

async function commandUtxos(args) {
  const profile = await loadProfile(args.network);
  if (!profile) throw new Error(`no wallet profile for ${args.network}; run "address" first`);
  const net = NETWORKS[args.network];
  const list = await fetchJson(`${net.explorer}/address/${profile.address}/utxo`);
  console.log(JSON.stringify({ ...profile, utxos: list }, null, 2));
}

async function commandSpend(args) {
  const profile = await loadProfile(args.network);
  if (!profile) throw new Error(`no wallet profile for ${args.network}; run "address" first`);
  const net = NETWORKS[args.network];
  const sourceScript = hexToBytes(profile.scriptPubKey);
  // Pick UTXO
  let utxo = args.utxo ? parseUtxo(args.utxo) : null;
  if (!utxo) {
    const list = await fetchJson(`${net.explorer}/address/${profile.address}/utxo`);
    const avail = list.filter((u) => args.includeUnconfirmed || u.status?.confirmed).sort((a, b) => b.value - a.value);
    if (!avail.length) throw new Error(`no confirmed UTXO for ${profile.address}; fund it first (or --include-unconfirmed)`);
    utxo = avail[0];
  }
  const inputValue = BigInt(utxo.value);
  if (inputValue <= args.feeSats) throw new Error(`UTXO value ${inputValue} <= fee ${args.feeSats}`);
  const toAddress = args.to === 'self' ? profile.address : args.to;
  const sendValue = args.amountSats === null ? inputValue - args.feeSats : BigInt(args.amountSats);
  const changeValue = inputValue - args.feeSats - sendValue;
  if (sendValue <= 0n) throw new Error('send value must be positive');
  if (changeValue < 0n) throw new Error(`insufficient: have ${inputValue}, need ${sendValue + args.feeSats}`);

  const tx = new Transaction({ version: 2, allowUnknownOutputs: true });
  tx.addInput({ txid: utxo.txid, index: utxo.vout, witnessUtxo: { amount: inputValue, script: sourceScript } });
  tx.addOutputAddress(toAddress, sendValue, net.btc);
  if (changeValue >= 330n) tx.addOutputAddress(profile.address, changeValue, net.btc);

  const msg32 = bytesToHex(tx.preimageWitnessV1(0, [sourceScript], SigHash.DEFAULT, [inputValue]));
  // Sign with the physical card: tweaked cosign using the STABLE client key.
  const r = await execPy([TWEAKED, '--client-secret-hex', profile.client_secret_hex, '--msg32', msg32]);
  if (r.status !== 'REAL_CARD_TWEAKED_COSIGN_OK') throw new Error(`card sign failed: ${JSON.stringify(r)}`);
  const sig = hexToBytes(r.final_signature64);
  if (!schnorr.verify(sig, hexToBytes(msg32), hexToBytes(profile.output_xonly32))) {
    throw new Error('local BIP340 verification failed');
  }
  tx.updateInput(0, { tapKeySig: sig }, true);
  tx.finalize();
  const rawTx = tx.hex;
  const result = {
    status: 'NURI_CARD_TX_READY',
    network: args.network,
    source_address: profile.address,
    destination_address: toAddress,
    utxo: `${utxo.txid}:${utxo.vout}`,
    input_sats: Number(inputValue),
    send_sats: Number(sendValue),
    change_sats: Number(changeValue),
    fee_sats: args.feeSats,
    raw_tx_hex: rawTx,
  };
  if (!args.broadcast) {
    result.next_step = 'Review raw_tx_hex, then re-run with --broadcast';
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  const resp = await fetch(`${net.explorer}/tx`, { method: 'POST', body: rawTx });
  const text = await resp.text();
  result.broadcast = resp.ok ? { txid: text.trim() } : { http_status: resp.status, body: text };
  console.log(JSON.stringify(result, null, 2));
}

function parseUtxo(s) {
  const [txid, vout, value] = s.split(':');
  if (!txid || vout === undefined || value === undefined) throw new Error('--utxo=<txid:vout:value>');
  return { txid, vout: Number(vout), value: Number(value) };
}

const args = parseArgs(process.argv.slice(2));
if (!['address', 'utxos', 'spend'].includes(args.command)) {
  console.error('Usage: nuri-card-wallet.mjs <address|utxos|spend> [--network=signet|mainnet] [--to=] [--amount-sats=] [--fee-sats=] [--broadcast] [--include-unconfirmed] [--utxo=txid:vout:value]');
  process.exit(1);
}
if (args.command === 'spend' && !args.to) { console.error('spend needs --to=<address|self>'); process.exit(1); }
try {
  if (args.command === 'address') await commandAddress(args);
  else if (args.command === 'utxos') await commandUtxos(args);
  else if (args.command === 'spend') await commandSpend(args);
} catch (e) {
  console.error(`error: ${e.message}`);
  process.exit(1);
}
