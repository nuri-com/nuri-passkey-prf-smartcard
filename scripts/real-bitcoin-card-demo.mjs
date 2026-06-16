#!/usr/bin/env node
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import process from 'node:process';
import { bech32m } from '@scure/base';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { SigHash, Transaction } from '@scure/btc-signer';

const PROFILE = process.env.REAL_CARD_COSIGN_PROFILE || '.nuri-card-musig2/browser-real-card.json';
const REAL_CARD_PYTHON = process.env.REAL_CARD_COSIGN_PYTHON || '/private/tmp/nuri-fido2-real-card-venv/bin/python';
const REAL_CARD_SCRIPT = process.env.REAL_CARD_COSIGN_SCRIPT || 'scripts/real-card-cosign-proof.py';

const NETWORKS = {
  mainnet: {
    hrp: 'bc',
    explorer: 'https://mempool.space/api',
  },
  signet: {
    hrp: 'tb',
    explorer: 'https://mempool.space/signet/api',
  },
  testnet4: {
    hrp: 'tb',
    explorer: 'https://mempool.space/testnet4/api',
  },
  testnet: {
    hrp: 'tb',
    explorer: 'https://mempool.space/testnet/api',
  },
  regtest: {
    hrp: 'bcrt',
    explorer: null,
  },
};

function usage() {
  console.log(`Usage:
  node scripts/real-bitcoin-card-demo.mjs address [--network=signet|testnet4|testnet|regtest]
  node scripts/real-bitcoin-card-demo.mjs utxos [--network=signet|testnet4|testnet]
  node scripts/real-bitcoin-card-demo.mjs spend --network=signet --to=<address|self> [--amount-sats=1337] [--op-return=Nuri.com] [--utxo=<txid:vout:value>] [--fee-sats=500] [--include-unconfirmed] [--broadcast] [--wait-confirmation] [--verbose]
  node scripts/real-bitcoin-card-demo.mjs status --network=signet --txid=<txid> [--wait-confirmation] [--poll-seconds=30] [--max-polls=120] [--verbose]

Notes:
  - address/utxos are safe read-only commands.
  - spend signs with the physical card and builds a real Taproot key-path spend.
  - spend does not broadcast unless --broadcast is present.
  - --verbose writes human-readable progress logs to stderr while keeping stdout JSON parseable.
  - default spend target is self, meaning the same card Taproot address minus fee.`);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const args = {
    command,
    network: 'signet',
    to: 'self',
    utxo: '',
    feeSats: 500n,
    amountSats: null,
    opReturn: '',
    includeUnconfirmed: false,
    broadcast: false,
    waitConfirmation: false,
    pollSeconds: 30,
    maxPolls: 120,
    txid: '',
    verbose: false,
  };
  for (const arg of rest) {
    if (arg.startsWith('--network=')) args.network = arg.slice('--network='.length);
    else if (arg.startsWith('--to=')) args.to = arg.slice('--to='.length);
    else if (arg.startsWith('--utxo=')) args.utxo = arg.slice('--utxo='.length);
    else if (arg.startsWith('--fee-sats=')) args.feeSats = BigInt(arg.slice('--fee-sats='.length));
    else if (arg.startsWith('--amount-sats=')) args.amountSats = BigInt(arg.slice('--amount-sats='.length));
    else if (arg.startsWith('--op-return=')) args.opReturn = arg.slice('--op-return='.length);
    else if (arg.startsWith('--txid=')) args.txid = arg.slice('--txid='.length);
    else if (arg.startsWith('--poll-seconds=')) args.pollSeconds = Number(arg.slice('--poll-seconds='.length));
    else if (arg.startsWith('--max-polls=')) args.maxPolls = Number(arg.slice('--max-polls='.length));
    else if (arg === '--include-unconfirmed') args.includeUnconfirmed = true;
    else if (arg === '--broadcast') args.broadcast = true;
    else if (arg === '--wait-confirmation') args.waitConfirmation = true;
    else if (arg === '--verbose') args.verbose = true;
    else if (arg === '--help' || arg === '-h') {
      usage();
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!args.command || !['address', 'utxos', 'spend', 'status'].includes(args.command)) {
    usage();
    process.exit(args.command ? 1 : 0);
  }
  if (!NETWORKS[args.network]) throw new Error(`unknown network: ${args.network}`);
  if (args.amountSats !== null && args.amountSats <= 0n) throw new Error('--amount-sats must be positive');
  if (!Number.isSafeInteger(args.pollSeconds) || args.pollSeconds < 1) throw new Error('--poll-seconds must be a positive integer');
  if (!Number.isSafeInteger(args.maxPolls) || args.maxPolls < 1) throw new Error('--max-polls must be a positive integer');
  if (args.txid && !/^[0-9a-fA-F]{64}$/.test(args.txid)) throw new Error('--txid must be 32-byte hex');
  return args;
}

function logStep(args, message, details = null) {
  if (!args.verbose) return;
  const suffix = details ? ` ${JSON.stringify(details)}` : '';
  console.error(`[real-card-demo] ${new Date().toISOString()} ${message}${suffix}`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function p2trScript(outputKey32) {
  if (outputKey32.length !== 32) throw new Error('taproot output key must be 32 bytes');
  return new Uint8Array([0x51, 0x20, ...outputKey32]);
}

function p2trAddress(outputKey32, network) {
  const words = [1, ...bech32m.toWords(outputKey32)];
  return bech32m.encode(network.hrp, words);
}

function decodeP2trAddress(address, network) {
  const decoded = bech32m.decode(address);
  if (decoded.prefix !== network.hrp) {
    throw new Error(`address HRP mismatch: expected ${network.hrp}, got ${decoded.prefix}`);
  }
  const words = decoded.words;
  if (words[0] !== 1) throw new Error('only taproot v1 outputs are supported in this demo');
  const program = Uint8Array.from(bech32m.fromWords(words.slice(1)));
  if (program.length !== 32) throw new Error('taproot witness program must be 32 bytes');
  return p2trScript(program);
}

function opReturnScript(text) {
  const data = new TextEncoder().encode(text);
  if (data.length > 80) throw new Error('--op-return must be 80 bytes or less');
  if (data.length < 0x4c) return new Uint8Array([0x6a, data.length, ...data]);
  return new Uint8Array([0x6a, 0x4c, data.length, ...data]);
}

async function loadProfile() {
  const profile = JSON.parse(await readFile(PROFILE, 'utf8'));
  for (const field of ['aggregate_xonly32', 'card_pk33', 'client_pk33', 'client_secret_hex']) {
    if (!profile[field]) throw new Error(`${PROFILE} missing ${field}; run npm run cosign:web:real-card:selftest first`);
  }
  return profile;
}

function publicIdentity(profile, networkName) {
  const network = NETWORKS[networkName];
  const aggregate = hexToBytes(profile.aggregate_xonly32);
  const script = p2trScript(aggregate);
  return {
    network: networkName,
    card_pk33: profile.card_pk33,
    client_pk33: profile.client_pk33,
    aggregate_xonly32: profile.aggregate_xonly32,
    address: p2trAddress(aggregate, network),
    scriptPubKey: bytesToHex(script),
  };
}

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} returned ${res.status}: ${await res.text()}`);
  return await res.json();
}

async function fetchText(url, options) {
  const res = await fetch(url, options);
  const text = await res.text();
  if (!res.ok) throw new Error(`${url} returned ${res.status}: ${text}`);
  return text;
}

async function fetchUtxos(address, networkName) {
  const network = NETWORKS[networkName];
  if (!network.explorer) throw new Error(`${networkName} has no configured public explorer`);
  return await fetchJson(`${network.explorer}/address/${address}/utxo`);
}

async function fetchTxStatus(txid, networkName) {
  const network = NETWORKS[networkName];
  if (!network.explorer) throw new Error(`${networkName} has no configured public explorer`);
  return await fetchJson(`${network.explorer}/tx/${txid}/status`);
}

async function waitForTxStatus(args, txid) {
  for (let attempt = 1; attempt <= args.maxPolls; attempt += 1) {
    const status = await fetchTxStatus(txid, args.network);
    logStep(args, 'checked transaction status', {
      txid,
      attempt,
      confirmed: Boolean(status.confirmed),
      block_height: status.block_height || null,
    });
    if (status.confirmed || !args.waitConfirmation) return status;
    if (attempt < args.maxPolls) await sleep(args.pollSeconds * 1000);
  }
  throw new Error(`transaction ${txid} was not confirmed after ${args.maxPolls} polls`);
}

function parseUtxo(spec) {
  const [txid, voutRaw, valueRaw] = spec.split(':');
  if (!/^[0-9a-fA-F]{64}$/.test(txid || '')) throw new Error('--utxo txid must be 32-byte hex');
  const vout = Number(voutRaw);
  if (!Number.isSafeInteger(vout) || vout < 0) throw new Error('--utxo vout must be a non-negative integer');
  const value = BigInt(valueRaw);
  if (value <= 0n) throw new Error('--utxo value must be positive sats');
  return { txid, vout, value: Number(value) };
}

function execFileJson(file, args) {
  return new Promise((resolve, reject) => {
    execFile(file, args, {
      cwd: process.cwd(),
      timeout: 60000,
      maxBuffer: 1024 * 1024,
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`${error.message}\n${stderr || stdout}`.trim()));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch (parseError) {
        reject(new Error(`could not parse JSON from real-card script: ${parseError.message}\n${stdout}\n${stderr}`.trim()));
      }
    });
  });
}

async function cardSign(profile, msg32) {
  const result = await execFileJson(REAL_CARD_PYTHON, [
    REAL_CARD_SCRIPT,
    '--use-existing-card-key',
    '--client-secret-hex',
    profile.client_secret_hex,
    '--msg32',
    msg32,
  ]);
  if (result.card_pk33 !== profile.card_pk33) throw new Error('card public key changed');
  if (result.client_pk33 !== profile.client_pk33) throw new Error('client public key changed');
  if (result.aggregate_xonly32 !== profile.aggregate_xonly32) throw new Error('aggregate public key changed');
  if (!result.card_partial_verified || !result.final_signature_verified) {
    throw new Error(`card signature did not verify: ${JSON.stringify(result)}`);
  }
  return result;
}

async function commandAddress(args) {
  logStep(args, 'loading real-card MuSig2 profile', { profile: PROFILE });
  const profile = await loadProfile();
  const identity = publicIdentity(profile, args.network);
  logStep(args, 'derived public Taproot identity', {
    network: args.network,
    address: identity.address,
    aggregate_xonly32: identity.aggregate_xonly32,
  });
  console.log(JSON.stringify(identity, null, 2));
}

async function commandUtxos(args) {
  logStep(args, 'loading real-card MuSig2 profile', { profile: PROFILE });
  const profile = await loadProfile();
  const identity = publicIdentity(profile, args.network);
  logStep(args, 'fetching UTXOs', { network: args.network, address: identity.address });
  const utxos = await fetchUtxos(identity.address, args.network);
  logStep(args, 'fetched UTXOs', { count: utxos.length });
  console.log(JSON.stringify({ ...identity, utxos }, null, 2));
}

async function selectUtxo(args, address) {
  if (args.utxo) return parseUtxo(args.utxo);
  const utxos = await fetchUtxos(address, args.network);
  const available = utxos
    .filter((u) => args.includeUnconfirmed || !u.status || u.status.confirmed || u.status.block_height || u.status.block_hash)
    .sort((a, b) => b.value - a.value);
  if (!available.length) {
    throw new Error(`no ${args.includeUnconfirmed ? '' : 'confirmed '}UTXO found for ${address} on ${args.network}; fund the address first`);
  }
  return available[0];
}

async function commandSpend(args) {
  logStep(args, 'loading real-card MuSig2 profile', { profile: PROFILE });
  const profile = await loadProfile();
  const network = NETWORKS[args.network];
  if (!network.explorer && args.broadcast) throw new Error(`${args.network} has no configured broadcaster`);
  const identity = publicIdentity(profile, args.network);
  logStep(args, 'using card/client aggregate identity', {
    network: args.network,
    source_address: identity.address,
    card_pk33: identity.card_pk33,
    client_pk33: identity.client_pk33,
    aggregate_xonly32: identity.aggregate_xonly32,
  });
  const sourceScript = hexToBytes(identity.scriptPubKey);
  logStep(args, 'selecting spend UTXO', {
    explicit_utxo: Boolean(args.utxo),
    include_unconfirmed: args.includeUnconfirmed,
  });
  const utxo = await selectUtxo(args, identity.address);
  const inputValue = BigInt(utxo.value);
  if (inputValue <= args.feeSats) throw new Error(`UTXO ${utxo.txid}:${utxo.vout} value ${inputValue} is <= fee ${args.feeSats}`);
  const toAddress = args.to === 'self' ? identity.address : args.to;
  const destScript = decodeP2trAddress(toAddress, network);
  const sendValue = args.amountSats === null ? inputValue - args.feeSats : args.amountSats;
  const changeValue = inputValue - args.feeSats - sendValue;
  const outputCount = 1 + (args.opReturn ? 1 : 0) + (changeValue > 0n ? 1 : 0);
  if (sendValue <= 0n) throw new Error('send value must be positive');
  if (changeValue < 0n) {
    throw new Error(`UTXO value ${inputValue} is too small for amount ${sendValue} plus fee ${args.feeSats}`);
  }
  logStep(args, 'selected UTXO and outputs', {
    utxo: `${utxo.txid}:${utxo.vout}`,
    input_sats: Number(inputValue),
    send_sats: Number(sendValue),
    fee_sats: Number(args.feeSats),
    change_sats: Number(changeValue),
    op_return: args.opReturn || null,
  });

  const tx = new Transaction({ version: 2, allowUnknownOutputs: true });
  tx.addInput({
    txid: utxo.txid,
    index: utxo.vout,
    witnessUtxo: {
      amount: inputValue,
      script: sourceScript,
    },
  });
  tx.addOutput({
    script: destScript,
    amount: sendValue,
  });
  if (args.opReturn) {
    tx.addOutput({
      script: opReturnScript(args.opReturn),
      amount: 0n,
    });
  }
  if (changeValue > 0n) {
    tx.addOutput({
      script: sourceScript,
      amount: changeValue,
    });
  }

  const msg32 = bytesToHex(tx.preimageWitnessV1(0, [sourceScript], SigHash.DEFAULT, [inputValue]));
  logStep(args, 'computed BIP341 Taproot sighash', { taproot_sighash32: msg32 });
  logStep(args, 'requesting physical card MuSig2 partial signature', {
    python: REAL_CARD_PYTHON,
    script: REAL_CARD_SCRIPT,
    card_pk33: profile.card_pk33,
  });
  const cardResult = await cardSign(profile, msg32);
  logStep(args, 'card partial verified and final MuSig2 signature assembled', {
    card_partial_verified: cardResult.card_partial_verified,
    final_signature_verified: cardResult.final_signature_verified,
    final_signature64: cardResult.final_signature64,
  });
  const finalSig = hexToBytes(cardResult.final_signature64);
  if (!schnorr.verify(finalSig, hexToBytes(msg32), hexToBytes(profile.aggregate_xonly32))) {
    throw new Error('local BIP340 verification failed');
  }
  logStep(args, 'local BIP340 verification passed', { aggregate_xonly32: profile.aggregate_xonly32 });
  tx.updateInput(0, { tapKeySig: finalSig }, true);
  tx.finalize();
  const rawTx = tx.hex;
  const result = {
    status: 'REAL_BITCOIN_CARD_TX_READY',
    network: args.network,
    source_address: identity.address,
    destination_address: toAddress,
    utxo: {
      txid: utxo.txid,
      vout: utxo.vout,
      value: Number(inputValue),
    },
    fee_sats: Number(args.feeSats),
    send_sats: Number(sendValue),
    change_sats: Number(changeValue),
    op_return: args.opReturn || null,
    taproot_sighash32: msg32,
    card_partial_verified: cardResult.card_partial_verified,
    final_signature_verified: true,
    final_signature64: cardResult.final_signature64,
    txid: tx.id,
    tx_vsize: tx.vsize,
    raw_tx_hex: rawTx,
    broadcasted: false,
  };
  logStep(args, 'finalized signed transaction', {
    txid: result.txid,
    tx_vsize: result.tx_vsize,
    outputs: outputCount,
  });
  if (args.broadcast) {
    logStep(args, 'broadcasting signed transaction', { endpoint: `${network.explorer}/tx`, txid: result.txid });
    try {
      const txid = await fetchText(`${network.explorer}/tx`, {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: rawTx,
      });
      result.broadcasted = true;
      result.broadcast_txid = txid.trim();
      logStep(args, 'broadcast accepted', { broadcast_txid: result.broadcast_txid });
      if (args.waitConfirmation) {
        result.confirmation_status = await waitForTxStatus(args, result.broadcast_txid);
      }
    } catch (error) {
      result.status = 'REAL_BITCOIN_CARD_TX_READY_BROADCAST_FAILED';
      result.broadcast_error = error?.message || String(error);
      logStep(args, 'broadcast failed', { error: result.broadcast_error });
    }
  }
  console.log(JSON.stringify(result, null, 2));
}

async function commandStatus(args) {
  if (!args.txid) throw new Error('status requires --txid=<txid>');
  logStep(args, 'checking transaction confirmation status', {
    network: args.network,
    txid: args.txid,
    wait_confirmation: args.waitConfirmation,
  });
  const status = await waitForTxStatus(args, args.txid);
  console.log(JSON.stringify({
    network: args.network,
    txid: args.txid,
    status,
    explorer_url: `${NETWORKS[args.network].explorer?.replace(/\/api$/, '')}/tx/${args.txid}`,
  }, null, 2));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.command === 'address') return commandAddress(args);
  if (args.command === 'utxos') return commandUtxos(args);
  if (args.command === 'spend') return commandSpend(args);
  if (args.command === 'status') return commandStatus(args);
  throw new Error(`unhandled command ${args.command}`);
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
});
