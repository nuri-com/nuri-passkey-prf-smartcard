#!/usr/bin/env node
import assert from 'node:assert/strict';
import { appendFile, mkdir, open, rename, unlink } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { sdk, EtherscanProvider, deriveAddresses, bytes, hex } from './deps.mjs';
import { CLIENT, SERVER, SCRIPT, SOURCE, CREDENTIAL, CardIdentity, guard, plan, validTo, validAmount, validateAddress, floorOf } from './core.mjs';

export function parseArgs(argv = []) {
 const options = { execute: false, to: SOURCE };
 const seen = new Set();
 for (let i = 0; i < argv.length; i++) {
  const flag = argv[i];
  assert(['--execute', '--dry-run', '--to', '--amount'].includes(flag), 'Usage: cli.mjs [--dry-run | --execute] [--to <ark1 address | @username>] [--amount <sats | all>]');
  assert(!seen.has(flag), `duplicate ${flag}`); seen.add(flag);
  if (flag === '--execute') options.execute = true;
  if (flag === '--to' || flag === '--amount') {
   const value = argv[++i]; assert(value && !value.startsWith('--'), `missing ${flag} value`);
   options[flag.slice(2)] = flag === '--to' ? validTo(value) : validAmount(value);
  }
 }
 assert(!(seen.has('--execute') && seen.has('--dry-run')), 'choose one mode');
 return options;
}

// The existing bridge validates its own execution guard. Never rewrite that
// environment variable to bypass a Python guard or export it in a receipt.
export class Bridge {
 constructor({ python, env = process.env, spawnChild = spawn } = {}) {
  this.queue = []; this.ended = false;
  this.child = spawnChild(python ?? env.PYTHON_BIN ?? 'python3', [fileURLToPath(new URL('./bridge.py', import.meta.url))], { stdio: ['pipe', 'pipe', 'inherit'], env });
  const fail = () => {
   this.ended = true;
   for (const q of this.queue.splice(0)) q.reject(new Error('card bridge ended; no retry'));
  };
  createInterface({ input: this.child.stdout }).on('line', line => {
   const q = this.queue.shift(); if (!q) return;
   try { const value = JSON.parse(line); if (value.error) throw new Error('card operation failed; no retry'); q.resolve(value); }
   catch { q.reject(new Error('card bridge response failed; no retry')); fail(); }
  });
  this.child.on('error', fail); this.child.on('exit', fail); this.child.stdin.on('error', fail);
 }
 request(op, payload) {
  if (this.ended) return Promise.reject(new Error('card bridge ended; no retry'));
  return new Promise((resolve, reject) => {
   this.queue.push({ resolve, reject });
   this.child.stdin.write(JSON.stringify({ op, payload }) + '\n');
  });
 }
 async getPublicKey() { return bytes((await this.request('pubkey')).pubkey); }
 async getNonces() { const n = await this.request('nonces'); return { publicNonce: bytes(n.publicNonce), token: bytes(n.token) }; }
 async finalize(payload) { return bytes((await this.request('finalize', hex(payload))).partial); }
 close() { this.child.stdin.end(); }
}

// Ethers' normal JSON-RPC provider POSTs even eth_call. Use the explorer's
// GET proxy instead; CCIP callbacks still go through the on-chain resolver.
class GetOnlyEnsProvider extends EtherscanProvider {
 async fetch(module, params) { return super.fetch(module, params, false); }
 async ccipReadFetch(tx, data, urls) {
  const getUrls = urls.filter(url => url.includes('{data}') && url.startsWith('https://'));
  assert(getUrls.length, 'ENS gateway must support HTTPS GET');
  return super.ccipReadFetch(tx, data, getUrls);
 }
}
export async function resolveRecipient(to, { env = process.env, providerFactory } = {}) {
 validTo(to);
 if (!to.startsWith('@')) return to;
 const provider = providerFactory ? providerFactory() : new GetOnlyEnsProvider(1, env.ETHERSCAN_API_KEY);
 try {
  const resolver = await provider.getResolver(`${to.slice(1)}.nuri.eth`);
  assert(resolver, 'ENS resolver unavailable');
  const address = await resolver.getText('com.nuri.arkade');
  assert(address, 'ENS com.nuri.arkade record empty');
  return address;
 } finally { provider.destroy?.(); }
}

export async function saveReceipt(path, receipt, { exclusive = false } = {}) {
 await mkdir(dirname(path), { recursive: true, mode: 0o700 });
 // The first journal is the operation reservation, never a check-then-write.
 // Leave even an incomplete reservation behind on failure: do not auto-resend.
 const temp = exclusive ? path : `${path}.${randomUUID()}.tmp`;
 let file;
 try {
  file = await open(temp, 'wx', 0o600);
  await file.writeFile(JSON.stringify(receipt, null, 2) + '\n');
  await file.sync(); await file.close(); file = undefined;
  if (!exclusive) await rename(temp, path);
  const directory = await open(dirname(path), 'r');
  try { await directory.sync(); } finally { await directory.close(); }
 } catch (error) {
  await file?.close().catch(() => {});
  if (!exclusive) await unlink(temp).catch(() => {});
  if (exclusive && error.code === 'EEXIST') throw new Error('receipt exists; inspect it, DO NOT RESEND');
  throw error;
 }
}
function completeVtxos(result) {
 assert(Array.isArray(result?.vtxos), 'indexer missing VTXOs');
 assert(!result.page?.next, 'unexpected pagination; refusing partial balance');
 return result.vtxos;
}
function makeTransaction(coins, summary, info, operator, derived) {
 const aggregate = bytes(derived.aggregate_pk33).slice(1), arkKey = bytes(operator.signerPubkey).slice(-32);
 const delay = Number(operator.unilateralExitDelay), nuriDelay = Number(info.nuri_server_csv.value);
 const cooperative = sdk.MultisigTapscript.encode({ pubkeys: [aggregate, arkKey] }).script;
 const tree = new sdk.VtxoScript([
  cooperative,
  sdk.CSVMultisigTapscript.encode({ pubkeys: [aggregate], timelock: { type: 'seconds', value: BigInt(delay) } }).script,
  sdk.CSVMultisigTapscript.encode({ pubkeys: [bytes(CLIENT).slice(1)], timelock: { type: 'seconds', value: BigInt(delay + nuriDelay) } }).script,
 ]);
 assert.equal(hex(tree.pkScript), SCRIPT);
 const unroll = sdk.CSVMultisigTapscript.decode(bytes(operator.checkpointTapscript));
 assert.equal(unroll.params.pubkeys.length, 1);
 assert.equal(hex(unroll.params.pubkeys[0]), hex(bytes(operator.forfeitPubkey).slice(-32)));
 const inputs = coins.map(c => ({ ...c, tapTree: tree.encode(), tapLeafScript: tree.findLeaf(hex(cooperative)) }));
 const outputs = [{ script: validateAddress(summary.recipient, operator.signerPubkey).pkScript, amount: BigInt(summary.recipient_sats) }];
 if (summary.change_sats) outputs.push({ script: bytes(SCRIPT), amount: BigInt(summary.change_sats) });
 const unsigned = sdk.buildOffchainTx(inputs, outputs, unroll);
 assert.equal(unsigned.arkTx.outputsLength, outputs.length + 1, 'unexpected output count');
 for (const [i, output] of outputs.entries()) {
  assert.equal(unsigned.arkTx.getOutput(i).amount, output.amount);
  assert.equal(hex(unsigned.arkTx.getOutput(i).script), hex(output.script));
 }
 const anchor = unsigned.arkTx.getOutput(outputs.length);
 assert.equal(anchor.amount, 0n); assert.equal(hex(anchor.script), '51024e73', 'unexpected anchor');
 return { inputs, outputs, unroll, unsigned };
}

/** Reusable send entry. Dependencies are lazy: dry/empty never construct a card.
 * beforeExecute({bridge,summary}) runs before intent creation and FIDO auth.
 * A caller-owned bridge is not closed; factory-created bridges always are.
 */
export async function runSend(options = {}, deps = {}) {
 const env = deps.env ?? process.env;
 const execute = options.execute === true, to = validTo(options.to ?? SOURCE);
 const amount = options.amount === undefined ? undefined : validAmount(String(options.amount));
 // Explicit amount guards fail before even public network reads. For the
 // operator-dependent default, resolve the floor and guard before card/POST.
 if (amount !== undefined) guard(execute, env.NURI_SEND_CONFIRM, to, amount);
 const logPath = resolve(options.logPath ?? env.NURI_SEND_LOG ?? `_launch/out/arkade-card/send-${Date.now()}.jsonl`);
 const receiptPath = resolve(options.receiptPath ?? env.NURI_RECEIPT_PATH ?? '_launch/out/arkade-card/receipt.json');
 const log = deps.log ?? (async (event, data = {}) => {
  await mkdir(dirname(logPath), { recursive: true, mode: 0o700 });
  await appendFile(logPath, JSON.stringify({ at: new Date().toISOString(), event, ...data }) + '\n', { mode: 0o600 });
 });
 const persist = deps.persistReceipt ?? ((receipt, options) => saveReceipt(receiptPath, receipt, options));
 const request = async (path, body) => {
  assert(path.startsWith('/') && !path.startsWith('//'), 'absolute route required');
  assert(body === undefined || execute, 'dry-run cannot POST');
  await log(body === undefined ? 'GET' : 'POST', { path: path.split('?')[0] });
  if (deps.request) return deps.request(path, body);
  const r = await (deps.fetch ?? fetch)(`https://arkade.nuri.com${path}`, {
   method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json' },
   ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(40000),
  });
  assert(r.ok, `Nuri ${path.split('?')[0]} HTTP ${r.status}; no automatic retry`);
  return r.json();
 };
 const operatorProvider = deps.operatorProvider ?? new sdk.RestArkProvider('https://arkade.computer');
 const indexer = deps.indexer ?? new sdk.RestIndexerProvider('https://arkade.computer');
 const resolveTo = deps.resolveRecipient ?? (target => resolveRecipient(target, { env }));
 const snapshot = async () => {
  const recipient = await resolveTo(to);
  const operator = await operatorProvider.getInfo();
  const floor = floorOf(operator);
  guard(execute, env.NURI_SEND_CONFIRM, to, amount ?? String(Math.max(546, floor)));
  const info = await request(`/v4/arkade/info?client_pk33=${CLIENT}&client_signer_pubkey=${CLIENT}&cred_id_b64u=${CREDENTIAL}`);
  assert.equal(info.server_pubkey, SERVER, 'server key changed');
  assert.equal(info.recovery?.registered, true, 'card credential not registered');
  assert.equal(info.username, 'arkade', 'card alias/credential linkage changed');
  const derived = (deps.deriveAddresses ?? deriveAddresses)(CLIENT, info, operator);
  assert.equal(derived.ark_address, SOURCE, 'source derivation mismatch'); assert.equal(derived.offchain_script, SCRIPT);
  const coins = completeVtxos(await indexer.getVtxos({ scripts: [SCRIPT], spendableOnly: true }));
  const summary = plan(recipient, coins, coins.reduce((sum,c) => sum + Number(c.value), 0), { amount, floor, operatorKey: operator.signerPubkey });
  return { recipient, operator, info, derived, coins, summary };
 };
 const first = await snapshot();
 const summary = { ...first.summary, to, mode: execute ? 'execute' : 'dry-run', receipt_file: receiptPath, log_file: logPath };
 if (summary.status === 'needs_funding') { await log('needs_funding', summary); return summary; }
 const tx = makeTransaction(first.coins, summary, first.info, first.operator, first.derived);
 summary.unsigned_ark_txid = tx.unsigned.arkTx.id;
 summary.checkpoint_txids = tx.unsigned.checkpoints.map(c => c.id);
 await log('plan', summary);
 if (!execute) return summary;
 let bridge = deps.bridge, identity, submitted = false;
 const receipt = { ...summary, status: 'planned', proofs: [], auth_accepted: null, indexer_verified: false, retry_allowed: false };
 const update = async status => {
  receipt.status = status; receipt.proofs = identity?.proofs ?? []; receipt.auth_accepted = identity?.authAccepted ?? null;
  await persist(receipt, { exclusive: status === 'planned' });
 };
 await update('planned');
 try {
  bridge ??= await (deps.bridgeFactory ?? (() => new Bridge({ env })))();
  await (deps.beforeExecute ?? options.beforeExecute)?.({ bridge, summary });
  const revalidate = async () => {
   const current = await snapshot();
   assert.deepEqual(current, first, 'live balances, addresses or server changed; new confirmation required');
  };
  await revalidate();
  const intent = await request('/v4/arkade/swap-intent/create', {
   kind: 'ark_send', cred_id_b64u: CREDENTIAL, client_signer_pubkey: CLIENT,
   final_recipient: summary.recipient, final_amount_sats: summary.recipient_sats,
   funding_address: summary.recipient, funding_script_hex: hex(tx.outputs[0].script), funding_amount_sats: summary.recipient_sats,
  });
  assert(intent.intent?.id, 'missing intent id');
  receipt.intent_id = intent.intent.id;
  identity = new CardIdentity({ card: bridge, http: request, intentId: intent.intent.id,
   approve: p => bridge.request('assert', p), log: event => { /* no request/response payloads */ } });
  const guardedOperator = {
   async submitTx(...args) {
    // A second live snapshot after authorization catches changes during prompts.
    await revalidate();
    await update('submission_pending'); // signed public proofs durable BEFORE submit
    submitted = true;
    return operatorProvider.submitTx(...args);
   },
   async finalizeTx(...args) { await update('finalization_pending'); return operatorProvider.finalizeTx(...args); },
  };
  const txid = await (deps.signAndSubmitOffchainTx ?? sdk.signAndSubmitOffchainTx)({ identity, provider: guardedOperator,
   inputs: tx.inputs, outputs: tx.outputs, serverUnrollScript: tx.unroll,
   verifyServerSignatures: { serverPubkey: bytes(first.operator.signerPubkey) } });
  assert.equal(txid, summary.unsigned_ark_txid, 'unexpected finalized txid');
  receipt.txid = txid; await update('finalized');
  const source = completeVtxos(await indexer.getVtxos({ scripts: [SCRIPT], spendableOnly: true }));
  const target = completeVtxos(await indexer.getVtxos({ scripts: [hex(tx.outputs[0].script)], spendableOnly: true }));
  const hasOutput = (rows, vout, value) => rows.some(v => v.txid === txid && v.vout === vout && Number(v.value) === value && !v.isSpent && !v.isSwept);
  assert(hasOutput(target, 0, summary.recipient_sats), 'recipient not reconciled; DO NOT RESEND');
  assert(!source.some(v => first.coins.some(c => c.txid === v.txid && c.vout === v.vout)), 'source inputs remain; DO NOT RESEND');
  if (summary.change_sats) assert(hasOutput(source, 1, summary.change_sats), 'change not reconciled; DO NOT RESEND');
  receipt.indexer_verified = true; await update('indexer_verified');
  await request('/api/arkade/send/complete', { challenge_token: identity.prepared.challenge_token, send_intent_id: intent.intent.id, txid });
  await update('completed'); return receipt;
 } catch (error) {
  // Provider exceptions may embed request bodies. Persist only a fixed status.
  receipt.failure_stage = submitted ? 'submission may have occurred; DO NOT RESEND' : 'before operator submission; inspect before a new operation';
  await update(submitted ? 'failed_unknown_outcome' : 'failed_before_submission');
  throw new Error(receipt.failure_stage); // never propagate token-bearing provider errors
 } finally { if (!deps.bridge) bridge?.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
 try { console.log(JSON.stringify(await runSend(parseArgs(process.argv.slice(2))), null, 2)); }
 catch (error) { console.error(error.message); process.exitCode = 1; }
}
