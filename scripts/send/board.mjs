#!/usr/bin/env node
// Boarding sweep: settle confirmed onchain boarding UTXOs into a card-owned
// Arkade VTXO. Mirrors the app's `ramps.onboard` -> `wallet.settle`
// (services/arkade/internal/receiveAutoSweep.ts:1099) with the card applet as
// the client MuSig2 half and /arkade/receive/boarding/sweep/approve as the
// WebAuthn approval (src/ArkadeServer.js:5942).
import assert from 'node:assert/strict';
import { appendFile, mkdir, open, rename, unlink } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { EventSource } from 'eventsource';
import { sdk, hex, bytes, tapLeafHash } from './deps.mjs';
import { CLIENT, SERVER, SCRIPT, SOURCE, CREDENTIAL } from './core.mjs';
import { Bridge, saveReceipt } from './cli.mjs';
import {
 boardingContext, boardingCandidates, planSweep, buildProof, registerMessage, deleteMessage,
 directRequests, applyDirectSignature, signDirect, signProof, treeMessage, signTree,
 cardSessions, DELETE_PROOF_SESSIONS, estimatedMs, guardBoard, confirmToken, CARD_SESSION_MS, CARD_NONCE_MS,
} from './board-core.mjs';

const OPERATOR = 'https://arkade.computer';
const ESPLORA = 'https://mempool.space/api';
const NURI = 'https://arkade.nuri.com';
const ORIGIN = 'https://arkade.nuri.com';
const CONFIRMATIONS = 1;

export function parseArgs(argv = []) {
 const options = { execute: false };
 const seen = new Set();
 for (let i = 0; i < argv.length; i++) {
  const flag = argv[i];
  assert(['--execute', '--dry-run', '--outpoint', '--expect', '--tree-limit'].includes(flag),
   'Usage: board.mjs [--dry-run | --execute] [--outpoint <txid:vout>] [--expect <bc1p address>] [--tree-limit <n>]');
  assert(!seen.has(flag), `duplicate ${flag}`); seen.add(flag);
  if (flag === '--execute') options.execute = true;
  if (flag === '--dry-run') options.execute = false;
  if (flag === '--outpoint') {
   const value = argv[++i];
   assert(/^[0-9a-f]{64}:[0-9]+$/.test(value || ''), 'outpoint must be txid:vout');
   options.outpoint = value;
  }
  if (flag === '--expect') {
   const value = argv[++i];
   assert(/^bc1p[0-9a-z]{58}$/.test(value || ''), 'expect must be a mainnet P2TR address');
   options.expect = value;
  }
  if (flag === '--tree-limit') {
   const value = Number(argv[++i]);
   assert(Number.isSafeInteger(value) && value > 0, 'tree-limit must be a positive integer');
   options.treeLimit = value;
  }
 }
 return options;
}

async function getJson(url) {
 const response = await (optionsFetch ?? fetch)(url, { signal: AbortSignal.timeout(30000) });
 assert(response.ok, `GET ${url} HTTP ${response.status}`);
 return response.json();
}
let optionsFetch;

const sha256Hex = value => createHash('sha256').update(value).digest('hex');

/** Public, card-free read of the wallet's live and static state. */
async function snapshot(options, deps, log) {
 const fetchImpl = deps.fetch ?? fetch;
 const client = deps.client ?? CLIENT;
 const operator = deps.operator ?? await getJson(`${OPERATOR}/v1/info`);
 const info = await request(deps, `/v4/arkade/info?client_pk33=${client}&client_signer_pubkey=${client}&cred_id_b64u=${CREDENTIAL}`, undefined, log);
 assert.equal(info.server_pubkey, deps.server ?? SERVER, 'server key changed');
 assert.equal(info.recovery?.registered, true, 'card credential not registered');
 assert.equal(info.username, 'arkade', 'card alias/credential linkage changed');
 const ctx = boardingContext(client, info, operator);
 if (options.expect) assert.equal(ctx.address, options.expect, 'boarding address changed');
 const floor = Math.max(Number(operator.vtxoMinAmount), Number(operator.dust));
 const raw = deps.esplora ? await deps.esplora(ctx.address) : await (await fetchImpl(`${ESPLORA}/address/${ctx.address}/utxo`, { signal: AbortSignal.timeout(30000) })).json();
 const rows = boardingCandidates(raw, { script: ctx.script, floor });
 const selected = options.outpoint ? rows.filter(r => `${r.txid}:${r.vout}` === options.outpoint) : rows;
 assert(!options.outpoint || selected.length, 'outpoint not found at the boarding address');
 const eligible = selected.filter(r => r.eligible);
 const plan = planSweep(eligible, { feeInfo: operator.fees, floor, dust: operator.dust, vtxoMin: operator.vtxoMinAmount });
 const sessions = cardSessions({ inputs: plan.inputs.length, treeTxs: 1 });
 return { operator, info, ctx, rows, selected, plan,
  summary: { ...plan, boarding_address: ctx.address, boarding_script: ctx.script, boarding_exit_delay: ctx.boarding_exit_delay,
   all_boarding_utxos: rows.length, confirmations_required: CONFIRMATIONS,
   card_sessions: plan.status === 'planned' ? sessions : 0,
   card_sessions_with_delete: plan.status === 'planned' ? sessions + DELETE_PROOF_SESSIONS : 0,
   estimated_ms_single_leaf: plan.status === 'planned' ? estimatedMs(sessions) : 0,
   operator_session_duration_s: Number(operator.sessionDuration),
   source: SOURCE, username: info.username, server_pubkey: info.server_pubkey } };
}

function makeRequest(deps, mode) {
 return (path, body) => request(deps, path, body, mode.log ?? (() => {}));
}
async function request(deps, path, body, log = () => {}) {
 assert(path.startsWith('/') && !path.startsWith('//'), 'absolute route required');
 if (deps.request) return deps.request(path, body);
 log('NURI', { method: body === undefined ? 'GET' : 'POST', path: path.split('?')[0] });
 const response = await (deps.fetch ?? fetch)(`${NURI}${path}`, {
  method: body === undefined ? 'GET' : 'POST',
  headers: { 'content-type': 'application/json' },
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  signal: AbortSignal.timeout(40000),
 });
 const text = await response.text();
 let data;
 try { data = text ? JSON.parse(text) : {}; } catch { throw new Error(`Nuri ${path.split('?')[0]} non-JSON HTTP ${response.status}`); }
 if (!response.ok) throw new Error(`Nuri ${path.split('?')[0]} HTTP ${response.status}: ${data.error || 'error'}${data.details ? ` (${data.details})` : ''}; no automatic retry`);
 return data;
}

/** Output script of the destination VTXO (our own offchain script). */
function offchainScript(arkAddress, expected = SCRIPT) {
 const decoded = sdk.ArkAddress.decode(arkAddress);
 assert.equal(decoded.hrp, 'ark', 'mainnet ark address required');
 assert.equal(hex(decoded.pkScript), expected, 'destination script is not the card source script');
 return decoded.pkScript;
}

function findCommitmentInput(tx, coin) {
 for (let i = 0; i < tx.inputsLength; i++) {
  const input = tx.getInput(i);
  if (hex(input.txid) === coin.txid && Number(input.index) === coin.vout) return i;
 }
 return -1;
}

/** Requests for EVERY commitment input, exactly as the server derives them. */
function commitmentRequests(tx, ctx) {
 const prev = [];
 for (let i = 0; i < tx.inputsLength; i++) {
  const input = tx.getInput(i);
  assert(input.witnessUtxo, `commitment input ${i} missing witnessUtxo`);
  prev.push(input.witnessUtxo);
 }
 const requests = [];
 for (let i = 0; i < tx.inputsLength; i++) {
  const input = tx.getInput(i);
  const sighash = input.sighashType ?? 0;
  let matched = false;
  for (const leaf of input.tapLeafScript ?? []) {
   const script = leaf[1].slice(0, -1), version = leaf[1].at(-1);
   let decoded;
   try { decoded = sdk.MultisigTapscript.decode(script); } catch { continue; }
   if (!decoded.params.pubkeys.some(p => hex(p) === ctx.aggregate_xonly)) continue;
   const msg = tx.preimageWitnessV1(i, prev.map(v => v.script), sighash, prev.map(v => v.amount), undefined, script, version);
   requests.push({ kind: 'direct', input_index: i, msg32: hex(msg), ours: true, leaf_script: script, leaf_version: version });
   matched = true;
  }
  if (!matched) {
   const msg = tx.preimageWitnessV1(i, prev.map(v => v.script), sighash, prev.map(v => v.amount));
   requests.push({ kind: 'direct', input_index: i, msg32: hex(msg), ours: false, tweak32: null });
  }
 }
 return requests;
}

const signBodyWith = client => row => ({ kind: row.kind ?? 'direct', msg32: row.msg32, client_pk33: client,
 ...(row.input_index === undefined ? {} : { input_index: row.input_index }),
 ...(row.txid ? { txid: row.txid } : {}), ...(row.tweak32 ? { tweak32: row.tweak32 } : {}) });

export async function runBoard(options = {}, deps = {}) {
 optionsFetch = deps.fetch ?? fetch;
 const env = deps.env ?? process.env;
 const execute = options.execute === true;
 const logPath = resolve(options.logPath ?? env.NURI_BOARD_LOG ?? `_launch/out/board/board-${Date.now()}.jsonl`);
 const receiptPath = resolve(options.receiptPath ?? env.NURI_BOARD_RECEIPT_PATH ?? '_launch/out/board/receipt.json');
 const log = deps.log ?? (async (event, data = {}) => {
  await mkdir(dirname(logPath), { recursive: true, mode: 0o700 });
  await appendFile(logPath, JSON.stringify({ at: new Date().toISOString(), event, ...data }) + '\n', { mode: 0o600 });
 });
 const persist = deps.persistReceipt ?? ((receipt, opts) => saveReceipt(receiptPath, receipt, opts));

 const client = deps.client ?? CLIENT;
 const server = deps.server ?? SERVER;
 const arkAddress = deps.arkAddress ?? SOURCE;
 const script = deps.script ?? SCRIPT;
 const signBody = signBodyWith(client);
 const first = await snapshot(options, deps, log);
 const summary = { ...first.summary, mode: execute ? 'execute' : 'dry-run', receipt_file: receiptPath, log_file: logPath, confirmation: confirmToken(first.plan.vtxo_sats) };
 if (first.plan.status !== 'planned') { await log('stopped', summary); return { ...summary, utxos: first.rows }; }
 guardBoard(execute, env.NURI_SEND_CONFIRM, first.plan.vtxo_sats);
 if (!execute) {
  const proof = buildProof(registerMessage({ cosigners: [first.ctx.aggregate_pk33] }), first.plan.inputs, [{ amount: BigInt(first.plan.vtxo_sats), script: offchainScript(arkAddress, script) }], first.ctx);
  const requests = directRequests(proof.tx, first.ctx.aggregate_xonly);
  await log('plan', summary);
  return { ...summary, utxos: first.rows, register_proof_id: proof.tx.id, register_proof_inputs: proof.tx.inputsLength,
   direct_sign_requests: requests.map(signBody), register_proof_psbt_b64_sha256: createHash('sha256').update(Buffer.from(proof.tx.toPSBT())).digest('hex') };
 }

 let bridge = deps.bridge, submitted = false;
 const receipt = { ...summary, status: 'planned', proofs: [], auth_accepted: null, indexer_verified: false, retry_allowed: false };
 const update = async status => { receipt.status = status; await persist(receipt, { exclusive: status === 'planned' }); };
 await update('planned');
 try {
  bridge ??= await (deps.bridgeFactory ?? (() => new Bridge({ env })))();
  const card = {
   getPublicKey: () => bridge.getPublicKey(),
   getNonces: () => bridge.getNonces(),
   finalize: payload => bridge.finalize(payload),
  };
  const http = makeRequest(deps, { log });
  const operator = deps.arkProvider ?? new sdk.RestArkProvider(OPERATOR);

  const revalidate = async () => {
   const current = await snapshot(options, deps, log);
   assert.equal(current.ctx.address, first.ctx.address, 'boarding address changed');
   assert.deepEqual(current.plan.inputs, first.plan.inputs, 'boarding inputs changed; new confirmation required');
   assert.equal(current.plan.vtxo_sats, first.plan.vtxo_sats, 'swept amount changed; new confirmation required');
  };

  // One passkey assertion authorizes the whole sweep: the approval is minted
  // for the register proof, then re-minted prompt-free from the returned
  // boarding sweep session token for the tree and the commitment (server token
  // mode, src/ArkadeServer.js:4850).
  const auth = await http('/v4/arkade/auth', { cred_id_b64u: CREDENTIAL, client_signer_pubkey: client });
  assert(auth.challenge && auth.token, 'auth challenge missing');
  const origins = Array.isArray(auth.origin) ? auth.origin : String(auth.origin).split(',').map(s => s.trim());
  assert(origins.includes(ORIGIN), 'server does not allow the card claim origin');
  log('FIDO2 assertion');
  const assertion = await bridge.request('assert', { challenge: auth.challenge, rp_id: auth.rp_id, origin: ORIGIN, credential: CREDENTIAL });
  assert.equal(hex(await bridge.getPublicKey()), client, 'wrong card key');
  // The server only knows boarding UTXOs of a registered boarding address,
  // loaded from Esplora on receive/sync (src/ArkadeServer.js:4398-4425, 4549).
  // Same order as the app: nuri-expo services/arkade/internal/walletSummary.ts:436.
  await http('/api/arkade/receive/boarding-address', { token: auth.token, client_data_b64u: assertion.client_data_b64u, auth_data_b64u: assertion.auth_data_b64u, sig_b64u: assertion.sig_b64u, client_signer_pubkey: client, boarding_address: first.ctx.address, metadata: { source: 'nuri-card-board' } });
  const synced = await http('/api/arkade/receive/sync', { cred_id_b64u: CREDENTIAL, client_public_key_33_hex: client });
  const known = new Set((synced.boarding ?? []).map(b => `${b.txid}:${b.vout}`));
  log('receive sync', { boarding: known.size });
  for (const i of first.plan.inputs) assert(known.has(`${i.txid}:${i.vout}`), `server does not see boarding outpoint ${i.txid}:${i.vout} after sync`);

  const approve = async (psbt, requests, sessionToken) => {
   const body = sessionToken
    ? { boarding_sweep_session_token: sessionToken }
    : { token: auth.token, client_data_b64u: assertion.client_data_b64u, auth_data_b64u: assertion.auth_data_b64u, sig_b64u: assertion.sig_b64u };
   const response = await http('/api/arkade/receive/boarding/sweep/approve', {
    ...body, client_pk33: client,
    selected_outpoints: first.plan.inputs.map(i => `${i.txid}:${i.vout}:${i.value}`),
    selected_total_sats: first.plan.gross_sats,
    psbt_b64: Buffer.from(psbt.toPSBT()).toString('base64'),
    sign_requests: requests.map(signBody),
   });
   assert(response.approval_token, 'missing approval token');
   assert.equal(response.approval_scope, 'boarding_sweep', 'unexpected approval scope');
   if (!sessionToken) {
    assert(response.boarding_sweep_session_token, 'missing boarding sweep session token');
    receipt.sweep_session_expires_at_ms = response.boarding_sweep_session_expires_at_ms ?? null;
    receipt.auth_accepted = { accepted: true, evidence: 'sweep/approve returned approval token', rp_id: auth.rp_id, origin: ORIGIN, card_key: CLIENT, server_key: SERVER };
   }
   return response;
  };
  const signCount = max => ({ signed: 0, get full() { return this.signed >= max; } });

  // 1. Register intent. Two proof inputs: the BIP322 message input and the coin.
  const proof = buildProof(registerMessage({ cosigners: [first.ctx.aggregate_pk33] }), first.plan.inputs,
   [{ amount: BigInt(first.plan.vtxo_sats), script: offchainScript(arkAddress, script) }], first.ctx);
  const proofRequests = directRequests(proof.tx, first.ctx.aggregate_xonly);
  const approval = await approve(proof.tx, proofRequests, null);
  receipt.session_token = approval.boarding_sweep_session_token;
  receipt.register_proof_id = proof.tx.id;
  receipt.register_proof_inputs = proof.tx.inputsLength;
  const sendSign = async (msg32, clientPubNonce) => http('/v4/arkade/sign', { ...signBody({ msg32 }), approval_token: approval.approval_token, client_pub_nonce: clientPubNonce });
  for (const request of proofRequests) {
   const { signature, proof: evidence } = await signDirect({ card, client, server, aggregate: first.ctx.aggregate_pk33, msg32: request.msg32, sign: sendSign, log });
   applyDirectSignature(proof.tx, request, first.ctx.aggregate_xonly, signature);
   receipt.proofs.push({ ...evidence, input_index: request.input_index, scope: 'register_intent' });
   await update('register_proof_signed');
  }
  const intent = { proof: Buffer.from(proof.tx.toPSBT()).toString('base64'), message: proof.message };
  receipt.intent_txid = proof.tx.id;
  await revalidate();
  await update('registering_intent');
  let intentId;
  try {
   intentId = await operator.registerIntent(intent);
  } catch (error) {
   // A refused registration leaves no intent, so the delete proof is only
   // needed now (the SDK signs it up front and uses it in the same place,
   // dist chunk-ZTGTQP2W.js:15756-15763).
   const proofDelay = buildProof(deleteMessage(), first.plan.inputs, [], first.ctx);
   const deleteApproval = await approve(proofDelay.tx, directRequests(proofDelay.tx, first.ctx.aggregate_xonly), receipt.session_token);
   const sendDelete = async (msg32, clientPubNonce) => http('/v4/arkade/sign', { ...signBody({ msg32 }), approval_token: deleteApproval.approval_token, client_pub_nonce: clientPubNonce });
   const signedDelete = await signProof(proofDelay.tx, first.ctx.aggregate_xonly, { card, client, server, aggregate: first.ctx.aggregate_pk33, sign: sendDelete, log });
   const deleteIntent = { proof: Buffer.from(signedDelete.tx.toPSBT()).toString('base64'), message: proofDelay.message };
   await operator.deleteIntent(deleteIntent).catch(e => { if (process.env.NURI_BOARD_DEBUG) console.error('DELETE FAILED', e.message); });
   receipt.delete_proof = true;
   throw error;
  }
  assert(intentId, 'missing intent id');
  receipt.intent_id = intentId;

  const abort = new AbortController();
  const treeSignatures = new Map();
  const treeNonces = new Map();
  const pendingNonces = new Map();
  let ourPubkey;
  let treeCount = 0, batchExpiry = null;

  const handler = {
   async onBatchStarted(event) {
    if (!event.intentIdHashes.includes(sha256Hex(new TextEncoder().encode(intentId)))) return { skip: true };
    // batchExpiry arrives on BatchStarted (sdk dist chunk-ZTGTQP2W.js:15611), not on TreeSigningStarted.
    batchExpiry = BigInt(event.batchExpiry);
    assert(batchExpiry >= 86400n, `batch expiry ${batchExpiry} below the 86400 s mainnet floor`);
    await operator.confirmRegistration(intentId);
    return { skip: false };
   },
   async onTreeSigningStarted(event, vtxoTree) {
    ourPubkey = first.ctx.aggregate_pk33;
    const xOnly = hex(bytes(first.ctx.aggregate_pk33).slice(1));
    assert(event.cosignersPublicKeys.some(k => hex(bytes(k)).slice(-64) === xOnly), 'card key not in tree cosigners');
    const commitment = sdk.Transaction.fromPSBT(Buffer.from(event.unsignedCommitmentTx, 'base64'));
    // event.batchExpiry is a raw bigint; the SDK wraps and floor-checks it
    // (sdk dist toTimelock + assertValidBatchExpiry: mainnet >= 86400 s, seconds-typed).
    assert(batchExpiry, 'tree signing before batch start');
    const sweepTapscript = sdk.CSVMultisigTapscript.encode({ timelock: { type: 'seconds', value: batchExpiry }, pubkeys: [bytes(first.operator.forfeitPubkey).slice(-32)] }).script;
    const sweepRoot = tapLeafHash(sweepTapscript);
    const rootAmount = commitment.getOutput(0)?.amount;
    assert(rootAmount, 'commitment shared output missing');
    (deps.validateTree ?? sdk.validateVtxoTxGraph)(vtxoTree, commitment, sweepRoot);
    const nodes = [...vtxoTree.iterator()];
    treeCount = nodes.length;
    const messages = nodes.map(node => ({ node, message: treeMessage(vtxoTree, node, { scriptRoot: sweepRoot, rootAmount }) }));
    if (process.env.NURI_BOARD_DEBUG) console.error('NODES', nodes.map(n => [n.txid, typeof n.txid, n.root?.id]));
    receipt.tree_txs = treeCount;
    receipt.card_sessions_actual = cardSessions({ inputs: first.plan.inputs.length, treeTxs: treeCount });
    receipt.estimated_ms_actual = estimatedMs(receipt.card_sessions_actual);
    if (options.treeLimit) assert(treeCount <= options.treeLimit, `tree has ${treeCount} txs, limit ${options.treeLimit}`);
    for (const { message } of messages) expectedNonces.set(message.txid, message.cosigners.length);
    const treeRequests = messages.map(({ message }) => ({ kind: 'tree', txid: message.txid, msg32: message.msg32, client_pk33: client, tweak32: message.tweak32 }));
    for (const input of first.plan.inputs) {
     const index = commitment.inputsLength && findCommitmentInput(commitment, input);
     assert(index !== undefined && index >= 0, 'boarding input missing from commitment');
     commitment.updateInput(index, { tapLeafScript: [first.ctx.leaf] });
    }
    const treeApproval = await approve(commitment, commitmentRequests(commitment, first.ctx).concat(treeRequests), receipt.session_token);
    const session = await http('/v4/arkade/tree/session-init', { approval_token: treeApproval.approval_token, client_pk33: client, txids: messages.map(m => m.message.txid) });
    assert(session.session_id, 'missing tree session id');
    for (const { message } of messages) {
     const nonce = await bridge.getNonces();
     const { signature, proof: evidence } = await signTree({ card, client, server, aggregate: first.ctx.aggregate_pk33, message, nonce, log,
      sign: {
       async nonce(msg, clientPubNonce) { return http('/v4/arkade/tree/nonce', { approval_token: treeApproval.approval_token, session_id: session.session_id, txid: msg.txid, msg32: msg.msg32, client_pk33: client, client_pub_nonce: clientPubNonce, tweak32: msg.tweak32 }); },
       async sign(msg, clientPubNonce) { return http('/v4/arkade/tree/sign', { approval_token: treeApproval.approval_token, session_id: session.session_id, txid: msg.txid, msg32: msg.msg32, client_pk33: client, client_pub_nonce: clientPubNonce, tweak32: msg.tweak32 }); },
      } });
     treeSignatures.set(message.txid, signature);
     pendingNonces.set(message.txid, { pubNonce: bytes(evidence.client_public_nonce) });
     receipt.proofs.push({ ...evidence, scope: 'tree' });
     await update('tree_signed');
    }
    await operator.submitTreeNonces(event.id, ourPubkey, pendingNonces);
    return { skip: false };
   },
   async onTreeNonces(event) {
    if (!treeSignatures.has(event.txid)) return { fullySigned: false };
    const row = receiptsNonces.get(event.txid) ?? new Set();
    for (const key of Object.keys(event.nonces ?? {})) row.add(key);
    receiptsNonces.set(event.txid, row);
    const complete = [...treeSignatures.keys()].every(txid => (receiptsNonces.get(txid)?.size ?? 0) >= (expectedNonces.get(txid) ?? 1));
    if (!complete) return { fullySigned: false };
    const signatures = new Map([...treeSignatures].map(([txid, sig]) => [txid, { encode: () => sig }]));
    await operator.submitTreeSignatures(event.id, ourPubkey, signatures);
    return { fullySigned: true };
   },
   async onBatchFinalization(event) {
    let settlement = sdk.Transaction.fromPSBT(Buffer.from(event.commitmentTx, 'base64'));
    for (const coin of first.plan.inputs) {
     const index = findCommitmentInput(settlement, coin);
     assert(index >= 0, `boarding input ${coin.txid}:${coin.vout} missing from commitment`);
     settlement.updateInput(index, { tapLeafScript: [first.ctx.leaf] });
    }
    const requests = commitmentRequests(settlement, first.ctx);
    const ours = requests.filter(r => r.ours);
    assert.equal(ours.length, first.plan.inputs.length, 'boarding inputs missing from commitment');
    const finalApproval = await approve(settlement, requests, receipt.sessionToken);
    const signIt = async (msg32, clientPubNonce) => http('/v4/arkade/sign', { ...signBody({ msg32 }), approval_token: finalApproval.approval_token, client_pub_nonce: clientPubNonce });
    for (const request of ours) {
     const leaf = first.ctx.leaf;
     const request2 = { ...request, leaf_script: leaf[1].slice(0, -1), leaf_version: leaf[1].at(-1), leaf_hash: hex(tapLeafHash(leaf[1].slice(0, -1), leaf[1].at(-1))) };
     const { signature, proof: evidence } = await signDirect({ card, client, server, aggregate: first.ctx.aggregate_pk33, msg32: request2.msg32, sign: signIt, log });
     applyDirectSignature(settlement, request2, first.ctx.aggregate_xonly, signature);
     receipt.proofs.push({ ...evidence, input_index: request2.input_index, scope: 'boarding_input' });
     await update('boarding_input_signed');
    }
    receipt.commitment_txid = settlement.id;
    await operator.submitSignedForfeitTxs([], Buffer.from(settlement.toPSBT()).toString('base64'));
    submitted = true;
    await update('submission_pending');
   },
   async onBatchFinalized(event) { receipt.batch_txid = event.txid; return; },
  };

  const receiptsNonces = new Map();
  const expectedNonces = new Map();
  const stream = operator.getEventStream(abort.signal, [first.ctx.aggregate_pk33, ...first.plan.inputs.map(i => `${i.txid}:${i.vout}`)]);
  try {
   const commitmentTxid = await sdk.Batch.join(stream, handler, { abortController: abort });
   receipt.commitment_txid ??= commitmentTxid;
   await update('finalized');
   // Reconcile: the VTXO must exist at our own script and the boarding coins be spent.
   const indexer = deps.indexer ?? new sdk.RestIndexerProvider(OPERATOR);
   const destination = hex(offchainScript(arkAddress, script));
   const vtxos = (await indexer.getVtxos({ scripts: [destination], spendableOnly: true })).vtxos ?? [];
   const settled = vtxos.find(v => Number(v.value) === first.plan.vtxo_sats && !v.isSpent && !v.isSwept);
   assert(settled, 'settled VTXO not found at the card script; DO NOT RESEND');
   receipt.vtxo = { txid: settled.txid, vout: settled.vout, value: Number(settled.value) };
   receipt.indexer_verified = true;
   await update('indexer_verified');
   return receipt;
  } finally { abort.abort(); }
 } catch (error) {
  const confirmed = receipt.indexer_verified === true;
  receipt.failure_stage = confirmed ? 'settled on indexer; only bookkeeping failed; DO NOT RESEND'
   : submitted ? 'submission may have occurred; DO NOT RESEND' : 'before operator submission; re-check boarding outpoints before a new attempt';
  if (process.env.NURI_BOARD_DEBUG) console.error(error.stack);
  await update(confirmed ? 'failed_completion_only' : submitted ? 'failed_unknown_outcome' : 'failed_before_submission');
  throw new Error(`${receipt.failure_stage} (${error.message})`);
 } finally { if (!deps.bridge) bridge?.close(); }
}

// EventSource for the operator's SSE stream (Node has no global one).
sdk.configureEventSource?.(url => new EventSource(url));

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
 try { console.log(JSON.stringify(await runBoard(parseArgs(process.argv.slice(2))), null, 2)); }
 catch (error) { console.error(error.message); process.exitCode = 1; }
}
