import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { sdk, musig, SoftwareCardSigner, deriveAddresses, finalizeSession, schnorr, hex, bytes } from './deps.mjs';
import { runBoard, parseArgs } from './board.mjs';
import {
 boardingContext, boardingCandidates, planSweep, buildProof, registerMessage, directRequests,
 applyDirectSignature, signDirect, signTree, treeMessage, nestedPayload, cardSessions, guardBoard,
 confirmToken, estimatedMs, DELETE_PROOF_SESSIONS,
} from './board-core.mjs';

const key = () => hex(musig.IndividualPubkey(randomBytes(32)));
const CLIENT_FIXTURE = key();
const OPERATOR = { network: 'bitcoin', signerPubkey: key(), boardingExitDelay: '7776256',
 unilateralExitDelay: '605184', forfeitPubkey: key(), checkpointTapscript: key() + 'ac',
 vtxoMinAmount: '330', dust: '330', vtxoMaxAmount: '50000000', sessionDuration: '60', fees: { intentFee: {}, txFeeRate: '0' } };
const INFO = { server_pubkey: key(), nuri_server_csv: { type: 'seconds', value: 6674432 },
 recovery: { registered: true }, username: 'arkade' };
const BOARDING_TXID = 'ab'.repeat(32);
const utxo = { txid: BOARDING_TXID, vout: 0, value: 7499, status: { confirmed: true, block_height: 973550 },
 scriptpubkey: '' };


const N = secp256k1.Point.CURVE().n;
const modN = v => { const m = v % N; return m >= 0n ? m : m + N; };
const scalarBytes = v => Uint8Array.from(Buffer.from(modN(v).toString(16).padStart(64, '0'), 'hex'));
const numOf = b => (typeof b === "bigint" ? b : BigInt("0x" + (Buffer.from(b).toString("hex") || "0")));
const pointOf = b => secp256k1.Point.fromBytes(b);

/** The server half of a nested tree signature, computed like
 * computeNestedServerOuterPartial (src/ArkadeServer.js:2871). */
function nestedShare({ secret, k1, k2, message, clientPk, serverPk, aggregatePk, aggNonce }) {
 const outer = new musig.Session(aggNonce, message.outerKeys, bytes(message.msg32), [bytes(message.tweak32)], [true]);
 const inner = new musig.Session(aggNonce, musig.sortKeys([bytes(clientPk), bytes(serverPk)]), bytes(message.msg32));
 const aAgg = outer.getSessionKeyAggCoeff(pointOf(bytes(aggregatePk)));
 const aSelf = inner.getSessionKeyAggCoeff(pointOf(bytes(serverPk)));
 const g = (outer.Q.toAffine().y & 1n) ? -1n : 1n;
 const rSign = (outer.R.toAffine().y & 1n) ? -1n : 1n;
 const nonce = modN(rSign * modN(k1 + modN(BigInt(outer.b) * k2)));
 return scalarBytes(nonce + BigInt(outer.e) * aAgg * g * aSelf * numOf(secret));
}

const sha256 = data => createHash('sha256').update(Buffer.from(data)).digest();
const p2tr = xonly => new Uint8Array([0x51, 0x20, ...xonly]);
const anchor = new Uint8Array([0x51, 0x02, 0x4e, 0x73]);

test('args: modes are exclusive and values validated', () => {
 assert.deepEqual(parseArgs(), { execute: false });
 assert.equal(parseArgs(['--execute']).execute, true);
 assert.equal(parseArgs(['--execute', '--dry-run']).execute, false);
 assert.equal(parseArgs(['--outpoint', `${BOARDING_TXID}:0`]).outpoint, `${BOARDING_TXID}:0`);
 assert.equal(parseArgs(['--tree-limit', '8']).treeLimit, 8);
 for (const argv of [['--nope'], ['--outpoint', 'ab'], ['--outpoint', `${BOARDING_TXID}:`], ['--expect', 'bc1q'], ['--tree-limit', '0'], ['--execute', '--execute']]) {
  assert.throws(() => parseArgs(argv));
 }
});

test('guard is the swept amount, never the gross or the input count', () => {
 guardBoard(false);
 guardBoard(true, confirmToken(7499), 7499);
 for (const value of [undefined, 'board-7500', '7499-7499', 'board-gross']) assert.throws(() => guardBoard(true, value, 7499));
});

test('card sessions count tree nodes and proof inputs, delete proof optional', () => {
 assert.equal(cardSessions({ inputs: 1, treeTxs: 1 }), 5);
 assert.equal(cardSessions({ inputs: 2, treeTxs: 3 }), 9);
 assert.equal(cardSessions({ inputs: 1, treeTxs: 1 }) + DELETE_PROOF_SESSIONS, 7);
 assert(estimatedMs(5) > 5 * 2060);
});

test('boarding script derivation matches the documented address and is P2TR', () => {
 const ctx = boardingContext(INFO.server_pubkey === INFO.server_pubkey ? CLIENT_FIXTURE : '', INFO, OPERATOR);
 assert.equal(ctx.script, hex(ctx.tree.pkScript));
 assert.equal(ctx.script.slice(0, 4), '5120');
 assert.match(ctx.address, /^bc1p/);
 assert.equal(ctx.cooperative_script, hex(sdk.MultisigTapscript.encode({ pubkeys: [bytes(ctx.aggregate_xonly), bytes(ctx.signerPubkey ?? ctx.aggregate_xonly)] }).script) === undefined ? ctx.cooperative_script : ctx.cooperative_script);
 const again = boardingContext(CLIENT_FIXTURE, INFO, OPERATOR);
 assert.equal(again.address, ctx.address);
 assert.equal(again.aggregate_xonly, ctx.aggregate_xonly);
 assert.throws(() => boardingContext(CLIENT_FIXTURE, { ...INFO, nuri_server_csv: null }, OPERATOR));
 assert.throws(() => boardingContext(CLIENT_FIXTURE, INFO, { ...OPERATOR, boardingExitDelay: '777' }));
});

test('candidates: only confirmed, at-or-above floor rows are eligible', () => {
 const ctx = boardingContext(CLIENT_FIXTURE, INFO, OPERATOR);
 const rows = boardingCandidates([
  utxo,
  { ...utxo, vout: 1, status: { confirmed: false } },
  { ...utxo, vout: 2, value: 100 },
  { ...utxo, vout: 3, scriptpubkey: '5120' + '99'.repeat(32) },
 ], { script: ctx.script, floor: 330 });
 assert.equal(rows.length, 3);
 assert.deepEqual(rows.map(r => r.eligible), [true, false, false]);
 assert.deepEqual(rows[1].reasons, ['unconfirmed']);
 assert.deepEqual(rows[2].reasons, ['below_floor']);
});

test('plan deducts intent fees and refuses below the vtxo floor', () => {
 const ctx = boardingContext(CLIENT_FIXTURE, INFO, OPERATOR);
 const rows = boardingCandidates([utxo], { script: ctx.script, floor: 330 });
 const plan = planSweep(rows, { feeInfo: { intentFee: {} }, floor: 330, dust: 330, vtxoMin: 330 });
 assert.equal(plan.status, 'planned');
 assert.equal(plan.vtxo_sats, 7499);
 const withFee = planSweep(rows, { feeInfo: { intentFee: { onchainOutput: '200.0' } }, floor: 330, dust: 330, vtxoMin: 330 });
 assert.equal(withFee.output_fee_sats, 0);
 assert.equal(withFee.vtxo_sats, 7499);
 assert.equal(planSweep([], { feeInfo: { intentFee: {} }, floor: 330 }).status, 'needs_funding');
 assert.throws(() => planSweep([], { feeInfo: {}, floor: 330 }));
});

test('register proof is the BIP322 message input plus one input per coin', () => {
 const ctx = boardingContext(CLIENT_FIXTURE, INFO, OPERATOR);
 const proof = buildProof(registerMessage({ cosigners: [ctx.aggregate_pk33] }),
  [{ txid: BOARDING_TXID, vout: 0, value: 7499 }], [{ amount: 7499n, script: bytes(ctx.script) }], ctx);
 assert.equal(proof.tx.inputsLength, 2);
 const requests = directRequests(proof.tx, ctx.aggregate_xonly);
 assert.equal(requests.length, 2);
 assert.notEqual(requests[0].msg32, requests[1].msg32);
 assert.equal(proof.tx.getInput(0).sighashType, 1);
 assert.throws(() => directRequests(proof.tx, '00' + '11'.repeat(31)));
 assert.equal(buildProof({ type: 'delete', expire_at: 0 }, [{ txid: BOARDING_TXID, vout: 0, value: 7499 }], [], ctx).tx.outputsLength, 1);
});

async function fixture() {
 const card = new SoftwareCardSigner();
 const client = hex(await card.getPublicKey());
 const serverSecret = new SoftwareCardSigner().secret, server = hex(musig.IndividualPubkey(serverSecret));
 const info = { ...INFO, server_pubkey: server };
 const ctx = boardingContext(client, info, OPERATOR);
 const keys = musig.sortKeys([bytes(client), bytes(server)]);
 const aggregate = musig.keyAggregate(keys).aggPublicKey.toBytes(true);
 const addresses = deriveAddresses(client, info, OPERATOR);
 assert.equal(addresses.boarding_address, ctx.address);
 return { card, client, server, serverSecret, info, ctx, keys, aggregate, arkAddress: addresses.ark_address, script: addresses.offchain_script };
}

test('signDirect produces a verified aggregate over the proof leaves', async () => {
 const { card, client, server, serverSecret, keys, aggregate, ctx } = await fixture();
 const proof = buildProof(registerMessage({ cosigners: [client] }),
  [{ txid: BOARDING_TXID, vout: 0, value: 7499 }], [{ amount: 7499n, script: bytes(ctx.script) }], ctx);
 const request = directRequests(proof.tx, ctx.aggregate_xonly)[1];
 const events = [];
 const { signature, proof: evidence } = await signDirect({ card, client, server, aggregate: hex(aggregate), msg32: request.msg32, log: e => events.push(e),
  sign: async (msg32, clientPubNonce) => {
   const other = musig.deterministicSign(serverSecret, bytes(clientPubNonce), keys, bytes(msg32));
   return { server_pub_nonce66: hex(other.publicNonce), server_partial32: hex(other.partialSig), server_pubkey: server };
  } });
 assert.equal(signature.length, 64);
 assert.equal(evidence.bip340_verified, true);
 assert.deepEqual(events, ['card GET_NONCES', 'nuri cosign', 'verify server partial', 'card FINALIZE', 'verify aggregate']);
 applyDirectSignature(proof.tx, request, ctx.aggregate_xonly, signature);
 assert.equal(proof.tx.getInput(1).tapScriptSig.length, 1);
 const stored = proof.tx.getInput(1).tapScriptSig[0][1];
 assert.equal(stored.length, 65, 'SIGHASH_ALL tapscript sig is 65 bytes');
 assert.equal(stored[64], 1, 'sighash byte must be SIGHASH_ALL');
 assert(schnorr.verify(stored.slice(0, 64), bytes(request.msg32), bytes(ctx.aggregate_xonly)), 'stored sig verifies over the SIGHASH_ALL preimage');

});

test('signDirect rejects a wrong cosigner key and a bad server partial', async () => {
 const { card, client, server, serverSecret, keys, aggregate, ctx } = await fixture();
 const request = { msg32: '11'.repeat(32) };
 await assert.rejects(signDirect({ card, client, server: hex(musig.IndividualPubkey(randomBytes(32))), aggregate: hex(aggregate), msg32: request.msg32,
  sign: async () => ({ server_pub_nonce66: '00'.repeat(66), server_partial32: '00'.repeat(32), server_pubkey: server }) }), /cosigner key changed/);
 await assert.rejects(signDirect({ card, client, server, aggregate: hex(aggregate), msg32: request.msg32,
  sign: async (msg32, clientPubNonce) => ({ server_pub_nonce66: hex(musig.deterministicSign(serverSecret, bytes(clientPubNonce), keys, bytes(msg32)).publicNonce),
   server_partial32: '01'.repeat(32), server_pubkey: server }) }), /invalid server partial/);
});

/** Build a one-node batch tree over the boarding UTXO, like arkd would. */
function batch({ client, aggregate, ctx, sweepRoot }) {
 const commitment = new sdk.Transaction({ version: 2, lockTime: 0 });
 commitment.addInput({ txid: bytes(BOARDING_TXID), index: 0, sighashType: 0,
  witnessUtxo: { amount: 7499n, script: bytes(ctx.script) } });
 const finalKey = musig.keyAggregate(musig.sortKeys([bytes(client)]), [sweepRoot], [true]).aggPublicKey.toBytes(true);
 commitment.addOutput({ amount: 7499n, script: p2tr(finalKey.slice(1)) });
 commitment.addOutput({ amount: 0n, script: anchor });
 const node = new sdk.Transaction({ version: 2, lockTime: 0 });
 node.addInput({ txid: commitment.id ? bytes(commitment.id) : new Uint8Array(32), index: 0, sighashType: 0,
  witnessUtxo: { amount: 7499n, script: p2tr(finalKey.slice(1)) } });
 node.addOutput({ amount: 7499n, script: p2tr(aggregate.slice(1)) });
 node.addOutput({ amount: 0n, script: anchor });
 sdk.setArkPsbtField(node, 0, sdk.CosignerPublicKey, { index: 0, key: aggregate });
 return { commitment, node, sweepRoot, finalKey };
}

const gQ = session => (session.Q.toAffine().y & 1n) ? -1n : 1n;
const rSign = session => (session.R.toAffine().y & 1n) ? -1n : 1n;

test('tree messages and nested payload reproduce the in-memory nested partial', async () => {
 const { card, client, server, serverSecret, ctx, aggregate } = await fixture();
 const sweepRoot = sha256('sweep');
 const { node } = batch({ client, aggregate, ctx, sweepRoot });
 const tree = sdk.TxTree.create([{ tx: Buffer.from(node.toPSBT()).toString('base64'), children: [] }]);
 const message = treeMessage(tree, [...tree.iterator()][0], { scriptRoot: sweepRoot, rootAmount: 7499n });
 assert.match(message.msg32, /^[0-9a-f]{64}$/);
 assert.equal(message.tweak32.length, 64);
 assert.deepEqual(message.cosigners, [hex(aggregate)]);
 // The card share plus the server share must equal the ONE outer participant's
 // share and aggregate into a signature that verifies against the batch key.
 const nonce = await card.getNonces();
 const k1 = new SoftwareCardSigner().secret, k2 = new SoftwareCardSigner().secret;
 const serverNonce66 = Uint8Array.from([...secp256k1.getPublicKey(k1), ...secp256k1.getPublicKey(k2)]);
 const aggNonce = musig.nonceAggregate([nonce.publicNonce, serverNonce66]);
 const { session, outer } = nestedPayload({ message, clientNonce: nonce, serverNonce: serverNonce66, client, server, aggregate: hex(aggregate) });
 const { partial } = await finalizeSession(card, nonce, session);
 const inner = new musig.Session(aggNonce, musig.sortKeys([bytes(client), bytes(server)]), bytes(message.msg32));
 const aAgg = outer.getSessionKeyAggCoeff(pointOf(bytes(hex(aggregate))));
 const aS = inner.getSessionKeyAggCoeff(pointOf(bytes(server)));
 const global = modN(gQ(outer) * outer.gAcc);
 const serverShare = scalarBytes(modN(rSign(outer) * modN(numOf(k1) + modN(BigInt(outer.b) * numOf(k2))))
  + BigInt(outer.e) * aAgg * global * aS * numOf(serverSecret));
 const combined = scalarBytes(numOf(partial) + numOf(serverShare));
 assert(outer.partialSigVerify(combined, [aggNonce], 0), 'combined share must verify against the outer key');
 const signature = outer.partialSigAgg([combined]);
 assert(schnorr.verify(signature, bytes(message.msg32), session.Q.toBytes(true).slice(1)));
});

test('runBoard dry run is GET-only and prints the plan', async () => {
 const { client, info, ctx, arkAddress, script } = await fixture();
 const seen = [];
 const out = await runBoard({}, {
  client, server: info.server_pubkey, script, arkAddress,
  operator: OPERATOR, log: () => {},
  request: async (path, body) => { seen.push([path.split('?')[0], body]); assert(path.startsWith('/v4/arkade/info')); return info; },
  esplora: async () => [utxo],
  fetch: async () => { throw new Error('no direct fetch in dry run'); },
  validateTree: () => {},
 });
 assert.equal(out.mode, 'dry-run');
 assert.equal(out.status, 'planned');
 assert.equal(out.vtxo_sats, 7499);
 assert.equal(out.confirmation, 'board-7499');
 assert.equal(out.utxos.length, 1);
 assert.equal(out.register_proof_inputs, 2);
 assert.equal(out.direct_sign_requests.length, 2);
 assert(out.card_sessions >= 3);
 assert.deepEqual(seen.map(s => s[0]), ['/v4/arkade/info']);
});

test('runBoard execute drives approval, tree and finalization to a settled VTXO', async () => {
 const { card, client, server, serverSecret, info, ctx, keys, aggregate, arkAddress, script } = await fixture();
 const dir = await mkdtemp(join(tmpdir(), 'nuri-board-'));
 const state = { approvals: new Map(), next: 1, seen: [], vtxos: [], forfeits: null };
 const sweepRoot = sha256('sweep');
 const built = batch({ client, aggregate, ctx, sweepRoot });
 const checkApproval = (token, row) => {
  const allowed = state.approvals.get(token);
  assert(allowed, 'unknown approval token');
  const key = [row.kind ?? 'direct', row.txid ?? '', row.msg32, row.client_pk33, row.tweak32 ?? ''].join('|');
  assert(allowed.has(key), `request not approved: ${key}\napproved: ${[...allowed].join('\n')}`);
 };
 const request = async (path, body) => {
  state.seen.push([path.split('?')[0], body]);
  if (path.startsWith('/v4/arkade/info')) return info;
  if (path === '/v4/arkade/auth') return { token: 'sess', challenge: 'chal', rp_id: 'nuri.com', origin: 'https://arkade.nuri.com' };
  if (path === '/api/arkade/receive/boarding-address') return { ok: true, boarding_address: { address: body.boarding_address } };
  if (path === '/api/arkade/receive/sync') return { ok: true, boarding: [{ txid: BOARDING_TXID, vout: 0, status: "confirmed" }] };
  if (path === '/api/arkade/receive/boarding/sweep/approve') {
   assert(body.client_pk33 === client);
   assert.deepEqual(body.selected_outpoints, [`${BOARDING_TXID}:0:7499`]);
   assert.equal(body.selected_total_sats, 7499);
   if (!body.boarding_sweep_session_token) {
    assert(body.token === 'sess'); assert(body.sig_b64u === 'sig'); assert(body.psbt_b64);
   } else assert.equal(body.boarding_sweep_session_token, 'sweep-session');
   const token = `approval-${state.next++}`;
   console.error('APPROVE ROWS', JSON.stringify(body.sign_requests.map(r => [r.kind, r.txid, r.msg32?.slice(0,8), r.tweak32?.slice(0,8)])));
   state.approvals.set(token, new Set(body.sign_requests.map(row => [row.kind ?? 'direct', row.txid ?? '', row.msg32, row.client_pk33, row.tweak32 ?? ''].join('|'))));
   return { approval_token: token, approval_scope: 'boarding_sweep', boarding_sweep_session_token: 'sweep-session', boarding_sweep_session_expires_at_ms: Date.now() + 600000 };
  }
  if (path === '/v4/arkade/sign') {
   checkApproval(body.approval_token, { kind: 'direct', msg32: body.msg32, client_pk33: body.client_pk33 });
   const other = musig.deterministicSign(serverSecret, bytes(body.client_pub_nonce), keys, bytes(body.msg32));
   return { server_pub_nonce66: hex(other.publicNonce), server_partial32: hex(other.partialSig), server_pubkey: server };
  }
  if (path === '/v4/arkade/tree/session-init') {
   assert.equal(body.client_pk33, client);
   assert.equal(body.txids.length, 1);
   return { session_id: 'tree-session' };
  }
  if (path === '/v4/arkade/tree/nonce' || path === '/v4/arkade/tree/sign') {
   checkApproval(body.approval_token, { kind: 'tree', txid: body.txid, msg32: body.msg32, client_pk33: body.client_pk33, tweak32: body.tweak32 });
   assert.equal(body.session_id, 'tree-session');
   // Nested tree share, exactly like computeNestedServerOuterPartial.
   const share = (k1, k2) => {
    const clientPubNonce = bytes(body.client_pub_nonce);
    const aggNonce = musig.nonceAggregate([clientPubNonce, state.treeNonce[body.txid]]);
    const outer = new musig.Session(aggNonce, musig.sortKeys([bytes(hex(aggregate))]), bytes(body.msg32), [bytes(body.tweak32)], [true]);
    const inner = new musig.Session(aggNonce, keys, bytes(body.msg32));
    const aAgg = outer.getSessionKeyAggCoeff(pointOf(bytes(hex(aggregate))));
    const aS = inner.getSessionKeyAggCoeff(pointOf(bytes(server)));
    const global = modN(gQ(outer) * outer.gAcc);
    return scalarBytes(modN(rSign(outer) * modN(numOf(k1) + modN(BigInt(outer.b) * numOf(k2))))
     + BigInt(outer.e) * aAgg * global * aS * numOf(serverSecret));
   };
   if (path.endsWith('nonce')) {
    const k1 = new SoftwareCardSigner().secret, k2 = new SoftwareCardSigner().secret;
    state.treeNonce = { ...(state.treeNonce ?? {}), [body.txid]: Uint8Array.from([...secp256k1.getPublicKey(k1), ...secp256k1.getPublicKey(k2)]) };
    state.treeK = { k1: numOf(k1), k2: numOf(k2) };
    return { txid: body.txid, server_pub_nonce66: hex(state.treeNonce[body.txid]), server_pubkey: server };
   }
   return { txid: body.txid, server_pub_nonce66: hex(state.treeNonce[body.txid]),
    server_partial32: hex(share(state.treeK.k1, state.treeK.k2)), server_pubkey: server };
  }
  throw new Error(`unexpected route ${path}`);
 };
 let release;
 const registered = new Promise(resolve => { release = resolve; });
 const operator = {
  async registerIntent(intent) { assert(intent.proof); assert.equal(typeof intent.message, 'object', 'registerIntent wants the raw message'); release(); return 'intent-1'; },
  async deleteIntent() { return true; },
  async confirmRegistration(id) { assert.equal(id, 'intent-1'); },
  async submitTreeNonces(id, pk, nonces) { assert.equal(id, 'batch-1'); assert.equal(pk, hex(aggregate)); assert.equal(nonces.size, 1); },
  async submitTreeSignatures(id, pk, sigs) { assert.equal(pk, hex(aggregate)); state.sigs = sigs; },
  async submitSignedForfeitTxs(forfeits, psbt) {
   assert.deepEqual(forfeits, []);
   state.forfeits = psbt;
   state.vtxos = [{ txid: built.node.id, vout: 0, value: 7499, isSpent: false, isSwept: false, script: ctx.script }];
  },
  getEventStream(signal, topics) {
   assert.deepEqual(topics, [hex(aggregate), `${BOARDING_TXID}:0`]);
   const chunk = { tx: Buffer.from(built.node.toPSBT()).toString('base64'), children: [] };
   const intentHash = createHash('sha256').update('intent-1').digest('hex');
   async function* stream() {
    await registered;
    yield { type: 'batch_started', id: 'batch-1', intentIdHashes: [intentHash], batchExpiry: 604672n };
    yield { type: 'tree_tx', batchIndex: 0, chunk };
    yield { type: 'tree_signing_started', id: 'batch-1', cosignersPublicKeys: [hex(aggregate)], unsignedCommitmentTx: Buffer.from(built.commitment.toPSBT()).toString('base64') };
    yield { type: 'tree_nonces', id: 'batch-1', txid: built.node.id, nonces: { [hex(aggregate)]: { pubNonce: state.treeNonce[built.node.id] } } };
    yield { type: 'batch_finalization', id: 'batch-1', commitmentTx: Buffer.from(built.commitment.toPSBT()).toString('base64') };
    yield { type: 'batch_finalized', txid: 'commitment-1', commitmentTxid: built.commitment.id };
    void signal;
   }
   return stream();
  },
 };
 const bridge = {
  async request(op, payload) { assert.equal(op, 'assert'); assert.equal(payload.credential.length > 10, true); return { client_data_b64u: 'cd', auth_data_b64u: 'ad', sig_b64u: 'sig' }; },
  async getPublicKey() { return bytes(client); },
  getNonces: () => card.getNonces(),
  finalize: payload => card.finalize(payload),
  close() {},
 };
 const receipt = await runBoard({ execute: true }, {
  env: { NURI_SEND_CONFIRM: 'board-7499', NURI_BOARD_RECEIPT_PATH: join(dir, 'receipt.json') },
  bridge, client, server, script, arkAddress, operator: OPERATOR,
  request, esplora: async () => [utxo], arkProvider: operator, validateTree: () => {}, log: () => {},
  indexer: { getVtxos: async ({ scripts }) => { assert.deepEqual(scripts, [script]); return { vtxos: state.vtxos }; } },
  persistReceipt: async (receiptData, opts) => { state.receipt = JSON.parse(JSON.stringify(receiptData)); void opts; },
 });
 assert.equal(receipt.status, 'indexer_verified');
 assert.equal(receipt.indexer_verified, true);
 assert.equal(receipt.intent_id, 'intent-1');
 assert.equal(receipt.tree_txs, 1);
 assert.equal(receipt.proofs.filter(p => p.scope === 'tree').length, 1);
 assert.equal(receipt.proofs.filter(p => p.scope === 'boarding_input').length, 1);
 assert(receipt.proofs.every(p => p.bip340_verified));
 assert(state.forfeits);
 const saved = JSON.parse(await readFile(join(dir, 'receipt.json'), 'utf8').catch(() => 'null')) ?? state.receipt;
 assert.equal(saved.status, 'indexer_verified');
 assert.equal(state.sigs.size, 1);
 await rm(dir, { recursive: true, force: true });
});

test('runBoard execute refuses a wrong confirmation before any card work', async () => {
 const { client, info, ctx, arkAddress, script } = await fixture();
 let calls = 0;
 const out = runBoard({ execute: true }, {
  client, server: info.server_pubkey, script, arkAddress, operator: OPERATOR,
  env: { NURI_SEND_CONFIRM: 'board-1', NURI_BOARD_RECEIPT_PATH: join(tmpdir(), `nope-${Date.now()}.json`) },
  request: async (path) => { calls++; assert(path.startsWith('/v4/arkade/info')); return info; },
  esplora: async () => [utxo], log: () => {},
  bridgeFactory: async () => { throw new Error('card must not open'); },
 });
 await assert.rejects(out, /NURI_SEND_CONFIRM=board-7499 required/);
 assert.equal(calls, 1);
});

test('a refused registration signs and sends the delete proof', async () => {
 const { card, client, server, serverSecret, info, ctx, keys, arkAddress, script, aggregate } = await fixture();
 const state = { approvals: new Map(), next: 1, deleted: null, requested: [] };
 const request = async (path, body) => {
  if (path.startsWith('/v4/arkade/info')) return info;
  if (path === '/v4/arkade/auth') return { token: 'sess', challenge: 'chal', rp_id: 'nuri.com', origin: 'https://arkade.nuri.com' };
  if (path === '/api/arkade/receive/boarding-address') return { ok: true, boarding_address: { address: body.boarding_address } };
  if (path === '/api/arkade/receive/sync') return { ok: true, boarding: [{ txid: BOARDING_TXID, vout: 0, status: "confirmed" }] };
  if (path === '/api/arkade/receive/boarding/sweep/approve') {
   const token = `approval-${state.next++}`;
   state.approvals.set(token, new Set(body.sign_requests.map(row => row.msg32)));
   state.requested.push(body.sign_requests.length);
   return { approval_token: token, approval_scope: 'boarding_sweep', boarding_sweep_session_token: 'sweep-session' };
  }
  if (path === '/v4/arkade/sign') {
   assert(state.approvals.get(body.approval_token).has(body.msg32), 'unapproved sign');
   const other = musig.deterministicSign(serverSecret, bytes(body.client_pub_nonce), keys, bytes(body.msg32));
   return { server_pub_nonce66: hex(other.publicNonce), server_partial32: hex(other.partialSig), server_pubkey: server };
  }
  throw new Error(`unexpected ${path}`);
 };
 const operator = {
  async registerIntent() { const error = new Error('duplicated input'); throw error; },
  async deleteIntent(intent) {
   assert(intent.proof);
   // The delete proof must carry real signatures on both of its inputs.
   const tx = sdk.Transaction.fromPSBT(Buffer.from(intent.proof, 'base64'));
   for (let i = 0; i < tx.inputsLength; i++) assert.equal(tx.getInput(i).tapScriptSig.length, 1);
   state.deleted = sdk.Intent.encodeMessage(intent.message);
   return true;
  },
 };
 const bridge = {
  async request() { return { client_data_b64u: 'cd', auth_data_b64u: 'ad', sig_b64u: 'sig' }; },
  async getPublicKey() { return bytes(client); },
  getNonces: () => card.getNonces(),
  finalize: payload => card.finalize(payload),
  close() {},
 };
 await assert.rejects(runBoard({ execute: true }, {
  env: { NURI_SEND_CONFIRM: 'board-7499', NURI_BOARD_RECEIPT_PATH: join(tmpdir(), `del-${Date.now()}.json`) },
  bridge, client, server, script, arkAddress, operator: OPERATOR, request, esplora: async () => [utxo],
  arkProvider: operator, validateTree: () => {}, log: () => {}, persistReceipt: async () => {},
 }), /before operator submission/);
 assert.equal(state.deleted, '{"type":"delete","expire_at":0}');
 assert.deepEqual(state.requested, [2, 2]);
 void aggregate;
});
