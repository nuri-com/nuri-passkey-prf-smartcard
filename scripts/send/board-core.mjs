// Pure boarding-sweep (onboard) protocol logic, no I/O.
//
// A sweep turns confirmed onchain boarding UTXOs into a VTXO in the card's own
// Arkade wallet by joining an operator batch. It is the flow the Nuri app runs
// through `Ramps.onboard` -> `wallet.settle` (services/arkade/internal/
// receiveAutoSweep.ts:1099), with the client MuSig2 half produced by the card
// applet instead of an in-memory key.
//
// Card signatures per sweep, all sequential (one nonce session at a time):
//   2  register-intent proof  (intentProofJobs: message input + one per coin)
//   2  delete-intent proof    (signed lazily, only if a registration must go)
//   N  boarding inputs        (commitment tx inputs, at batch finalization)
//   T  vtxo-tree transactions (every tree node this client is a cosigner of)
// The tree joins the client key as the OUTER cosigner and the client's partial
// is its contribution to the *inner* (client+server) aggregate, scaled into the
// outer session - see nestedPayload.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sdk, musig, schnorr, finalizeSession, tapLeafHash, hex, bytes } from './deps.mjs';

const N = secp256k1.Point.CURVE().n;
const sha256 = data => new Uint8Array(createHash('sha256').update(Buffer.from(data)).digest());
const point = b => secp256k1.Point.fromBytes(b);
const modN = v => { const m = v % N; return m >= 0n ? m : m + N; };
const TAP_TWEAK_TAG = sha256(new TextEncoder().encode('TapTweak'));

// Measured on the physical card (scripts/send/README.md): GET_NONCES ~0.29 s,
// FINALIZE ~2.06 s. The batch budget is derived from these, never guessed.
export const CARD_NONCE_MS = 290;
export const CARD_FINALIZE_MS = 2060;
export const CARD_SESSION_MS = CARD_NONCE_MS + CARD_FINALIZE_MS;
export const HTTP_RTT_MS = 300;

export function confirmToken(sats) {
 return `board-${sats}`;
}
export function guardBoard(execute, confirmation, sats) {
 if (execute) assert.equal(confirmation, confirmToken(sats), `NURI_SEND_CONFIRM=${confirmToken(sats)} required`);
}

/** Card sessions a sweep needs. The delete proof is optional (signed lazily). */
export function cardSessions({ inputs, treeTxs }) {
 assert(Number.isSafeInteger(inputs) && inputs >= 0);
 assert(Number.isSafeInteger(treeTxs) && treeTxs >= 0);
 return 2 * (1 + inputs) + treeTxs;
}
export const DELETE_PROOF_SESSIONS = 2;
export function estimatedMs(sessions) {
 return sessions * (CARD_SESSION_MS + HTTP_RTT_MS);
}

/**
 * The boarding script of a card wallet.
 *
 * Same three-leaf program as the offchain script (aggregate cooperative spend,
 * CSV aggregate exit, CSV client-only recovery) timed with the operator's
 * boardingExitDelay: scripts/arkade-card-e2e.mjs:106-115. The UTXO pays a plain
 * P2TR to the tweaked key, so it moves cooperatively (batch) or through the CSV
 * exits only.
 */
export function boardingContext(client, info, operator) {
 assert.equal(operator?.network, 'bitcoin', 'mainnet operator required');
 const clientKey = bytes(client), serverKey = bytes(info?.server_pubkey), arkKey = bytes(operator.signerPubkey).slice(1);
 const aggregate = musig.keyAggregate(musig.sortKeys([clientKey, serverKey])).aggPublicKey.toBytes(true);
 const nuri = info?.nuri_server_csv;
 assert.equal(nuri?.type, 'seconds', 'nuri recovery timelock missing');
 const delay = Number(operator.boardingExitDelay);
 assert(Number.isSafeInteger(delay) && delay > 0 && delay % 512 === 0, 'operator boarding delay invalid');
 assert(Number.isSafeInteger(nuri.value) && nuri.value > 0 && nuri.value % 512 === 0, 'nuri recovery timelock invalid');
 const cooperative = sdk.MultisigTapscript.encode({ pubkeys: [aggregate.slice(1), arkKey] }).script;
 const tree = new sdk.VtxoScript([
  cooperative,
  sdk.CSVMultisigTapscript.encode({ pubkeys: [aggregate.slice(1)], timelock: { type: 'seconds', value: BigInt(delay) } }).script,
  sdk.CSVMultisigTapscript.encode({ pubkeys: [clientKey.slice(1)], timelock: { type: 'seconds', value: BigInt(delay + nuri.value) } }).script,
 ]);
 const leaf = tree.findLeaf(hex(cooperative));
 assert.equal(leaf.length, 2, 'cooperative leaf malformed');
 assert.equal(hex(tree.pkScript).slice(0, 4), '5120', 'boarding output must be P2TR');
 return { script: hex(tree.pkScript), address: tree.onchainAddress(), boarding_exit_delay: delay,
  nuri_recovery_delay: nuri.value, aggregate_pk33: hex(aggregate), aggregate_xonly: hex(aggregate.slice(1)),
  cooperative_script: hex(cooperative), tree, leaf };
}

/** Validate raw Esplora rows against the boarding script; flag ineligibility. */
export function boardingCandidates(raw, { script, floor }) {
 assert(Array.isArray(raw), 'missing boarding utxos');
 assert(/^5120[0-9a-f]{64}$/.test(script), 'invalid boarding script');
 assert(Number.isSafeInteger(floor) && floor > 0, 'invalid operator floor');
 const seen = new Set();
 const rows = [];
 for (const utxo of raw) {
  assert(/^[0-9a-f]{64}$/.test(String(utxo?.txid || '')), 'invalid boarding txid');
  assert(Number.isSafeInteger(utxo?.vout) && utxo.vout >= 0, 'invalid boarding vout');
  const key = `${utxo.txid}:${utxo.vout}`;
  assert(!seen.has(key), 'duplicate boarding outpoint');
  seen.add(key);
  const value = Number(utxo.value);
  assert(Number.isSafeInteger(value) && value > 0, 'invalid boarding value');
  if (utxo.scriptpubkey && String(utxo.scriptpubkey).toLowerCase() !== script) continue;
  const height = utxo.status?.confirmed === true ? Number(utxo.status.block_height) : null;
  const reasons = [];
  if (!Number.isSafeInteger(height) || height <= 0) reasons.push('unconfirmed');
  if (value < floor) reasons.push('below_floor');
  rows.push({ txid: utxo.txid, vout: utxo.vout, value, height, script, eligible: reasons.length === 0, reasons });
 }
 rows.sort((a, b) => `${a.txid}:${a.vout}`.localeCompare(`${b.txid}:${b.vout}`));
 return rows;
}

/**
 * Amount planning. The operator charges an intent fee per onchain input and per
 * offchain output (/v1/info `fees.intentFee`; `txFeeRate` is 0 for this
 * operator today), both deducted from the swept amount. The VTXO must clear the
 * operator's VTXO floor and dust.
 */
export function planSweep(utxos, { feeInfo, floor, dust, vtxoMin }) {
 assert(feeInfo?.intentFee, 'operator fee info unavailable');
 assert(Number.isSafeInteger(floor) && floor > 0, 'invalid operator floor');
 const estimator = new sdk.Estimator(feeInfo.intentFee);
 const selected = [];
 let gross = 0, inputFee = 0;
 for (const utxo of utxos) {
  assert(utxo.eligible, 'ineligible boarding utxo selected');
  const fee = estimator.evalOnchainInput({ amount: BigInt(utxo.value) }).satoshis;
  if (BigInt(fee) >= BigInt(utxo.value)) continue;
  selected.push(utxo); gross += utxo.value; inputFee += Number(fee);
 }
 const net0 = gross - inputFee;
 const outputFee = net0 > 0 ? estimator.evalOffchainOutput({ amount: BigInt(net0), script: '' }).satoshis : 0;
 const net = net0 - outputFee;
 const minimum = Math.max(floor, Number(vtxoMin ?? 0), Number(dust ?? 0));
 const summary = {
  inputs: selected.map(u => ({ txid: u.txid, vout: u.vout, value: u.value, height: u.height })),
  gross_sats: gross, input_fee_sats: inputFee, output_fee_sats: Number(outputFee), vtxo_sats: net,
  floor_sats: floor, minimum_vtxo_sats: minimum, type: 'ark_onboard',
 };
 if (!selected.length) return { ...summary, status: 'needs_funding', message: 'no confirmed boarding utxo at or above the operator floor' };
 assert(net > 0, 'boarding amount does not cover operator fees');
 if (net < minimum) return { ...summary, status: 'below_minimum', message: `swept amount ${net} below vtxo minimum ${minimum}` };
 return { ...summary, status: 'planned' };
}

/** Intent proof messages, byte-identical to the SDK's encodeMessage. */
export function registerMessage({ validAt = 0, cosigners }) {
 return { type: 'register', onchain_output_indexes: [], valid_at: Math.floor(validAt), expire_at: 0, cosigners_public_keys: cosigners };
}
export function deleteMessage() {
 return { type: 'delete', expire_at: 0 };
}

/** Unsigned intent proof PSBT over the given boarding coins (sdk Intent.create). */
export function buildProof(message, coins, outputs, ctx) {
 const inputs = coins.map(coin => ({ txid: coin.txid, vout: coin.vout, value: coin.value,
  tapTree: ctx.tree.encode(), intentTapLeafScript: ctx.leaf }));
 // Raw message: RestArkProvider.registerIntent/deleteIntent encode it themselves.
 return { tx: sdk.Intent.create(message, inputs, outputs), message, encoded: sdk.Intent.encodeMessage(message) };
}

/**
 * Direct (PSBT) sign requests, replicating the server's own derivation
 * (src/arkade-sign-requests.js:95-165) so a dry run can show exactly what the
 * approval will cover before any card session exists.
 */
export function directRequests(tx, aggregateXonly) {
 assert(tx.inputsLength > 0, 'psbt has no inputs');
 const prev = [];
 for (let i = 0; i < tx.inputsLength; i++) {
  const input = tx.getInput(i);
  assert(input.witnessUtxo, `psbt input ${i} missing witnessUtxo`);
  assert.equal(input.sighashType ?? 0, 1, `psbt input ${i} must use SIGHASH_ALL`);
  assert.equal(input.tapLeafScript?.length, 1, `psbt input ${i} needs exactly one leaf`);
  const script = input.tapLeafScript[0][1].slice(0, -1);
  assert(sdk.MultisigTapscript.decode(script).params.pubkeys.some(p => hex(p) === aggregateXonly), `input ${i}: owner not in leaf`);
  prev.push(input.witnessUtxo);
 }
 return Array.from({ length: tx.inputsLength }, (_, i) => {
  const leaf = tx.getInput(i).tapLeafScript[0];
  const script = leaf[1].slice(0, -1), version = leaf[1].at(-1);
  const msg = tx.preimageWitnessV1(i, prev.map(v => v.script), 1, prev.map(v => v.amount), undefined, script, version);
  return { kind: 'direct', input_index: i, msg32: hex(msg), leaf_script: script, leaf_version: version, leaf_hash: hex(tapLeafHash(script, version)) };
 });
}

export function applyDirectSignature(tx, request, aggregateXonly, signature) {
 // Inputs are SIGHASH_ALL (asserted in directRequests), so BIP341 wants the
 // 65-byte form sig64||0x01 (nuri-expo lib/bitcoin/taproot.ts:36-41).
 const sig = signature.length === 64 ? Uint8Array.from([...signature, 1]) : signature;
 assert.equal(sig.length, 65, 'tapscript signature must be 65 bytes for SIGHASH_ALL');
 tx.updateInput(request.input_index, { tapScriptSig: [[{ pubKey: bytes(aggregateXonly), leafHash: bytes(request.leaf_hash) }, sig]] });
 return tx;
}

/**
 * Sign one message through the card and the Nuri cosigner, mirroring
 * CardIdentity.signSerial (core.mjs:79-134) and verifying every partial.
 */
export async function signDirect({ card, client, server, aggregate, msg32, sign, log = () => {} }) {
 assert(/^[0-9a-f]{64}$/.test(msg32), 'invalid message');
 const keys = musig.sortKeys([bytes(client), bytes(server)]);
 log('card GET_NONCES');
 const nonce = await card.getNonces();
 log('nuri cosign');
 const response = await sign(msg32, hex(nonce.publicNonce));
 assert.equal(String(response.server_pubkey).toLowerCase(), server, 'cosigner key changed');
 const sn = bytes(response.server_pub_nonce66), sp = bytes(response.server_partial32);
 const session = new musig.Session(musig.nonceAggregate([nonce.publicNonce, sn]), keys, bytes(msg32));
 log('verify server partial');
 assert(session.partialSigVerifyInternal(sp, sn, bytes(server)), 'invalid server partial');
 log('card FINALIZE');
 const { partial } = await finalizeSession(card, nonce, session);
 assert(session.partialSigVerifyInternal(partial, nonce.publicNonce, bytes(client)), 'invalid card partial');
 const signature = session.partialSigAgg([partial, sp]);
 log('verify aggregate');
 assert(schnorr.verify(signature, bytes(msg32), bytes(aggregate).slice(1)), 'invalid aggregate signature');
 return { signature, proof: {
  msg32, client_public_nonce: hex(nonce.publicNonce), server_public_nonce: response.server_pub_nonce66,
  card_partial: hex(partial), server_partial: response.server_partial32,
  aggregate_signature: hex(signature), card_partial_verified: true, server_partial_verified: true, bip340_verified: true,
 } };
}

/** Sign and stamp every input of a proof PSBT. */
export async function signProof(tx, aggregateXonly, deps) {
 const requests = directRequests(tx, aggregateXonly);
 const signed = tx.clone();
 const proofs = [];
 for (const request of requests) {
  const { signature, proof } = await signDirect({ ...deps, msg32: request.msg32 });
  applyDirectSignature(signed, request, aggregateXonly, signature);
  proofs.push({ ...proof, input_index: request.input_index });
 }
 return { tx: signed, proofs };
}

/**
 * Signing material for one tree node.
 *
 * Outer cosigners come from the operator's PSBT field (the intent's declared
 * cosigner = the client key), the tweak from the batch sweep script root, and
 * the prevout from the graph - exactly what TreeSignerSession.signPartial does
 * (dist chunk-ZTGTQP2W.js:202-262).
 */
export function treeMessage(graph, node, { scriptRoot, rootAmount, expectRootScript }) {
 const tx = node.root;
 assert(tx?.inputsLength === 1, 'tree node must have exactly one input');
 const cosigners = sdk.getArkPsbtFields(tx, 0, sdk.CosignerPublicKey).map(c => c.key);
 assert(cosigners.length > 0, 'tree node has no cosigners');
 const outerKeys = musig.sortKeys(cosigners);
 // TapTweak(untweaked x-only, scriptRoot), exactly as the SDK's aggregateKeys /
 // createSession (@arkade-os/sdk chunk-ZTGTQP2W.js:38-43, :94-100). The raw
 // scriptRoot is NOT the tweak (live attempt 16: operator INVALID_SIGNATURE).
 const preTweaked = musig.keyAggregate(outerKeys).aggPublicKey.toBytes(true);
 const tweakBytes = sha256(new Uint8Array([...TAP_TWEAK_TAG, ...TAP_TWEAK_TAG, ...preTweaked.slice(1), ...scriptRoot]));
 const finalKey = musig.keyAggregate(outerKeys, [tweakBytes], [true]).aggPublicKey.toBytes(true);
 const prev = [];
 for (let i = 0; i < tx.inputsLength; i++) {
  let amount, script;
  if (node.txid === graph.txid) {
   amount = rootAmount; script = new Uint8Array([0x51, 0x20, ...finalKey.slice(1)]);
  } else {
   const parentInput = tx.getInput(i);
   const parent = graph.find(hex(parentInput.txid));
   assert(parent, 'tree parent missing');
   const out = parent.root.getOutput(Number(parentInput.index));
   assert(out?.amount, 'tree parent output missing');
   amount = out.amount; script = out.script;
  }
  prev.push({ amount, script });
 }
 const msg = tx.preimageWitnessV1(0, prev.map(p => p.script), 0, prev.map(p => p.amount));
 if (node.txid === graph.txid && expectRootScript) assert.equal(hex(prev[0].script), hex(expectRootScript), 'tree root key does not match the commitment batch output');
 return { txid: node.txid, msg32: hex(msg), tweak32: hex(tweakBytes), cosigners: cosigners.map(c => hex(c)), outerKeys };
}

/**
 * FINALIZE payload inputs for a nested tree signature.
 *
 * The card returns s = +/-(k1 + b*k2) + e*a*d. With
 *   a = outerCoeff * gAcc * innerCoeff   and   e = outer.e
 * FINALIZE's own R-parity sign applied to the nonce term yields exactly the
 * partial ArkadeRemoteSignerSession.computeNestedClientOuterPartial computes
 * with the private key in memory (ArkadeRemoteSignerSession.ts:130-165).
 */
export function nestedPayload({ message, clientNonce, serverNonce, client, server, aggregate, outerAggNonce }) {
 const serverNonceBytes = typeof serverNonce === 'string' ? bytes(serverNonce) : serverNonce;
 // With other outer cosigners (the operator) the session nonce is the aggregate
 // over ALL outer participants (ArkadeRemoteSignerSession.ts:580-650); alone it
 // is just card+server.
 const aggNonce = outerAggNonce ?? musig.nonceAggregate([clientNonce.publicNonce, serverNonceBytes]);
 const outer = new musig.Session(aggNonce, message.outerKeys, bytes(message.msg32), [bytes(message.tweak32)], [true]);
 const inner = new musig.Session(aggNonce, musig.sortKeys([bytes(client), bytes(server)]), bytes(message.msg32));
 // The outer cosigner key is the aggregate (client+server): ArkadeRemoteIdentity
 // .compressedPublicKey returns aggregatedPk33 (ArkadeRemoteIdentity.ts:2300).
 const aggregatePoint = point(bytes(aggregate));
 const clientPoint = point(bytes(client));
 assert(outer.getSessionKeyAggCoeff(aggregatePoint) !== 0n, 'aggregate not an outer cosigner');
 // FINALIZE itself applies the R parity to the nonce term and the Q parity +
 // gAcc to `a`, so `a` is only outerCoeff * innerCoeff. The server's share
 // carries the parity/global factor (computeNestedServerOuterPartial,
 // src/ArkadeServer.js:2871); the two shares sum to the verifier's expectation.
 const a = modN(outer.getSessionKeyAggCoeff(aggregatePoint) * inner.getSessionKeyAggCoeff(clientPoint));
 const session = {
  Q: outer.Q, R: outer.R, b: outer.b, e: outer.e, gAcc: outer.gAcc,
  getSessionKeyAggCoeff: () => a,
  partialSigVerifyInternal: (...args) => outer.partialSigVerifyInternal(...args),
  partialSigAgg: sigs => outer.partialSigAgg(sigs),
 };
 return { session, aggNonce, outer };
}

/** Sign one tree node through the card and the Nuri cosigner. */
export async function signTree({ card, client, server, aggregate, message, nonce, sign, log = () => {} }) {
 log('nuri tree nonce');
 const nonceResponse = await sign.nonce(message, hex(nonce.publicNonce));
 assert.equal(String(nonceResponse.server_pubkey).toLowerCase(), server, 'tree cosigner key changed');
 const serverNonce = nonceResponse.server_pub_nonce66;
 assert(/^[0-9a-f]{132}$/.test(serverNonce), 'invalid server tree nonce');
 const { session, aggNonce, outer } = nestedPayload({ message, clientNonce: nonce, serverNonce, client, server, aggregate });
 log('card FINALIZE (tree)');
 const { partial } = await finalizeSession(card, nonce, session);
 log('nuri tree sign');
 const signResponse = await sign.sign(message, hex(nonce.publicNonce), serverNonce);
 assert.equal(String(signResponse.server_pubkey).toLowerCase(), server, 'tree cosigner key changed');
 const serverPartial = bytes(signResponse.server_partial32);
 // The client share and the server share add up to the ONE outer participant's
 // share (ArkadeRemoteSignerSession.ts:757-800): verify the sum, then aggregate it.
 const combined = scalarOf(modN(scalarValue(partial) + scalarValue(serverPartial)));
 assert(outer.partialSigVerify(combined, [aggNonce], 0), 'invalid combined tree partial');
 const signature = outer.partialSigAgg([combined]);
 assert(schnorr.verify(signature, bytes(message.msg32), session.Q.toBytes(true).slice(1)), 'invalid tree aggregate signature');
 return { txid: message.txid, signature, proof: {
  txid: message.txid, msg32: message.msg32, tweak32: message.tweak32, client_public_nonce: hex(nonce.publicNonce),
  server_public_nonce: serverNonce, card_partial: hex(partial), server_partial: hex(serverPartial),
  aggregate_signature: hex(signature), card_partial_verified: true, server_partial_verified: true, bip340_verified: true,
 } };
}

/**
 * Round 1 of a tree node: card nonce + Nuri server nonce. The pair aggregate is
 * this client's ONE outer nonce, submitted to the operator
 * (ArkadeRemoteSignerSession.getNonces, :509-560).
 */
export async function treeNonce({ server, message, nonce, sign, log = () => {} }) {
 log('nuri tree nonce');
 const res = await sign.nonce(message, hex(nonce.publicNonce));
 assert.equal(String(res.server_pubkey).toLowerCase(), server, 'tree cosigner key changed');
 assert(/^[0-9a-f]{132}$/.test(res.server_pub_nonce66), 'invalid server tree nonce');
 const outerPubNonce = musig.nonceAggregate([nonce.publicNonce, bytes(res.server_pub_nonce66)]);
 return { serverNonce: res.server_pub_nonce66, outerPubNonce };
}

/**
 * Outer aggregate nonce from the operator's tree_nonces event: every cosigner
 * (x-only keyed) in PSBT order, ours replaced by our own pair aggregate
 * (ArkadeRemoteSignerSession.aggregatedNonces, :580-650).
 */
export function outerAggregate(message, eventNonces, aggregate, outerPubNonce) {
 const mine = hex(bytes(aggregate).slice(1));
 const byKey = new Map();
 const entries = eventNonces instanceof Map ? [...eventNonces] : Object.entries(eventNonces ?? {});
 for (const [k, v] of entries) { const n = v?.pubNonce ?? v; byKey.set(String(k).toLowerCase().slice(-64), typeof n === "string" ? bytes(n) : Uint8Array.from(n)); }
 byKey.set(mine, outerPubNonce);
 const byPk33 = new Map();
 const ordered = message.cosigners.map(pk => {
  const n = byKey.get(pk.slice(-64));
  if (!n) return null;
  byPk33.set(pk, n);
  return n;
 });
 if (ordered.some(n => !n)) return null;
 return { aggNonce: musig.nonceAggregate(ordered), byPk33 };
}

/**
 * Round 2: card FINALIZE + server nested partial under the outer aggregate
 * nonce; their sum is our outer participant's partial, verified against the
 * outer session before it goes to the operator (ArkadeRemoteSignerSession.sign, :660-845).
 */
export async function treeSign({ card, client, server, aggregate, message, nonce, serverNonce, outer: agg, sign, log = () => {} }) {
 const { session, outer } = nestedPayload({ message, clientNonce: nonce, serverNonce, client, server, aggregate, outerAggNonce: agg.aggNonce });
 log('card FINALIZE (tree)');
 const { partial } = await finalizeSession(card, nonce, session);
 log('nuri tree sign');
 const res = await sign.sign(message, hex(nonce.publicNonce), hex(agg.aggNonce));
 assert.equal(String(res.server_pubkey).toLowerCase(), server, 'tree cosigner key changed');
 const serverPartial = bytes(res.server_partial32);
 const combined = scalarOf(modN(scalarValue(partial) + scalarValue(serverPartial)));
 const keys = message.outerKeys.map(k => hex(k));
 const index = keys.indexOf(aggregate);
 assert(index >= 0, 'aggregate not in outer keys');
 const ordered = keys.map(k => agg.byPk33.get(k));
 assert(outer.partialSigVerify(combined, ordered, index), 'invalid combined tree partial');
 return { txid: message.txid, partial: combined, proof: {
  txid: message.txid, msg32: message.msg32, tweak32: message.tweak32, client_public_nonce: hex(nonce.publicNonce),
  server_public_nonce: serverNonce, outer_agg_nonce: hex(agg.aggNonce), outer_cosigners: keys.length,
  card_partial: hex(partial), server_partial: hex(serverPartial), combined_partial: hex(combined), combined_partial_verified: true,
 } };
}

function scalarValue(bytes32) { return BigInt('0x' + Buffer.from(bytes32).toString('hex')); }
function scalarOf(value) { return bytes(value.toString(16).padStart(64, '0')); }
