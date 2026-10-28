import assert from 'node:assert/strict';
import { sdk, musig, schnorr, finalizeSession, tapLeafHash, hex, bytes } from './deps.mjs';
export const SOURCE = 'ark1qzpq904am6clw3pgqwyh4p02708fy4xs0hcpwt7rwfdttuxsjameepfv6ed2mgaw4k2tdts49m4wkk3zqyrjv44sr2gcgxrm47gy7sqnlyjr3x';
export const SCRIPT = '5120852cd65aada3aead94b6ae152eeaeb5a2201072656b01a9184187baf904f4013';
export const CLIENT = '02b935bfc0d6d379243205d5c110732400cc8ae82e2fe94d6384963c7c9a62cae6';
export const SERVER = '031dbb179bb996bcd6dc9c9cfccd73c649f987c10c6016650b53789056ae641e29';
export const CREDENTIAL = 'SUulp_FdnSxmGnT_KExCDld8_Ibwt1NOw1AlLau0xsKs8th4iw0sXrvcwHjHAwidXkbJYxzhk1R3WB5gP1GQTY65PbDUpQq2G969WwHhf_23f6upE7cHbUa2a9iWy0HPMSX29OelLq5w4Qr62BVIPg';
export function guard(execute, confirmation, to = SOURCE, amount = '546') {
 if (execute) assert.equal(confirmation, `${to}-${amount}`, `NURI_SEND_CONFIRM=${to}-${amount} required`);
}
export function validTo(to) {
 assert(typeof to === 'string' && (/^@[a-z0-9][a-z0-9-]{0,62}$/.test(to) || /^ark1[0-9a-z]+$/.test(to)), 'to must be an ark1 address or @username');
 return to;
}
export function validAmount(amount) {
 assert(amount === 'all' || (typeof amount === 'string' && /^[1-9][0-9]*$/.test(amount) && Number.isSafeInteger(Number(amount))), 'amount must be positive integer sats or all');
 return amount;
}
export function validateAddress(address, operatorKey) {
 const decoded = sdk.ArkAddress.decode(address);
 assert.equal(decoded.hrp, 'ark', 'mainnet ark address required');
 assert.equal(decoded.version, 0, 'unsupported address version');
 assert.equal(decoded.encode(), address, 'noncanonical address');
 if (operatorKey) assert.equal(hex(decoded.serverPubKey), hex(bytes(operatorKey).slice(-32)), 'address operator mismatch');
 return decoded;
}
export function floorOf(operator) {
 const amounts = [operator.vtxoMinAmount, operator.dust].filter(value => value != null).map(Number);
 assert(amounts.length && amounts.every(value => Number.isSafeInteger(value) && value >= 0), 'node VTXO floor invalid');
 const floor = Math.max(...amounts);
 assert(floor > 0, 'node VTXO floor invalid');
 return floor;
}
export function plan(destination, coins, reportedTotal, { amount, floor = 546, operatorKey } = {}) {
 validateAddress(SOURCE, operatorKey); validateAddress(destination, operatorKey);
 assert.equal(hex(sdk.ArkAddress.decode(SOURCE).pkScript), SCRIPT);
 assert(Number.isSafeInteger(floor) && floor > 0, 'invalid floor');
 const wanted = amount === undefined ? String(Math.max(546, floor)) : validAmount(String(amount));
 assert(Array.isArray(coins), 'missing VTXOs');
 assert.equal(new Set(coins.map(c => `${c.txid}:${c.vout}`)).size, coins.length, 'duplicate coins');
 for (const c of coins) {
  assert(/^[0-9a-f]{64}$/.test(c.txid) && Number.isSafeInteger(c.vout) && c.vout >= 0, 'invalid outpoint');
  assert(Number.isSafeInteger(Number(c.value)) && Number(c.value) > 0, 'invalid coin value');
  assert(!c.isSpent && !c.isSwept, 'spent/swept coin');
  assert(!c.assets?.length, 'asset-bearing coin requires a different send');
  if (c.script) assert.equal(c.script, SCRIPT, 'source script mismatch');
 }
 const rows = coins.map(c => [c.txid, c.vout, Number(c.value)]).sort((a,b) => `${a[0]}:${a[1]}`.localeCompare(`${b[0]}:${b[1]}`));
 const total = rows.reduce((s, c) => s + c[2], 0);
 assert(Number.isSafeInteger(total), 'unsafe total'); assert.equal(total, reportedTotal, 'indexer total differs');
 const sent = wanted === 'all' ? total : Number(wanted);
 if (wanted !== 'all') assert(sent >= floor, 'recipient below operator floor');
 const required = wanted === 'all' ? Math.max(546, floor) : sent;
 const summary = { source: SOURCE, recipient: destination, inputs: rows, input_sats: total, recipient_sats: sent,
  fee_sats: 0, change_sats: total - sent, floor_sats: floor, amount: wanted, type: 'ark_offchain' };
 if (total === 0) return { ...summary, recipient_sats: wanted === 'all' ? required : sent, change_sats: 0,
  status: 'needs_funding', minimum_funding_sats: required, message: `fund ${SOURCE} >=${required} sats` };
 assert(sent >= floor, 'recipient below operator floor'); assert(sent <= total, 'insufficient balance');
 assert(total === sent || total - sent >= floor, 'change below operator floor; use a smaller amount or all');
 return { ...summary, status: 'planned' };
}

// The adapter signs ONLY script-path aggregate-key leaves. No fallback key-path
// spend, settling, recovery or arbitrary digest signing is implemented.
export class CardIdentity {
 constructor({ card, http, client = CLIENT, server = SERVER, credential = CREDENTIAL, intentId, approve, log = () => {} }) {
  Object.assign(this, { card, http, client, server, credential, intentId, approve, log });
  this.keys = musig.sortKeys([bytes(client), bytes(server)]);
  this.aggregate = musig.keyAggregate(this.keys).aggPublicKey.toBytes(true).slice(1);
 }
 async sign(tx, indexes) {
  // SDK signs checkpoints with Promise.all; one physical card nonce session
  // must nevertheless finish before the next GET_NONCES.
  const previous = this.signQueue ?? Promise.resolve();
  const current = previous.then(() => this.signSerial(tx, indexes));
  this.signQueue = current;
  return current;
 }
 async signSerial(tx, indexes) {
  const result = tx.clone();
  const psbt = Buffer.from(tx.toPSBT()).toString('base64');
  const prev = Array.from({ length: tx.inputsLength }, (_, i) => tx.getInput(i).witnessUtxo);
  assert(prev.every(Boolean), 'missing prevout');
  const pkg = { cred_id_b64u: this.credential, client_signer_pubkey: this.client,
   route_scope: 'direct_send_session', approval_scope: 'direct_send_session', psbt_b64: psbt, send_intent_id: this.intentId };
  if (!this.prepared) {
   this.log('send/prepare');
   this.prepared = await this.http('/api/arkade/send/prepare', pkg);
   assert(this.prepared.challenge_token && this.prepared.challenge);
   assert.equal(this.prepared.rp_id, 'nuri.com');
   const origins = Array.isArray(this.prepared.origin) ? this.prepared.origin : String(this.prepared.origin).split(',').map(s => s.trim());
   assert(origins.includes('https://arkade.nuri.com'), 'server does not allow card claim origin');
   this.log('FIDO2 assertion');
   this.assertion = await this.approve({ challenge: this.prepared.challenge, rp_id: this.prepared.rp_id, origin: 'https://arkade.nuri.com', credential: this.credential });
   assert.equal(hex(await this.card.getPublicKey()), this.client, 'wrong card key');
  }
  for (const i of indexes ?? Array.from({ length: tx.inputsLength }, (_, k) => k)) {
   const input = tx.getInput(i);
   assert.equal(input.sighashType ?? 0, 0, 'only SIGHASH_DEFAULT supported');
   assert.equal(input.tapLeafScript?.length, 1, 'exactly one script leaf required');
   const leaf = input.tapLeafScript[0][1];
   const script = leaf.slice(0, -1), version = leaf.at(-1);
   // Match a real 32-byte push in the cooperative 2-key CHECKSIG leaf,
   // not an incidental byte substring in a different script.
   const decoded = sdk.MultisigTapscript.decode(script);
   assert(decoded.params.pubkeys.some(p => hex(p) === hex(this.aggregate)), 'owner not in leaf');
   const msg = tx.preimageWitnessV1(i, prev.map(v => v.script), 0, prev.map(v => v.amount), undefined, script, version);
   this.log('card GET_NONCES');
   const nonce = await this.card.getNonces();
   this.log('send/cosign');
   const response = await this.http('/api/arkade/send/cosign', {
    ...pkg, ...this.assertion, challenge_token: this.prepared.challenge_token,
    cosign_requests: [{ msg32: hex(msg), input_index: i, client_pk33: this.client, client_pub_nonce: hex(nonce.publicNonce) }],
   });
   assert.equal(response.server_pubkey, this.server, 'cosigner key changed');
   const row = response.signatures?.[0] ?? response;
   assert.equal(row.msg32, hex(msg), 'cosigner message mismatch');
   const sn = bytes(row.server_pub_nonce66), sp = bytes(row.server_partial32);
   const session = new musig.Session(musig.nonceAggregate([nonce.publicNonce, sn]), this.keys, msg);
   this.log('verify server partial');
   assert(session.partialSigVerifyInternal(sp, sn, bytes(this.server)), 'invalid server partial');
   this.authAccepted = { accepted: true, evidence: 'send/cosign returned verified server partial', rp_id: this.prepared.rp_id, origin: 'https://arkade.nuri.com', client_key: this.client, server_key: this.server };
   this.log('card FINALIZE');
   const { partial } = await finalizeSession(this.card, nonce, session);
   assert(session.partialSigVerifyInternal(partial, nonce.publicNonce, bytes(this.client)), 'invalid card partial');
   const signature = session.partialSigAgg([partial, sp]);
   this.log('verify aggregate');
   assert(schnorr.verify(signature, msg, this.aggregate), 'invalid aggregate signature');
   this.proofs ??= [];
   this.proofs.push({ transaction_id: tx.id, input_index: i, msg32: hex(msg), client_key: this.client, server_key: this.server, aggregate_key: hex(this.aggregate), client_public_nonce: hex(nonce.publicNonce), server_public_nonce: hex(sn), card_partial: hex(partial), server_partial: hex(sp), aggregate_signature: hex(signature), card_partial_verified: true, server_partial_verified: true, bip340_verified: true });
   result.updateInput(i, { tapScriptSig: [[{ pubKey: this.aggregate, leafHash: tapLeafHash(script, version) }, signature]] });
  }
  return result;
 }
}
