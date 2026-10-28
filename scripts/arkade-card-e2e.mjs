#!/usr/bin/env node
// Zero-funds probe. No transaction submission, intent registration or batch joining.
import assert from 'node:assert/strict';
import { randomBytes, createHash, generateKeyPairSync, sign as p256sign, createPrivateKey } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import * as musig from '@scure/btc-signer/musig2.js';
import { NETWORK } from '@scure/btc-signer';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { VtxoScript, MultisigTapscript, CSVMultisigTapscript, RestIndexerProvider } from '@arkade-os/sdk';
const N = secp256k1.Point.CURVE().n;
const hex = b => Buffer.from(b).toString('hex');
const bytes = h => Uint8Array.from(Buffer.from(h, 'hex'));
const num = b => BigInt('0x' + hex(b));
const scalar = n => bytes(((n % N + N) % N).toString(16).padStart(64, '0'));
const mod = n => (n % N + N) % N;
const sha = b => createHash('sha256').update(b).digest();
const cat = (...b) => Uint8Array.from(Buffer.concat(b.map(x => Buffer.from(x))));
const point = b => secp256k1.Point.fromBytes(b);
const randomScalar = () => { let b; do { b = randomBytes(32); } while (num(b) === 0n || num(b) >= N); return b; };
export const CARD_COMPARISON_KEY = '02a0d209ad2861d00e527376db77810865a5284879e029ec07f4d29a26e1475e96';

// Exact card scalar semantics: s = +/- (k1+b*k2) + e*a*d mod n.
// Host incorporates aggregate-key parity in a; applet does not do this itself.
export class SoftwareCardSigner {
  constructor(secret = randomScalar()) {
    let d = num(secret); assert(d > 0n && d < N);
    if (secp256k1.getPublicKey(scalar(d))[0] === 3) d = N - d;
    this.secret = scalar(d);
  }
  async getPublicKey() { return secp256k1.getPublicKey(this.secret); }
  async getNonces() {
    this.k1?.fill(0); this.k2?.fill(0);
    this.k1 = randomScalar(); this.k2 = randomScalar(); this.token = randomBytes(4);
    return { publicNonce: cat(secp256k1.getPublicKey(this.k1), secp256k1.getPublicKey(this.k2)), token: Uint8Array.from(this.token) };
  }
  async finalize(payload) {
    const k1 = this.k1, k2 = this.k2, token = this.token;
    this.k1 = this.k2 = this.token = null; // burn before validation, including failures
    try {
      assert(k1 && k2, 'nonce session absent or already consumed');
      assert.equal(payload.length, 231, 'FINALIZE must be 231 bytes');
      assert.deepEqual(Buffer.from(payload.slice(97, 101)), token, 'nonce token mismatch');
      const parity = payload[64]; assert(parity === 0 || parity === 1);
      const R = point(payload.slice(101, 166)); point(payload.slice(166, 231));
      assert.equal(Number(R.toAffine().y & 1n), parity, 'R parity mismatch');
      const a = num(payload.slice(0, 32)), b = num(payload.slice(32, 64)), e = num(payload.slice(65, 97));
      const nonce = mod(num(k1) + b * num(k2));
      return scalar((parity ? -nonce : nonce) + e * a * num(this.secret));
    } finally { k1?.fill(0); k2?.fill(0); }
  }
}

// Persistent JSON-lines child preserves the PC/SC connection and nonce token.
// Never constructed by the default software command; explicitly opt in later.
export class PythonCardSigner {
  constructor() {
    assert(process.env.NURI_CARD_PIN, 'NURI_CARD_PIN environment required');
    assert(process.env.NURI_MUSIG2_AID, 'NURI_MUSIG2_AID environment required');
    this.child = spawn(process.env.PYTHON_BIN || 'python3', [new URL('./arkade-card-e2e-bridge.py', import.meta.url).pathname], { stdio: ['pipe', 'pipe', 'inherit'], env: process.env });
    this.pending = [];
    createInterface({ input: this.child.stdout }).on('line', l => {
      const p = this.pending.shift(); if (!p) return;
      try { const v = JSON.parse(l); v.error ? p.reject(new Error(v.error)) : p.resolve(v); } catch (e) { p.reject(e); }
    });
    const fail = e => { for (const p of this.pending.splice(0)) p.reject(e); };
    this.child.on('error', fail); this.child.on('exit', () => fail(new Error('card bridge exited')));
  }
  request(op, payload) { return new Promise((resolve, reject) => { this.pending.push({ resolve, reject }); this.child.stdin.write(JSON.stringify({ op, payload }) + '\n'); }); }
  async getPublicKey() { return bytes((await this.request('pubkey')).pubkey); }
  async getNonces() { const v = await this.request('nonces'); return { publicNonce: bytes(v.publicNonce), token: bytes(v.token) }; }
  async finalize(payload) { return bytes((await this.request('finalize', hex(payload))).partial); }
  close() { this.child.stdin.end(); }
}

export async function finalizeSession(signer, nonce, session) {
  const pk = await signer.getPublicKey();
  const a = session.getSessionKeyAggCoeff(point(pk));
  const g = (session.Q.toAffine().y & 1n) ? -1n : 1n;
  const payload = cat(scalar(a * g * session.gAcc), scalar(session.b), [Number(session.R.toAffine().y & 1n)], scalar(session.e), nonce.token, session.R.toBytes(false), session.Q.toBytes(false));
  return { partial: await signer.finalize(payload), payload };
}

export async function localProof(signer = new SoftwareCardSigner()) {
  const pk = await signer.getPublicKey(), otherSecret = randomScalar(), otherPk = musig.IndividualPubkey(otherSecret);
  const keys = musig.sortKeys([pk, otherPk]), msg = sha('Nuri W35 zero-funds domain-separated software proof');
  const nonce = await signer.getNonces();
  const other = musig.deterministicSign(otherSecret, nonce.publicNonce, keys, msg);
  const session = new musig.Session(musig.nonceAggregate([nonce.publicNonce, other.publicNonce]), keys, msg);
  const { partial, payload } = await finalizeSession(signer, nonce, session);
  assert(session.partialSigVerifyInternal(partial, nonce.publicNonce, pk));
  assert(session.partialSigVerifyInternal(other.partialSig, other.publicNonce, otherPk));
  const signature = session.partialSigAgg([partial, other.partialSig]);
  assert(schnorr.verify(signature, msg, session.Q.toBytes(true).slice(1)));
  return { scope: 'LOCAL_SOFTWARE_COUNTERPARTY_NOT_LIVE_SERVER', finalize_bytes: payload.length, client_pk33: hex(pk), aggregate_xonly: hex(session.Q.toBytes(true).slice(1)), msg32: hex(msg), signature64: hex(signature), bip340_verified: true };
}

export function deriveAddresses(clientHex, info, operator) {
  assert.equal(operator.network, 'bitcoin');
  const client = bytes(clientHex), server = bytes(info.server_pubkey), ark = bytes(operator.signerPubkey).slice(1);
  const aggregate = musig.keyAggregate(musig.sortKeys([client, server])).aggPublicKey.toBytes(true);
  const nuri = info.nuri_server_csv;
  assert.equal(nuri.type, 'seconds');
  const make = delay => {
    const value = Number(delay); assert(value > 0 && value % 512 === 0); assert(nuri.value > 0 && nuri.value % 512 === 0);
    return new VtxoScript([
      MultisigTapscript.encode({ pubkeys: [aggregate.slice(1), ark] }).script,
      CSVMultisigTapscript.encode({ pubkeys: [aggregate.slice(1)], timelock: { type: 'seconds', value: BigInt(value) } }).script,
      CSVMultisigTapscript.encode({ pubkeys: [client.slice(1)], timelock: { type: 'seconds', value: BigInt(value + nuri.value) } }).script,
    ]);
  };
  const offchain = make(operator.unilateralExitDelay), boarding = make(operator.boardingExitDelay);
  return { client_pk33: clientHex, server_pk33: info.server_pubkey, aggregate_pk33: hex(aggregate), ark_address: offchain.address('ark', ark).encode(), boarding_address: boarding.onchainAddress(NETWORK), offchain_script: hex(offchain.pkScript), boarding_script: hex(boarding.pkScript) };
}

async function request(url, body) {
  const u = new URL(url);
  assert(['arkade.nuri.com', 'arkade.computer', 'mempool.space'].includes(u.hostname));
  if (body) assert(['/v4/arkade/auth', '/v4/arkade/sign', '/v4/arkade/tree/nonce'].includes(u.pathname), 'No broadcast/settle/send endpoints allowed');
  const r = await fetch(u, { method: body ? 'POST' : 'GET', headers: { 'content-type': 'application/json', 'user-agent': 'nuri-w35-zero-funds/1' }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(30000) });
  const text = await r.text(); let data; try { data = JSON.parse(text); } catch { throw new Error(`${u.hostname}${u.pathname}: non-JSON HTTP ${r.status}`); }
  return { status: r.status, data };
}
async function get(url) { const r = await request(url); assert.equal(r.status, 200, `GET ${url}`); return r.data; }
async function state(path) {
  try { return JSON.parse(await readFile(path, 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const s = { client_secret: hex(randomScalar()), credential_id: randomBytes(32).toString('base64url'), p256_private_pem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), p256_public_b64u: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
  await mkdir(new URL('.', pathToFileURL(path)).pathname, { recursive: true, mode: 0o700 });
  await writeFile(path, JSON.stringify(s), { mode: 0o600, flag: 'wx' }); return s;
}
export async function runLive(statePath) {
  const s = await state(statePath), signer = new SoftwareCardSigner(bytes(s.client_secret));
  const clientPk = hex(await signer.getPublicKey()), base = 'https://arkade.nuri.com/v4/arkade';
  const operator = await get('https://arkade.computer/v1/info');
  const before = await get(`${base}/info?client_pk33=${clientPk}`);
  // Only registration is a persistent production write; never registers the existing card key.
  assert.notEqual(clientPk, CARD_COMPARISON_KEY);
  const auth = await request(`${base}/auth`, { cred_id_b64u: s.credential_id, cred_pubkey_b64u: s.p256_public_b64u, client_signer_pubkey: clientPk });
  assert.equal(auth.status, 200, 'live software credential registration');
  const info = await get(`${base}/info?client_pk33=${clientPk}&cred_id_b64u=${s.credential_id}`);
  assert.equal(info.recovery?.registered, true, 'registration readback');
  const addresses = deriveAddresses(clientPk, info, operator);
  const cardInfo = await get(`${base}/info?client_pk33=${CARD_COMPARISON_KEY}`);
  const comparison = deriveAddresses(CARD_COMPARISON_KEY, cardInfo, operator);
  const indexer = new RestIndexerProvider('https://arkade.computer');
  const balances = {};
  for (const [label, a] of [['software', addresses], ['existing_card', comparison]]) {
    const offchain = await indexer.getVtxos({ scripts: [a.offchain_script], spendableOnly: true });
    const boarding = await get(`https://mempool.space/api/address/${a.boarding_address}/utxo`);
    assert(!offchain.page?.next, 'pagination must be exhausted');
    balances[label] = { vtxos: offchain.vtxos, page: offchain.page, boarding_utxos: boarding, offchain_sats: offchain.vtxos.reduce((n, v) => n + Number(v.value), 0), boarding_sats: boarding.reduce((n, u) => n + u.value, 0) };
  }
  // Test authorization boundary with a non-transaction digest. No intent, swap or batch is created.
  const msg = sha('Nuri W35 LIVE zero-funds MuSig2 test message - NOT A TRANSACTION');
  const nonce = await signer.getNonces();
  const origins = auth.data.origin; const origin = Array.isArray(origins) ? origins[0] : origins.split(',')[0].trim();
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: auth.data.challenge, origin }));
  const authData = Buffer.concat([sha(auth.data.rp_id), Buffer.from([5, 0, 0, 0, 0])]);
  const assertion = { token: auth.data.token, client_data_b64u: clientData.toString('base64url'), auth_data_b64u: authData.toString('base64url'), sig_b64u: p256sign('sha256', Buffer.concat([authData, sha(clientData)]), createPrivateKey(s.p256_private_pem)).toString('base64url') };
  const signing = await request(`${base}/sign`, { ...assertion, msg32: hex(msg), client_pk33: clientPk, client_pub_nonce: hex(nonce.publicNonce), tweak32: '' });
  let liveSignature = null;
  if (signing.status === 200) {
    assert.equal(signing.data.server_pubkey, before.server_pubkey);
    const keys = musig.sortKeys([await signer.getPublicKey(), bytes(info.server_pubkey)]);
    const otherNonce = bytes(signing.data.server_pub_nonce66), otherPartial = bytes(signing.data.server_partial32);
    const session = new musig.Session(musig.nonceAggregate([nonce.publicNonce, otherNonce]), keys, msg);
    assert(session.partialSigVerifyInternal(otherPartial, otherNonce, bytes(info.server_pubkey)));
    const { partial } = await finalizeSession(signer, nonce, session);
    assert(session.partialSigVerifyInternal(partial, nonce.publicNonce, await signer.getPublicKey()));
    const sig = session.partialSigAgg([partial, otherPartial]); assert(schnorr.verify(sig, msg, bytes(addresses.aggregate_pk33).slice(1)));
    liveSignature = { msg32: hex(msg), signature64: hex(sig), bip340_verified: true };
  }
  const tree = await request(`${base}/tree/nonce`, { ...assertion, session_id: 'w35-zero-funds', txid: hex(sha('not-a-real-txid-w35')), msg32: hex(msg), client_pk33: clientPk, client_pub_nonce: hex(nonce.publicNonce) });
  // Token, challenge and assertion are never emitted; only public metadata / policy errors.
  return { timestamp: new Date().toISOString(), mode: 'SOFTWARE_ONLY_NO_SATS_MOVED', registration: { status: auth.status, readback_registered: info.recovery.registered, credential_id: s.credential_id, client_pk33: clientPk, rp_id: auth.data.rp_id, origin: auth.data.origin }, deployment: { nuri: info.nuri_server_deployment_version, server_version: info.server_version, server_sdk: info.arkade_sdk_version, operator: operator.version }, addresses, comparison, balances, live_sign: signing.status === 200 ? { status: 200, proof: liveSignature } : signing, live_tree_nonce: tree.status === 200 ? { status: 200, note: 'nonce returned; no tree signing attempted' } : tree, local_card_semantics: await localProof(signer), not_executed: ['card / PCSC / phone', 'funding', 'intent registration', 'settle', 'send', 'broadcast', 'operator cooperative signing (needs approved funded transaction)'] };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const allowed = args.every(a => a === '--local' || a === '--live' || a.startsWith('--state=') || a.startsWith('--out='));
  assert(allowed && args.filter(a => a === '--live' || a === '--local').length === 1, 'Usage: --local | --live [--state=<absolute private state>] [--out=<receipt.json>]');
  const result = args.includes('--live') ? await runLive(args.find(a => a.startsWith('--state='))?.slice(8) || `${process.cwd()}/.w35-private/state.json`) : await localProof();
  const output = JSON.stringify(result, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2) + '\n';
  const out = args.find(a => a.startsWith('--out='))?.slice(6); if (out) await writeFile(out, output);
  process.stdout.write(output);
}
