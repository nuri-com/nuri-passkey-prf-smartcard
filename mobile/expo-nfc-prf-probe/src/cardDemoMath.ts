// Pure PIN2 demo math; no NFC, React Native, network, or persistent secrets.
// The caller must provide a secure crypto.getRandomValues implementation.
import * as musig2 from '@scure/btc-signer/musig2.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const mod = (x: bigint) => ((x % N) + N) % N;
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
function bytes(value: Uint8Array, length: number, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new Error(`${name} must be ${length} bytes`);
  return value.slice();
}
function scalar(value: bigint): Uint8Array {
  const result = new Uint8Array(32);
  let x = mod(value);
  for (let i = 31; i >= 0; i--) { result[i] = Number(x & 255n); x >>= 8n; }
  return result;
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}
function point(value: Uint8Array) {
  if (value.length !== 33 || (value[0] !== 2 && value[0] !== 3)) throw new Error('Expected compressed secp256k1 point');
  const result = secp256k1.Point.fromBytes(value);
  result.assertValidity();
  return result;
}

// Checked adapter for the pinned @scure/btc-signer 2.2.0 runtime fields.
type Internals = {
  b: bigint; e: bigint; gAcc: bigint;
  R: ReturnType<typeof point>; Q: ReturnType<typeof point>;
  getSessionKeyAggCoeff: (p: ReturnType<typeof point>) => bigint;
};
function internals(session: musig2.Session): Internals {
  const s = session as unknown as Internals;
  if (typeof s.b !== 'bigint' || typeof s.e !== 'bigint' || typeof s.gAcc !== 'bigint'
    || typeof s.R?.y !== 'bigint' || typeof s.Q?.y !== 'bigint'
    || typeof s.R?.toBytes !== 'function' || typeof s.Q?.toBytes !== 'function'
    || typeof s.getSessionKeyAggCoeff !== 'function') throw new Error('Unsupported MuSig2 session internals');
  return s;
}

export type DemoSignature = {
  pubkey: Uint8Array; // Aggregate BIP340 x-only public key, 32 bytes.
  signature: Uint8Array; // BIP340 signature, 64 bytes.
  verified: true;
};
export type DemoSession = {
  payload: Uint8Array; // a32 || b32 || parity1 || e32 || token4 || R65 || Q65.
  finish: (cardPartial32: Uint8Array) => DemoSignature;
};

/** One-use, random local cosigner for a NON-BROADCAST demo message.
 * cardNonces70 is the entire GET_NONCES response: two points then token4.
 * The returned closure holds only this session's ephemeral secret/nonce. Calling
 * finish consumes and best-effort wipes them even on invalid card responses.
 * JavaScript cannot guarantee erasure of copies held by the runtime/crypto library.
 */
export function prepareDemoSession(cardPubkey33: Uint8Array, cardNonces70: Uint8Array, msg32: Uint8Array): DemoSession {
  const cardKey = bytes(cardPubkey33, 33, 'cardPubkey33');
  const nonces = bytes(cardNonces70, 70, 'cardNonces70');
  const message = bytes(msg32, 32, 'msg32');
  const cardPoint = point(cardKey);
  // Current PIN2 provisioning uses even-y individual card keys.
  if (cardKey[0] !== 2) throw new Error('PIN2 demo requires an even-y card key');
  point(nonces.subarray(0, 33));
  point(nonces.subarray(33, 66));
  const cardNonce = nonces.slice(0, 66);
  let secret: Uint8Array = new Uint8Array(32);
  let secretNonce: Uint8Array | undefined;
  try {
    let publicKey: Uint8Array | undefined;
    let keys: Uint8Array[] | undefined;
    // Match the real-card proof: normalize the local key, then retry until Q
    // is even. Never change/reprovision the card key to satisfy this constraint.
    for (let attempt = 0; attempt < 128; attempt++) {
      secret.fill(0);
      secret = secp256k1.utils.randomSecretKey();
      let p = secp256k1.Point.fromBytes(musig2.IndividualPubkey(secret));
      if (p.y & 1n) {
        const normalized = scalar(-BigInt(`0x${Array.from(secret, b => b.toString(16).padStart(2, '0')).join('')}`));
        secret.fill(0); secret = normalized; p = p.negate();
      }
      const candidate = p.toBytes(true);
      if (same(candidate, cardKey)) continue;
      const sorted = musig2.sortKeys([cardKey, candidate]);
      if (musig2.keyAggregate(sorted).aggPublicKey.y & 1n) continue;
      publicKey = candidate; keys = sorted; break;
    }
    if (!keys || !publicKey) throw new Error('Could not generate even-y demo aggregate key');
    const aggregate = musig2.keyAggregate(keys);
    const pubkey = musig2.keyAggExport(aggregate);
    const localNonces = musig2.nonceGen(publicKey, secret, pubkey, message);
    secretNonce = localNonces.secret;
    const publicNonces = keys.map(k => same(k, cardKey) ? cardNonce : localNonces.public);
    const cardIndex = keys.findIndex(k => same(k, cardKey));
    const localIndex = 1 - cardIndex;
    const session = new musig2.Session(musig2.nonceAggregate(publicNonces), keys, message);
    const s = internals(session);
    const g = s.Q.y & 1n ? -1n : 1n;
    const coefficient = mod(s.getSessionKeyAggCoeff(cardPoint) * g * s.gAcc);
    const payload = concat(scalar(coefficient), scalar(s.b), new Uint8Array([Number(s.R.y & 1n)]),
      scalar(s.e), nonces.slice(66), s.R.toBytes(false), s.Q.toBytes(false));
    if (payload.length !== 231) throw new Error('Invalid PIN2 payload length');
    let consumed = false;
    return {
      payload,
      finish(cardPartial32) {
        if (consumed) throw new Error('Demo session already consumed');
        consumed = true;
        try {
          const partial = bytes(cardPartial32, 32, 'cardPartial32');
          if (!session.partialSigVerify(partial, publicNonces, cardIndex)) throw new Error('Card partial signature verification failed');
          const localPartial = session.sign(secretNonce!, secret);
          if (!session.partialSigVerify(localPartial, publicNonces, localIndex)) throw new Error('Local partial signature verification failed');
          const ordered = keys!.map((_, i) => i === cardIndex ? partial : localPartial);
          const signature = session.partialSigAgg(ordered);
          if (!schnorr.verify(signature, message, pubkey)) throw new Error('Aggregate signature verification failed');
          return { pubkey: pubkey.slice(), signature, verified: true };
        } finally {
          secret.fill(0); secretNonce?.fill(0);
        }
      },
    };
  } catch (error) {
    secret.fill(0); secretNonce?.fill(0);
    throw error;
  }
}
