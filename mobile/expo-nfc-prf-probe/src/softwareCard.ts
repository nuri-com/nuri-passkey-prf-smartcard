// Volatile, pure software PIN2 signing primitive. Not NFC/PIN authentication.
// Caller supplies secure crypto.getRandomValues (as for cardDemoMath).
import { secp256k1 } from '@noble/curves/secp256k1.js';

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const mod = (x: bigint) => ((x % N) + N) % N;
function integer(bytes: Uint8Array): bigint {
  let x = 0n;
  for (const byte of bytes) x = (x << 8n) | BigInt(byte);
  return x;
}
function scalar(x: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  x = mod(x);
  for (let i = 31; i >= 0; i--) { bytes[i] = Number(x & 255n); x >>= 8n; }
  return bytes;
}
function checkedPoint(bytes: Uint8Array, name: string) {
  if (bytes.length !== 65 || bytes[0] !== 4) throw new Error(`${name} must be an uncompressed point`);
  const point = secp256k1.Point.fromBytes(bytes);
  point.assertValidity();
  return point;
}
function randomScalar(): bigint {
  const bytes = secp256k1.utils.randomSecretKey();
  try { return integer(bytes); } finally { bytes.fill(0); }
}

/** In-memory PIN2 scalar emulator; no persistence, device, transport or funds.
 * Each nonces() replaces the outstanding nonce pair. Every finalize attempt
 * burns that pair, including invalid requests. JavaScript cannot promise erasure
 * of bigint secrets or library/runtime copies. This is not a hardware vault.
 */
export class SoftwareCard {
  #secret: bigint;
  #pubkey: Uint8Array;
  #nextToken = integer(globalThis.crypto.getRandomValues(new Uint8Array(4)));
  #issued = 0n;
  #pending?: { k1: bigint; k2: bigint; token: Uint8Array };

  constructor() {
    let x = randomScalar();
    let p = secp256k1.Point.BASE.multiply(x);
    if (p.y & 1n) { x = N - x; p = p.negate(); }
    this.#secret = x;
    this.#pubkey = p.toBytes(true);
  }

  async pubkey(): Promise<Uint8Array> { return this.#pubkey.slice(); }

  /** R1(33) || R2(33) || token(4); token is unique within this card instance. */
  async nonces(): Promise<Uint8Array> {
    this.#pending = undefined;
    if (this.#issued === 0x100000000n) throw new Error('Nonce token space exhausted');
    const k1 = randomScalar(), k2 = randomScalar();
    const token = scalar((this.#nextToken + this.#issued++) & 0xffffffffn).slice(28);
    this.#pending = { k1, k2, token };
    const response = new Uint8Array(70);
    response.set(secp256k1.Point.BASE.multiply(k1).toBytes(true));
    response.set(secp256k1.Point.BASE.multiply(k2).toBytes(true), 33);
    response.set(token, 66);
    return response;
  }

  /** a32 || b32 || parity1 || e32 || token4 || R65 || Q65 -> s32.
   * Checks canonical scalars, valid R/Q, R parity and demo's even-y Q.
   * R/Q aggregation, a/b derivation and e's message binding cannot be checked:
   * this wire format contains neither the peer key/nonces nor the message.
   * The host must verify the partial and final signature (cardDemoMath does).
   */
  async finalize(payload: Uint8Array): Promise<Uint8Array> {
    const pending = this.#pending;
    this.#pending = undefined;
    if (!pending) throw new Error('No active nonces (not generated or already consumed)');
    if (!(payload instanceof Uint8Array) || payload.length !== 231) throw new Error('Payload must be 231 bytes');
    let mismatch = 0;
    for (let i = 0; i < 4; i++) mismatch |= payload[97 + i] ^ pending.token[i];
    if (mismatch !== 0) throw new Error('Invalid nonce token');
    const a = integer(payload.subarray(0, 32));
    const b = integer(payload.subarray(32, 64));
    const parity = payload[64];
    const e = integer(payload.subarray(65, 97));
    if (a >= N || b >= N || e >= N) throw new Error('Non-canonical scalar');
    if (parity !== 0 && parity !== 1) throw new Error('Parity must be 0 or 1');
    const R = checkedPoint(payload.subarray(101, 166), 'R');
    const Q = checkedPoint(payload.subarray(166, 231), 'Q');
    if (Number(R.y & 1n) !== parity) throw new Error('R parity mismatch');
    if (Q.y & 1n) throw new Error('PIN2 demo requires even-y Q');
    let r = mod(pending.k1 + b * pending.k2);
    if (parity) r = mod(-r);
    return scalar(r + e * a * this.#secret);
  }
}
