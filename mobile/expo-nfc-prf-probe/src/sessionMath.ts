// BIP327 session math helpers — the intermediate values the card needs
// (a_i, b, parity, e) that @scure/btc-signer computes internally but doesn't
// expose. These mirror the Python code in scripts/card-cosign-tweaked.py.

import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

type Point = { x: bigint; y: bigint } | null;

function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBigInt(hex: string): bigint {
  return BigInt('0x' + hex);
}

function i2b(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let val = v;
  for (let i = 31; i >= 0; i--) { out[i] = Number(val & 0xffn); val >>= 8n; }
  return out;
}

function b2i(d: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < d.length; i++) v = (v << 8n) | BigInt(d[i]);
  return v;
}

export function taggedHash(tag: string, data: Uint8Array): Uint8Array {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(tagHash, tagHash, data));
}

function msqrt(v: bigint): bigint | null {
  if (v === 0n) return 0n;
  const r = modPow(v, (P + 1n) / 4n, P);
  return (r * r - v) % P === 0n ? r : null;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function inv(v: bigint, m: bigint = P): bigint {
  // Extended Euclidean or Fermat's little theorem
  return modPow(v, m - 2n, m);
}

export function liftX(x: bigint): Point {
  const y = msqrt((modPow(x, 3n, P) + 7n) % P);
  if (y === null) throw new Error('x not on curve');
  return { x, y: y % 2n === 0n ? y : (-y + P) % P };
}

export function liftComp(c: Uint8Array): Point {
  if (c.length !== 33 || (c[0] !== 2 && c[0] !== 3)) throw new Error('bad compressed pubkey');
  const x = b2i(c.slice(1));
  const pt = liftX(x);
  if (!pt) throw new Error('point not on curve');
  return (pt.y & 1n) === BigInt(c[0] & 1) ? pt : { x: pt.x, y: (-pt.y + P) % P };
}

export function padd(a: Point, b: Point): Point {
  if (a === null) return b;
  if (b === null) return a;
  const [x1, y1] = [a.x, a.y];
  const [x2, y2] = [b.x, b.y];
  if (x1 === x2 && (y1 + y2) % P === 0n) return null;
  let lam: bigint;
  if (x1 === x2 && y1 === y2) {
    lam = ((3n * x1 * x1) * inv((2n * y1) % P)) % P;
  } else {
    lam = ((y2 - y1) * inv((x2 - x1 + P) % P)) % P;
  }
  const x3 = (lam * lam - x1 - x2) % P;
  return { x: x3, y: (lam * (x1 - x3) - y1) % P };
}

export function pneg(p: Point): Point {
  if (p === null) return null;
  return { x: p.x, y: (-p.y + P) % P };
}

export function pmul(k: bigint, pt: Point): Point {
  k %= N;
  if (k === 0n || pt === null) return null;
  let r: Point = null;
  let a: Point = pt;
  let val = k;
  while (val > 0n) {
    if (val & 1n) r = padd(r, a);
    a = padd(a, a);
    val >>= 1n;
  }
  return r;
}

export function compress(pt: Point): Uint8Array {
  if (pt === null) throw new Error('cannot compress null point');
  const prefix = pt.y % 2n === 0n ? 0x02 : 0x03;
  return new Uint8Array([prefix, ...i2b(pt.x)]);
}

// BIP327 key aggregation coefficients
export function computeCoeffs(sortedPubkeys: Uint8Array[]): Record<string, bigint> {
  const keys = sortedPubkeys.map((k) => bytesToHex(k));
  const L = taggedHash('KeyAgg list', concatBytes(...sortedPubkeys));
  const second = keys.length > 1 && keys[1] !== keys[0] ? keys[1] : null;
  const coeffs: Record<string, bigint> = {};
  for (const pk of keys) {
    if (second !== null && pk === second) {
      coeffs[pk] = 1n;
    } else {
      const pkBytes = hexToBytes(pk);
      coeffs[pk] = b2i(taggedHash('KeyAgg coefficient', concatBytes(L, pkBytes))) % N;
    }
  }
  return coeffs;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}
