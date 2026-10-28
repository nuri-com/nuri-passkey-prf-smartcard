// Run: node scripts/test-card-demo.mjs (no NFC hardware or React Native).
import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(path.join(root, 'package.json'));
const ts = require('typescript');
const { secp256k1, schnorr } = require('@noble/curves/secp256k1.js');
if (!globalThis.crypto) globalThis.crypto = webcrypto;
// Transpile only the owned pure module; resolve its imports through the app's
// existing dependencies. No installation, generated repository file or RN shim.
const scratch = await mkdtemp(path.join(process.env.TMPDIR || tmpdir(), 'card-demo-test-'));
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const mod = x => ((x % N) + N) % N;
const int = b => BigInt(`0x${Buffer.from(b).toString('hex')}`);
const scalar = x => Uint8Array.from(Buffer.from(mod(x).toString(16).padStart(64, '0'), 'hex'));
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts));
const random = () => secp256k1.utils.randomSecretKey();
const point = x => secp256k1.Point.BASE.multiply(x);
let checks = 0;
const check = (value, message) => { assert.ok(value, message); checks++; };
const rejects = (fn, pattern) => { assert.throws(fn, pattern); checks++; };
function fakeCard() {
  let x = int(random());
  if (point(x).y & 1n) x = N - x;
  const k1 = int(random()), k2 = int(random());
  const key = point(x).toBytes(true);
  const token = webcrypto.getRandomValues(new Uint8Array(4));
  const nonces = concat(point(k1).toBytes(true), point(k2).toBytes(true), token);
  return { key, nonces, finalize(payload) {
    assert.equal(payload.length, 231);
    assert.deepEqual(payload.slice(97, 101), token);
    const R = secp256k1.Point.fromBytes(payload.slice(101, 166));
    const Q = secp256k1.Point.fromBytes(payload.slice(166, 231));
    assert.equal(Number(R.y & 1n), payload[64]);
    assert.equal(Q.y & 1n, 0n);
    assert.ok(payload[64] === 0 || payload[64] === 1);
    const a = int(payload.slice(0, 32)), b = int(payload.slice(32, 64)), e = int(payload.slice(65, 97));
    assert.ok(a < N && b < N && e < N);
    // Independent applet equation, not scure Session.sign for the card.
    let r = mod(k1 + b * k2);
    if (payload[64]) r = mod(-r);
    return scalar(r + e * a * x);
  } };
}
try {
  await symlink(path.dirname(require.resolve('typescript/package.json')).replace(/[/\\]typescript$/, ''), path.join(scratch, 'node_modules'));
  const source = await readFile(path.join(root, 'src/cardDemoMath.ts'), 'utf8');
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }, reportDiagnostics: true });
  assert.equal(compiled.diagnostics?.length ?? 0, 0);
  await writeFile(path.join(scratch, 'math.mjs'), compiled.outputText);
  const { prepareDemoSession } = await import(pathToFileURL(path.join(scratch, 'math.mjs')).href);
  const parities = [0, 0];
  for (let i = 0; i < 64; i++) {
    const card = fakeCard();
    const msg = webcrypto.getRandomValues(new Uint8Array(32));
    const session = prepareDemoSession(card.key, card.nonces, msg);
    parities[session.payload[64]]++;
    const partial = card.finalize(session.payload);
    const expectedMessage = msg.slice();
    // Caller mutation of inputs and payload must not mutate verification state.
    card.key.fill(0); card.nonces.fill(0); msg.fill(0);
    session.payload.fill(0);
    const result = session.finish(partial);
    check(result.verified && result.pubkey.length === 32 && result.signature.length === 64, 'valid aggregate');
    check(schnorr.verify(result.signature, expectedMessage, result.pubkey), 'independent BIP340 verification');
    rejects(() => session.finish(partial), /already consumed/);
  }
  check(parities.every(n => n > 0), 'exercise both R parities');
  console.log(`PASS 64 random software-card sessions; R parity even=${parities[0]} odd=${parities[1]}`);

  const card = fakeCard(), msg = random();
  const tampered = prepareDemoSession(card.key, card.nonces, msg);
  const badPartial = card.finalize(tampered.payload); badPartial[31] ^= 1;
  rejects(() => tampered.finish(badPartial), /verification failed/);
  rejects(() => tampered.finish(card.finalize(tampered.payload)), /already consumed/);
  for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(32).fill(255), 'not bytes']) {
    const s = prepareDemoSession(card.key, card.nonces, msg);
    rejects(() => s.finish(bad), /cardPartial32|range|verification failed/);
    rejects(() => s.finish(new Uint8Array(32)), /already consumed/);
  }
  console.log('PASS tampered/out-of-range/malformed partials rejected; sessions consumed on success and failure');
  const cases = [
    [new Uint8Array(32), card.nonces, msg],
    [card.key, new Uint8Array(66), msg],
    [card.key, card.nonces, new Uint8Array(31)],
    [new Uint8Array(33), card.nonces, msg],
    [card.key, new Uint8Array(70), msg],
    [null, card.nonces, msg],
    [card.key, card.nonces, 'not bytes'],
  ];
  const oddKey = card.key.slice(); oddKey[0] = 3;
  cases.push([oddKey, card.nonces, msg]);
  const badSecond = card.nonces.slice(); badSecond.fill(0, 33, 66);
  cases.push([card.key, badSecond, msg]);
  for (const args of cases) rejects(() => prepareDemoSession(...args), /bytes|point|even-y/);
  console.log(`PASS ${cases.length} malformed key/nonce/message cases rejected`);
  // Separate final verification with retained input to rule out output-only claims.
  const retained = prepareDemoSession(card.key, card.nonces, msg);
  const final = retained.finish(card.finalize(retained.payload));
  check(schnorr.verify(final.signature, msg, final.pubkey), 'independent BIP340 verification');
  const changed = msg.slice(); changed[0] ^= 1;
  check(!schnorr.verify(final.signature, changed, final.pubkey), 'changed message rejected');
  console.log(`PASS independent BIP340 verification + wrong-message rejection; ${checks} assertions`);
} finally {
  await rm(scratch, { recursive: true, force: true });
}
