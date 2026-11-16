// Run: node scripts/test-software-card.mjs. Offline; no RN/NFC/PCSC or funds.
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
const scratch = await mkdtemp(path.join(process.env.TMPDIR || tmpdir(), 'software-card-test-'));
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const scalar = x => Uint8Array.from(Buffer.from(x.toString(16).padStart(64, '0'), 'hex'));
const message = () => webcrypto.getRandomValues(new Uint8Array(32));
let assertions = 0;
const check = (value, label) => { assert.ok(value, label); assertions++; };
const rejects = async (fn, pattern) => { await assert.rejects(fn, pattern); assertions++; };
try {
  await symlink(path.dirname(require.resolve('typescript/package.json')).replace(/[/\\]typescript$/, ''), path.join(scratch, 'node_modules'));
  for (const name of ['softwareCard', 'cardDemoMath']) {
    const source = await readFile(path.join(root, `src/${name}.ts`), 'utf8');
    const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }, reportDiagnostics: true });
    assert.equal(compiled.diagnostics?.length ?? 0, 0);
    await writeFile(path.join(scratch, `${name}.mjs`), compiled.outputText);
  }
  const { SoftwareCard } = await import(pathToFileURL(path.join(scratch, 'softwareCard.mjs')).href);
  const { prepareDemoSession } = await import(pathToFileURL(path.join(scratch, 'cardDemoMath.mjs')).href);
  const card = new SoftwareCard();
  const key = await card.pubkey();
  check(key.length === 33 && key[0] === 2, 'even-y compressed key');
  const returnedKey = await card.pubkey(); returnedKey.fill(0);
  assert.deepEqual(await card.pubkey(), key); assertions++;
  check(!Buffer.from(await new SoftwareCard().pubkey()).equals(Buffer.from(key)), 'new instance uses a fresh key');
  await rejects(() => card.finalize(new Uint8Array(231)), /No active nonces/);
  const tokens = new Set(), parities = [0, 0];
  for (let i = 0; i < 64; i++) {
    const nonces = await card.nonces();
    check(nonces.length === 70, '70 byte response');
    secp256k1.Point.fromBytes(nonces.slice(0, 33)).assertValidity();
    secp256k1.Point.fromBytes(nonces.slice(33, 66)).assertValidity();
    const token = Buffer.from(nonces.slice(66)).toString('hex');
    check(!tokens.has(token), 'token not reused'); tokens.add(token);
    const msg = message();
    const session = prepareDemoSession(key, nonces, msg);
    parities[session.payload[64]]++;
    // Mutating returned nonce bytes cannot corrupt card-owned nonce/token state.
    nonces.fill(0);
    const partial = await card.finalize(session.payload);
    check(partial.length === 32, '32 byte partial');
    const result = session.finish(partial);
    check(result.verified === true && schnorr.verify(result.signature, msg, result.pubkey), 'real scure aggregate and independent BIP340 verify');
    const changed = msg.slice(); changed[0] ^= 1;
    check(!schnorr.verify(result.signature, changed, result.pubkey), 'wrong message fails');
    await rejects(() => card.finalize(session.payload), /No active nonces/);
    assert.throws(() => session.finish(partial), /already consumed/); assertions++;
  }
  check(parities.every(n => n > 0), 'both nonce parity branches exercised');
  console.log(`PASS 64 real SoftwareCard + prepareDemoSession signatures; R parity even=${parities[0]} odd=${parities[1]}`);

  async function fresh() {
    return prepareDemoSession(await card.pubkey(), await card.nonces(), message());
  }
  const invalid = [
    ['wrong token', p => { p[97] ^= 1; return p; }, /Invalid nonce token/],
    ['short', p => p.slice(0, 230), /231 bytes/],
    ['long', p => new Uint8Array([...p, 0]), /231 bytes/],
    ['wrong type', () => 'not bytes', /231 bytes/],
    ['null', () => null, /231 bytes/],
    ['parity range', p => { p[64] = 2; return p; }, /Parity must/],
    ['R parity correspondence', p => { p[64] ^= 1; return p; }, /R parity mismatch/],
    ['R encoding', p => { p[101] = 2; return p; }, /uncompressed point/],
    ['Q encoding', p => { p[166] = 2; return p; }, /uncompressed point/],
    ['invalid R', p => { p.fill(0, 102, 166); return p; }, /./],
    ['invalid Q', p => { p.fill(0, 167, 231); return p; }, /./],
    ['odd Q', p => { p.set(secp256k1.Point.fromBytes(p.slice(166)).negate().toBytes(false), 166); return p; }, /even-y Q/],
    ...[0, 32, 65].map(offset => [`scalar >= n at ${offset}`, p => { p.set(scalar(N), offset); return p; }, /Non-canonical scalar/]),
  ];
  for (const [label, mutate, pattern] of invalid) {
    const session = await fresh();
    await rejects(() => card.finalize(mutate(session.payload.slice())), pattern);
    await rejects(() => card.finalize(session.payload), /No active nonces/);
  }
  console.log(`PASS ${invalid.length} malformed/token/scalar/point cases; every invalid attempt burns its nonces`);

  // Requesting fresh nonces invalidates the old token, even before any signing.
  const old = await fresh();
  await fresh();
  await rejects(() => card.finalize(old.payload), /Invalid nonce token/);
  const clean = await fresh();
  check(clean.finish(await card.finalize(clean.payload)).verified, 'new session recovers after rejection');

  // a/b/e and aggregate R/Q cannot be reconstructed from the wire format.
  // The host must catch a well-formed but session-incorrect scalar.
  const altered = await fresh();
  const bad = altered.payload.slice(); bad.fill(0, 65, 97);
  const partial = await card.finalize(bad);
  assert.throws(() => altered.finish(partial), /verification failed/); assertions++;
  await rejects(() => card.finalize(bad), /No active nonces/);
  console.log(`PASS replacement invalidates old token; host rejects wrong partial; ${assertions} assertions total`);
} finally {
  await rm(scratch, { recursive: true, force: true });
}
