import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const ts = require('typescript');
const source = fs.readFileSync(new URL('../src/musig2CardPin.ts', import.meta.url), 'utf8');
const code = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true } }).outputText;
const calls = [];
let mode = 'ok', cancelled = 0;
const payload = new Uint8Array(231);
const manager = {
  start: async () => {}, requestTechnology: async () => {},
  cancelTechnologyRequest: async () => { cancelled++; },
  isoDepHandler: { transceive: async a => {
    calls.push(a);
    if (a[1] === 0xa4) { assert.equal(Buffer.from(a.slice(5, -1)).toString('hex'), '4e5552494d55473201'); return [0x90, 0]; }
    if (a[1] === 0x20) return mode === 'wrong' ? [0x63, 0xc3] : [0x90, 0];
    if (a[1] === 0x03) return [...new Uint8Array(33), 0x90, 0];
    if (a[1] === 0x40) return [...new Uint8Array(20), 0x61, 50];
    if (a[1] === 0xc0) { assert.equal(a[4], 50); return [...new Uint8Array(50), 0x90, 0]; }
    if (a[1] === 0x41) { assert.equal(a[4], 231); assert.equal(a.at(-1), 32); return [...new Uint8Array(32), 0x90, 0]; }
    throw new Error('Unexpected APDU');
  } },
};
const module = { exports: {} };
new Function('require', 'module', 'exports', code)(name => {
  if (name === 'react-native-nfc-manager') return { __esModule: true, default: manager, NfcTech: { IsoDep: 'IsoDep' } };
  if (name === './cardDemoMath') return { prepareDemoSession: (key, nonce, msg) => {
    assert.equal(key.length, 33); assert.equal(nonce.length, 70); assert.equal(msg.length, 32);
    return { payload, finish: partial => { assert.equal(partial.length, 32); return { pubkey: new Uint8Array(32), signature: new Uint8Array(64), verified: true }; } };
  } };
  return require(name);
}, module, module.exports);
// Generate a throwaway test PIN; never store a card/user PIN literal.
const testPin = String(100000 + Math.floor(Math.random() * 900000));
const statuses = [];
const result = await module.exports.signCardDemo('transport test', testPin, s => statuses.push(s));
assert.equal(result.verified, true);
assert.ok(!calls.some(a => a[1] === 4));
assert.ok(!statuses.some(s => s.includes(testPin)));
assert.equal(cancelled, 1);
mode = 'wrong'; calls.length = 0;
await assert.rejects(module.exports.signCardDemo('transport test', testPin, () => {}), e => e.triesLeft === 3 && /tries left: 3/.test(e.message));
assert.deepEqual(calls.map(a => a[1]), [0xa4, 0x20]);
assert.equal(cancelled, 2);
console.log('PASS PIN2 SELECT/VERIFY/GET_PUBKEY/70-byte GET RESPONSE/231-byte FINALIZE Le=32; no KEYGEN, no PIN status leak');
console.log('PASS wrong PIN SW 63C3 exposes 3 tries, stops signing, closes NFC');
