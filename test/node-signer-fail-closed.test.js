// Offline-only boundaries: subprocesses are synthetic Node helpers, never PC/SC.
import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import net from 'node:net';
import { runInNewContext } from 'node:vm';
import { once } from 'node:events';
import { runCardCosignFlow } from '../src/musig2/cosign-flow.js';
import { SimulatedCardArkadeSigner, runArkadeClientSignerProof, runArkadeClientSignerProofSuite } from '../src/musig2/arkade-client-signer.js';
import { requireCardResult, requireCardSubprocess } from '../src/signer-policy.js';

const ROOT = resolve(import.meta.dirname, '..');
const LOCAL = 'scripts/local-card-cosign-server.mjs';
const MCP = 'scripts/card-mcp-server.mjs';
const WALLET = 'scripts/nuri-card-wallet.mjs';
const TOKEN = '0123456789abcdef'.repeat(4);

async function fixture(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'node-signer-policy-'));
  const helper = join(dir, 'fake-card-helper');
  await writeFile(helper, `#!${process.execPath}
import { appendFileSync } from 'node:fs';
appendFileSync(process.env.FAKE_LOG, JSON.stringify({ argv: process.argv.slice(2), eth1: process.env.NURI_ALLOW_ETH1_DEMO ?? null }) + '\\n');
if (process.env.FAKE_KIND === 'absent') { console.error('FAKE_CARD_ABSENT'); process.exit(3); }
if (process.env.FAKE_KIND === 'malformed') { console.log('NOT JSON'); process.exit(0); }
if (process.argv.includes('derive')) { console.log('11'.repeat(32)); process.exit(0); }
console.log(JSON.stringify({ mode: 'sim', backend: 'software', status: 'REAL_CARD_COSIGN_FLOW_OK', final_signature_verified: true, card_partial_verified: true }));
`, { mode: 0o700 });
  const env = {
    ...process.env, REAL_CARD_COSIGN_PYTHON: helper,
    REAL_CARD_COSIGN_PROFILE: join(dir, 'profile.json'),
    NURI_CARD_TOKEN_FILE: join(dir, 'token'),
    NURI_MCP_TOKEN: TOKEN, NURI_COSIGN_TOKEN: TOKEN,
    FAKE_LOG: join(dir, 'calls.jsonl'), FAKE_KIND: 'absent',
  };
  delete env.COSIGN_BACKEND;
  delete env.NURI_ALLOW_ETH1_DEMO;
  delete env.NURI_LOCAL_DEMO_ASP_SECRET32;
  try { return await fn({ dir, env }); }
  finally { await rm(dir, { recursive: true, force: true }); }
}

function run(script, args, env) {
  return new Promise((resolveRun) => execFile(process.execPath, [script, ...args],
    { cwd: ROOT, env, timeout: 15000 }, (error, stdout, stderr) => resolveRun({ code: error?.code || 0, stdout, stderr })));
}
async function calls(env) {
  try { return (await readFile(env.FAKE_LOG, 'utf8')).trim().split('\n').map(JSON.parse); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
}
async function freePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port;
  await new Promise((done) => server.close(done)); return port;
}
async function start(script, args, env, fn) {
  const port = await freePort();
  const child = spawn(process.execPath, [script, ...args, ...(script === LOCAL ? [`--port=${port}`] : [])],
    { cwd: ROOT, env: { ...env, PORT: String(port), NURI_HELPER_REQUEST_TIMEOUT_MS: '1000' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '';
  child.stdout.on('data', (data) => { out += data; });
  child.stderr.on('data', (data) => { err += data; });
  try {
    const deadline = Date.now() + 10000;
    while (!out.includes('http://127.0.0.1:')) {
      if (child.exitCode !== null || Date.now() > deadline) throw new Error(`startup failed: ${out}${err}`);
      await new Promise((done) => setTimeout(done, 10));
    }
    return await fn({ base: `http://127.0.0.1:${port}`, port, output: () => out + err });
  } finally {
    if (child.exitCode === null) { const closed = once(child, 'exit'); child.kill(); await closed; }
  }
}
const authHeaders = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };
async function raw(port, request) {
  const socket = net.connect(port, '127.0.0.1');
  socket.setEncoding('utf8'); let result = '';
  socket.on('data', (data) => { result += data; });
  socket.on('error', () => {});
  await once(socket, 'connect'); socket.write(request);
  await once(socket, 'close'); return result;
}

for (const [script, args] of [[LOCAL, ['--selftest']], [MCP, ['--selftest']], [WALLET, ['address']]]) {
  test(`${script}: missing card helper fails, never falls back to software`, () => fixture(async ({ dir, env }) => {
    const result = await run(script, args, env);
    assert.notEqual(result.code, 0, result.stdout + result.stderr);
    assert.match(result.stderr, /FAKE_CARD_ABSENT/);
    assert.doesNotMatch(result.stdout, /"final_signature_verified": true|"address":/);
    assert.ok((await calls(env)).length > 0, 'actual subprocess boundary was exercised');
    await assert.rejects(readFile(join(dir, 'profile.json')), { code: 'ENOENT' });
  }));
  test(`${script}: explicit child simulator downgrade is refused`, () => fixture(async ({ env }) => {
    const result = await run(script, args, { ...env, FAKE_KIND: 'sim' });
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /non-card result; refusing signer downgrade/);
    assert.doesNotMatch(result.stdout, /"final_signature_verified": true|"address":/);
  }));
  test(`${script}: malformed helper output is an error, not fallback`, () => fixture(async ({ env }) => {
    const result = await run(script, args, { ...env, FAKE_KIND: 'malformed' });
    assert.notEqual(result.code, 0);
    assert.doesNotMatch(result.stdout, /"final_signature_verified": true|"address":/);
  }));
}

test('local server defaults to card; absent card HTTP signing fails and never provisions a key', () => fixture(async ({ dir, env }) => {
  await start(LOCAL, [], env, async ({ base, output }) => {
    const info = await (await fetch(base + '/api/cosign/info', { headers: authHeaders })).json();
    assert.equal(info.mode, 'card'); assert.equal(info.backend, 'real-card-pcsc-apdu');
    assert.equal(info.card_pk33, undefined); assert.doesNotMatch(output(), /Simulated|SIMULATION/);
    const response = await fetch(base + '/api/cosign/sign', { method: 'POST', headers: authHeaders, body: '{}' });
    assert.equal(response.status, 500);
    assert.equal((await response.json()).mode, 'card');
    const log = await calls(env);
    assert.equal(log.length, 1);
    assert.ok(log[0].argv.includes('--use-existing-card-key'), 'first request must never implicitly KEYGEN');
    assert.equal(log[0].eth1, null, 'Node must not arm ETH1 demo access');
    await assert.rejects(readFile(join(dir, 'profile.json')), { code: 'ENOENT' });
  });
}));

for (const flag of ['--sim', '--backend=simulated']) {
  test(`${flag}: loud startup warning, valid simulator selftest, no physical helper`, () => fixture(async ({ env }) => {
    const result = await run(LOCAL, [flag, '--selftest'], env);
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stderr, /WARNING: SIMULATION ONLY.*mode: sim/);
    const proof = JSON.parse(result.stdout);
    assert.equal(proof.mode, 'sim'); assert.equal(proof.final_signature_verified, true);
    assert.deepEqual(await calls(env), []);
  }));
}

test('simulation environment cannot silently replace the card; unsupported flags fail', () => fixture(async ({ env }) => {
  const environment = await run(LOCAL, ['--selftest'], { ...env, COSIGN_BACKEND: 'simulated' });
  assert.notEqual(environment.code, 0); assert.match(environment.stderr, /explicit --sim/);
  for (const script of [MCP, WALLET]) {
    const result = await run(script, [script === WALLET ? 'address' : '--selftest', '--sim'], env);
    assert.notEqual(result.code, 0); assert.match(result.stderr, /unknown argument: --sim/);
  }
  for (const mixed of [['--sim', '--backend=real-card'], ['--backend=real-card', '--sim']]) {
    const conflict = await run(LOCAL, [...mixed, '--selftest'], env);
    assert.notEqual(conflict.code, 0);
    assert.match(conflict.stderr, /choose exactly one backend flag/);
    assert.equal(JSON.parse(conflict.stderr.trim().split('\n').at(-1)).mode, 'sim');
  }
  const invalid = await run(LOCAL, ['--sim', '--bogus'], env);
  assert.notEqual(invalid.code, 0);
  assert.match(invalid.stderr, /SIMULATION ONLY/);
  assert.equal(JSON.parse(invalid.stderr.trim().split('\n').at(-1)).mode, 'sim');
  assert.deepEqual(await calls(env), []);
}));

test('simulation tags success, auth/JSON/404/signing/framing errors, HTML and parser/deadline errors', () => fixture(async ({ env }) => {
  await start(LOCAL, ['--sim'], env, async ({ base, port, output }) => {
    assert.match(output(), /WARNING: SIMULATION ONLY/);
    const requests = [
      ['/api/cosign/info', { headers: authHeaders }, 200],
      ['/api/cosign/info', {}, 401],
      ['/missing', {}, 404],
      ['/api/cosign/sign', { method: 'POST', headers: authHeaders, body: '{' }, 400],
      ['/api/cosign/sign', { method: 'POST', headers: authHeaders, body: '{"msg32":"00"}' }, 500],
      ['/api/cosign/sign', { method: 'POST', headers: authHeaders, body: '{}' }, 200],
      ['/api/wallet/address', { method: 'POST', headers: authHeaders, body: '{}' }, 409],
      ['/api/card/account', { headers: authHeaders }, 409],
      ['/api/cosign/sign', { method: 'POST', headers: { ...authHeaders, 'content-type': 'text/plain' }, body: '{}' }, 415],
    ];
    for (const [path, opts, status] of requests) {
      const response = await fetch(base + path, opts);
      assert.equal(response.status, status, path);
      assert.equal(response.headers.get('x-nuri-signer-mode'), 'sim', path);
      assert.equal((await response.json()).mode, 'sim', path);
    }
    const html = await fetch(base + '/');
    assert.equal(html.headers.get('x-nuri-signer-mode'), 'sim');
    assert.match(await html.text(), /data-signer-mode="sim"/);
    const js = await fetch(base + '/helper-pair.js');
    assert.equal(js.headers.get('x-nuri-signer-mode'), 'sim');
    const invalidRequests = [
      'POST /api/cosign/sign HTTP/1.1\r\nHost: 127.0.0.1:' + port + '\r\n\r\n',
      'POST /api/cosign/sign HTTP/1.1\r\nHost: 127.0.0.1:' + port + '\r\nContent-Length: 9999999\r\n\r\n',
      'GET / HTTP/1.1\r\nBad Header: value\r\n\r\n',
      'GET / HTTP/1.1\r\nHo', // pre-header absolute deadline
      'POST /api/cosign/sign HTTP/1.1\r\nHost: 127.0.0.1:' + port + '\r\nContent-Length: 10\r\nContent-Type: application/json\r\nAuthorization: Bearer ' + TOKEN + '\r\n\r\n{',
    ];
    for (const request of invalidRequests) {
      const response = await raw(port, request);
      assert.match(response, /HTTP\/1.1 (400|408|411|413)/);
      assert.match(response, /x-nuri-signer-mode: sim/i);
      assert.equal(JSON.parse(response.split('\r\n\r\n')[1].replace(/^[0-9a-f]+\r\n/i, '').split('\r\n')[0]).mode, 'sim');
    }
    assert.deepEqual(await calls(env), [], 'simulation may never invoke physical helper endpoints');
  });
}));

for (const [script, args, override] of [
  [LOCAL, ['--selftest'], 'REAL_CARD_COSIGN_SCRIPT'],
  [MCP, ['--selftest'], 'REAL_CARD_COSIGN_SCRIPT'],
  [WALLET, ['address'], 'NURI_CARD_PRF_SCRIPT'],
]) {
  test(`${script}: explicit ETH1 helper requires exact opt-in before any subprocess`, () => fixture(async ({ env }) => {
    const config = { ...env, [override]: 'scripts/card-eth-test.py' };
    for (const flag of [undefined, '0', 'true']) {
      const result = await run(script, args, { ...config, ...(flag === undefined ? {} : { NURI_ALLOW_ETH1_DEMO: flag }) });
      assert.notEqual(result.code, 0);
      assert.match(result.stderr, /ETH1 demo access requires NURI_ALLOW_ETH1_DEMO=1/);
      assert.deepEqual(await calls(env), [], 'reject ETH1 before launching even the fake executable');
    }
    const allowed = await run(script, args, { ...config, NURI_ALLOW_ETH1_DEMO: '1' });
    assert.notEqual(allowed.code, 0, 'the explicitly allowed fake card is still absent');
    assert.match(allowed.stderr, /FAKE_CARD_ABSENT/);
    const log = await calls(env);
    assert.equal(log.length, 1); assert.equal(log[0].eth1, '1');
  }));
}

test('generic signing flows require explicit signers and counterparty keys', async () => {
  assert.throws(() => runCardCosignFlow(), /card signer is required/);
  await assert.rejects(runArkadeClientSignerProof(), /signer is required/);
  await assert.rejects(runArkadeClientSignerProofSuite(), /signer or signerFactory is required/);
  await assert.rejects(runArkadeClientSignerProof({ signer: new SimulatedCardArkadeSigner() }), /aspSecret is required/);
  assert.throws(() => requireCardResult({ mode: 'sim' }), /non-card result/);
  assert.throws(() => requireCardResult({ backend: 'software' }), /non-card result/);
  assert.deepEqual(requireCardResult({ mode: 'card' }), { mode: 'card' });
  assert.throws(() => requireCardSubprocess(['--applet=eth1'], {}), /ETH1 demo access/);
  assert.throws(() => requireCardSubprocess(['4E55524945544801'], {}), /ETH1 demo access/);
  assert.doesNotThrow(() => requireCardSubprocess(['4E5552494554483201'], {}));
});

test('claim subprocess boundary rejects nonzero exit, malformed JSON and simulator results', async () => {
  // Isolate the actual function without importing/starting the live wallet server.
  const source = await readFile(join(ROOT, LOCAL), 'utf8');
  const match = source.match(/function spawnClaimRunner\(cfg\) \{[\s\S]*?\n\}/);
  assert.ok(match, 'claim subprocess function must be exercised, not a copied implementation');
  let stdin;
  const invoke = (error, stdout) => {
    const fn = runInNewContext(`(${match[0]})`, {
      process: { execPath: process.execPath }, CARD_CLAIM_RUNNER: 'synthetic-claim-helper',
      requireCardSubprocess, requireCardResult, redactPins: String,
      execFile: (_file, _args, _options, done) => {
        queueMicrotask(() => done(error, stdout, 'synthetic helper diagnostics'));
        return { stdin: { end(value) { stdin = value; } } };
      },
    });
    return fn({ synthetic: true });
  };
  await assert.rejects(invoke(new Error('exit 3'), '{"mode":"card","status":"OK"}'), /synthetic helper diagnostics/);
  await assert.rejects(invoke(null, '{"mode":"sim","status":"OK"}'), /non-card result/);
  await assert.rejects(invoke(null, 'not JSON'), /synthetic helper diagnostics/);
  assert.equal((await invoke(null, '{"mode":"card","status":"OK"}')).mode, 'card');
  assert.deepEqual(JSON.parse(stdin), { synthetic: true });
});

test('real local Arkade proof has no known ASP software signer default', () => fixture(async ({ env }) => {
  await start(LOCAL, [], env, async ({ base }) => {
    const response = await fetch(base + '/api/card/account', { headers: authHeaders });
    assert.notEqual(response.status, 200);
    const body = await response.json();
    assert.match(body.error, /NURI_LOCAL_DEMO_ASP_SECRET32/);
    assert.equal(body.mode, 'card');
    assert.deepEqual(await calls(env), [], 'missing explicit counterparty key must fail before card access');
  });
}));
