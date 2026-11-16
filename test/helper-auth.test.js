// Guard tests for the two Node helper servers (scripts/card-mcp-server.mjs,
// scripts/local-card-cosign-server.mjs) + the shared scripts/helper-auth.mjs.
// Each server is started as a real child process on a random free port with
// a fake token file in a temp dir. No card, no reader: the cosign server runs
// --backend=simulated and the MCP server is only asked tools/list + a mainnet
// spend that must be refused before any card script runs.
import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { createServer, connect } from 'node:net';
import { request } from 'node:http';
import { mkdtemp, readFile, rm, stat, chmod, writeFile, symlink, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { guardRequest, pairingPage, isLoopbackHost, allowedHosts, loadOrCreateToken, checkBind, PairingSessions } from '../scripts/helper-auth.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TOKEN = '0123456789abcdef'.repeat(4);

function freePort() {
  return new Promise((res, rej) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); });
    s.on('error', rej);
  });
}

async function startServer(script, { args = [], env = {}, port }) {
  const dir = await mkdtemp(join(tmpdir(), 'nuri-helper-test-'));
  const child = spawn(process.execPath, [join(ROOT, script), ...args], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', NURI_CARD_TOKEN_FILE: join(dir, 'token'), ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`server exited early: ${out}`);
    try {
      const r = await fetch(`http://127.0.0.1:${port}/healthz`);
      if (r.status) break;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  return {
    child, dir, port,
    output: () => out,
    async stop() { child.kill('SIGTERM'); await new Promise((r) => child.once('exit', r)); await rm(dir, { recursive: true, force: true }); },
  };
}

// Raw node:http (not fetch): undici strips the forbidden `Host` header, and we need to forge it.
function req(port, path, { method = 'GET', headers = {}, body, host } = {}) {
  return new Promise((resolve, reject) => {
    const h = { ...headers };
    for (const k of Object.keys(h)) if (h[k] === undefined) delete h[k];
    if (host) h.host = host;
    if (body !== undefined && !Object.keys(h).some(k => k.toLowerCase() === 'content-length')) h['content-length'] = Buffer.byteLength(body);
    const r = request({ host: '127.0.0.1', port, path, method, headers: h, setHost: !host }, (res) => {
      let data = '';
      res.on('data', (d) => { data += d; });
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: { get: (k) => res.headers[k.toLowerCase()] ?? null },
        text: async () => data,
        json: async () => JSON.parse(data),
      }));
    });
    r.on('error', reject);
    if (body !== undefined) r.write(body);
    r.end();
  });
}

const rpc = (id, method, params) => JSON.stringify({ jsonrpc: '2.0', id, method, params });

// ---------------------------------------------------------------- unit: guardRequest

test('guardRequest: pure rules', () => {
  const base = { port: 8799, token: TOKEN };
  const ok = (h, method = 'POST', url = '/mcp') => guardRequest({ method, url, headers: h }, base);
  const good = { host: '127.0.0.1:8799', 'content-type': 'application/json', authorization: `Bearer ${TOKEN}` };
  assert.equal(ok(good), null);
  assert.equal(ok({ ...good, host: 'localhost:8799' }), null);
  assert.equal(ok({ ...good, host: 'localhost:8799', origin: 'http://localhost:8799' }), null);
  assert.equal(ok({ ...good, origin: 'http://localhost:8799' }).status, 403);
  assert.equal(ok({ ...good, host: 'evil.example:8799' }).status, 403);
  assert.equal(ok({ ...good, host: '127.0.0.1:1' }).status, 403);
  assert.equal(ok({ ...good, origin: 'https://evil.example' }).status, 403);
  assert.equal(ok({ ...good, origin: 'null' }).status, 403);
  assert.equal(ok({ ...good, 'content-type': 'text/plain' }).status, 415);
  assert.equal(ok({ ...good, authorization: undefined }).status, 401);
  assert.equal(ok({ ...good, authorization: 'Bearer nope' }).status, 401);
  assert.equal(ok(good, 'OPTIONS').status, 403);
  // unprotected paths need Host but not token
  assert.equal(ok({ host: '127.0.0.1:8799' }, 'GET', '/healthz'), null);
  assert.equal(ok({ host: 'evil:1' }, 'GET', '/healthz').status, 403);
  assert.equal(ok({ host: '127.0.0.1:8799' }, 'GET', '/api/x').status, 401);
  // empty token never matches
  assert.equal(guardRequest({ method: 'POST', url: '/mcp', headers: { ...good, authorization: 'Bearer ' } }, { port: 8799, token: '' }).status, 401);
  assert.ok(isLoopbackHost('127.0.0.1') && isLoopbackHost('localhost') && !isLoopbackHost('0.0.0.0'));
  assert.deepEqual([...allowedHosts(1)].sort(), ['127.0.0.1:1', '[::1]:1', 'localhost:1']);
  assert.ok(!allowedHosts(1, { remote: true, bindHost: '0.0.0.0' }).has('0.0.0.0:1'));
});

test('public pairing script carries no credential', () => {
  const html = pairingPage('<html><head></head><body></body></html>');
  assert.match(html, /src="\/helper-pair.js"/);
  assert.doesNotMatch(html, /Bearer|NURI_CARD_TOKEN|var t=/);
});

// ---------------------------------------------------------------- MCP server

test('card-mcp-server: 401/403/415/200 on /mcp, mainnet broadcast refused without NURI_ALLOW_MAINNET', async () => {
  const port = await freePort();
  const srv = await startServer('scripts/card-mcp-server.mjs', { port, env: { NURI_MCP_TOKEN: TOKEN, NURI_COSIGN_TOKEN: TOKEN } });
  try {
    assert.equal((await req(port, '/healthz')).status, 200);
    const good = { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}` };

    let r = await req(port, '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: rpc(1, 'tools/list') });
    assert.equal(r.status, 401);
    r = await req(port, '/mcp', { method: 'POST', headers: { 'content-type': 'text/plain', authorization: good.authorization }, body: rpc(1, 'tools/list') });
    assert.equal(r.status, 415, 'CORS simple request (text/plain) must be refused');
    r = await req(port, '/mcp', { method: 'POST', headers: good, host: 'evil.example', body: rpc(1, 'tools/list') });
    assert.equal(r.status, 403);
    r = await req(port, '/mcp', { method: 'POST', headers: { ...good, origin: 'https://evil.example' }, body: rpc(1, 'tools/list') });
    assert.equal(r.status, 403);
    r = await req(port, '/mcp', { method: 'OPTIONS', headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' } });
    assert.equal(r.status, 403);
    assert.equal(r.headers.get('access-control-allow-origin'), null, 'no CORS headers ever');

    r = await req(port, '/mcp', { method: 'POST', headers: good, body: rpc(1, 'tools/list') });
    assert.equal(r.status, 200);
    const list = await r.json();
    const names = list.result.tools.map((t) => t.name);
    assert.ok(names.includes('nuri_card_wallet_spend'));
    const tweaked = list.result.tools.find((t) => t.name === 'nuri_card_cosign_tweaked');
    assert.ok(!('client_secret_hex' in tweaked.inputSchema.properties), 'no client secret over MCP');

    r = await req(port, '/mcp', { method: 'POST', headers: { ...good, origin: `http://127.0.0.1:${port}` }, body: rpc(2, 'tools/call', { name: 'nuri_card_wallet_spend', arguments: { network: 'mainnet', to: 'self', broadcast: true } }) });
    assert.equal(r.status, 200);
    const spend = await r.json();
    assert.equal(spend.result.isError, true);
    assert.match(spend.result.content[0].text, /NURI_ALLOW_MAINNET=1/);
    assert.doesNotMatch(srv.output(), /ngrok/i, 'no tunnel advice in the banner');
  } finally {
    await srv.stop();
  }
});

test('card-mcp-server: refuses non-loopback HOST without NURI_ALLOW_REMOTE', async () => {
  const port = await freePort();
  const dir = await mkdtemp(join(tmpdir(), 'nuri-helper-test-'));
  const child = spawn(process.execPath, [join(ROOT, 'scripts/card-mcp-server.mjs')], {
    cwd: ROOT, env: { ...process.env, PORT: String(port), HOST: '0.0.0.0', NURI_MCP_TOKEN: TOKEN, NURI_COSIGN_TOKEN: TOKEN, NURI_CARD_TOKEN_FILE: join(dir, 'token') }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let err = '';
  child.stderr.on('data', (d) => { err += d; });
  const code = await new Promise((r) => child.once('exit', r));
  await rm(dir, { recursive: true, force: true });
  assert.notEqual(code, 0);
  assert.match(err, /refusing to bind 0\.0\.0\.0/);
});

test('card-mcp-server: generates a 0600 token file when NURI_CARD_TOKEN is unset', async () => {
  const port = await freePort();
  const srv = await startServer('scripts/card-mcp-server.mjs', { port });
  try {
    const path = join(srv.dir, 'token.mcp');
    const token = (await readFile(path, 'utf8')).trim();
    assert.equal(token.length, 64);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.doesNotMatch(srv.output(), new RegExp(token), 'bearer is never printed');
    const r = await req(port, '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: rpc(1, 'tools/list') });
    assert.equal(r.status, 200);
  } finally {
    await srv.stop();
  }
});

// ---------------------------------------------------------------- cosign demo server (simulated backend)

test('local-card-cosign-server (simulated): pages open, /api needs token, Host/Origin/Content-Type enforced', async () => {
  const port = await freePort();
  const srv = await startServer('scripts/local-card-cosign-server.mjs', { port, args: [`--port=${port}`, '--backend=simulated'], env: { NURI_MCP_TOKEN: TOKEN, NURI_COSIGN_TOKEN: TOKEN } });
  try {
    let r = await req(port, '/cosign-demo.html');
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.match(html, /helper-pair.js/);
    assert.doesNotMatch(html, new RegExp(TOKEN));
    assert.doesNotMatch(html, /NURI_CARD_TOKEN|var t=/);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.match(r.headers.get('content-security-policy'), /default-src 'self'.*frame-ancestors 'none'/);

    r = await req(port, '/api/cosign/info');
    assert.equal(r.status, 401);
    r = await req(port, '/api/cosign/info', { headers: { authorization: `Bearer ${TOKEN}` }, host: 'evil.example' });
    assert.equal(r.status, 403);
    r = await req(port, '/api/cosign/info', { headers: { authorization: `Bearer ${TOKEN}`, origin: 'https://evil.example' } });
    assert.equal(r.status, 403);
    r = await req(port, '/api/cosign/sign', { method: 'POST', headers: { 'content-type': 'text/plain', authorization: `Bearer ${TOKEN}` }, body: '{"message":"x"}' });
    assert.equal(r.status, 415);
    r = await req(port, '/api/cosign/sign', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"message":"x"}' });
    assert.equal(r.status, 401);

    r = await req(port, '/api/cosign/info', { headers: { authorization: `Bearer ${TOKEN}` } });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).backend, 'simulated-on-card-keygen');
    r = await req(port, '/api/cosign/sign', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}`, origin: `http://127.0.0.1:${port}` }, body: JSON.stringify({ message: 'guard test' }) });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).final_signature_verified, true);
  } finally {
    await srv.stop();
  }
});

test('local-card-cosign-server: --host=0.0.0.0 refused without NURI_ALLOW_REMOTE', async () => {
  const port = await freePort();
  const dir = await mkdtemp(join(tmpdir(), 'nuri-helper-test-'));
  const child = spawn(process.execPath, [join(ROOT, 'scripts/local-card-cosign-server.mjs'), `--port=${port}`, '--host=0.0.0.0', '--backend=simulated'], {
    cwd: ROOT, env: { ...process.env, NURI_MCP_TOKEN: TOKEN, NURI_COSIGN_TOKEN: TOKEN, NURI_CARD_TOKEN_FILE: join(dir, 'token') }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let err = '';
  child.stderr.on('data', (d) => { err += d; });
  const code = await new Promise((r) => child.once('exit', r));
  await rm(dir, { recursive: true, force: true });
  assert.notEqual(code, 0);
  assert.match(err, /refusing to bind 0\.0\.0\.0/);
});
