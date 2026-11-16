// No reader/card: only fake token stores and localhost simulated helpers.
import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { connect, createServer } from 'node:net';
import { mkdtemp, readFile, rm, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadOrCreateToken, checkBind, PairingSessions } from '../scripts/helper-auth.mjs';
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TOKEN = '0123456789abcdef'.repeat(4);

async function tokenEnv(dir, fn) {
  const saved = { ...process.env };
  for (const key of Object.keys(process.env)) if (/^NURI_.*TOKEN/.test(key)) delete process.env[key];
  process.env.NURI_CARD_TOKEN_FILE = join(dir, 'token');
  try { return await fn(); } finally {
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
  }
}
test('token files: scoped and private; 0644, readable directory, symlinks, weak/shared token refused', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'nuri-token-test-'));
  try {
    await tokenEnv(dir, async () => {
      const logs = [];
      const opts = (service) => ({ service, log: s => logs.push(s) });
      const a = loadOrCreateToken(opts('mcp')), b = loadOrCreateToken(opts('cosign'));
      assert.notEqual(a.token, b.token); assert.notEqual(a.source, b.source);
      assert.doesNotMatch(logs.join('\n'), new RegExp(`${a.token}|${b.token}`));
      assert.equal(loadOrCreateToken(opts('mcp')).token, a.token);
      await chmod(join(dir, 'token.mcp'), 0o644);
      assert.throws(() => loadOrCreateToken(opts('mcp')), /0600/);
      await rm(join(dir, 'token.mcp'));
      await symlink(join(dir, 'token.cosign'), join(dir, 'token.mcp'));
      assert.throws(() => loadOrCreateToken(opts('mcp')));
      await chmod(dir, 0o755);
      assert.throws(() => loadOrCreateToken(opts('cosign')), /0700/);
      await chmod(dir, 0o700);
      await symlink(dir, join(dir, 'alias'));
      process.env.NURI_MCP_TOKEN_FILE = join(dir, 'alias', 'other');
      assert.throws(() => loadOrCreateToken(opts('mcp')));
      delete process.env.NURI_MCP_TOKEN_FILE;
      process.env.NURI_MCP_TOKEN = 'a'.repeat(64);
      assert.throws(() => loadOrCreateToken(opts('mcp')), /random/);
      delete process.env.NURI_MCP_TOKEN;
      process.env.NURI_CARD_TOKEN = TOKEN;
      assert.throws(() => loadOrCreateToken(opts('mcp')), /no longer accepted/);
    });
  } finally { await chmod(dir, 0o700); await rm(dir, { recursive: true, force: true }); }
});
test('atomic token creation: eight starters read the same complete winner', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'nuri-token-race-'));
  try {
    await tokenEnv(dir, async () => {
      const code = `import{loadOrCreateToken}from ${JSON.stringify(new URL('../scripts/helper-auth.mjs', import.meta.url).href)};console.log(loadOrCreateToken({service:'mcp',log:()=>{}}).token)`;
      const tokens = await Promise.all(Array.from({ length: 8 }, () => new Promise((resolve, reject) => {
        const p = spawn(process.execPath, ['--input-type=module', '-e', code], { env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
        let out = '', err = ''; p.stdout.on('data', d => { out += d; }); p.stderr.on('data', d => { err += d; });
        p.on('error', reject); p.on('exit', c => c === 0 ? resolve(out.trim()) : reject(new Error(err)));
      })));
      assert.equal(new Set(tokens).size, 1); assert.match(tokens[0], /^[0-9a-f]{64}$/);
      assert.equal((await readFile(join(dir, 'token.mcp'), 'utf8')).trim(), tokens[0]);
    });
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test('remote override cannot enable a non-loopback card helper', () => {
  const old = process.env.NURI_ALLOW_REMOTE; process.env.NURI_ALLOW_REMOTE = '1';
  try { assert.throws(() => checkBind('0.0.0.0', { tokenSource: 'env' }), /no remote override/); }
  finally { if (old === undefined) delete process.env.NURI_ALLOW_REMOTE; else process.env.NURI_ALLOW_REMOTE = old; }
});
test('pairing: single use, expiry, service scope; cookie is not a bearer', () => {
  const s = new PairingSessions({ log: () => {}, ttlMs: 1000 });
  const code = s.code; assert.equal(s.exchange('wrong'), null);
  const cookie = s.exchange(code);
  assert.match(cookie, /Path=\/api\/; Max-Age=1; HttpOnly; SameSite=Strict/);
  assert.doesNotMatch(cookie, new RegExp(TOKEN)); assert.equal(s.exchange(code), null);
  const headers = { cookie: cookie.split(';')[0], 'sec-fetch-site': 'same-origin' };
  assert.equal(s.accepts({ headers }), true);
  assert.equal(s.accepts({ headers: { cookie: headers.cookie } }), false);
  assert.equal(new PairingSessions({ service: 'mcp', log: () => {} }).accepts({ headers }), false);
  s.sessions.clear(); assert.equal(s.accepts({ headers }), false);
  s.codeUntil = 0; assert.equal(s.exchange(s.code), null);
});
let port;
async function start(script) {
  port = await new Promise((resolve, reject) => { const s = createServer(); s.on('error', reject); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
  const dir = await mkdtemp(join(tmpdir(), 'nuri-http-hardening-'));
  const cosign = script.includes('local-card');
  const p = spawn(process.execPath, [join(ROOT, script), ...(cosign ? [`--port=${port}`, '--backend=simulated'] : [])], {
    cwd: ROOT, env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', NURI_MCP_TOKEN: TOKEN, NURI_COSIGN_TOKEN: TOKEN, NURI_CARD_TOKEN_FILE: join(dir, 'token'), NURI_HELPER_REQUEST_TIMEOUT_MS: '350' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = ''; p.stdout.on('data', d => { out += d; }); p.stderr.on('data', d => { out += d; });
  for (let i = 0; i < 100; i++) {
    if (p.exitCode !== null) throw new Error(out);
    try { const r = await fetch(`http://127.0.0.1:${port}/`); await r.text(); return { out: () => out, async stop() { p.kill(); await new Promise(r => p.once('exit', r)); await rm(dir, { recursive: true, force: true }); } }; } catch {}
    await new Promise(r => setTimeout(r, 30));
  }
  p.kill(); throw new Error(`startup timed out: ${out}`);
}
function raw(data, trickle = false) {
  return new Promise((resolve, reject) => {
    const s = connect(port, '127.0.0.1'); let out = '', timer;
    s.setTimeout(5000, () => { s.destroy(); reject(new Error('connection failed to close')); });
    s.on('connect', () => { s.write(data); if (trickle) timer = setInterval(() => s.write(' '), 50); });
    s.on('data', d => { out += d; }); s.on('error', reject);
    s.on('close', () => { clearInterval(timer); resolve(out); });
  });
}
test('HTTP pairing: public pages leak no token/code; secret code required once, cookie scoped', async () => {
  const srv = await start('scripts/local-card-cosign-server.mjs');
  const base = `http://127.0.0.1:${port}`;
  try {
    const code = /Browser pairing code: ([0-9a-f]{16})/.exec(srv.out())?.[1]; assert.ok(code, srv.out());
    for (const path of ['/', '/wallet', '/terminal', '/checkout', '/profile', '/passkey-wallet.html', '/helper-pair.js']) {
      const r = await fetch(base + path);
      assert.equal(r.status, 200); assert.doesNotMatch(await r.text(), new RegExp(`${TOKEN}|${code}|NURI_CARD_TOKEN|var t=`));
      assert.equal(r.headers.get('set-cookie'), null); assert.equal(r.headers.get('x-frame-options'), 'DENY');
      assert.match(r.headers.get('content-security-policy'), /default-src 'self'.*frame-ancestors 'none'/);
    }
    const pair = code => fetch(base + '/pair', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code }) });
    assert.equal((await pair('')).status, 401);
    const race = await Promise.all([pair(code), pair(code)]);
    assert.deepEqual(race.map(r => r.status).sort(), [200, 401], 'exactly one concurrent code exchange succeeds');
    const r = race.find(r => r.status === 200);
    const cookie = r.headers.get('set-cookie'); assert.match(cookie, /Path=\/api\/;.*HttpOnly; SameSite=Strict/);
    assert.deepEqual(await r.json(), { paired: true, mode: 'sim' }); assert.equal((await pair(code)).status, 401);
    const headers = { cookie: cookie.split(';')[0], 'sec-fetch-site': 'same-origin' };
    assert.equal((await fetch(base + '/api/cosign/info', { headers })).status, 200);
    assert.equal((await fetch(base + '/api/cosign/info', { headers: { cookie: headers.cookie } })).status, 401);
    assert.equal((await fetch(base + '/api/cosign/info', { headers: { ...headers, origin: `http://localhost:${port}` } })).status, 403);
  } finally { await srv.stop(); }
});
for (const script of ['scripts/card-mcp-server.mjs', 'scripts/local-card-cosign-server.mjs']) {
  test(`${script}: body cap, invalid lengths, no drain, absolute header/body slowloris deadlines`, async () => {
    const srv = await start(script);
    const path = script.includes('local-card') ? '/api/cosign/sign' : '/mcp';
    const head = `POST ${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/json\r\n`;
    try {
      assert.match(await raw(`${head}Content-Length: 1048577\r\n\r\n`), /^HTTP\/1.1 413/);
      assert.match(await raw(`${head}Content-Length: -1\r\n\r\n`), /^HTTP\/1.1 400/);
      assert.match(await raw(`${head}Content-Length: 3\r\nContent-Length: 3\r\n\r\n{}`), /^HTTP\/1.1 400/);
      assert.match(await raw(`${head}Transfer-Encoding: chunked\r\n\r\n`), /^HTTP\/1.1 400/);
      let at = Date.now();
      assert.match(await raw(`${head}Authorization: Bearer ${TOKEN}\r\nContent-Length: 10000\r\n\r\n{`, true), /^HTTP\/1.1 408/);
      assert.ok(Date.now() - at < 2000, 'trickled bytes cannot extend deadline');
      assert.match(await raw(`POST ${path} HTTP/1.1\r\nHost:`, true), /^HTTP\/1.1 408/);
      at = Date.now(); assert.match(await raw(`${head}Content-Length: 999999\r\n\r\n`), /^HTTP\/1.1 401/);
      assert.ok(Date.now() - at < 1000, 'rejection never drains attacker body');
      assert.equal((await fetch(`http://127.0.0.1:${port}${path === '/mcp' ? '/healthz' : '/'}`)).status, 200);
    } finally { await srv.stop(); }
  });
}
