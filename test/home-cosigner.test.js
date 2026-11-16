// Fake-hardware tests for the home cosigner: LaunchAgent plist, wrapper gates and
// the /api/send passthrough. No reader, no card, no network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const script = (p) => join(root, 'scripts', 'home-cosigner', p);
const PIN = '481516';
const TO = 'ark1qzpq904am6clw3pgqwyh4p02708fy4xs0hcpwt7rwfdttuxsjameepfv6ed2mgaw4k2tdts49m4wkk3zqyrjv44sr2g2gxrm47gy7sqnlyjr3x';
const mode = (p) => (statSync(p).mode & 0o777).toString(8);
const PORT = 20000 + (process.pid % 5000);

function tmp(label) { return mkdtempSync(join(tmpdir(), `nuri-${label}-`)); }

function run(cmd, args, { env = {}, cwd = root } = {}) {
  return new Promise((resolvePromise) => {
    execFile(cmd, args, { cwd, env: { ...process.env, ...env }, timeout: 30000 }, (error, stdout, stderr) => {
      resolvePromise({ code: error ? 1 : 0, stdout, stderr });
    });
  });
}

// A fake `security` on PATH: the wrapper must work without a real keychain.
function fakeSecurity(dir, { pin = PIN } = {}) {
  const bin = join(dir, 'security');
  writeFileSync(bin, pin === null
    ? '#!/bin/sh\nexit 44\n'
    : `#!/bin/sh\n[ "$1" = find-generic-password ] || exit 2\nprintf '%s\\n' '${pin}'\n`);
  chmodSync(bin, 0o755);
  return dir;
}

test('install-macos writes a valid LaunchAgent and a private log, without the PIN', async () => {
  const home = tmp('home');
  const r = await run('bash', [script('install-macos.sh'), '--no-load'], { env: { HOME: home } });
  assert.equal(r.code, 0, r.stderr);
  const plistPath = join(home, 'Library/LaunchAgents/com.nuri.home-cosigner.plist');
  const plist = readFileSync(plistPath, 'utf8');
  if (process.platform === 'darwin') {
    const lint = await run('plutil', ['-lint', plistPath]);
    assert.match(lint.stdout + lint.stderr, /OK/);
    const parsed = (await run('plutil', ['-convert', 'json', '-o', '-', plistPath])).stdout;
    assert.equal(JSON.parse(parsed).Label, 'com.nuri.home-cosigner');
  }
  assert.match(plist, /<key>Label<\/key>\s*<string>com\.nuri\.home-cosigner<\/string>/);
  assert.ok(plist.includes(script('run.sh')), 'plist must run the wrapper');
  assert.match(plist, /<key>RunAtLoad<\/key><true\/>/);
  assert.match(plist, /<key>KeepAlive<\/key>\s*<dict><key>SuccessfulExit<\/key><false\/><\/dict>/);
  assert.ok(plist.includes(join(home, '.nuri-card/logs/home-cosigner.log')), 'log path');
  // The PIN is a runtime value: it must not be baked into the plist.
  assert.equal(plist.includes(PIN), false);
  assert.equal(plist.includes('NURI_CARD_PIN'), false);
  assert.equal(mode(join(home, '.nuri-card/logs/home-cosigner.log')), '600');
  assert.equal(mode(join(home, '.nuri-card/logs')), '700');

  const un = await run('bash', [script('install-macos.sh'), '--uninstall'], { env: { HOME: home } });
  assert.equal(un.code, 0, un.stderr);
  assert.equal(existsSync(plistPath), false);
});

test('wrapper refuses to start without a PIN and never puts the PIN in argv', async () => {
  const home = tmp('pinless');
  mkdirSync(join(home, '.nuri-card'), { recursive: true });
  const env = { HOME: home, NURI_HOME_COSIGNER_SECURITY: join(fakeSecurity(tmp('nosec'), { pin: null }), 'security') };

  const missing = await run('bash', [script('run.sh')], { env });
  assert.notEqual(missing.code, 0);
  assert.match(missing.stderr, /security add-generic-password -s nuri-card-pin/);
  assert.equal(missing.stderr.includes(PIN), false);

  const short = await run('bash', [script('run.sh')], {
    env: { ...env, NURI_HOME_COSIGNER_SECURITY: join(fakeSecurity(tmp('short'), { pin: '12' }), 'security') },
  });
  assert.notEqual(short.code, 0);
  assert.match(short.stderr, /not 4-12 digits/);

  const good = await run('bash', [script('run.sh')], {
    env: { ...env, NURI_HOME_COSIGNER_SECURITY: join(fakeSecurity(tmp('good')), 'security'), NURI_HOME_COSIGNER_PRINT_CMD: '1' },
  });
  assert.equal(good.code, 0, good.stderr);
  assert.match(good.stdout, /local-card-cosign-server\.mjs --host=127\.0\.0\.1 --port=8787 --backend=real-card/);
  assert.equal(good.stdout.includes(PIN), false, 'the PIN reaches the server through the environment only');
});

test('wrapper enforces the 0600 PIN file used on Linux', async () => {
  const home = tmp('pinfile');
  mkdirSync(join(home, '.nuri-card'), { recursive: true });
  const pinFile = join(home, '.nuri-card/pin');
  const env = { HOME: home, NURI_HOME_COSIGNER_PIN_SOURCE: 'file', NURI_HOME_COSIGNER_PRINT_CMD: '1', PATH: '/opt/homebrew/bin:/usr/bin:/bin' };

  const absent = await run('bash', [script('run.sh')], { env });
  assert.notEqual(absent.code, 0);
  assert.match(absent.stderr, /no PIN file/);

  writeFileSync(pinFile, `${PIN}\n`, { mode: 0o644 });
  const loose = await run('bash', [script('run.sh')], { env });
  assert.notEqual(loose.code, 0);
  assert.match(loose.stderr, /must be mode 600/);

  chmodSync(pinFile, 0o600);
  const ok = await run('bash', [script('run.sh')], { env });
  assert.equal(ok.code, 0, ok.stderr);
  assert.equal(ok.stdout.includes(PIN), false);
});

// --- POST /api/send ----------------------------------------------------------

function fakeCli(dir) {
  const file = join(dir, 'fake-cli.mjs');
  writeFileSync(file, `#!/usr/bin/env node
const argv = process.argv.slice(2);
const pin = process.env.NURI_FIDO_PIN || '';
if (process.env.FAKE_SEND_FAIL === '1') { console.error('boom pin=' + pin); process.exit(3); }
console.log(JSON.stringify({ status: 'planned', argv, confirm: process.env.NURI_SEND_CONFIRM, pin_present: /^[0-9]{4,12}$/.test(pin),
  pin_in_argv: pin !== '' && argv.includes(pin), receipt: process.env.NURI_RECEIPT_PATH }));
`);
  chmodSync(file, 0o755);
  return file;
}

async function withServer(fn, { pin = PIN, extraEnv = {} } = {}) {
  const dir = tmp('srv');
  const env = {
    PATH: process.env.PATH,
    HOME: dir,
    NURI_COSIGN_TOKEN: randomBytes(32).toString('hex'),
    NURI_CARD_SEND_CLI: fakeCli(dir),
    NURI_CARD_SEND_OUT_DIR: join(dir, 'send'),
    ...(pin ? { NURI_CARD_PIN: pin } : {}),
    ...extraEnv,
  };
  const child = spawn(process.execPath, ['scripts/local-card-cosign-server.mjs', '--backend=real-card', `--port=${PORT}`], {
    cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  for (let i = 0; i < 120 && !/cosign demo server at/.test(out); i += 1) await new Promise((r) => setTimeout(r, 100));
  assert.match(out, /cosign demo server at/, `server did not start: ${out}`);
  const call = (body) => fetch(`http://127.0.0.1:${PORT}/api/send`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${env.NURI_COSIGN_TOKEN}` },
    body: JSON.stringify(body),
  }).then(async (r) => ({ status: r.status, body: await r.json() }));
  try { return await fn({ call, out: () => out }); } finally { child.kill('SIGTERM'); }
}

test('POST /api/send passes args through, defaults to a dry run, and hides the PIN', async () => {
  await withServer(async ({ call, out }) => {
    const r = await call({ to: TO, amount: 1000 });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.argv, ['--dry-run', '--to', TO, '--amount', '1000']);
    assert.equal(r.body.confirm, `${TO}-1000`, 'the confirmation is derived, not caller-supplied');
    assert.equal(r.body.pin_present, true);
    assert.equal(r.body.pin_in_argv, false);
    assert.match(r.body.receipt, /\.receipt\.json$/);
    assert.equal(out().includes(PIN), false, 'the PIN must not reach server stdout/stderr');

    const exec = await call({ to: '@emino', amount: 'all', execute: true });
    assert.equal(exec.status, 200, JSON.stringify(exec.body));
    assert.deepEqual(exec.body.argv, ['--execute', '--to', '@emino', '--amount', 'all']);
    assert.equal(exec.body.confirm, '@emino-all');

    const ignored = await call({ to: TO, amount: 5, execute: true, NURI_SEND_CONFIRM: '@elsewhere-9' });
    assert.deepEqual(ignored.body.argv, ['--execute', '--to', TO, '--amount', '5']);
    assert.equal(ignored.body.confirm, `${TO}-5`);
  });
});

test('POST /api/send rejects a bad target or amount before anything runs', async () => {
  await withServer(async ({ call }) => {
    assert.equal((await call({ to: 'bc1qxyz', amount: 1000 })).status, 400);
    assert.equal((await call({ to: TO })).status, 400);
    assert.equal((await call({ to: TO, amount: '0' })).status, 400);
    assert.equal((await call({ to: TO, amount: '1.5' })).status, 400);
  });
});

test('POST /api/send reports a missing PIN as 503 and a card failure as a redacted 502', async () => {
  await withServer(async ({ call }) => {
    const r = await call({ to: TO, amount: 1000 });
    assert.equal(r.status, 503);
    assert.match(r.body.error, /NURI_CARD_PIN/);
  }, { pin: '' });

  await withServer(async ({ call }) => {
    const r = await call({ to: TO, amount: 1000 });
    assert.equal(r.status, 502);
    assert.match(r.body.error, /send failed: boom pin=\[PIN\]/);
  }, { extraEnv: { FAKE_SEND_FAIL: '1' } });
});
