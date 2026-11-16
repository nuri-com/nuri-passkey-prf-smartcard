// Host-caller tests for MuSig2 applet 1.14 (PIN) through the Node servers.
// No hardware: REAL_CARD_COSIGN_PYTHON points at test/musig2-fake-python.py,
// which runs the real card scripts against test/musig2_fake_card.py.
import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const PYTHON = [process.env.NURI_TEST_PYTHON, join(ROOT, '.build/card-v1-python/bin/python'), '/opt/homebrew/bin/python3', '/usr/bin/python3']
  .find((p) => p && existsSync(p));
const PIN = '482915';
const havePython = Boolean(PYTHON);

function run(script, args, env) {
  return new Promise((res) => {
    execFile(process.execPath, [script, ...args], { cwd: ROOT, env, timeout: 120000, maxBuffer: 4 << 20 },
      (err, stdout, stderr) => res({ code: err ? err.code ?? 1 : 0, stdout, stderr }));
  });
}

function fakeEnv(dir, extra) {
  // execFile needs one executable: py.sh (see withShim) = python + fake runner.
  return {
    ...process.env,
    REAL_CARD_COSIGN_PYTHON: join(dir, 'py.sh'),
    FAKE_MUSIG2_ARGV_LOG: join(dir, 'argv.log'),
    REAL_CARD_COSIGN_PROFILE: join(dir, 'profile.json'),
    NURI_CARD_TOKEN_FILE: join(dir, 'token'),
    FIDO2_BACKUP_PIN: '',
    ...extra,
  };
}

async function withShim(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'musig2-pin-'));
  const shim = join(dir, 'py.sh');
  writeFileSync(shim, `#!/bin/sh\nexec "${PYTHON}" "${join(ROOT, 'test/musig2-fake-python.py')}" "$@"\n`);
  chmodSync(shim, 0o755);
  try { return await fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function argvLog(dir) {
  return readFileSync(join(dir, 'argv.log'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
}

test('card-mcp-server selftest on applet 1.14: PIN via env only, never argv, never printed', { skip: !havePython }, () => withShim(async (dir) => {
  const env = fakeEnv(dir, { FAKE_MUSIG2_VERSION: '1.14', FAKE_MUSIG2_PIN: PIN, NURI_CARD_PIN: PIN });
  const r = await run('scripts/card-mcp-server.mjs', ['--selftest'], env);
  assert.equal(r.code, 0, r.stderr + r.stdout);
  assert.match(r.stdout, /CARD_MCP_SELFTEST_OK/);
  assert.ok(!r.stdout.includes(PIN) && !r.stderr.includes(PIN), 'PIN leaked to output');
  const calls = argvLog(dir);
  assert.ok(calls.length >= 2);
  for (const c of calls) {
    assert.equal(c.pin_env_present, true);
    assert.ok(!c.argv.some((a) => a.includes(PIN)), `PIN in argv: ${c.argv}`);
  }
}));

test('card-mcp-server on applet 1.14 without NURI_CARD_PIN fails closed and says why', { skip: !havePython }, () => withShim(async (dir) => {
  const env = fakeEnv(dir, { FAKE_MUSIG2_VERSION: '1.14', FAKE_MUSIG2_PIN: PIN });
  delete env.NURI_CARD_PIN;
  const r = await run('scripts/card-mcp-server.mjs', ['--selftest'], env);
  assert.notEqual(r.code, 0);
  assert.match(r.stderr + r.stdout, /NURI_CARD_PIN/);
}));

test('card-mcp-server selftest on legacy 1.13 demo applet still works without a PIN', { skip: !havePython }, () => withShim(async (dir) => {
  const env = fakeEnv(dir, { FAKE_MUSIG2_VERSION: '1.13' });
  delete env.NURI_CARD_PIN;
  const r = await run('scripts/card-mcp-server.mjs', ['--selftest'], env);
  assert.equal(r.code, 0, r.stderr + r.stdout);
  assert.match(r.stdout, /CARD_MCP_SELFTEST_OK/);
}));

for (const version of ['1.13', '1.14']) {
  test(`local-card-cosign-server real-card selftest on applet ${version} (provision + reuse profile)`, { skip: !havePython }, () => withShim(async (dir) => {
    const env = fakeEnv(dir, { FAKE_MUSIG2_VERSION: version, FAKE_MUSIG2_PIN: PIN, NURI_CARD_PIN: PIN });
    for (const round of [1, 2]) {
      const r = await run('scripts/local-card-cosign-server.mjs', ['--backend=real-card', '--selftest'], env);
      assert.equal(r.code, 0, `round ${round}: ${r.stderr}${r.stdout}`);
      const out = JSON.parse(r.stdout);
      assert.equal(out.status, 'REAL_CARD_COSIGN_FLOW_OK');
      assert.equal(out.profile_created, round === 1);
      assert.equal(out.card_protocol, version === '1.14' ? 'pin-1.14' : 'legacy-pre-1.14');
      assert.equal(out.card_pin_verified, version === '1.14');
      assert.ok(!r.stdout.includes(PIN) && !r.stderr.includes(PIN));
    }
    for (const c of argvLog(dir)) assert.ok(!c.argv.some((a) => a.includes(PIN)));
  }));
}
