import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';

function run(script, args = []) {
  return spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', timeout: 15000 });
}

for (const [script, backends] of [
  ['scripts/arkade-card-signer-proof.mjs', ['card-sim', 'software-passkey']],
  ['scripts/server-cosigner-smoke.mjs', ['software', 'card-sim', 'apdu-sim']],
]) {
  test(`${script}: no implicit demonstration signer`, () => {
    const out = run(script, ['--json']);
    assert.notEqual(out.status, 0);
    const response = JSON.parse(out.stdout);
    assert.equal(response.mode, 'invalid');
    assert.match(response.error, /backend must be/);
    assert.equal(response.final_signature64, undefined);
  });
  for (const backend of backends) {
    test(`${script}: explicit ${backend} is loudly simulation`, () => {
      const out = run(script, [`--backend=${backend}`, '--json']);
      assert.equal(out.status, 0, out.stderr);
      assert.match(out.stderr, /WARNING: SIMULATOR/);
      const response = JSON.parse(out.stdout);
      assert.equal(response.mode, 'sim');
      if (response.cases) assert.ok(response.cases.every(p => p.final_signature_verified));
      else assert.equal(response.final_signature_verified, true);
    });
  }
}

test('simulator CLI requires --sim and declares mode on success', () => {
  const absent = run('src/musig2/card-sim-cli.js');
  assert.notEqual(absent.status, 0);
  assert.equal(absent.stdout, '');
  assert.match(absent.stderr, /requires explicit --sim/);
  const sim = run('src/musig2/card-sim-cli.js', ['--sim']);
  assert.equal(sim.status, 0, sim.stderr);
  assert.match(sim.stderr, /WARNING: SIMULATOR/);
  assert.match(sim.stdout, /mode=sim/);
  assert.match(sim.stdout, /verified=true/);
});

test('explicit demo errors still identify simulation', () => {
  const out = run('scripts/server-cosigner-smoke.mjs', ['--backend=card-sim', '--msg32=00', '--json']);
  assert.notEqual(out.status, 0);
  assert.equal(JSON.parse(out.stdout).mode, 'sim');
  assert.match(out.stderr, /WARNING: SIMULATOR/);
});
