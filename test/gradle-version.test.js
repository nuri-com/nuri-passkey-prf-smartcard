import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));
const helper = path.join(root, 'scripts/require-system-gradle.sh');

function fixture(run) {
  mkdirSync(path.join(root, '.build'), { recursive: true });
  const dir = mkdtempSync(path.join(root, '.build/gradle-check-'));
  try {
    return run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function fakeGradle(dir, output, exit = 0) {
  const bin = path.join(dir, 'fake gradle');
  writeFileSync(bin, `#!/bin/bash\n[[ "$1" == --version ]] || exit 99\nprintf '%s\\n' '${output}'\nexit ${exit}\n`, { mode: 0o755 });
  return bin;
}

function check(bin) {
  return spawnSync('/bin/bash', ['-c',
    'set -euo pipefail; source "$1"; require_system_gradle; printf "ACCEPTED %s\\n" "$GRADLE_VERSION"',
    'gradle-version-test', helper], {
    cwd: root, env: { ...process.env, GRADLE_BIN: bin }, encoding: 'utf8',
  });
}

for (const version of ['8.2', '8.2.1', '8.14.3', '9.0.0', '10.0']) {
  test(`installed Gradle ${version} satisfies minimum`, () => fixture((dir) => {
    const result = check(fakeGradle(dir, `Gradle ${version}`));
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `ACCEPTED ${version}\n`);
  }));
}

for (const version of ['7.6.4', '8.0', '8.1.1']) {
  test(`installed Gradle ${version} is rejected`, () => fixture((dir) => {
    const result = check(fakeGradle(dir, `Gradle ${version}`));
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Gradle 8\.2 or newer is required; found/);
    assert.doesNotMatch(result.stdout, /ACCEPTED/);
  }));
}

test('missing Gradle has an actionable installation error', () => fixture((dir) => {
  const result = check(path.join(dir, 'missing-gradle'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Install it separately.*not found:/);
}));

test('failed Gradle --version retains diagnostics and stops', () => fixture((dir) => {
  const result = check(fakeGradle(dir, 'unsupported Java runtime', 7));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unsupported Java runtime/);
  assert.match(result.stderr, /--version failed/);
}));

test('unknown Gradle version is rejected rather than assumed usable', () => fixture((dir) => {
  const result = check(fakeGradle(dir, 'not a Gradle version'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Could not determine the installed Gradle version/);
}));

for (const script of ['build-card-v1-release.sh', 'run-fido2-prf-sim-tests.sh']) {
  test(`${script} rejects old Gradle before downloads or build setup`, () => fixture((dir) => {
    const result = spawnSync('/bin/bash', [path.join(root, 'scripts', script)], {
      cwd: root,
      env: { ...process.env, GRADLE_BIN: fakeGradle(dir, 'Gradle 8.1') },
      encoding: 'utf8',
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Gradle 8\.2 or newer is required; found 8\.1/);
    assert.equal(result.stdout, '');
  }));
}
