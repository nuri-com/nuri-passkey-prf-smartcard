import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('tracked release files contain no developer-home paths or personal infrastructure IPs', () => {
  const files = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
  const pattern = /\/(?:Users)\/[A-Za-z][A-Za-z0-9._-]*\/|\b(?:188\.34\.194\.25|195\.201\.123\.221)\b|https?:\/\/[^\s/]+\.(?:ngrok-free\.app|ngrok\.io)/g;
  const failures = [];
  for (const file of files) {
    const path = resolve(root, file);
    if (!existsSync(path)) continue; // staged deletions, before the docs commit
    const hits = readFileSync(path).toString('latin1').match(pattern);
    if (hits) failures.push(`${file}: ${hits.length} publication leak(s)`);
  }
  assert.deepEqual(failures, []);
});

test('README evidence labels stay bounded and demo tooling stays explicit', () => {
  const readme = readFileSync(resolve(root, 'README.md'), 'utf8');
  // Keep room for the restored comparisons, HSM guide and capability reference.
  assert.ok(readme.split('\n').length < 1200, 'README should remain under 1200 lines');
  for (const heading of [
    'Compare the card',
    'Why it beats YubiKey',
    'Use cases',
    'For developers',
    'Wallet architecture reference',
    'The card as a hardware security module',
    'PKCS#11: built and tested, with explicit limits',
    'The vision',
    'Roadmap to the vision',
    'Capability reference',
  ]) assert.ok(readme.includes(heading), `Missing restored section: ${heading}`);
  assert.match(readme, /```mermaid/);
  const selling = readme.split('## For developers')[0];
  assert.match(selling, /Free with a \$1,000\+ BTC deposit, otherwise \$19\.99/);
  assert.ok(selling.indexOf('## What it does') < selling.indexOf('## Compare the card'));
  assert.doesNotMatch(selling, /Research stack|no product certification established|no screen|blind signing/);
  assert.doesNotMatch(readme, /Verify applet PIN; request public nonces/);
  const featureSection = readme.split('## Feature status')[1].split('### Supported readers')[0];
  const rows = featureSection.split('\n').filter(line => /^\| /.test(line)).slice(1);
  const allowed = new Set(['proven on a physical card', 'simulator only', 'planned']);
  for (const row of rows) assert.ok(allowed.has(row.split('|')[2].trim()), row);
  assert.match(readme, /not externally audited/);
  assert.match(readme, /not a certified hardware wallet/);
  assert.match(readme, /no screen/);
  assert.match(readme, /blind signing/);
  assert.match(readme, /Card presence is not user touch/);
  const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
  assert.equal(pkg.scripts['web:tunnel'], undefined);
  assert.equal(existsSync(resolve(root, 'scripts/serve-prf-ngrok.sh')), false);
});
