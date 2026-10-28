// SPDX-License-Identifier: MIT
// Run in cloud CI with a separate pinned parser dependency directory.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
const require = createRequire(resolve(process.argv[2], 'package.json'));
const { JSDOM } = require('jsdom');
const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
globalThis.window = dom.window;
globalThis.document = dom.window.document;
globalThis.DOMPurify = undefined;
const { default: mermaid } = await import(pathToFileURL(require.resolve('mermaid')).href);
mermaid.initialize({ startOnLoad: false, securityLevel: 'strict' });
const results = [];
for (const file of ['README.md', 'docs/e2e-proof.md']) {
 const text = await readFile(file, 'utf8');
 const blocks = [...text.matchAll(/^```mermaid\n([\s\S]*?)^```/gm)];
 assert(blocks.length > 0, `${file} has no Mermaid`);
 for (const match of blocks) {
  await mermaid.parse(match[1]);
  results.push({ file, line: text.slice(0, match.index).split('\n').length, sha256: createHash('sha256').update(match[1]).digest('hex'), passed: true });
 }
}
await assert.rejects(mermaid.parse('sequenceDiagram\n THIS IS NOT VALID ->>'));
const report = { parser: 'mermaid@11.12.0', negative_control_rejected: true, blocks: results };
await writeFile(process.argv[3], JSON.stringify(report, null, 2));
console.log(`MERMAID_OK ${results.length} blocks, negative control rejected`);
