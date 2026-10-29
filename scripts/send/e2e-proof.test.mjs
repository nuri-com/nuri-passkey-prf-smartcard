// SPDX-License-Identifier: MIT
import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { runProof, renderProof, proofPaths } from './e2e-proof.mjs';
import { CREDENTIAL } from './core.mjs';
const prf = { deterministic: true, client_pk33: '02' + '11'.repeat(32), prf_commitment_sha256: '22'.repeat(32), raw_prf: 'MUST_NOT_LEAK' };
test('dry proof records funding and never requests a card', async () => {
 let saved;
 const report = await runProof({}, { save: async r => { saved = r; }, runSend: async (options, deps) => {
  assert.equal(options.execute, undefined);
  return { status: 'needs_funding', registration: { username: 'arkade' }, message: 'fund source >=546 sats' };
 } });
 assert.equal(saved, report); assert.equal(report.steps.length, 4); assert(!report.complete);
 assert(report.steps.every(s => s.status === 'not run')); assert.match(renderProof(report), /username arkade/);
});
test('proof executes PRF before send and allowlists public evidence', async () => {
 const report = await runProof({ execute: true }, { save: async () => {}, runSend: async (options, deps) => {
  await deps.beforeExecute({ bridge: { request: async (op, payload) => {
   assert.equal(op, 'prf-proof'); assert.equal(payload.credential, CREDENTIAL); return prf;
  } } });
  return { auth_accepted: { accepted: true }, proofs: [{ card_partial_verified: true, server_partial_verified: true, bip340_verified: true }], indexer_verified: true, txid: 'ab'.repeat(32) };
 } });
 assert(report.complete); assert.equal(report.steps.length, 4); assert(report.steps.every(s => s.status === 'verified'));
 assert(!JSON.stringify(report).includes('MUST_NOT_LEAK'));
});
test('nondeterministic PRF aborts before a mock send can finalize and writes failure', async () => {
 let saved, finalized = false;
 await assert.rejects(runProof({ execute: true }, { save: async r => { saved = r; }, runSend: async (options, deps) => {
  await deps.beforeExecute({ bridge: { request: async () => ({ ...prf, deterministic: false }) } });
  finalized = true;
 } }), /DO NOT RESEND/);
 assert(!finalized); assert(!saved.complete); assert.equal(saved.steps.length, 4);
});
test('dry run never targets the committed hardware receipt', () => {
 assert.equal(proofPaths({}).json, resolve('_launch/out/e2e-proof/proofs/e2e-proof.json'));
 assert.equal(proofPaths({}).markdown, resolve('_launch/out/e2e-proof/e2e-proof.md'));
 assert.equal(proofPaths({ execute: true }).json, resolve('docs/proofs/e2e-proof.json'));
 assert.equal(proofPaths({ execute: true }).markdown, resolve('docs/e2e-proof.md'));
});
test('public report keeps local receipt and log paths repo-relative', async () => {
 const report = await runProof({}, { save: async () => {}, runSend: async () => ({ status: 'needs_funding',
  receipt_file: resolve('_launch/out/send/receipt.json'), log_file: resolve('_launch/out/send/send-1.jsonl') }) });
 assert.equal(report.send.receipt_file, '_launch/out/send/receipt.json');
 assert.equal(report.send.log_file, '_launch/out/send/send-1.jsonl');
 assert(!renderProof(report).includes(process.cwd()));
});
test('missing partial proof cannot produce a complete proof even after indexer readback', async () => {
 let saved;
 await assert.rejects(runProof({ execute: true }, { save: async r => { saved = r; }, runSend: async (options, deps) => {
  await deps.beforeExecute({ bridge: { request: async () => prf } });
  return { auth_accepted: { accepted: true }, proofs: [], indexer_verified: true };
 } }), /DO NOT RESEND/);
 assert(!saved.complete); assert.equal(saved.steps.length, 4);
});
