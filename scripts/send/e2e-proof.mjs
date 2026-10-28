#!/usr/bin/env node
// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runSend, parseArgs, saveReceipt } from './cli.mjs';
import { CREDENTIAL } from './core.mjs';

export function renderProof(receipt) {
 const steps = receipt.steps;
 return `# End-to-end proof\n\nGenerated: ${receipt.generated_at}. Mode: **${receipt.mode}**.\n\n` +
  `This is an evidence report, not a claim that unexecuted hardware steps passed. The PRF-derived public key is distinct from the non-exportable MuSig2 applet key.\n\n` +
  `| Step | Status | Evidence |\n| --- | --- | --- |\n` + steps.map(s => `| ${s.name} | ${s.status} | ${s.evidence} |`).join('\n') + '\n\n' +
  `## Run\n\nSee [send tool](../scripts/send/README.md) for installation and exact guarded commands. The default is GET-only, no card. Hardware runs require funding and operator authorization.\n\n` +
  `## Derivation\n\nThe bridge evaluates CTAP2 hmac-secret twice with WebAuthn PRF salt SHA-256(UTF-8(\"WebAuthn PRF\") || 0x00 || UTF-8(\"nuri-prf-salt-v1\")). It requires equal outputs and derives Nuri key1 using the existing wallet HKDF-SHA256 and BIP86 derivation in [card-arkade-key](../scripts/card-arkade-key.mjs). Only the compressed public key and SHA-256 commitment of the PRF output are recorded, never raw PRF, private keys, PIN, assertion or approval tokens. This local determinism check is not remote PRF attestation. FIDO and MuSig2 use the same exact reader name but separate selections, so this transcript alone does not cryptographically attest cross-applet identity or rule out a physical card swap.\n\n` +
  `## Sequence\n\n\`\`\`mermaid\nsequenceDiagram\n    participant Host\n    participant Card\n    participant Nuri\n    participant Operator\n    participant Indexer\n    Host->>Indexer: GET spendable VTXOs\n    Host->>Card: FIDO2 hmac-secret twice with same salt\n    Card-->>Host: Deterministic PRF key1 public key and commitment\n    Host->>Nuri: POST send prepare\n    Nuri-->>Host: RP challenge and approval token\n    Host->>Card: FIDO2 assertion for nuri.com\n    Host->>Nuri: Assertion and public MuSig2 nonce\n    Nuri-->>Host: Server nonce and partial signature\n    Host->>Card: Verified MuSig2 FINALIZE context\n    Card-->>Host: Card partial signature\n    Host->>Host: Verify both BIP327 partials and BIP340 aggregate\n    Host->>Operator: Submit and finalize Ark transaction\n    Host->>Indexer: GET exact recipient and consumed inputs\n    Indexer-->>Host: Finalized output readback\n\`\`\`\n\n` +
  `## Public receipt\n\n\`\`\`json\n${JSON.stringify(receipt, null, 2)}\n\`\`\`\n`;
}

export async function runProof(options = {}, deps = {}) {
 const report = { schema: 'nuri-card-e2e-proof/v1', generated_at: new Date().toISOString(), mode: options.execute ? 'execute' : 'dry-run', steps: [] };
 const step = (name, status, evidence) => report.steps.push({ name, status, evidence });
 let prf;
 try {
  const send = await (deps.runSend ?? runSend)(options, { ...deps.sendDeps,
   beforeExecute: async ({ bridge }) => {
    const result = await bridge.request('prf-proof', { credential: CREDENTIAL });
    // Allowlist only public outputs even from a malformed bridge/mock.
    assert.equal(result.deterministic, true, 'PRF is not deterministic');
    assert.match(result.client_pk33, /^(02|03)[0-9a-f]{64}$/);
    assert.match(result.prf_commitment_sha256, /^[0-9a-f]{64}$/);
    prf = { deterministic: true, client_pk33: result.client_pk33, prf_commitment_sha256: result.prf_commitment_sha256 };
   },
  });
  report.send = send;
  if (prf) report.prf = prf;
  step('PASSKEY + PRF', prf ? 'verified' : 'not run', prf ? 'Same salt evaluated twice, public key1 and commitment recorded' : 'Hardware required, no card opened');
  const auth = send.auth_accepted?.accepted === true;
  step('AUTH', auth ? 'verified' : 'not run', auth ? 'Nuri accepted assertion and returned a verified server partial' : `Public registration GET only, username ${send.registration?.username ?? 'not recorded'}`);
  const proofs = send.proofs ?? [];
  const cosigned = proofs.length > 0 && proofs.every(p => p.card_partial_verified && p.server_partial_verified && p.bip340_verified);
  step('COSIGN', cosigned ? 'verified' : 'not run', cosigned ? `${proofs.length} card/server partials and BIP340 aggregates verified` : 'Physical MuSig2 AID3 and authenticated server required');
  step('ARKADE', send.indexer_verified ? 'verified' : 'not run', send.indexer_verified ? `Operator finalized ${send.txid}, exact indexer output and spent inputs verified` : send.message ?? 'Dry run, no operator submission');
  report.complete = !!(prf && auth && cosigned && send.indexer_verified);
  if (options.execute && send.status !== 'needs_funding') assert(report.complete, 'incomplete proof');
 } catch {
  if (prf) report.prf = prf;
  report.complete = false; report.failure = 'Proof stopped, inspect private send receipt before another operation. DO NOT RESEND.';
  if (report.steps.length === 0) {
   step('PASSKEY + PRF', prf ? 'verified' : 'not run', prf ? 'Determinism check completed before failure' : 'Not reached or failed');
   step('AUTH', 'unverified', 'Inspect private send receipt');
   step('COSIGN', 'unverified', 'Inspect private send receipt');
   step('ARKADE', 'unverified', report.failure);
  }
 }
 assert.equal(report.steps.length, 4, 'proof must record all four stages');
 const jsonPath = resolve(options.proofReceiptPath ?? 'docs/proofs/e2e-proof.json');
 const markdownPath = resolve(options.proofMarkdownPath ?? 'docs/e2e-proof.md');
 await (deps.save ?? (async () => {
  await saveReceipt(jsonPath, report);
  await mkdir(dirname(markdownPath), { recursive: true });
  await writeFile(markdownPath, renderProof(report));
 })) (report);
 if (report.failure) throw new Error(report.failure);
 return report;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
 try { console.log(JSON.stringify(await runProof(parseArgs(process.argv.slice(2))), null, 2)); }
 catch (error) { console.error(error.message); process.exitCode = 1; }
}
