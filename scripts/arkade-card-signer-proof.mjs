#!/usr/bin/env node
import process from 'node:process';
import { bytesToHex } from '@noble/curves/abstract/utils';
import {
  SimulatedCardArkadeSigner,
  SoftwarePasskeyArkadeSigner,
  runArkadeClientSignerProof,
  sha256Bytes,
} from '../src/musig2/arkade-client-signer.js';
import { SimulatedMuSig2Card } from '../src/musig2/card-sim.js';

const BACKENDS = new Set(['card-sim', 'software-passkey']);
const CASES = new Set(['all', 'untweaked', 'tweaked']);

function fixedSecret(byte) {
  return new Uint8Array(32).fill(byte);
}

function parseArgs(argv) {
  const args = {
    backend: 'card-sim',
    proofCase: 'all',
    json: false,
    scriptRoot32: bytesToHex(sha256Bytes('nuri arkade vtxo script root proof')),
  };
  for (const arg of argv) {
    if (arg === '--json') args.json = true;
    else if (arg.startsWith('--backend=')) args.backend = arg.slice('--backend='.length);
    else if (arg.startsWith('--case=')) args.proofCase = arg.slice('--case='.length);
    else if (arg.startsWith('--script-root32=')) args.scriptRoot32 = arg.slice('--script-root32='.length);
    else if (arg === '--help' || arg === '-h') {
      console.log([
        'Usage: node scripts/arkade-card-signer-proof.mjs [options]',
        '',
        'Options:',
        '  --backend=card-sim|software-passkey',
        '  --case=all|untweaked|tweaked',
        '  --script-root32=<64 hex>',
        '  --json',
      ].join('\n'));
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!BACKENDS.has(args.backend)) {
    throw new Error(`backend must be one of: ${[...BACKENDS].join(', ')}`);
  }
  if (!CASES.has(args.proofCase)) {
    throw new Error(`case must be one of: ${[...CASES].join(', ')}`);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(args.scriptRoot32)) {
    throw new Error('--script-root32 must be 32 bytes of hex');
  }
  return args;
}

function makeSigner(backend) {
  if (backend === 'software-passkey') return new SoftwarePasskeyArkadeSigner(fixedSecret(0x41));
  return new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(fixedSecret(0x51)));
}

async function run(args) {
  const cases = [];
  if (args.proofCase === 'all' || args.proofCase === 'untweaked') {
    cases.push(await runArkadeClientSignerProof({
      signer: makeSigner(args.backend),
      aspSecret: fixedSecret(0x72),
      message: 'nuri arkade card client signer untweaked proof',
      sessionId: `arkade-${args.backend}-untweaked`,
    }));
  }
  if (args.proofCase === 'all' || args.proofCase === 'tweaked') {
    cases.push(await runArkadeClientSignerProof({
      signer: makeSigner(args.backend),
      aspSecret: fixedSecret(0x72),
      message: 'nuri arkade card client signer script-root-tweaked proof',
      sessionId: `arkade-${args.backend}-tweaked`,
      scriptRoot32: args.scriptRoot32,
    }));
  }
  return {
    status: 'ARKADE_CARD_CLIENT_SIGNER_PROOF_SUITE_OK',
    backend: args.backend,
    cases,
  };
}

try {
  const args = parseArgs(process.argv.slice(2));
  const result = await run(args);
  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`status=${result.status}`);
    console.log(`backend=${result.backend}`);
    for (const proof of result.cases) {
      console.log(`case=${proof.tweak_mode}`);
      console.log(`client_pk33=${proof.client_pk33}`);
      console.log(`asp_pk33=${proof.asp_pk33}`);
      console.log(`signing_xonly32=${proof.signing_xonly32}`);
      if (proof.tweak32) console.log(`tweak32=${proof.tweak32}`);
      console.log(`asp_partial_verified=${proof.asp_partial_verified}`);
      console.log(`client_partial_verified=${proof.client_partial_verified}`);
      console.log(`final_signature_verified=${proof.final_signature_verified}`);
      console.log(`final_signature64=${proof.final_signature64}`);
    }
  }
} catch (error) {
  console.error(error?.message || String(error));
  process.exit(1);
}
