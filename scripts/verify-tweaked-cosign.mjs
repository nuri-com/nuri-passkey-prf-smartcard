#!/usr/bin/env node
// Cross-check the card's tweaked cosign against scure + Nuri's exact derivation.
// Reads card-cosign-tweaked.py JSON on stdin (or runs nothing if given a fixture).
// Proves: (1) the card's tweaked output key == the Nuri musig2(client,card)+CSV
// Taproot output key derived by @scure/btc-signer, and (2) the card's final
// signature verifies as a BIP340 key-path signature for that output key.
import process from 'node:process';
import * as btc from '@scure/btc-signer';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils';

const CSV_BLOCKS = 52500; // must match scripts/card-cosign-tweaked.py and nuriBitcoin.ts

function nuriOutput(clientPk33Hex, cardPk33Hex) {
  // Mirrors nuri-v1a-sign-2fa/mcp/src/lib/nuriBitcoin.ts taprootCsvAddress():
  // internal key = musig2 aggregate of (client, card); single leaf = client CSV.
  const sorted = musig2.sortKeys([hexToBytes(clientPk33Hex), hexToBytes(cardPk33Hex)]);
  const aggComp = musig2.keyAggExport(musig2.keyAggregate(sorted));
  const Px = aggComp.length === 33 ? aggComp.slice(1) : aggComp;
  const userXOnly = hexToBytes(clientPk33Hex).slice(1);
  const leaf = {
    script: btc.Script.encode([userXOnly, 'CHECKSIGVERIFY', CSV_BLOCKS, 'CHECKSEQUENCEVERIFY']),
    leafVersion: 0xc0,
  };
  const p2tr = btc.p2tr(Px, [leaf], btc.NETWORK, true);
  return {
    internalXOnly: bytesToHex(Px),
    outputXOnly: bytesToHex(p2tr.script.slice(2)),
    address: p2tr.address,
  };
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

const raw = await readStdin();
const r = JSON.parse(raw.slice(raw.indexOf('{'), raw.lastIndexOf('}') + 1));

const nuri = nuriOutput(r.client_pk33, r.card_pk33);
const checks = {
  internal_key_matches: nuri.internalXOnly === r.internal_aggregate_xonly32,
  output_key_matches_nuri_scure: nuri.outputXOnly === r.tweaked_output_xonly32,
  signature_valid_bip340: schnorr.verify(
    hexToBytes(r.final_signature64),
    hexToBytes(r.msg32),
    hexToBytes(r.tweaked_output_xonly32),
  ),
};

const pass = Object.values(checks).every(Boolean);
console.log(JSON.stringify({
  ...checks,
  nuri_taproot_address: nuri.address,
  output_xonly: nuri.outputXOnly,
  status: pass ? 'CARD_TWEAKED_COSIGN_MATCHES_NURI_SCURE' : 'MISMATCH',
}, null, 2));
process.exit(pass ? 0 : 1);
