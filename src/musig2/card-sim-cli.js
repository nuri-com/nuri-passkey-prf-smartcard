#!/usr/bin/env node
import { schnorr } from '@noble/curves/secp256k1.js';
import { SimulatedMuSig2Card, createSigningSession, hex } from './card-sim.js';

const msg = new Uint8Array(32).fill(5);
const cards = [
  new SimulatedMuSig2Card(),
  new SimulatedMuSig2Card(),
  new SimulatedMuSig2Card(),
];

const result = createSigningSession(cards, msg);
const verified = schnorr.verify(result.finalSignature, result.message, result.aggregatePubkey);

console.log(`aggregate_pubkey=${hex(result.aggregatePubkey)}`);
console.log(`aggregate_nonce=${hex(result.aggregateNonce)}`);
console.log(`partial_signatures=${result.partialSignatures.map(hex).join(',')}`);
console.log(`final_signature=${hex(result.finalSignature)}`);
console.log(`verified=${verified}`);

if (!verified) process.exit(1);
