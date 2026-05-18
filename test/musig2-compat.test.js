import assert from 'node:assert/strict';
import test from 'node:test';
import { schnorr } from '@noble/curves/secp256k1.js';
import { SimulatedMuSig2Card, createSigningSession } from '../src/musig2/card-sim.js';

test('simulated card produces scure-compatible MuSig2 partial signatures', () => {
  const cards = [
    new SimulatedMuSig2Card(new Uint8Array(32).fill(1)),
    new SimulatedMuSig2Card(new Uint8Array(32).fill(2)),
    new SimulatedMuSig2Card(new Uint8Array(32).fill(3)),
  ];
  const msg = new Uint8Array(32).fill(5);
  const result = createSigningSession(cards, msg);

  assert.equal(result.aggregatePubkey.length, 32);
  assert.equal(result.aggregateNonce.length, 66);
  assert.equal(result.partialSignatures.length, 3);
  assert.equal(result.finalSignature.length, 64);
  assert.equal(schnorr.verify(result.finalSignature, msg, result.aggregatePubkey), true);
});

test('card nonce is single-use', () => {
  const cards = [
    new SimulatedMuSig2Card(new Uint8Array(32).fill(7)),
    new SimulatedMuSig2Card(new Uint8Array(32).fill(8)),
  ];
  const msg = new Uint8Array(32).fill(9);
  const result = createSigningSession(cards, msg);

  assert.throws(
    () => cards[0].partialSign({ session: result.session, sessionId: 'signer-0' }),
    /already used/
  );
});
