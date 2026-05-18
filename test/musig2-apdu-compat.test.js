import assert from 'node:assert/strict';
import test from 'node:test';
import { schnorr } from '@noble/curves/secp256k1.js';
import * as musig2 from '@scure/btc-signer/musig2.js';
import {
  ApduMuSig2Card,
  INS,
  SW,
  command,
  splitResponse,
} from '../src/musig2/apdu-sim.js';
import { hex } from '../src/musig2/card-sim.js';

function concatBytes(...parts) {
  const len = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function tx(card, apdu) {
  const { data, sw } = splitResponse(card.transmit(apdu));
  assert.equal(sw, SW.OK);
  return data;
}

test('APDU simulator signs a scure-compatible MuSig2 session', () => {
  const sessionRegistry = new Map();
  const cards = [
    new ApduMuSig2Card(new Uint8Array(32).fill(0x11), sessionRegistry),
    new ApduMuSig2Card(new Uint8Array(32).fill(0x22), sessionRegistry),
    new ApduMuSig2Card(new Uint8Array(32).fill(0x33), sessionRegistry),
  ];
  const msg = new Uint8Array(32).fill(0x44);
  const sessionIds = cards.map((_, index) => new Uint8Array(16).fill(index + 1));

  const version = tx(cards[0], command(INS.GET_VERSION));
  assert.match(new TextDecoder().decode(version), /^nuri-musig2-apdu-sim\//);

  const pubkeys = cards.map((card) => tx(card, command(INS.GET_INDIVIDUAL_PUBKEY, Uint8Array.of(0))));
  const sortedPubkeys = musig2.sortKeys(pubkeys);
  const aggregatePubkey = musig2.keyAggExport(musig2.keyAggregate(sortedPubkeys));

  const publicNonces = cards.map((card, index) =>
    tx(
      card,
      command(
        INS.NONCE_GEN,
        concatBytes(Uint8Array.of(0), sessionIds[index], aggregatePubkey, msg)
      )
    )
  );
  const aggregateNonce = musig2.nonceAggregate(publicNonces);
  const session = new musig2.Session(aggregateNonce, sortedPubkeys, msg);
  for (const sessionId of sessionIds) sessionRegistry.set(hex(sessionId), session);

  const partialSignatures = cards.map((card, index) =>
    tx(card, command(INS.PARTIAL_SIGN, concatBytes(Uint8Array.of(0), sessionIds[index])))
  );
  const finalSignature = session.partialSigAgg(partialSignatures);

  assert.equal(schnorr.verify(finalSignature, msg, aggregatePubkey), true);

  const replay = splitResponse(
    cards[0].transmit(command(INS.PARTIAL_SIGN, concatBytes(Uint8Array.of(0), sessionIds[0])))
  );
  assert.equal(replay.sw, SW.WRONG_DATA);
});

test('APDU simulator rejects missing host session context', () => {
  const card = new ApduMuSig2Card(new Uint8Array(32).fill(0x55));
  const missingSession = new Uint8Array(16).fill(0xaa);
  const { sw } = splitResponse(
    card.transmit(command(INS.PARTIAL_SIGN, concatBytes(Uint8Array.of(0), missingSession)))
  );

  assert.equal(sw, SW.CONDITIONS_NOT_SATISFIED);
});
