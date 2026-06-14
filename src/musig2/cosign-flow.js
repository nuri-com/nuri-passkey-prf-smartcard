import { createHash, randomBytes } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { SimulatedMuSig2Card, bytes } from './card-sim.js';

export function sha256Bytes(value) {
  return new Uint8Array(createHash('sha256').update(value).digest());
}

export function concatBytes(...parts) {
  const len = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function makeSessionId(label = 'nuri-card-cosign-demo') {
  return sha256Bytes(`${label}:${Date.now()}:${bytesToHex(randomBytes(16))}`).slice(0, 16);
}

export function orderedNonces(sortedKeys, clientPk, cardPk, clientPubNonce, cardPubNonce) {
  const clientHex = bytesToHex(clientPk).toLowerCase();
  const cardHex = bytesToHex(cardPk).toLowerCase();
  return sortedKeys.map((pk) => {
    const current = bytesToHex(pk).toLowerCase();
    if (current === clientHex) return clientPubNonce;
    if (current === cardHex) return cardPubNonce;
    throw new Error('sorted key not recognized');
  });
}

export function parseMsg32({ msg32, message } = {}) {
  if (msg32) {
    const parsed = hexToBytes(msg32);
    if (parsed.length !== 32) throw new Error('msg32 must be exactly 32 bytes');
    return {
      msg32: parsed,
      source: 'provided_msg32',
    };
  }
  const text = message || 'nuri card cosign demo message';
  return {
    msg32: sha256Bytes(text),
    source: 'sha256_message',
    message: text,
  };
}

export function createOnCardGeneratedCard() {
  return new SimulatedMuSig2Card();
}

export function runCardCosignFlow({
  card = createOnCardGeneratedCard(),
  clientSecret = randomBytes(32),
  msg32,
  message,
  sessionId = makeSessionId(),
  backend = 'simulated-on-card-keygen',
} = {}) {
  const parsed = parseMsg32({ msg32, message });
  const clientSk = bytes(clientSecret, 'clientSecret');
  const clientPk = musig2.IndividualPubkey(clientSk);
  const cardPk = card.getIndividualPubkey();
  const sortedKeys = musig2.sortKeys([clientPk, cardPk]);
  const aggregateXonly = musig2.keyAggExport(musig2.keyAggregate(sortedKeys));

  const clientNonces = musig2.nonceGen(clientPk, clientSk, aggregateXonly, parsed.msg32);
  const cardPubNonce = card.nonceGen({
    aggregatePubkey: aggregateXonly,
    msg: parsed.msg32,
    sessionId: bytesToHex(sessionId),
  });
  const aggregateNonce = musig2.nonceAggregate([clientNonces.public, cardPubNonce]);
  const session = new musig2.Session(aggregateNonce, sortedKeys, parsed.msg32);
  const cardPartial = card.partialSign({
    session,
    sessionId: bytesToHex(sessionId),
  });

  const cardIndex = sortedKeys.findIndex((pk) => bytesToHex(pk) === bytesToHex(cardPk));
  const cardPartialVerified = session.partialSigVerify(
    cardPartial,
    orderedNonces(sortedKeys, clientPk, cardPk, clientNonces.public, cardPubNonce),
    cardIndex,
  );
  if (!cardPartialVerified) throw new Error('card partial signature verification failed');

  const clientPartial = session.sign(clientNonces.secret, clientSk);
  const finalSignature = session.partialSigAgg([clientPartial, cardPartial]);
  const finalSignatureVerified = schnorr.verify(finalSignature, parsed.msg32, aggregateXonly);
  if (!finalSignatureVerified) throw new Error('final aggregate signature verification failed');

  return {
    status: 'NURI_CARD_COSIGN_FLOW_OK',
    backend,
    key_origin: 'card-generated-non-exportable-in-backend',
    caveat: backend === 'simulated-on-card-keygen'
      ? 'Simulation: the card object generated the key internally and only exposes pubkey/nonce/partial-sign. The matching real-card proof is npm run cosign:real-card.'
      : undefined,
    msg32_source: parsed.source,
    message: parsed.message,
    msg32: bytesToHex(parsed.msg32),
    session_id16: bytesToHex(sessionId),
    client_pk33: bytesToHex(clientPk),
    card_pk33: bytesToHex(cardPk),
    sorted_pubkeys33: sortedKeys.map((pk) => bytesToHex(pk)),
    aggregate_xonly32: bytesToHex(aggregateXonly),
    client_pub_nonce66: bytesToHex(clientNonces.public),
    card_pub_nonce66: bytesToHex(cardPubNonce),
    aggregate_nonce66: bytesToHex(aggregateNonce),
    card_partial32: bytesToHex(cardPartial),
    client_partial32: bytesToHex(clientPartial),
    final_signature64: bytesToHex(finalSignature),
    card_partial_verified: cardPartialVerified,
    final_signature_verified: finalSignatureVerified,
    broadcast_note:
      'final_signature64 is a valid BIP340 Schnorr signature for msg32 and aggregate_xonly32. To broadcast Bitcoin, msg32 must be the real Taproot sighash for a funded transaction and final_signature64 must be inserted as the Taproot witness signature.',
  };
}
