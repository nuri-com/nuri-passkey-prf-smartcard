import * as btc from '@scure/btc-signer';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';

export function hex(bytes) {
  return bytesToHex(bytes);
}

export function bytes(value, name = 'value') {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string') return hexToBytes(value);
  throw new TypeError(`${name} must be a Uint8Array or hex string`);
}

export class SimulatedMuSig2Card {
  constructor(secretKey = btc.utils.randomPrivateKeyBytes()) {
    this.secretKey = bytes(secretKey, 'secretKey');
    this.individualPubkey = musig2.IndividualPubkey(this.secretKey);
    this.sessions = new Map();
  }

  getIndividualPubkey() {
    return this.individualPubkey;
  }

  nonceGen({ aggregatePubkey, msg, sessionId = 'default' }) {
    const aggregate = bytes(aggregatePubkey, 'aggregatePubkey');
    const message = bytes(msg, 'msg');
    const nonces = musig2.nonceGen(this.individualPubkey, this.secretKey, aggregate, message);
    this.sessions.set(sessionId, {
      msg: message,
      aggregatePubkey: aggregate,
      publicNonce: nonces.public,
      secretNonce: nonces.secret,
      used: false,
    });
    return nonces.public;
  }

  partialSign({ session, sessionId = 'default' }) {
    const state = this.sessions.get(sessionId);
    if (!state) throw new Error(`unknown session: ${sessionId}`);
    if (state.used) throw new Error(`session already used: ${sessionId}`);
    state.used = true;
    return session.sign(state.secretNonce, this.secretKey);
  }

  resetSession(sessionId = 'default') {
    this.sessions.delete(sessionId);
  }
}

export function createSigningSession(cards, msg) {
  const message = bytes(msg, 'msg');
  const pubkeys = musig2.sortKeys(cards.map((card) => card.getIndividualPubkey()));
  const keyAggContext = musig2.keyAggregate(pubkeys);
  const aggregatePubkey = musig2.keyAggExport(keyAggContext);
  const publicNonces = cards.map((card, index) =>
    card.nonceGen({ aggregatePubkey, msg: message, sessionId: `signer-${index}` })
  );
  const aggregateNonce = musig2.nonceAggregate(publicNonces);
  const session = new musig2.Session(aggregateNonce, pubkeys, message);
  const partialSignatures = cards.map((card, index) =>
    card.partialSign({ session, sessionId: `signer-${index}` })
  );
  const finalSignature = session.partialSigAgg(partialSignatures);
  return {
    message,
    pubkeys,
    aggregatePubkey,
    publicNonces,
    aggregateNonce,
    session,
    partialSignatures,
    finalSignature,
  };
}
