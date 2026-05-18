import { SimulatedMuSig2Card, bytes, hex } from './card-sim.js';

export const CLA_NURI = 0x80;

export const INS = Object.freeze({
  GET_VERSION: 0x01,
  GET_INDIVIDUAL_PUBKEY: 0x10,
  NONCE_GEN: 0x20,
  PARTIAL_SIGN: 0x30,
  RESET_SESSION: 0x40,
});

export const SW = Object.freeze({
  OK: 0x9000,
  WRONG_LENGTH: 0x6700,
  CONDITIONS_NOT_SATISFIED: 0x6985,
  WRONG_DATA: 0x6a80,
  INS_NOT_SUPPORTED: 0x6d00,
  CLA_NOT_SUPPORTED: 0x6e00,
});

const VERSION = new TextEncoder().encode('nuri-musig2-apdu-sim/0.1');
const KEY_SLOT_INTERNAL = 0;
const SESSION_ID_LEN = 16;

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

function statusWord(sw) {
  return Uint8Array.of((sw >> 8) & 0xff, sw & 0xff);
}

function response(data = new Uint8Array(), sw = SW.OK) {
  return concatBytes(data, statusWord(sw));
}

function parseShortApdu(apdu) {
  const input = bytes(apdu, 'apdu');
  if (input.length < 4) throw new RangeError('APDU header is too short');
  if (input.length === 4) {
    return {
      cla: input[0],
      ins: input[1],
      p1: input[2],
      p2: input[3],
      data: new Uint8Array(),
    };
  }
  const lc = input[4];
  if (input.length !== 5 + lc) throw new RangeError('wrong APDU Lc');
  return {
    cla: input[0],
    ins: input[1],
    p1: input[2],
    p2: input[3],
    data: input.slice(5),
  };
}

function requireInternalSlot(slot) {
  if (slot !== KEY_SLOT_INTERNAL) throw new Error('unsupported key slot');
}

function readSessionId(data, offset) {
  return hex(data.slice(offset, offset + SESSION_ID_LEN));
}

export function command(ins, data = new Uint8Array(), { cla = CLA_NURI, p1 = 0, p2 = 0 } = {}) {
  const payload = bytes(data, 'data');
  if (payload.length > 255) throw new RangeError('short APDU payload exceeds 255 bytes');
  return concatBytes(Uint8Array.of(cla, ins, p1, p2, payload.length), payload);
}

export function splitResponse(apduResponse) {
  const raw = bytes(apduResponse, 'response');
  if (raw.length < 2) throw new RangeError('response missing status word');
  const data = raw.slice(0, -2);
  const sw = (raw[raw.length - 2] << 8) | raw[raw.length - 1];
  return { data, sw };
}

export class ApduMuSig2Card {
  constructor(secretKey, sessionRegistry = new Map()) {
    this.card = new SimulatedMuSig2Card(secretKey);
    this.sessionRegistry = sessionRegistry;
  }

  transmit(apdu) {
    let parsed;
    try {
      parsed = parseShortApdu(apdu);
    } catch {
      return response(new Uint8Array(), SW.WRONG_LENGTH);
    }

    if (parsed.cla !== CLA_NURI) return response(new Uint8Array(), SW.CLA_NOT_SUPPORTED);

    try {
      switch (parsed.ins) {
        case INS.GET_VERSION:
          if (parsed.data.length !== 0) return response(new Uint8Array(), SW.WRONG_LENGTH);
          return response(VERSION);
        case INS.GET_INDIVIDUAL_PUBKEY:
          return this.getIndividualPubkey(parsed.data);
        case INS.NONCE_GEN:
          return this.nonceGen(parsed.data);
        case INS.PARTIAL_SIGN:
          return this.partialSign(parsed.data);
        case INS.RESET_SESSION:
          return this.resetSession(parsed.data);
        default:
          return response(new Uint8Array(), SW.INS_NOT_SUPPORTED);
      }
    } catch {
      return response(new Uint8Array(), SW.WRONG_DATA);
    }
  }

  getIndividualPubkey(data) {
    if (data.length !== 1) return response(new Uint8Array(), SW.WRONG_LENGTH);
    requireInternalSlot(data[0]);
    return response(this.card.getIndividualPubkey());
  }

  nonceGen(data) {
    if (data.length !== 1 + SESSION_ID_LEN + 32 + 32) {
      return response(new Uint8Array(), SW.WRONG_LENGTH);
    }
    requireInternalSlot(data[0]);
    const sessionId = readSessionId(data, 1);
    const aggregatePubkey = data.slice(1 + SESSION_ID_LEN, 1 + SESSION_ID_LEN + 32);
    const msg = data.slice(1 + SESSION_ID_LEN + 32);
    return response(this.card.nonceGen({ aggregatePubkey, msg, sessionId }));
  }

  partialSign(data) {
    if (data.length !== 1 + SESSION_ID_LEN) return response(new Uint8Array(), SW.WRONG_LENGTH);
    requireInternalSlot(data[0]);
    const sessionId = readSessionId(data, 1);
    const session = this.sessionRegistry.get(sessionId);
    if (!session) return response(new Uint8Array(), SW.CONDITIONS_NOT_SATISFIED);
    return response(this.card.partialSign({ session, sessionId }));
  }

  resetSession(data) {
    if (data.length !== SESSION_ID_LEN) return response(new Uint8Array(), SW.WRONG_LENGTH);
    this.card.resetSession(readSessionId(data, 0));
    return response();
  }
}
