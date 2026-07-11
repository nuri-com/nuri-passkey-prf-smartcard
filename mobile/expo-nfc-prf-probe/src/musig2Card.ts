// MuSig2 card bridge over NFC (ISO-DEP).
// Extends the existing ctapPrf.ts ISO-DEP pattern to the MuSig2 applet.
// The card's key never leaves the card. This module only sends APDUs and
// returns pubkeys, nonces, and partial signatures.

import NfcManager, { NfcTech } from 'react-native-nfc-manager';

const MUSIG2_AID = '4E5552494D554701';

export type LogSink = (line: string) => void;

export type CardPubkey = Uint8Array; // 33 bytes
export type CardNonce = Uint8Array;  // 66 bytes (two compressed points)
export type CardPartial = Uint8Array; // 32 bytes

export type MuSig2Card = {
  pubkey: CardPubkey;
  version: string;
  nonces: () => Promise<CardNonce>;
  finalize: (a_i: Uint8Array, b32: Uint8Array, parity: number, e32: Uint8Array) => Promise<CardPartial>;
};

// --- helpers (same pattern as ctapPrf.ts) ------------------------------------

function hexToBytes(value: string): Uint8Array {
  const clean = value.replace(/[^0-9a-f]/gi, '');
  if (clean.length % 2 !== 0) throw new Error('Hex input has an odd length.');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = Number.parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array | number[]): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

// --- ISO-DEP APDU exchange (adapted from ctapPrf.ts) -------------------------

async function transceive(apdu: Uint8Array, log: LogSink): Promise<{ data: Uint8Array; sw1: number; sw2: number }> {
  log(`> ${bytesToHex(apdu)}`);
  const response = await NfcManager.isoDepHandler.transceive(Array.from(apdu));
  if (response.length < 2) throw new Error('Short APDU response.');
  const sw1 = response[response.length - 2];
  const sw2 = response[response.length - 1];
  const data = new Uint8Array(response.slice(0, -2));
  log(`< ${bytesToHex(data)} ${sw1.toString(16).padStart(2, '0')}${sw2.toString(16).padStart(2, '0')}`);
  return { data, sw1, sw2 };
}

async function exchangeApdu(
  cla: number,
  ins: number,
  p1: number,
  p2: number,
  data: Uint8Array,
  log: LogSink,
): Promise<{ data: Uint8Array; sw1: number; sw2: number }> {
  // Chained APDU for data > 250 bytes (same as ctapPrf.ts)
  let remaining = data;
  while (remaining.length > 250) {
    const chunk = remaining.slice(0, 250);
    remaining = remaining.slice(250);
    const response = await transceive(
      concatBytes(new Uint8Array([cla | 0x10, ins, p1, p2, chunk.length]), chunk),
      log,
    );
    if (response.sw1 !== 0x90 || response.sw2 !== 0x00) return response;
  }

  const body = remaining.length
    ? concatBytes(new Uint8Array([cla, ins, p1, p2, remaining.length]), remaining, new Uint8Array([0x00]))
    : new Uint8Array([cla, ins, p1, p2, 0x00]);
  let response = await transceive(body, log);
  let out = response.data;

  // GET RESPONSE chaining (SW=0x61xx)
  while (response.sw1 === 0x61) {
    response = await transceive(new Uint8Array([0x00, 0xc0, 0x00, 0x00, response.sw2]), log);
    out = concatBytes(out, response.data);
  }

  return { data: out, sw1: response.sw1, sw2: response.sw2 };
}

async function selectMusig2(log: LogSink): Promise<void> {
  const aid = hexToBytes(MUSIG2_AID);
  const response = await exchangeApdu(0x00, 0xa4, 0x04, 0x00, aid, log);
  if (response.sw1 !== 0x90 || response.sw2 !== 0x00) {
    throw new Error(`MuSig2 AID select failed: ${response.sw1.toString(16)}${response.sw2.toString(16)}`);
  }
}

// --- card operations ---------------------------------------------------------

// ponytail: the card APDU contract is simple — 4 commands, no CBOR, no crypto
// on the host side. The card does the MuSig2 partial; the host does BIP327
// session math via @scure/btc-signer. Ceiling: the applet has no PIN gate yet,
// so a compromised app could ask it to sign malicious hashes. Documented in
// docs/tap-to-pay-concept.md.

export async function withMusig2Card<T>(
  operation: (card: MuSig2Card) => Promise<T>,
  log: LogSink = () => {},
): Promise<T> {
  if (_nfcOpen) {
    // NFC already open — just select AID and run
    await selectMusig2(log);
    const verResp = await exchangeApdu(0x00, 0x01, 0x00, 0x00, new Uint8Array(), log);
    if (verResp.sw1 !== 0x90 || verResp.sw2 !== 0x00) throw new Error(`GET_VERSION failed: ${verResp.sw1.toString(16)}${verResp.sw2.toString(16)}`);
    const version = `${verResp.data[0]}.${verResp.data[1]}`;
    const pkResp = await exchangeApdu(0x00, 0x03, 0x00, 0x00, new Uint8Array(), log);
    if (pkResp.sw1 !== 0x90 || pkResp.sw2 !== 0x00) throw new Error(`GET_PUBKEY failed: ${pkResp.sw1.toString(16)}${pkResp.sw2.toString(16)}`);
    if (pkResp.data.length !== 33) throw new Error(`GET_PUBKEY returned ${pkResp.data.length} bytes, expected 33`);
    const card: MuSig2Card = {
      pubkey: pkResp.data,
      version,
      nonces: async () => {
        const resp = await exchangeApdu(0x00, 0x40, 0x00, 0x00, new Uint8Array(), log);
        if (resp.sw1 !== 0x90 || resp.sw2 !== 0x00) throw new Error(`GET_NONCES failed: ${resp.sw1.toString(16)}${resp.sw2.toString(16)}`);
        if (resp.data.length !== 66) throw new Error(`GET_NONCES returned ${resp.data.length} bytes, expected 66`);
        return resp.data;
      },
      finalize: async (a_i: Uint8Array, b32: Uint8Array, parity: number, e32: Uint8Array) => {
        const payload = concatBytes(a_i, b32, new Uint8Array([parity & 0xff]), e32);
        const resp = await exchangeApdu(0x00, 0x41, 0x00, 0x00, payload, log);
        if (resp.sw1 !== 0x90 || resp.sw2 !== 0x00) throw new Error(`FINALIZE failed: ${resp.sw1.toString(16)}${resp.sw2.toString(16)}`);
        if (resp.data.length !== 32) throw new Error(`FINALIZE returned ${resp.data.length} bytes, expected 32`);
        return resp.data;
      },
    };
    return await operation(card);
  }
  await NfcManager.start();
  await NfcManager.requestTechnology(NfcTech.IsoDep, {
    alertMessage: 'Hold the Nuri card near the phone.',
  });
  try {
    await selectMusig2(log);

    // INS 0x01: GET_VERSION → 2 bytes (major.minor)
    const verResp = await exchangeApdu(0x00, 0x01, 0x00, 0x00, new Uint8Array(), log);
    if (verResp.sw1 !== 0x90 || verResp.sw2 !== 0x00) {
      throw new Error(`GET_VERSION failed: ${verResp.sw1.toString(16)}${verResp.sw2.toString(16)}`);
    }
    const version = `${verResp.data[0]}.${verResp.data[1]}`;

    // INS 0x03: GET_PUBKEY → 33 bytes (compressed secp256k1)
    const pkResp = await exchangeApdu(0x00, 0x03, 0x00, 0x00, new Uint8Array(), log);
    if (pkResp.sw1 !== 0x90 || pkResp.sw2 !== 0x00) {
      throw new Error(`GET_PUBKEY failed: ${pkResp.sw1.toString(16)}${pkResp.sw2.toString(16)}`);
    }
    if (pkResp.data.length !== 33) {
      throw new Error(`GET_PUBKEY returned ${pkResp.data.length} bytes, expected 33`);
    }
    const pubkey = pkResp.data;

    const card: MuSig2Card = {
      pubkey,
      version,
      nonces: async () => {
        // INS 0x40: GET_NONCES → 66 bytes (two compressed points)
        const resp = await exchangeApdu(0x00, 0x40, 0x00, 0x00, new Uint8Array(), log);
        if (resp.sw1 !== 0x90 || resp.sw2 !== 0x00) {
          throw new Error(`GET_NONCES failed: ${resp.sw1.toString(16)}${resp.sw2.toString(16)}`);
        }
        if (resp.data.length !== 66) {
          throw new Error(`GET_NONCES returned ${resp.data.length} bytes, expected 66`);
        }
        return resp.data;
      },
      finalize: async (a_i: Uint8Array, b32: Uint8Array, parity: number, e32: Uint8Array) => {
        // INS 0x41: FINALIZE → input: a_i(32) || b(32) || parity(1) || e(32) = 97 bytes
        const payload = concatBytes(a_i, b32, new Uint8Array([parity & 0xff]), e32);
        const resp = await exchangeApdu(0x00, 0x41, 0x00, 0x00, payload, log);
        if (resp.sw1 !== 0x90 || resp.sw2 !== 0x00) {
          throw new Error(`FINALIZE failed: ${resp.sw1.toString(16)}${resp.sw2.toString(16)}`);
        }
        if (resp.data.length !== 32) {
          throw new Error(`FINALIZE returned ${resp.data.length} bytes, expected 32`);
        }
        return resp.data;
      },
    };

    return await operation(card);
  } finally {
    if (!_nfcOpen) await NfcManager.cancelTechnologyRequest({ throwOnError: false });
  }
}

let _nfcOpen = false;
export function setNfcSessionOpen(open: boolean) { _nfcOpen = open; }

// Convenience: read just the pubkey (no signing, read-only)
export async function readCardPubkey(log: LogSink = () => {}): Promise<{ pubkey: CardPubkey; version: string }> {
  return withMusig2Card(async (card) => ({ pubkey: card.pubkey, version: card.version }), log);
}

// Convenience: run a full MuSig2 signing round over NFC.
// getAspPartial is a callback that contacts the ASP for the server nonce +
// partial. The host does all BIP327 session math via @scure/btc-signer.
export async function musig2SignOverNfc(params: {
  msg32: Uint8Array;
  aggregateXonly: Uint8Array;
  getAspPartial: (cardPubnonce66: Uint8Array) => Promise<{
    serverPubkey33: Uint8Array;
    serverPubnonce66: Uint8Array;
    serverPartial32: Uint8Array;
  }>;
  tweak32?: Uint8Array;
  log?: LogSink;
}): Promise<{
  cardPubkey33: Uint8Array;
  cardPubnonce66: Uint8Array;
  serverPubkey33: Uint8Array;
  serverPubnonce66: Uint8Array;
  cardPartial32: Uint8Array;
  serverPartial32: Uint8Array;
  finalSignature64: Uint8Array;
}> {
  const log = params.log || (() => {});
  return withMusig2Card(async (card) => {
    // Lazy-load musig2 — keeps the module importable in Node for testing
    const musig2 = await import('@scure/btc-signer/musig2.js');
    const { schnorr, secp256k1 } = await import('@noble/curves/secp256k1.js');

    // 1. Card nonce
    const cardPubnonce66 = await card.nonces();
    log(`card pubnonce: ${bytesToHex(cardPubnonce66)}`);

    // 2. ASP partial (server nonce + partial)
    const asp = await params.getAspPartial(cardPubnonce66);
    log(`server pubkey: ${bytesToHex(asp.serverPubkey33)}`);
    log(`server pubnonce: ${bytesToHex(asp.serverPubnonce66)}`);

    // 3. BIP327 session math
    const sortedKeys = musig2.sortKeys([card.pubkey, asp.serverPubkey33]);
    const cardIndex = sortedKeys.findIndex((k: Uint8Array) => bytesToHex(k) === bytesToHex(card.pubkey));
    const aspIndex = sortedKeys.findIndex((k: Uint8Array) => bytesToHex(k) === bytesToHex(asp.serverPubkey33));

    const tweaks = params.tweak32 ? [params.tweak32] : [];
    const tweakModes = params.tweak32 ? [true] : [];
    const curveOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
    const internalAgg = musig2.keyAggregate(sortedKeys);
    const internalXonly = musig2.keyAggExport(internalAgg);
    const signingAgg = musig2.keyAggregate(sortedKeys, tweaks, tweakModes);
    const verificationXonly = musig2.keyAggExport(signingAgg);

    // Verify aggregate matches what the caller expects
    if (bytesToHex(internalXonly) !== bytesToHex(params.aggregateXonly)) {
      throw new Error(`aggregate mismatch: card+ASP = ${bytesToHex(internalXonly)}, expected ${bytesToHex(params.aggregateXonly)}`);
    }

    const aggregateNonce = musig2.nonceAggregate([cardPubnonce66, asp.serverPubnonce66]);
    const session = new musig2.Session(aggregateNonce, sortedKeys, params.msg32, tweaks, tweakModes);

    // 4. Verify the ASP partial
    const pubNonces = sortedKeys.map((k: Uint8Array) => {
      const hex = bytesToHex(k);
      if (hex === bytesToHex(card.pubkey)) return cardPubnonce66;
      if (hex === bytesToHex(asp.serverPubkey33)) return asp.serverPubnonce66;
      throw new Error('unknown sorted key');
    });

    const aspPartialOk = session.partialSigVerify(asp.serverPartial32, pubNonces, aspIndex);
    if (!aspPartialOk) throw new Error('ASP partial signature verification failed');

    // 5. Feed the card the values from the SAME BIP327 Session that verified
    // the server partial. Do not independently reimplement point arithmetic
    // here: Python and JavaScript modulo semantics differ, which previously
    // allowed the two host-side signing paths to drift.
    //
    // @scure currently marks these session values private in its TypeScript
    // declaration, but they are ordinary runtime fields in the pinned v2 API.
    // This checked adapter is deliberately the only place that reaches them.
    type SessionInternals = {
      b: bigint;
      e: bigint;
      R: { y: bigint };
      Q: { y: bigint };
      gAcc: bigint;
      getSessionKeyAggCoeff: (point: unknown) => bigint;
    };
    const sessionValues = session as unknown as SessionInternals;
    if (
      typeof sessionValues.b !== 'bigint'
      || typeof sessionValues.e !== 'bigint'
      || typeof sessionValues.R?.y !== 'bigint'
      || typeof sessionValues.Q?.y !== 'bigint'
      || typeof sessionValues.gAcc !== 'bigint'
      || typeof sessionValues.getSessionKeyAggCoeff !== 'function'
    ) {
      throw new Error('MuSig2 session internals unavailable; refusing to sign');
    }
    const scalar32 = (value: bigint): Uint8Array => {
      const out = new Uint8Array(32);
      let remaining = value % curveOrder;
      for (let i = 31; i >= 0; i--) { out[i] = Number(remaining & 0xffn); remaining >>= 8n; }
      return out;
    };
    const b32 = scalar32(sessionValues.b);
    const e32 = scalar32(sessionValues.e);
    const parity = sessionValues.R.y % 2n === 0n ? 0 : 1;
    const cardPoint = secp256k1.Point.fromBytes(card.pubkey);
    const cardCoeff = sessionValues.getSessionKeyAggCoeff(cardPoint);
    const g = sessionValues.Q.y % 2n === 0n ? 1n : curveOrder - 1n;
    const fold = (g * sessionValues.gAcc) % curveOrder;
    const cardCoeff32 = scalar32((cardCoeff * fold) % curveOrder);
    log(`session b: ${bytesToHex(b32)}`);
    log(`session e: ${bytesToHex(e32)}`);
    log(`session parity: ${parity}`);

    // 6. Send to card
    const cardPartial32 = await card.finalize(cardCoeff32, b32, parity, e32);
    log(`card partial: ${bytesToHex(cardPartial32)}`);

    // 7. Verify both partials with that same session.
    const cardPartialOk = session.partialSigVerify(cardPartial32, pubNonces, cardIndex);
    log(`card partial verify: ${cardPartialOk}`);
    if (!cardPartialOk) throw new Error('card partial signature verification failed');
    log(`server partial: ${bytesToHex(asp.serverPartial32)}`);
    log(`server partial verify: ${aspPartialOk}`);

    // 8. Aggregate with the same session, including any tweak term.
    const finalSignature = session.partialSigAgg([cardPartial32, asp.serverPartial32]);

    // 9. Verify final BIP340 signature
    const finalOk = schnorr.verify(finalSignature, params.msg32, verificationXonly);
    log(`final signature: ${bytesToHex(finalSignature)}`);
    log(`final aggregate verify: ${finalOk}`);
    if (!finalOk) throw new Error('final aggregate signature verification failed');

    return {
      cardPubkey33: card.pubkey,
      cardPubnonce66,
      serverPubkey33: asp.serverPubkey33,
      serverPubnonce66: asp.serverPubnonce66,
      cardPartial32,
      serverPartial32: asp.serverPartial32,
      finalSignature64: finalSignature,
    };
  }, log);
}
