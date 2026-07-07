import { createHash, randomBytes } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import * as musig2 from '@scure/btc-signer/musig2.js';
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

export function taggedHash(tag, ...messages) {
  const tagHash = sha256Bytes(new TextEncoder().encode(tag));
  return sha256Bytes(concatBytes(tagHash, tagHash, ...messages));
}

export function tapTweakFromScriptRoot(internalXonly32, scriptRoot32) {
  return taggedHash('TapTweak', bytes(internalXonly32, 'internalXonly32'), bytes(scriptRoot32, 'scriptRoot32'));
}

export function makeArkadeSessionId(label = 'nuri-arkade-card-signer-proof') {
  return bytesToHex(sha256Bytes(`${label}:${Date.now()}:${bytesToHex(randomBytes(16))}`).slice(0, 16));
}

export function parseHex32(value, name) {
  const parsed = hexToBytes(value);
  if (parsed.length !== 32) throw new Error(`${name} must be exactly 32 bytes`);
  return parsed;
}

export function parseHex33(value, name) {
  const parsed = hexToBytes(value);
  if (parsed.length !== 33) throw new Error(`${name} must be exactly 33 bytes`);
  return parsed;
}

export function parseHex66(value, name) {
  const parsed = hexToBytes(value);
  if (parsed.length !== 66) throw new Error(`${name} must be exactly 66 bytes`);
  return parsed;
}

export function parseMsg32({ msg32, message } = {}) {
  if (msg32) {
    return {
      msg32: parseHex32(msg32, 'msg32'),
      source: 'provided_msg32',
    };
  }
  const text = message || 'nuri arkade card signer proof';
  return {
    msg32: sha256Bytes(text),
    source: 'sha256_message',
    message: text,
  };
}

export function orderedNonces(sortedPubkeys, clientPk, aspPk, clientPubNonce, aspPubNonce) {
  const clientHex = bytesToHex(clientPk).toLowerCase();
  const aspHex = bytesToHex(aspPk).toLowerCase();
  return sortedPubkeys.map((pk) => {
    const current = bytesToHex(pk).toLowerCase();
    if (current === clientHex) return clientPubNonce;
    if (current === aspHex) return aspPubNonce;
    throw new Error('sorted key not recognized');
  });
}

function tweakArgs(tweak32) {
  if (!tweak32) return { tweaks: [], tweakModes: [] };
  return { tweaks: [parseHex32(tweak32, 'tweak32')], tweakModes: [true] };
}

function assertSessionState(state, input, ownPk33) {
  if (!state) throw new Error(`unknown session: ${input.sessionId}`);
  if (state.used) throw new Error(`session already used: ${input.sessionId}`);
  const msg32 = parseHex32(input.msg32, 'msg32');
  if (bytesToHex(msg32) !== state.msg32) throw new Error('session msg32 mismatch');

  const sortedPubkeys = input.sortedPubkeys33.map((pk, index) => parseHex33(pk, `sortedPubkeys33[${index}]`));
  if (!sortedPubkeys.some((pk) => bytesToHex(pk) === bytesToHex(ownPk33))) {
    throw new Error('sortedPubkeys33 does not include signer pubkey');
  }
  const aggregateXonly = musig2.keyAggExport(musig2.keyAggregate(sortedPubkeys));
  if (bytesToHex(aggregateXonly) !== state.aggregateXonly32) {
    throw new Error('session aggregate pubkey mismatch');
  }

  const aggregateNonce = parseHex66(input.aggregateNonce66, 'aggregateNonce66');
  const { tweaks, tweakModes } = tweakArgs(input.tweak32);
  return {
    msg32,
    sortedPubkeys,
    aggregateNonce,
    session: new musig2.Session(aggregateNonce, sortedPubkeys, msg32, tweaks, tweakModes),
  };
}

export class SoftwarePasskeyArkadeSigner {
  kind = 'software-passkey';

  constructor(secretKey) {
    this.secretKey = bytes(secretKey, 'secretKey');
    this.clientPk33 = musig2.IndividualPubkey(this.secretKey);
    this.sessions = new Map();
  }

  async getClientPk33() {
    return bytesToHex(this.clientPk33);
  }

  async beginSign(input) {
    const msg32 = parseHex32(input.msg32, 'msg32');
    const aggregateXonly = parseHex32(input.aggregatedXonly32, 'aggregatedXonly32');
    const nonces = musig2.nonceGen(this.clientPk33, this.secretKey, aggregateXonly, msg32);
    this.sessions.set(input.sessionId, {
      msg32: bytesToHex(msg32),
      aggregateXonly32: bytesToHex(aggregateXonly),
      secretNonce: nonces.secret,
      used: false,
    });
    return { clientPubNonce66: bytesToHex(nonces.public) };
  }

  async partialSign(input) {
    const state = this.sessions.get(input.sessionId);
    const { session } = assertSessionState(state, input, this.clientPk33);
    state.used = true;
    this.sessions.delete(input.sessionId);
    return { clientPartial32: bytesToHex(session.sign(state.secretNonce, this.secretKey)) };
  }
}

export class SimulatedCardArkadeSigner {
  kind = 'card';

  constructor(card = new SimulatedMuSig2Card(), { proofDevOnly = true } = {}) {
    this.card = card;
    this.proofDevOnly = proofDevOnly;
    this.clientPk33 = this.card.getIndividualPubkey();
    this.sessions = new Map();
    this.activeSessionId = null;
  }

  async getClientPk33() {
    return bytesToHex(this.clientPk33);
  }

  async beginSign(input) {
    if (this.activeSessionId && this.activeSessionId !== input.sessionId) {
      throw new Error(`card signer already has active session: ${this.activeSessionId}`);
    }
    const msg32 = parseHex32(input.msg32, 'msg32');
    const aggregateXonly = parseHex32(input.aggregatedXonly32, 'aggregatedXonly32');
    const clientPubNonce = this.card.nonceGen({
      aggregatePubkey: aggregateXonly,
      msg: msg32,
      sessionId: input.sessionId,
    });
    this.sessions.set(input.sessionId, {
      msg32: bytesToHex(msg32),
      aggregateXonly32: bytesToHex(aggregateXonly),
      clientPubNonce66: bytesToHex(clientPubNonce),
      used: false,
    });
    this.activeSessionId = input.sessionId;
    return { clientPubNonce66: bytesToHex(clientPubNonce) };
  }

  async partialSign(input) {
    const state = this.sessions.get(input.sessionId);
    const { session } = assertSessionState(state, input, this.clientPk33);
    state.used = true;
    this.activeSessionId = null;
    const clientPartial = this.card.partialSign({
      session,
      sessionId: input.sessionId,
    });
    return { clientPartial32: bytesToHex(clientPartial) };
  }
}

export async function runArkadeClientSignerProof({
  signer = new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(new Uint8Array(32).fill(0x51))),
  aspSecret = new Uint8Array(32).fill(0x72),
  msg32,
  message,
  sessionId = makeArkadeSessionId(),
  scriptRoot32,
  tweak32,
  signerTweak32,
  aspPubNonceOverride,
  sortedPubkeysOverride,
} = {}) {
  const parsed = parseMsg32({ msg32, message });
  const aspSk = bytes(aspSecret, 'aspSecret');
  const aspPk = musig2.IndividualPubkey(aspSk);
  const clientPk = parseHex33(await signer.getClientPk33(), 'clientPk33');
  const sortedPubkeys = sortedPubkeysOverride
    ? sortedPubkeysOverride.map((pk, index) => parseHex33(pk, `sortedPubkeysOverride[${index}]`))
    : musig2.sortKeys([clientPk, aspPk]);
  if (!sortedPubkeys.some((pk) => bytesToHex(pk) === bytesToHex(clientPk))) {
    throw new Error('sortedPubkeys33 does not include signer pubkey');
  }
  if (!sortedPubkeys.some((pk) => bytesToHex(pk) === bytesToHex(aspPk))) {
    throw new Error('sortedPubkeys33 does not include ASP pubkey');
  }
  const internalAggregateXonly = musig2.keyAggExport(musig2.keyAggregate(sortedPubkeys));
  const effectiveTweak32 = tweak32
    || (scriptRoot32 ? bytesToHex(tapTweakFromScriptRoot(internalAggregateXonly, parseHex32(scriptRoot32, 'scriptRoot32'))) : '');
  const { tweaks, tweakModes } = tweakArgs(effectiveTweak32);
  const verificationXonly = musig2.keyAggExport(musig2.keyAggregate(sortedPubkeys, tweaks, tweakModes));

  const { clientPubNonce66 } = await signer.beginSign({
    sessionId,
    msg32: bytesToHex(parsed.msg32),
    aggregatedXonly32: bytesToHex(internalAggregateXonly),
  });
  const clientPubNonce = parseHex66(clientPubNonce66, 'clientPubNonce66');

  const aspNonces = musig2.nonceGen(aspPk, aspSk, internalAggregateXonly, parsed.msg32);
  const aspPubNonce = aspPubNonceOverride ? parseHex66(aspPubNonceOverride, 'aspPubNonceOverride') : aspNonces.public;
  const aggregateNonce = musig2.nonceAggregate([clientPubNonce, aspPubNonce]);
  const session = new musig2.Session(aggregateNonce, sortedPubkeys, parsed.msg32, tweaks, tweakModes);
  const pubNonces = orderedNonces(sortedPubkeys, clientPk, aspPk, clientPubNonce, aspPubNonce);
  const aspIndex = sortedPubkeys.findIndex((pk) => bytesToHex(pk) === bytesToHex(aspPk));
  const clientIndex = sortedPubkeys.findIndex((pk) => bytesToHex(pk) === bytesToHex(clientPk));

  const aspPartial = session.sign(aspNonces.secret, aspSk);
  const aspPartialVerified = session.partialSigVerify(aspPartial, pubNonces, aspIndex);
  if (!aspPartialVerified) throw new Error('ASP partial signature verification failed');

  const { clientPartial32 } = await signer.partialSign({
    sessionId,
    msg32: bytesToHex(parsed.msg32),
    sortedPubkeys33: sortedPubkeys.map((pk) => bytesToHex(pk)),
    aggregateNonce66: bytesToHex(aggregateNonce),
    tweak32: signerTweak32 ?? effectiveTweak32,
  });
  const clientPartial = parseHex32(clientPartial32, 'clientPartial32');
  const clientPartialVerified = session.partialSigVerify(clientPartial, pubNonces, clientIndex);
  if (!clientPartialVerified) throw new Error('card client partial signature verification failed');

  const finalSignature = session.partialSigAgg([clientPartial, aspPartial]);
  const finalSignatureVerified = schnorr.verify(finalSignature, parsed.msg32, verificationXonly);
  if (!finalSignatureVerified) throw new Error('final aggregate signature verification failed');

  return {
    status: 'ARKADE_CARD_CLIENT_SIGNER_PROOF_OK',
    signer_kind: signer.kind,
    proof_dev_only: signer.proofDevOnly === true,
    msg32_source: parsed.source,
    message: parsed.message,
    msg32: bytesToHex(parsed.msg32),
    session_id: sessionId,
    client_pk33: bytesToHex(clientPk),
    asp_pk33: bytesToHex(aspPk),
    sorted_pubkeys33: sortedPubkeys.map((pk) => bytesToHex(pk)),
    internal_aggregate_xonly32: bytesToHex(internalAggregateXonly),
    tweak_mode: effectiveTweak32 ? 'arkade-script-root-taptweak-xonly' : 'none',
    script_root32: scriptRoot32 || undefined,
    tweak32: effectiveTweak32 || undefined,
    signing_xonly32: bytesToHex(verificationXonly),
    client_pub_nonce66: bytesToHex(clientPubNonce),
    asp_pub_nonce66: bytesToHex(aspPubNonce),
    aggregate_nonce66: bytesToHex(aggregateNonce),
    asp_partial32: bytesToHex(aspPartial),
    client_partial32: bytesToHex(clientPartial),
    final_signature64: bytesToHex(finalSignature),
    asp_partial_verified: aspPartialVerified,
    client_partial_verified: clientPartialVerified,
    final_signature_verified: finalSignatureVerified,
    model:
      'card is the Arkade client signer; ASP/server is the second MuSig2 signer and Lightning/payment infrastructure',
    caveat:
      signer.kind === 'card'
        ? 'simulator/dev proof only until nonce/sign APDUs are PIN/UV-gated on-card'
        : undefined,
  };
}

export async function runArkadeClientSignerProofSuite(options = {}) {
  const {
    signer,
    signerFactory,
    sessionId,
    message,
    tweakedSessionId,
    tweakedMessage,
    scriptRoot32,
    tweak32,
    ...sharedOptions
  } = options;
  const makeSigner = () => signerFactory
    ? signerFactory()
    : signer || new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(new Uint8Array(32).fill(0x51)));
  const untweaked = await runArkadeClientSignerProof({
    ...sharedOptions,
    signer: makeSigner(),
    sessionId: sessionId || 'arkade-card-client-untweaked',
    message: message || 'nuri arkade card client signer untweaked proof',
  });
  const tweaked = await runArkadeClientSignerProof({
    ...sharedOptions,
    signer: makeSigner(),
    sessionId: tweakedSessionId || 'arkade-card-client-tweaked',
    message: tweakedMessage || 'nuri arkade card client signer tweaked proof',
    scriptRoot32: tweak32 ? undefined : scriptRoot32 || bytesToHex(sha256Bytes('nuri arkade vtxo script root proof')),
    tweak32,
  });
  return {
    status: 'ARKADE_CARD_CLIENT_SIGNER_PROOF_SUITE_OK',
    cases: [untweaked, tweaked],
  };
}
