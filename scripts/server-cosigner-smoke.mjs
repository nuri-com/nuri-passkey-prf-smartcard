#!/usr/bin/env node
import { createHash } from 'node:crypto';
import process from 'node:process';
import { schnorr } from '@noble/curves/secp256k1.js';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { bytesToHex, hexToBytes } from '@noble/curves/utils.js';
import { ApduMuSig2Card, INS, SW, command, splitResponse } from '../src/musig2/apdu-sim.js';
import { SimulatedMuSig2Card } from '../src/musig2/card-sim.js';

const BACKENDS = new Set(['software', 'card-sim', 'apdu-sim']);

function sha256(text) {
  return new Uint8Array(createHash('sha256').update(text).digest());
}

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

function parseArgs(argv) {
  const out = {
    backend: null,
    json: false,
    msgHex: '',
  };
  for (const arg of argv) {
    if (arg === '--json') out.json = true;
    else if (arg.startsWith('--backend=')) out.backend = arg.slice('--backend='.length);
    else if (arg.startsWith('--msg32=')) out.msgHex = arg.slice('--msg32='.length);
    else if (arg === '--help' || arg === '-h') {
      console.log('Usage: node scripts/server-cosigner-smoke.mjs [--backend=software|card-sim|apdu-sim] [--msg32=<64 hex>] [--json]');
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!BACKENDS.has(out.backend)) {
    throw new Error(`backend must be one of: ${[...BACKENDS].join(', ')}`);
  }
  return out;
}

function tx(card, apdu) {
  const { data, sw } = splitResponse(card.transmit(apdu));
  if (sw !== SW.OK) throw new Error(`APDU failed with SW=${sw.toString(16)}`);
  return data;
}

function orderedNonces(sortedKeys, clientPk, cosignerPk, clientPubNonce, cosignerPubNonce) {
  return sortedKeys.map((pk) => {
    const current = bytesToHex(pk).toLowerCase();
    if (current === bytesToHex(clientPk).toLowerCase()) return clientPubNonce;
    if (current === bytesToHex(cosignerPk).toLowerCase()) return cosignerPubNonce;
    throw new Error('sorted key not recognized');
  });
}

function makeSoftwareBackend(secretKey, cosignerPk) {
  const sessions = new Map();
  return {
    kind: 'software',
    publicKey: () => cosignerPk,
    nonce({ sessionId, aggregateXonly, msg32 }) {
      const nonces = musig2.nonceGen(cosignerPk, secretKey, aggregateXonly, msg32);
      sessions.set(bytesToHex(sessionId), {
        secretNonce: nonces.secret,
        publicNonce: nonces.public,
      });
      return nonces.public;
    },
    partialSign({ sessionId, session }) {
      const state = sessions.get(bytesToHex(sessionId));
      if (!state) throw new Error('software nonce missing');
      sessions.delete(bytesToHex(sessionId));
      return session.sign(state.secretNonce, secretKey);
    },
  };
}

function makeCardSimBackend(secretKey) {
  const card = new SimulatedMuSig2Card(secretKey);
  return {
    kind: 'card-sim',
    publicKey: () => card.getIndividualPubkey(),
    nonce({ sessionId, aggregateXonly, msg32 }) {
      return card.nonceGen({
        aggregatePubkey: aggregateXonly,
        msg: msg32,
        sessionId: bytesToHex(sessionId),
      });
    },
    partialSign({ sessionId, session }) {
      return card.partialSign({
        session,
        sessionId: bytesToHex(sessionId),
      });
    },
  };
}

function makeApduSimBackend(secretKey) {
  const sessionRegistry = new Map();
  const card = new ApduMuSig2Card(secretKey, sessionRegistry);
  return {
    kind: 'apdu-sim',
    publicKey: () => tx(card, command(INS.GET_INDIVIDUAL_PUBKEY, Uint8Array.of(0))),
    nonce({ sessionId, aggregateXonly, msg32 }) {
      return tx(card, command(INS.NONCE_GEN, concatBytes(Uint8Array.of(0), sessionId, aggregateXonly, msg32)));
    },
    partialSign({ sessionId, session }) {
      sessionRegistry.set(bytesToHex(sessionId), session);
      return tx(card, command(INS.PARTIAL_SIGN, concatBytes(Uint8Array.of(0), sessionId)));
    },
  };
}

function makeBackend(kind, secretKey, cosignerPk) {
  if (kind === 'software') return makeSoftwareBackend(secretKey, cosignerPk);
  if (kind === 'card-sim') return makeCardSimBackend(secretKey);
  return makeApduSimBackend(secretKey);
}

function runSmoke(args) {
  const msg32 = args.msgHex ? hexToBytes(args.msgHex) : sha256('nuri-server-card-cosigner-smoke-v1');
  if (msg32.length !== 32) throw new Error('msg32 must be 32 bytes');

  const clientSecret = new Uint8Array(32).fill(0x41);
  const cosignerSecret = new Uint8Array(32).fill(0x72);
  const clientPk = musig2.IndividualPubkey(clientSecret);
  const cosignerPk = musig2.IndividualPubkey(cosignerSecret);
  const backend = makeBackend(args.backend, cosignerSecret, cosignerPk);
  const backendPk = backend.publicKey();

  if (bytesToHex(backendPk) !== bytesToHex(cosignerPk)) {
    throw new Error('backend public key mismatch');
  }

  const sortedKeys = musig2.sortKeys([clientPk, backendPk]);
  const aggregateXonly = musig2.keyAggExport(musig2.keyAggregate(sortedKeys));
  const sessionId = sha256(`nuri-server-card-cosigner-smoke:${args.backend}`).slice(0, 16);

  const clientNonces = musig2.nonceGen(clientPk, clientSecret, aggregateXonly, msg32);
  const cosignerPubNonce = backend.nonce({
    sessionId,
    aggregateXonly,
    msg32,
  });
  const aggregateNonce = musig2.nonceAggregate([clientNonces.public, cosignerPubNonce]);
  const session = new musig2.Session(aggregateNonce, sortedKeys, msg32);
  const cosignerPartial = backend.partialSign({
    sessionId,
    session,
  });

  const cosignerIndex = sortedKeys.findIndex((pk) => bytesToHex(pk) === bytesToHex(backendPk));
  const partialOk = session.partialSigVerify(
    cosignerPartial,
    orderedNonces(sortedKeys, clientPk, backendPk, clientNonces.public, cosignerPubNonce),
    cosignerIndex,
  );
  if (!partialOk) throw new Error('cosigner partial verification failed');

  const clientPartial = session.sign(clientNonces.secret, clientSecret);
  const finalSignature = session.partialSigAgg([clientPartial, cosignerPartial]);
  const finalOk = schnorr.verify(finalSignature, msg32, aggregateXonly);
  if (!finalOk) throw new Error('final aggregate signature verification failed');

  return {
    mode: 'sim',
    status: 'SERVER_CARD_COSIGNER_SMOKE_OK',
    backend: backend.kind,
    msg32: bytesToHex(msg32),
    client_pk33: bytesToHex(clientPk),
    cosigner_pk33: bytesToHex(backendPk),
    aggregate_xonly32: bytesToHex(aggregateXonly),
    client_pub_nonce66: bytesToHex(clientNonces.public),
    cosigner_pub_nonce66: bytesToHex(cosignerPubNonce),
    cosigner_partial32: bytesToHex(cosignerPartial),
    final_signature64: bytesToHex(finalSignature),
    cosigner_partial_verified: partialOk,
    final_signature_verified: finalOk,
  };
}

try {
  const args = parseArgs(process.argv.slice(2));
  console.error('WARNING: SIMULATOR: public software test keys, NOT a hardware card.');
  const result = runSmoke(args);
  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    for (const [key, value] of Object.entries(result)) console.log(`${key}=${value}`);
  }
} catch (error) {
  if (process.argv.includes('--json')) console.log(JSON.stringify({ mode: process.argv.some(a => a.startsWith('--backend=')) ? 'sim' : 'invalid', error: error?.message || String(error) }));
  console.error(error?.message || String(error));
  process.exit(1);
}
