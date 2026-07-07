import assert from 'node:assert/strict';
import test from 'node:test';
import { bytesToHex } from '@noble/curves/abstract/utils';
import * as musig2 from '@scure/btc-signer/musig2.js';
import {
  SimulatedCardArkadeSigner,
  SoftwarePasskeyArkadeSigner,
  parseHex33,
  runArkadeClientSignerProof,
  runArkadeClientSignerProofSuite,
  sha256Bytes,
} from '../src/musig2/arkade-client-signer.js';
import { SimulatedMuSig2Card } from '../src/musig2/card-sim.js';

function fixedSecret(byte) {
  return new Uint8Array(32).fill(byte);
}

async function makeDirectSession({ signer, msgLabel = 'direct arkade signer test', sessionId = 'direct-session' }) {
  const msg32 = sha256Bytes(msgLabel);
  const aspSecret = fixedSecret(0x72);
  const aspPk = musig2.IndividualPubkey(aspSecret);
  const clientPk = parseHex33(await signer.getClientPk33(), 'clientPk33');
  const sortedPubkeys = musig2.sortKeys([clientPk, aspPk]);
  const aggregateXonly = musig2.keyAggExport(musig2.keyAggregate(sortedPubkeys));
  const { clientPubNonce66 } = await signer.beginSign({
    sessionId,
    msg32: bytesToHex(msg32),
    aggregatedXonly32: bytesToHex(aggregateXonly),
  });
  const aspNonces = musig2.nonceGen(aspPk, aspSecret, aggregateXonly, msg32);
  const aggregateNonce = musig2.nonceAggregate([
    Buffer.from(clientPubNonce66, 'hex'),
    aspNonces.public,
  ]);
  return {
    msg32,
    sessionId,
    sortedPubkeys,
    aggregateNonce,
  };
}

test('Arkade card client signer proof verifies ASP partial, card partial, and final signature', async () => {
  const result = await runArkadeClientSignerProof({
    signer: new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(fixedSecret(0x51))),
    aspSecret: fixedSecret(0x72),
    message: 'nuri deterministic Arkade card client signer proof',
    sessionId: 'arkade-card-client-proof',
  });

  assert.equal(result.status, 'ARKADE_CARD_CLIENT_SIGNER_PROOF_OK');
  assert.equal(result.signer_kind, 'card');
  assert.equal(result.asp_partial_verified, true);
  assert.equal(result.client_partial_verified, true);
  assert.equal(result.final_signature_verified, true);
  assert.equal(result.client_pk33.length, 66);
  assert.equal(result.asp_pk33.length, 66);
  assert.equal(result.client_pub_nonce66.length, 132);
  assert.equal(result.asp_pub_nonce66.length, 132);
  assert.equal(result.client_partial32.length, 64);
  assert.equal(result.asp_partial32.length, 64);
  assert.equal(result.final_signature64.length, 128);
});

test('Arkade software-passkey signer still satisfies the same app-facing contract', async () => {
  const result = await runArkadeClientSignerProof({
    signer: new SoftwarePasskeyArkadeSigner(fixedSecret(0x41)),
    aspSecret: fixedSecret(0x72),
    message: 'nuri deterministic Arkade software passkey proof',
    sessionId: 'arkade-software-passkey-proof',
  });

  assert.equal(result.status, 'ARKADE_CARD_CLIENT_SIGNER_PROOF_OK');
  assert.equal(result.signer_kind, 'software-passkey');
  assert.equal(result.final_signature_verified, true);
  assert.equal(Object.hasOwn(result, 'client_secret'), false);
});

test('Arkade card client signer supports Arkade-style x-only Taproot tweak signing', async () => {
  const scriptRoot32 = bytesToHex(sha256Bytes('deterministic Arkade VTXO script root'));
  const result = await runArkadeClientSignerProof({
    signer: new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(fixedSecret(0x51))),
    aspSecret: fixedSecret(0x72),
    message: 'nuri deterministic Arkade tweaked signer proof',
    sessionId: 'arkade-card-client-tweaked-proof',
    scriptRoot32,
  });

  assert.equal(result.status, 'ARKADE_CARD_CLIENT_SIGNER_PROOF_OK');
  assert.equal(result.tweak_mode, 'arkade-script-root-taptweak-xonly');
  assert.equal(result.script_root32, scriptRoot32);
  assert.equal(result.tweak32.length, 64);
  assert.notEqual(result.signing_xonly32, result.internal_aggregate_xonly32);
  assert.equal(result.client_partial_verified, true);
  assert.equal(result.final_signature_verified, true);
});

test('Arkade proof suite keeps untweaked and tweaked cases distinct', async () => {
  const suite = await runArkadeClientSignerProofSuite({
    signerFactory: () => new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(fixedSecret(0x51))),
    aspSecret: fixedSecret(0x72),
    scriptRoot32: bytesToHex(sha256Bytes('suite script root')),
  });

  assert.equal(suite.status, 'ARKADE_CARD_CLIENT_SIGNER_PROOF_SUITE_OK');
  assert.equal(suite.cases.length, 2);
  assert.equal(suite.cases[0].tweak_mode, 'none');
  assert.equal(suite.cases[1].tweak_mode, 'arkade-script-root-taptweak-xonly');
  assert.notEqual(suite.cases[0].signing_xonly32, suite.cases[1].signing_xonly32);
});

test('Arkade card client signer rejects partial signing for a different msg32', async () => {
  const signer = new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(fixedSecret(0x51)));
  const direct = await makeDirectSession({ signer, sessionId: 'wrong-msg-session' });

  await assert.rejects(
    () => signer.partialSign({
      sessionId: direct.sessionId,
      msg32: bytesToHex(sha256Bytes('different msg')),
      sortedPubkeys33: direct.sortedPubkeys.map((pk) => bytesToHex(pk)),
      aggregateNonce66: bytesToHex(direct.aggregateNonce),
    }),
    /msg32 mismatch/
  );
});

test('Arkade host proof rejects an ASP partial bound to the wrong server nonce', async () => {
  const fakeSecret = fixedSecret(0x33);
  const fakePk = musig2.IndividualPubkey(fakeSecret);
  const fakeNonce = musig2.nonceGen(
    fakePk,
    fakeSecret,
    new Uint8Array(32).fill(0x01),
    sha256Bytes('fake server nonce')
  ).public;

  await assert.rejects(
    () => runArkadeClientSignerProof({
      signer: new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(fixedSecret(0x51))),
      aspSecret: fixedSecret(0x72),
      message: 'wrong server nonce proof',
      sessionId: 'wrong-server-nonce-proof',
      aspPubNonceOverride: bytesToHex(fakeNonce),
    }),
    /ASP partial signature verification failed|Partial signature verification failed/
  );
});

test('Arkade host proof rejects a card partial produced for the wrong tweak', async () => {
  const scriptRoot32 = bytesToHex(sha256Bytes('real script root'));
  const wrongTweak32 = bytesToHex(sha256Bytes('wrong tweak'));

  await assert.rejects(
    () => runArkadeClientSignerProof({
      signer: new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(fixedSecret(0x51))),
      aspSecret: fixedSecret(0x72),
      message: 'wrong tweak proof',
      sessionId: 'wrong-tweak-proof',
      scriptRoot32,
      signerTweak32: wrongTweak32,
    }),
    /card client partial signature verification failed/
  );
});

test('Arkade card client signer burns a nonce after one partial signature', async () => {
  const signer = new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(fixedSecret(0x51)));
  const direct = await makeDirectSession({ signer, sessionId: 'nonce-reuse-session' });
  const input = {
    sessionId: direct.sessionId,
    msg32: bytesToHex(direct.msg32),
    sortedPubkeys33: direct.sortedPubkeys.map((pk) => bytesToHex(pk)),
    aggregateNonce66: bytesToHex(direct.aggregateNonce),
  };

  const first = await signer.partialSign(input);
  assert.equal(first.clientPartial32.length, 64);
  await assert.rejects(() => signer.partialSign(input), /already used/);
});

test('Arkade card client signer rejects sorted pubkeys that omit the card client key', async () => {
  const wrongClientSecret = fixedSecret(0x23);
  const aspSecret = fixedSecret(0x72);
  const wrongClientPk = musig2.IndividualPubkey(wrongClientSecret);
  const aspPk = musig2.IndividualPubkey(aspSecret);

  await assert.rejects(
    () => runArkadeClientSignerProof({
      signer: new SimulatedCardArkadeSigner(new SimulatedMuSig2Card(fixedSecret(0x51))),
      aspSecret,
      message: 'wrong client pubkey proof',
      sessionId: 'wrong-client-pubkey-proof',
      sortedPubkeysOverride: musig2.sortKeys([wrongClientPk, aspPk]).map((pk) => bytesToHex(pk)),
    }),
    /does not include signer pubkey/
  );
});
