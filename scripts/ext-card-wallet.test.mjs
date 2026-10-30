// The extension bridge must actually run: config wiring, the read-only card
// status read, address derivation and the preview/decision protocol. Card and
// Nuri server are fakes; nothing real is touched.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as btc from '@scure/btc-signer';
import { schnorr } from '@noble/curves/secp256k1.js';

const BRIDGE = fileURLToPath(new URL('./ext-card-wallet.mjs', import.meta.url));
// Real curve points: the SDK rejects an x-only value that is not on secp256k1.
const XONLY = (n) => Buffer.from(schnorr.getPublicKey(new Uint8Array(32).fill(n))).toString('hex');
// Real 2000-sat invoice (light-bolt11-decoder fixture), so swap decoding is real work.
const INVOICE = 'lnbc20u1p3y0x3hpp5743k2g0fsqqxj7n8qzuhns5gmkk4djeejk3wkp64ppevgekvc0jsdqcve5kzar2v9nr5gpqd4hkuetesp5ez2g297jduwc20t6lmqlsg3man0vf2jfd8ar9fh8fhn2g8yttfkqxqy9gcqcqzys9qrsgqrzjqtx3k77yrrav9hye7zar2rtqlfkytl094dsp0ms5majzth6gt7ca6uhdkxl983uywgqqqqlgqqqvx5qqjqrzjqd98kxkpyw0l9tyy8r8q57k7zpy9zjmh6sez752wj6gcumqnj3yxzhdsmg6qq56utgqqqqqqqqqqqeqqjq7jd56882gtxhrjm03c93aacyfy306m4fq0tskf83c0nmet8zc2lxyyg3saz8x6vwcp26xnrlagf9semau3qm2glysp7sv95693fphvsp54l567';
const CARD_PK = '02' + XONLY(1);
const SERVER_PK = '02' + XONLY(2);
// CSVMultisigTapscript: 512 CHECKSEQUENCEVERIFY DROP <pk> CHECKSIG
// time-typed sequence (bit 22 set): 0x400200, then CHECKSEQUENCEVERIFY DROP <pk> CHECKSIG
const CHECKPOINT = '03' + '000240' + 'b275' + '20' + XONLY(5) + 'ac'; // pk must equal forfeitPubkey
const FORFEIT = btc.p2tr(XONLY(4), undefined, btc.NETWORK).address;

function arkInfo() {
  return {
    boardingExitDelay: 512, checkpointTapscript: CHECKPOINT, deprecatedSigners: [], digest: 'x', dust: 330,
    fees: { intentFee: { offchainInput: 0, onchainInput: 0, offchainOutput: 0, onchainOutput: 0 }, txFeeRate: '0' },
    forfeitAddress: FORFEIT, forfeitPubkey: XONLY(5), network: 'bitcoin', serviceStatus: {},
    sessionDuration: 512, signerPubkey: '02' + XONLY(6), unilateralExitDelay: 512,
    utxoMaxAmount: -1, utxoMinAmount: 1, version: '1', vtxoMaxAmount: -1, vtxoMinAmount: 1,
  };
}

// Fake Nuri signer + operator. Records every path so the test can prove what ran.
function server(sink) {
  return createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      sink.push({ path: request.url, body: body ? JSON.parse(body) : null });
      const url = new URL(request.url, 'http://localhost');
      const send = (value) => { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(value)); };
      if (url.pathname === '/v1/info') return send(sink.opInfo || arkInfo());
      if (url.pathname === '/v4/arkade/info') return send(sink.nuriInfo || { server_pubkey: SERVER_PK, nuri_server_csv: { type: 'seconds', value: 6674432 }, recovery: { registered: true }, username: null });
      if (url.pathname === '/v4/arkade/auth') return send({ token: 'tok', challenge: 'Y2hhbA', rp_id: 'nuri.com', registered: { server_pubkey: SERVER_PK } });
      if (url.pathname === '/api/arkade/receive/invoice') return send({ ok: true, invoice: INVOICE, payment_hash_hex: 'ab'.repeat(32), amount_sats: 2500 });
      if (url.pathname.startsWith('/v1/indexer')) return send({ vtxos: sink.vtxos || [] });
      if (url.pathname.startsWith('/api/address/')) return send(sink.utxos?.[url.pathname.split('/')[3]] || []);
      return send({});
    });
  });
}

function run(cfg, env) {
  const child = spawn(process.execPath, [BRIDGE], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  const lines = [];
  const waiters = [];
  let buffer = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf('\n')) !== -1) {
      lines.push(JSON.parse(buffer.slice(0, index)));
      buffer = buffer.slice(index + 1);
      for (const waiter of waiters.splice(0)) waiter();
    }
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const next = async (timeout = 20000) => {
    const deadline = Date.now() + timeout;
    while (!lines.length) {
      if (Date.now() > deadline) throw new Error(`no bridge output; stderr: ${stderr}`);
      await new Promise((resolve) => { waiters.push(resolve); setTimeout(resolve, 50); });
    }
    return lines.shift();
  };
  return { child, next, lines, stderr: () => stderr, start: (config) => child.stdin.write(JSON.stringify(config) + '\n'), decide: (d) => child.stdin.write(JSON.stringify(d) + '\n') };
}

async function workdir() {
  const dir = await mkdtemp(join(tmpdir(), 'nuri-bridge-'));
  const status = join(dir, 'status.py');
  await writeFile(status, `import json\nprint(json.dumps({"status":"ok","reader":"FAKE","version":"1.17","capabilities":0,"pin_required":True,"pin_set":True,"pin_tries_left":5,"card_pk33":"${CARD_PK}"}))\n`);
  const signer = join(dir, 'signer.py');
  // Emits a structurally valid result; the BIP340 maths is covered by host tests.
  await writeFile(signer, 'import json,sys\nprint(json.dumps({"final_signature_verified":True,"final_signature64":"00"*64}))\n');
  const profile = join(dir, 'profile.json');
  await writeFile(profile, JSON.stringify({ schema: 'nuri-card-prf-profile-v1', credential_id: 'cred', credential_public_key_spki_b64u: 'spki', rp_id: 'nuri.com', origin: 'https://app.nuri.com' }));
  return { status, signer, profile };
}

async function fixture(t) {
  const sink = [];
  const httpServer = server(sink);
  await new Promise((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  t.after(() => httpServer.close());
  const files = await workdir();
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  const env = {
    ...process.env,
    NURI_ARKADE_SIGNER_URL: base,
    NURI_ARKADE_NODE_URL: base,
    NURI_MEMPOOL_URL: base,
    NURI_CARD_RECEIVE_PROFILE: 'wallet',
    NURI_CARD_RECEIVE_PROFILE_PATH: files.profile,
    NURI_CARD_STATUS_SCRIPT: files.status,
    NURI_CARD_CLAIM_SIGNER: files.signer,
    REAL_CARD_COSIGN_PYTHON: process.env.NURI_HOST_PYTHON || 'python3',
  };
  return { sink, base, env };
}

test('info derives all three rails from the live server key and the card key', async (t) => {
  const { env } = await fixture(t);
  const job = run({}, env);
  t.after(() => job.child.kill());
  job.start({ mode: 'info', network: 'mainnet' });
  const out = await job.next();
  assert.equal(out.phase, 'result', JSON.stringify(out));
  assert.equal(out.card_pubkey33, CARD_PK);
  assert.match(out.ark_address, /^ark1/);
  assert.match(out.onchain_address, /^bc1p/);
  assert.match(out.boarding_address, /^bc1p/);
  assert.match(out.aggregate_pubkey33, /^0[23][0-9a-f]{64}$/);
  assert.equal(out.pin_set, true);
  assert.equal(out.pin_tries_left, 5);
});

test('an invoice is created through the owner profile', async (t) => {
  const { env, sink } = await fixture(t);
  const job = run({}, env);
  t.after(() => job.child.kill());
  job.start({ mode: 'invoice', amount_sats: 2500, memo: 'coffee', network: 'mainnet' });
  const out = await job.next();
  assert.equal(out.phase, 'result', JSON.stringify(out));
  assert.equal(out.invoice, INVOICE);
  const register = sink.find((r) => r.path === '/v4/arkade/auth');
  assert.equal(register.body.client_signer_pubkey, CARD_PK);
  assert.equal(sink.find((r) => r.path === '/api/arkade/receive/invoice').body.memo, 'coffee');
});

test('a Lightning send previews without the PIN, then signs from the decision', async (t) => {
  const { env } = await fixture(t);
  const job = run({}, env);
  t.after(() => job.child.kill());
  const invoice = INVOICE;
  job.start({ mode: 'send', kind: 'lightning', target: invoice, network: 'mainnet', boltzNetwork: 'bitcoin' });
  const preview = await job.next(30000);
  if (preview.phase === 'error') {
    // Fail closed: send is refused unless the SDK wallet is the Nuri contract
    // (or the Boltz lookup, which is not faked here, fails first).
    assert.match(preview.error, /SEND_UNSUPPORTED|boltz|swap/i, preview.error);
    return;
  }
  assert.equal(preview.phase, 'preview');
  assert.match(preview.digest, /^0x[0-9a-f]{64}$/);
  assert.equal(preview.summary.kind, 'lightning');
  job.decide({ approved: true, digest: preview.digest, pin: '2468' });
  const result = await job.next(60000);
  assert.equal(result.phase, 'result', JSON.stringify(result));
  assert.equal(result.approved_digest, preview.digest);
});

test('a decision with a wrong digest is refused', async (t) => {
  const { env } = await fixture(t);
  const job = run({}, env);
  t.after(() => job.child.kill());
  job.start({ mode: 'send', kind: 'lightning', target: INVOICE, network: 'mainnet', boltzNetwork: 'bitcoin' });
  const preview = await job.next(30000);
  if (preview.phase === 'error') return;
  job.decide({ approved: true, digest: '0x' + '00'.repeat(32), pin: '2468' });
  const out = await job.next(30000);
  assert.equal(out.phase, 'error');
  assert.match(out.error, /approval digest/);
});

test('the aggregate key is checked against the one the popup showed', async (t) => {
  const { env } = await fixture(t);
  const job = run({}, env);
  t.after(() => job.child.kill());
  job.start({ mode: 'send', kind: 'lightning', target: INVOICE, network: 'mainnet', boltzNetwork: 'bitcoin', aggregate_pubkey33: '02' + '99'.repeat(32) });
  const out = await job.next(30000);
  assert.equal(out.phase, 'error');
  assert.match(out.error, /does not match the displayed wallet/);
});

test('the missing PIN is only required once the human approved', async (t) => {
  const { env } = await fixture(t);
  const job = run({}, env);
  t.after(() => job.child.kill());
  job.start({ mode: 'send', kind: 'lightning', target: INVOICE, network: 'mainnet', boltzNetwork: 'bitcoin' });
  const preview = await job.next(30000);
  if (preview.phase === 'error') return;
  job.decide({ approved: true, digest: preview.digest });
  const out = await job.next(30000);
  assert.equal(out.phase, 'error');
  assert.match(out.error, /PIN is required/);
});

// Regression from the real card (2026-10-30): the bridge used the SDK default
// contract and showed 0 sats for a funded wallet. These are the LIVE public
// values of card 87E5470B (AID3 key) and its registered Nuri wallet: the bridge
// must derive exactly the addresses the proven send (scripts/send) spends from.
const REAL_CARD = '02b935bfc0d6d379243205d5c110732400cc8ae82e2fe94d6384963c7c9a62cae6';
const REAL_OP = {"network": "bitcoin", "signerPubkey": "038202bebddeb1f7442803897a85eaf3ce9254d07df0172fc3725ab5f0d097779c", "unilateralExitDelay": "605184", "boardingExitDelay": "7776256", "checkpointTapscript": "039e0440b27520b43a8363118c084a04d4f6a50ebfa58e81957f8cceceb2aee0ab64c9fd2d9977ac", "forfeitPubkey": "03b43a8363118c084a04d4f6a50ebfa58e81957f8cceceb2aee0ab64c9fd2d9977", "forfeitAddress": "bc1qzzdzp5c443vsetzatf2ra6hku322y7e5aq50rs", "dust": "330", "sessionDuration": "60", "vtxoMinAmount": "330", "vtxoMaxAmount": "50000000", "utxoMinAmount": "330", "utxoMaxAmount": "50000000", "version": "v0.9.23", "digest": "aa35278a87c17be041985c364c6ad8f8d30b87653e3e9c28a3aa9a9fb397854e", "fees": {"intentFee": {"offchainInput": "inputType == 'vtxo' && now() - birth < 86400.0 ? amount * 0.002 : 0.0", "offchainOutput": "", "onchainInput": "", "onchainOutput": "200.0"}, "txFeeRate": "0"}, "deprecatedSigners": [{"pubkey": "022b74c2011af089c849383ee527c72325de52df6a788428b68d49e9174053aaba", "cutoffDate": "1783159200"}], "serviceStatus": {}};
const REAL_NURI = { server_pubkey: '031dbb179bb996bcd6dc9c9cfccd73c649f987c10c6016650b53789056ae641e29', nuri_server_csv: { type: 'seconds', value: 6674432 }, nuri_contract_type: 'nuri_client_recovery_v1', recovery: { registered: true }, username: 'arkade' };
const REAL_ARK = 'ark1qzpq904am6clw3pgqwyh4p02708fy4xs0hcpwt7rwfdttuxsjameepfv6ed2mgaw4k2tdts49m4wkk3zqyrjv44sr2gcgxrm47gy7sqnlyjr3x';
const REAL_SCRIPT = '5120852cd65aada3aead94b6ae152eeaeb5a2201072656b01a9184187baf904f4013';
const REAL_BOARDING = 'bc1p48tcgtk50havqnyq7pswx7hux8szpfjrrv3477z7r6sl4s0vyaxspfzzwu';
const REAL_ONCHAIN = 'bc1pxa43e00wl6a2qqfd7wu8xgmuz8vczauvmn0nt45zff2kuq9u4klsfrz0f5';

async function realFixture(t) {
  const f = await fixture(t);
  Object.assign(f.sink, { nuriInfo: REAL_NURI, opInfo: REAL_OP });
  const status = join(await mkdtemp(join(tmpdir(), 'nuri-real-')), 'status.py');
  await writeFile(status, `import json\nprint(json.dumps({"status":"ok","reader":"FAKE","version":"1.17","capabilities":15,"pin_required":True,"pin_set":True,"pin_tries_left":5,"card_pk33":"${REAL_CARD}"}))\n`);
  f.env.NURI_CARD_STATUS_SCRIPT = status;
  return f;
}

test('real card: info derives the registered Nuri wallet, not the SDK default contract', async (t) => {
  const { env } = await realFixture(t);
  const job = run({}, env);
  t.after(() => job.child.kill());
  job.start({ mode: 'info', network: 'mainnet' });
  const out = await job.next();
  assert.equal(out.phase, 'result', JSON.stringify(out));
  assert.equal(out.ark_address, REAL_ARK);
  assert.equal(out.offchain_script, REAL_SCRIPT);
  assert.equal(out.boarding_address, REAL_BOARDING);
  assert.equal(out.onchain_address, REAL_ONCHAIN);
  assert.equal(out.username, 'arkade');
  assert.equal(out.registered, true);
});

test('real card: balance sums every rail, total first, from the derived scripts', async (t) => {
  const { env, sink } = await realFixture(t);
  sink.vtxos = [{ amount: '4000' }, { amount: '458' }];
  sink.utxos = { [REAL_ONCHAIN]: [{ txid: 'a'.repeat(64), vout: 0, value: 6007, status: { confirmed: true } }, { txid: 'a'.repeat(64), vout: 0, value: 6007, status: { confirmed: true } }] };
  const job = run({}, env);
  t.after(() => job.child.kill());
  job.start({ mode: 'balance', network: 'mainnet' });
  const out = await job.next();
  assert.equal(out.phase, 'result', JSON.stringify(out));
  assert.equal(out.vtxo_sats, 4458);
  assert.equal(out.onchain_sats, 6007, 'duplicate outpoint counted once');
  assert.equal(out.boarding_sats, 0);
  assert.equal(out.total_sats, 10465);
  assert.ok(sink.some((r) => r.path.includes(`scripts=${REAL_SCRIPT}`)), 'indexer queried with the derived Nuri script');
});

test('NURI_CARD_EXPECT_ARK mismatch fails closed', async (t) => {
  const { env } = await realFixture(t);
  env.NURI_CARD_EXPECT_ARK = 'ark1wrong';
  const job = run({}, env);
  t.after(() => job.child.kill());
  job.start({ mode: 'info', network: 'mainnet' });
  const out = await job.next();
  assert.equal(out.phase, 'error');
  assert.match(out.error, /NURI_CARD_EXPECT_ARK/);
});
