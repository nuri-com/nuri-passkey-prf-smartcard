import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { sdk, musig, SoftwareCardSigner, deriveAddresses, hex, bytes } from './deps.mjs';
import { plan, guard, SOURCE, SCRIPT, CLIENT, SERVER, CardIdentity, floorOf } from './core.mjs';
import { parseArgs, runSend, resolveRecipient, Bridge, saveReceipt } from './cli.mjs';
const coins = [4444, 1010, 1664].map((value, i) => ({ txid: String(i + 1).repeat(64), vout: i, value }));
const destination = new sdk.ArkAddress(sdk.ArkAddress.decode(SOURCE).serverPubKey, bytes('ab'.repeat(32)), 'ark').encode();

test('args default to dry self; amount and recipient strictly parsed', () => {
 assert.deepEqual(parseArgs(), { execute: false, to: SOURCE });
 assert.deepEqual(parseArgs(['--to', '@emino', '--amount', 'all']), { execute: false, to: '@emino', amount: 'all' });
 assert.equal(parseArgs(['--execute', '--amount', '546']).execute, true);
 for (const args of [['--unknown'], ['--to'], ['--amount', '0'], ['--amount', '-1'], ['--amount', '5.5'], ['--amount', '01'], ['--amount', '9007199254740992'], ['--to', '@foo.bar'], ['--to', 'ARK1'], ['--execute','--dry-run'], ['--execute','--execute']]) assert.throws(() => parseArgs(args));
});
test('guard binds original recipient and exact amount, never legacy sweep', () => {
 guard(false); guard(true, '@emino-546', '@emino', '546');
 guard(true, `${SOURCE}-all`, SOURCE, 'all');
 for (const value of [undefined, 'emino-7118', '@emino-all', `${SOURCE}-546`]) assert.throws(() => guard(true, value, '@emino', '546'));
});
test('partial send and change conserve value; sweep all is explicit', () => {
 const p = plan(destination, coins, 7118);
 assert.equal(p.recipient_sats, 546); assert.equal(p.change_sats, 6572); assert.equal(p.fee_sats, 0);
 assert.equal(plan(destination, coins, 7118, { amount: 'all' }).change_sats, 0);
 assert.equal(plan(SOURCE, coins, 7118, { amount: '1000', floor: 1000 }).change_sats, 6118);
 assert.equal(plan(SOURCE, coins, 7118, { floor: 1000 }).recipient_sats, 1000);
});
test('empty source reports funding minimum and higher operator floor', () => {
 assert.match(plan(SOURCE, [], 0).message, new RegExp(`^fund ${SOURCE} >=546 sats$`));
 assert.equal(plan(SOURCE, [], 0, { floor: 1000 }).minimum_funding_sats, 1000);
 assert.equal(plan(SOURCE, [], 0, { amount: 'all', floor: 1000 }).minimum_funding_sats, 1000);
 assert.equal(plan(SOURCE, [], 0, { amount: '2000', floor: 1000 }).minimum_funding_sats, 2000);
 assert.throws(() => plan(SOURCE, [], 0, { amount: '500', floor: 1000 }));
 assert.equal(floorOf({ dust: '330' }), 330);
 assert.equal(floorOf({ vtxoMinAmount: 0n, dust: 330n }), 330);
 assert.equal(floorOf({ vtxoMinAmount: 100n, dust: 330n }), 330);
 assert.equal(floorOf({ vtxoMinAmount: 1000n, dust: 330n }), 1000);
 assert.throws(() => floorOf({})); assert.throws(() => floorOf({ vtxoMinAmount: -1, dust: 330 }));
});
test('reject unsafe amount, changed total, duplicates, assets, spent, wrong script/operator, dusty change', () => {
 assert.throws(() => plan('other', coins, 7118));
 assert.throws(() => plan(destination, coins, 7117));
 assert.throws(() => plan(destination, [...coins, coins[0]], 11562));
 assert.throws(() => plan(destination, [{ ...coins[0], assets: [{}] }, ...coins.slice(1)], 7118));
 assert.throws(() => plan(destination, [{ ...coins[0], isSpent: true }, ...coins.slice(1)], 7118));
 assert.throws(() => plan(destination, [{ ...coins[0], script: '00' }, ...coins.slice(1)], 7118));
 assert.throws(() => plan(destination, coins, 7118, { amount: '7000' }));
 assert.throws(() => plan(destination, coins, 7118, { amount: 'all', operatorKey: '02' + '11'.repeat(32) }));
});
async function fixture(badPartial = false) {
 const card = new SoftwareCardSigner();
 const client = hex(await card.getPublicKey());
 const secret = randomBytes(32), server = hex(musig.IndividualPubkey(secret));
 const keys = musig.sortKeys([bytes(client), bytes(server)]);
 const aggregate = musig.keyAggregate(keys).aggPublicKey.toBytes(true).slice(1);
 const operator = musig.IndividualPubkey(randomBytes(32)).slice(1);
 const tree = new sdk.VtxoScript([
  sdk.MultisigTapscript.encode({ pubkeys: [aggregate, operator] }).script,
  sdk.CSVMultisigTapscript.encode({ pubkeys: [bytes(client).slice(1)], timelock: { type: 'seconds', value: 512n } }).script,
 ]);
 const unroll = sdk.CSVMultisigTapscript.encode({ pubkeys: [operator], timelock: { type: 'seconds', value: 512n } });
 const txs = sdk.buildOffchainTx(coins.map(c => ({ ...c, tapTree: tree.encode(), tapLeafScript: tree.findLeaf(hex(sdk.MultisigTapscript.encode({ pubkeys: [aggregate, operator] }).script)) })), [{ amount: 7118n, script: tree.pkScript }], unroll);
 const events = [];
 let firstPsbt;
 const identity = new CardIdentity({ card, client, server, credential: 'software', intentId: 'mock-intent', log: e => events.push(e),
  approve: async () => ({ client_data_b64u: 'mock', auth_data_b64u: 'mock', sig_b64u: 'mock', assertion_cred_id_b64u: 'software' }),
  http: async (path, body) => {
   if (path.endsWith('/prepare')) { firstPsbt = body.psbt_b64; return { challenge_token: 'mock', challenge: 'mock', rp_id: 'nuri.com', origin: 'https://arkade.nuri.com' }; }
   assert(path.endsWith('/cosign'));
   assert.equal(body.challenge_token, 'mock');
   const row = body.cosign_requests[0];
   const other = musig.deterministicSign(secret, bytes(row.client_pub_nonce), keys, bytes(row.msg32));
   return { server_pubkey: server, signatures: [{ msg32: row.msg32, server_pub_nonce66: hex(other.publicNonce), server_partial32: badPartial ? '00'.repeat(32) : hex(other.partialSig) }] };
  },
 });
 return { identity, txs, events, firstPsbt };
}
test('real software MuSig2 signs three Ark inputs then three checkpoints in app order', async () => {
 const { identity, txs, events } = await fixture();
 const signed = await identity.sign(txs.arkTx);
 for (let i = 0; i < signed.inputsLength; i++) assert.equal(signed.getInput(i).tapScriptSig.length, 1);
 await Promise.all(txs.checkpoints.map(checkpoint => identity.sign(checkpoint)));
 assert.deepEqual(events.slice(0, 2), ['send/prepare', 'FIDO2 assertion']);
 const one = ['card GET_NONCES', 'send/cosign', 'verify server partial', 'card FINALIZE', 'verify aggregate'];
 assert.deepEqual(events.slice(2), Array.from({ length: 6 }, () => one).flat());
 assert.equal(events.filter(e => e === 'send/prepare').length, 1);
 console.log('PROOF: six card partials verified; six aggregate BIP340 signatures verified; single FIDO approval; opening Ark transaction first, checkpoints follow');
});
test('invalid server partial rejected before card FINALIZE', async () => {
 const { identity, txs, events } = await fixture(true);
 await assert.rejects(identity.sign(txs.arkTx));
 assert(!events.includes('card FINALIZE'));
});

// Captured public contract constants; no network or card reader in tests.
const operatorInfo = {
 network: 'bitcoin', signerPubkey: '038202bebddeb1f7442803897a85eaf3ce9254d07df0172fc3725ab5f0d097779c',
 forfeitPubkey: '03b43a8363118c084a04d4f6a50ebfa58e81957f8cceceb2aee0ab64c9fd2d9977',
 checkpointTapscript: '039e0440b27520b43a8363118c084a04d4f6a50ebfa58e81957f8cceceb2aee0ab64c9fd2d9977ac',
 unilateralExitDelay: '605184', boardingExitDelay: '7776256', vtxoMinAmount: '330',
};
const info = { server_pubkey: SERVER, recovery: { registered: true }, username: 'arkade', nuri_server_csv: { type: 'seconds', value: 6674432 } };
function runFixture({ funded = true, floor = '330' } = {}) {
 const events = [], receipts = [];
 let rows = funded ? coins.map(c => ({ ...c })) : [];
 const deps = {
  env: {}, log: async event => events.push(event),
  persistReceipt: async receipt => { receipts.push(structuredClone(receipt)); events.push(`receipt:${receipt.status}`); },
  resolveRecipient: async to => to === '@emino' ? destination : to,
  operatorProvider: { getInfo: async () => ({ ...operatorInfo, vtxoMinAmount: floor }),
   submitTx: async () => { events.push('operator:submit'); throw new Error('submission lost TOKEN_MUST_NOT_LEAK'); },
   finalizeTx: async () => { events.push('operator:finalize'); },
  },
  request: async (path, body) => {
   if (!body) return structuredClone(info);
   events.push(`write:${path}`);
   if (path.endsWith('/create')) return { intent: { id: 'mock-intent' } };
   if (path.endsWith('/complete')) return {};
   throw new Error('unexpected auth call in harness');
  },
  indexer: { getVtxos: async () => ({ vtxos: structuredClone(rows) }) },
  bridgeFactory: () => { events.push('card:open'); return { close: () => events.push('card:close') }; },
 };
 return { deps, events, receipts, setRows: value => { rows = value; } };
}

test('runSend empty/default is GET-only, reports fund SOURCE >=546, no card/POST/receipt', async () => {
 const f = runFixture({ funded: false });
 const summary = await runSend({}, f.deps);
 assert.equal(summary.status, 'needs_funding'); assert.equal(summary.recipient, SOURCE);
 assert.equal(summary.minimum_funding_sats, 546);
 assert(f.events.includes('GET')); assert(!f.events.some(e => e.startsWith('card:') || e.startsWith('write:')));
 assert.equal(f.receipts.length, 0);
});
test('runSend empty honors higher floor, including guarded execute without card/POST', async () => {
 const f = runFixture({ funded: false, floor: '1000' });
 f.deps.env.NURI_SEND_CONFIRM = `${SOURCE}-1000`;
 const summary = await runSend({ execute: true }, f.deps);
 assert.equal(summary.minimum_funding_sats, 1000);
 assert(!f.events.some(e => e.startsWith('card:') || e.startsWith('write:')));
});
test('runSend funded dry builds partial+self outputs but never constructs card or POSTs', async () => {
 const f = runFixture(); const summary = await runSend({}, f.deps);
 assert.equal(summary.recipient_sats, 546); assert.equal(summary.change_sats, 6572);
 assert.match(summary.unsigned_ark_txid, /^[0-9a-f]{64}$/); assert.equal(summary.checkpoint_txids.length, 3);
 assert(!f.events.some(e => e.startsWith('card:') || e.startsWith('write:'))); assert.equal(f.receipts.length, 0);
});
test('runSend explicit guard rejects before public reads and any card access', async () => {
 const f = runFixture(); let reads = 0;
 f.deps.operatorProvider.getInfo = async () => { reads++; return operatorInfo; };
 await assert.rejects(runSend({ execute: true, to: '@emino', amount: 'all' }, f.deps), /NURI_SEND_CONFIRM=@emino-all/);
 assert.equal(reads, 0); assert.deepEqual(f.events, []);
});
test('runSend PRF hook precedes auth; changed live server blocks intent', async () => {
 const f = runFixture(); f.deps.env.NURI_SEND_CONFIRM = `${SOURCE}-546`;
 let reads = 0;
 f.deps.request = async () => ({ ...info, server_pubkey: ++reads === 1 ? SERVER : CLIENT });
 f.deps.beforeExecute = async ({ bridge, summary }) => {
  assert(bridge); assert.equal(summary.recipient_sats, 546); f.events.push('prf-hook');
 };
 await assert.rejects(runSend({ execute: true }, f.deps), /before operator submission/);
 assert(f.events.indexOf('prf-hook') > f.events.indexOf('card:open'));
 assert(!f.events.some(e => e.startsWith('write:')));
 assert.equal(f.receipts.at(-1).status, 'failed_before_submission'); assert(f.events.includes('card:close'));
});
test('runSend rejects pagination and changed input set', async () => {
 const paginated = runFixture(); paginated.deps.indexer.getVtxos = async () => ({ vtxos: coins, page: { next: 'more' } });
 await assert.rejects(runSend({}, paginated.deps), /pagination/);
 const f = runFixture(); f.deps.env.NURI_SEND_CONFIRM = `${SOURCE}-546`;
 f.deps.beforeExecute = async () => f.setRows(coins.slice(1));
 await assert.rejects(runSend({ execute: true }, f.deps), /before operator submission/);
 assert(!f.events.some(e => e.startsWith('write:')));
});
test('runSend persists proof/auth metadata BEFORE submit; sanitizes failure without retry', async () => {
 const f = runFixture(); f.deps.env.NURI_SEND_CONFIRM = '@emino-all';
 let submits = 0;
 f.deps.signAndSubmitOffchainTx = async ({ identity, provider }) => {
  identity.proofs = [{ bip340_verified: true, aggregate_signature: 'public' }];
  identity.authAccepted = { accepted: true, rp_id: 'nuri.com' }; submits++;
  return provider.submitTx('signed-public-psbt');
 };
 await assert.rejects(runSend({ execute: true, to: '@emino', amount: 'all' }, f.deps), error => {
  assert(!error.message.includes('TOKEN_MUST_NOT_LEAK')); assert.equal(error.cause, undefined);
  return /DO NOT RESEND/.test(error.message);
 });
 assert.equal(submits, 1);
 const before = f.events.indexOf('receipt:submission_pending'), submit = f.events.indexOf('operator:submit');
 assert(before >= 0 && before < submit);
 const journal = f.receipts.find(r => r.status === 'submission_pending');
 assert.equal(journal.proofs[0].bip340_verified, true); assert.equal(journal.auth_accepted.accepted, true);
 assert.equal(f.receipts.at(-1).status, 'failed_unknown_outcome');
 assert(!JSON.stringify(f.receipts).includes('TOKEN_MUST_NOT_LEAK'));
});
test('runSend cannot submit when pre-submission receipt persistence fails', async () => {
 const f = runFixture(); f.deps.env.NURI_SEND_CONFIRM = `${SOURCE}-546`;
 f.deps.persistReceipt = async r => { if (r.status === 'submission_pending') throw new Error('disk full'); };
 f.deps.signAndSubmitOffchainTx = async ({ provider }) => provider.submitTx();
 await assert.rejects(runSend({ execute: true }, f.deps), /before operator submission/);
 assert(!f.events.includes('operator:submit'));
});
test('runSend partial self-send reconciles exact recipient+change and old inputs', async () => {
 const f = runFixture(); f.deps.env.NURI_SEND_CONFIRM = `${SOURCE}-546`;
 let signed;
 f.deps.operatorProvider.submitTx = async () => { f.events.push('operator:submit'); return {}; };
 f.deps.signAndSubmitOffchainTx = async ({ identity, provider, inputs, outputs, serverUnrollScript }) => {
  identity.prepared = { challenge_token: 'private-mock' };
  signed = sdk.buildOffchainTx(inputs, outputs, serverUnrollScript);
  await provider.submitTx(); await provider.finalizeTx();
  f.setRows(outputs.map((o,vout) => ({ txid: signed.arkTx.id, vout, value: Number(o.amount) })));
  return signed.arkTx.id;
 };
 const receipt = await runSend({ execute: true }, f.deps);
 assert.equal(receipt.status, 'completed'); assert.equal(receipt.indexer_verified, true);
 assert.equal(receipt.change_sats, 6572); assert.equal(receipt.txid, signed.arkTx.id);
 assert(!JSON.stringify(receipt).includes('private-mock'));
});
test('resolveRecipient reads name.nuri.eth text; direct address does not construct provider', async () => {
 const calls = [], factory = () => ({ getResolver: async name => { calls.push(name); return { getText: async key => { calls.push(key); return destination; } }; }, destroy: () => calls.push('destroy') });
 assert.equal(await resolveRecipient('@emino', { providerFactory: factory }), destination);
 assert.deepEqual(calls, ['emino.nuri.eth', 'com.nuri.arkade', 'destroy']);
 assert.equal(await resolveRecipient(SOURCE, { providerFactory: () => { throw new Error('must not construct'); } }), SOURCE);
});
test('receipt exclusive reservation wins once, then durably replaces the journal', async () => {
 const dir = await mkdtemp(join(tmpdir(), 'arkade-receipt-'));
 const path = join(dir, 'receipt.json');
 try {
  const attempts = await Promise.allSettled([
   saveReceipt(path, { status: 'planned', operation: 'one' }, { exclusive: true }),
   saveReceipt(path, { status: 'planned', operation: 'two' }, { exclusive: true }),
  ]);
  assert.equal(attempts.filter(r => r.status === 'fulfilled').length, 1);
  assert.match(attempts.find(r => r.status === 'rejected').reason.message, /DO NOT RESEND/);
  const original = JSON.parse(await readFile(path, 'utf8'));
  await saveReceipt(path, { ...original, status: 'submission_pending' });
  assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), { ...original, status: 'submission_pending' });
  const f = runFixture(); f.deps.env.NURI_SEND_CONFIRM = `${SOURCE}-546`;
  delete f.deps.persistReceipt;
  await assert.rejects(runSend({ execute: true, receiptPath: path }, f.deps), /DO NOT RESEND/);
  assert(!f.events.includes('card:open')); assert(!f.events.some(e => e.startsWith('write:')));
 } finally { await rm(dir, { recursive: true, force: true }); }
});
test('Bridge preserves Python nonces/finalize interface and original guard without hardware', async () => {
 const child = new EventEmitter(); child.stdout = new PassThrough(); child.stdin = new PassThrough();
 const payloads = []; child.stdin.on('data', data => {
  const message = JSON.parse(data.toString()); payloads.push(message);
  const response = message.op === 'nonces' ? { publicNonce: '11'.repeat(66), token: '22'.repeat(4) } : { partial: '33'.repeat(32) };
  child.stdout.write(JSON.stringify(response) + '\n');
 });
 const env = { NURI_SEND_CONFIRM: `${SOURCE}-546` };
 const bridge = new Bridge({ env, spawnChild: (python,args,options) => { assert.equal(options.env, env); assert(args[0].endsWith('/send/bridge.py')); return child; } });
 const nonce = await bridge.getNonces(); assert.equal(nonce.publicNonce.length, 66); assert.equal(nonce.token.length, 4);
 assert.equal((await bridge.finalize(bytes('aa'))).length, 32);
 assert.deepEqual(payloads, [{ op: 'nonces' }, { op: 'finalize', payload: 'aa' }]); bridge.close();
});
