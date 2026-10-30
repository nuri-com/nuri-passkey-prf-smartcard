const test = require('node:test');
const assert = require('node:assert/strict');
const { createHarness } = require('./harness');

const ARK = 'ark1qzpq904am6clw3pgqwyh4p02708fy4xs0hcpwt7rwfdttuxsjameepfv6ed2mgaw4k2tdts49m4wkk3zqyrjv44sr2gcgxrm47gy7sqnlyjr3x';
const LN = 'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4js';
const ONCHAIN = 'bc1pxa43e00wl6a2qqfd7wu8xgmuz8vczauvmn0nt45zff2kuq9u4klsfrz0f5';

function setup(t, options = {}) {
  const h = createHarness({ local: { connectedOrigins: { 'https://dapp.test': 1 } }, ...options });
  t.after(h.dispose);
  return h;
}
// mempool.space + ENS are the only extension-side network calls.
const http = (onchain = 6007) => async (url, req) => {
  if (url.includes('mempool.space')) {
    return { ok: true, json: async () => ({ chain_stats: { funded_txo_sum: onchain, spent_txo_sum: 0 }, mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0 } }) };
  }
  const body = JSON.parse(req?.body || '{}');
  if (body.method === 'eth_getBalance') return { ok: true, json: async () => ({ result: '0xde0b6b3a7640000' }) };
  return { ok: true, json: async () => ({ result: '0x0' }) };
};

test('account view leads with the total over every rail and keeps ETH separate', async (t) => {
  const h = setup(t, { httpFetch: http(6007) });
  const r = await h.message({ type: 'popup:account' }, { id: 'test', url: h.chrome.runtime.getURL('popup.html') });
  assert.ok(r.bitcoin, JSON.stringify(r));
  assert.equal(r.bitcoin.total, 4926 + 0 + 6007);
  assert.deepEqual(r.bitcoin.rails.map((rail) => rail.rail), ['Arkade', 'Boarding', 'Onchain (MuSig2 + CSV)']);
  assert.equal(r.bitcoin.rails[2].address, ONCHAIN);
  assert.equal(r.ethBalance, '1.0');
});

test('an unreadable onchain rail is reported instead of silently dropped', async (t) => {
  const h = setup(t, { httpFetch: async (url, req) => url.includes('mempool.space') ? { ok: false, status: 502 } : { ok: true, json: async () => ({ result: '0x0' }) } });
  const r = await h.message({ type: 'popup:account' }, { id: 'test', url: h.chrome.runtime.getURL('popup.html') });
  assert.equal(r.bitcoin.rails[2].sats, null);
  assert.match(r.bitcoin.onchainError, /mempool HTTP 502/);
});

test('the simulator has no MuSig2 key, so the Bitcoin rail fails closed', async (t) => {
  const h = setup(t, { mode: 'sim', httpFetch: http() });
  const r = await h.message({ type: 'popup:account' }, { id: 'test', url: h.chrome.runtime.getURL('popup.html') });
  assert.match(r.bitcoinError, /needs the card/);
  assert.equal(h.calls.filter((c) => c.method.startsWith('bitcoin_')).length, 0);
});

test('a Lightning spend is previewed, approved under the digest, then signed once', async (t) => {
  const h = setup(t, { httpFetch: http() });
  const result = h.rpc('nuri_bitcoinSend', [{ kind: 'lightning', invoice: LN }]);
  const id = await h.pendingWindow();
  const view = await h.open(id);
  assert.equal(view.request.kind, 'bitcoin_send');
  assert.equal(view.request.summary.destination, LN.toLowerCase());
  assert.equal(view.request.summary.amountSats, 2100);
  assert.equal(view.request.summary.amountBtc, '0.000021');
  assert.equal(view.request.summary.kind, 'lightning');
  const preview = h.calls.find((c) => c.method === 'bitcoin_preview');
  assert.equal(preview.params.kind, 'lightning');
  assert.equal(view.hash, h.calls.find((c) => c.method === 'bitcoin_preview') && view.hash);
  assert.match(view.hash, /^0x[0-9a-f]{64}$/);
  assert.equal(h.calls.some((c) => c.method === 'bitcoin_sign_partial'), false, 'nothing is signed before approval');
  await h.decide(view);
  const signed = await result;
  assert.equal(signed.result.ark_txid, 'cd'.repeat(32));
  const sign = h.calls.filter((c) => c.method === 'bitcoin_sign_partial');
  assert.equal(sign.length, 1);
  assert.equal(sign[0].params.digest, view.hash);
  assert.equal(sign[0].params.pin, undefined);
});

test('an Arkade address spend carries the amount and rejects a bad checksum before any card work', async (t) => {
  const h = setup(t, { httpFetch: http() });
  const good = h.rpc('nuri_bitcoinSend', [{ kind: 'ark', address: ARK, amountSats: 1200 }]);
  const view = await h.open(await h.pendingWindow());
  assert.equal(view.request.summary.amountSats, 1200);
  assert.equal(view.request.summary.destination, ARK);
  await h.decide(view);
  assert.ok((await good).result);
  const calls = h.calls.length;
  const bad = await h.rpc('nuri_bitcoinSend', [{ kind: 'ark', address: ARK.slice(0, -1) + 'q', amountSats: 5 }]);
  assert.equal(bad.error.code, -32602);
  assert.equal(h.calls.length, calls, 'no preview is built for an invalid address');
});

test('a username spend resolves the ENS text record and shows where it came from', async (t) => {
  const h = setup(t, { httpFetch: http() });
  // The worker loads its own ethers copy through importScripts, so patch that one.
  const E = h.sandbox.NuriHashing.ethers;
  const original = E.EnsResolver.fromName;
  E.EnsResolver.fromName = async () => ({ address: '0x01', async getText(k) { return k === 'ark' ? ARK : ''; }, async getAddress() { return null; } });
  t.after(() => { E.EnsResolver.fromName = original; });
  const pending = h.rpc('nuri_bitcoinSend', [{ kind: 'nuri', name: 'emino', amountSats: 900 }]);
  const view = await h.open(await h.pendingWindow());
  assert.equal(view.request.summary.destination, ARK.toLowerCase());
  assert.equal(view.request.summary.destinationSource, 'emino.nuri.eth (text:ark)');
  await h.decide(view);
  assert.ok((await pending).result);
});

test('PIN: required up front when the applet is protected, wrong PIN keeps the same digest', async (t) => {
  const h = setup(t, { httpFetch: http(), bitcoinPin: '2468' });
  const pending = h.rpc('nuri_bitcoinSend', [{ kind: 'lightning', invoice: LN }]);
  const view = await h.open(await h.pendingWindow());
  assert.equal(view.request.summary.pinRequired, true);
  const needed = await h.decide(view);
  assert.equal(needed.error.data.code, 'PIN_REQUIRED');
  const wrong = await h.decide(view, true, '0000');
  assert.equal(wrong.error.data.code, 'PIN_WRONG');
  assert.equal(wrong.error.data.tries_left, 4);
  const good = await h.decide(view, true, '2468');
  assert.ok(good.ok);
  assert.ok((await pending).result);
  const hashes = h.calls.filter((c) => c.method === 'bitcoin_sign_partial').map((c) => c.params.digest);
  assert.equal(new Set(hashes).size, 1, 'every retry rides the same previewed digest');
  assert.equal(JSON.stringify(h.storage).includes('2468'), false);
});

test('closing or rejecting the popup cancels the pending host job', async (t) => {
  for (const how of ['close', 'reject', 'timeout']) {
    const h = setup(t, { httpFetch: http() });
    const pending = h.rpc('nuri_bitcoinSend', [{ kind: 'lightning', invoice: LN }]);
    const id = await h.pendingWindow();
    const view = await h.open(id);
    if (how === 'close') await h.chrome.windows.remove(id);
    else if (how === 'reject') await h.decide(view, false);
    else h.expire();
    assert.equal((await pending).error.code, 4001);
    assert.equal(h.calls.some((c) => c.method === 'bitcoin_sign_partial'), false);
    const cancel = h.calls.find((c) => c.method === 'bitcoin_cancel');
    assert.ok(cancel, how + ' must cancel the job');
    assert.equal(cancel.params.job_id, view.request.summary.jobId);
  }
});

test('an invoice is created only with amount and memo', async (t) => {
  const h = setup(t, { httpFetch: http() });
  const ok = await h.message({ type: 'popup:invoice', amountSats: 2500, memo: 'coffee' }, { id: 'test', url: h.chrome.runtime.getURL('popup.html') });
  assert.equal(ok.result.amount_sats, 2500);
  const params = h.calls.find((c) => c.method === 'bitcoin_invoice').params;
  assert.deepEqual(params, { amount_sats: 2500, memo: 'coffee' });
});

test('a host preview failure surfaces as an RPC error and opens no popup', async (t) => {
  const h = setup(t, { httpFetch: http(), nativeHandler: async (msg, info, wallet, bitcoin) => {
    if (msg.method === 'info') return { result: info };
    if (msg.method === 'bitcoin_info') return { result: await bitcoin.bitcoinInfo() };
    if (msg.method === 'bitcoin_preview') return { error: { code: 'BITCOIN_ERROR', message: 'send/prepare failed: no route' } };
    return {};
  } });
  const r = await h.rpc('nuri_bitcoinSend', [{ kind: 'lightning', invoice: LN }]);
  assert.equal(r.error.code, -32603);
  assert.match(r.error.message, /no route/);
  await h.tick();
  assert.equal(h.windows.size, 0);
});
