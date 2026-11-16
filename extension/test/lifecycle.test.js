const test = require('node:test');
const assert = require('node:assert/strict');
const { createHarness, tick } = require('./harness');
test('popup request waits for Chrome window id even if script starts before create resolves', async (t) => {
  let release, early;
  const h = createHarness({ autoApprove: false, local: { connectedOrigins: { 'https://dapp.test': 1 } }, windowCreated: (id) => {
    early = h.open(id);
    return new Promise((resolve) => { release = resolve; });
  } }); t.after(h.dispose);
  const result = h.rpc('personal_sign', ['creation race', h.wallet.address]);
  await h.pendingWindow(); await tick(); release();
  const view = await early; assert.ok(view.request, JSON.stringify(view));
  assert.ok((await h.decide(view)).ok); assert.ok((await result).result);
});
test('popup closed before Chrome create resolves cancels without signing', async (t) => {
  const h = createHarness({ autoApprove: false, local: { connectedOrigins: { 'https://dapp.test': 1 } }, windowCreated: (id) => h.chrome.windows.remove(id) }); t.after(h.dispose);
  const result = await h.rpc('personal_sign', ['close race', h.wallet.address]);
  assert.equal(result.error.code, 4001); assert.equal(h.calls.filter((c) => c.method === 'sign_hash').length, 0);
});
test('native disconnect cancels pending request; toolbar retains mode when balance RPC fails', async (t) => {
  const h = createHarness({ autoApprove: false, local: { connectedOrigins: { 'https://dapp.test': 1 } }, mode: 'sim' }); t.after(h.dispose);
  const result = h.rpc('personal_sign', ['disconnect', h.wallet.address]);
  const view = await h.open(await h.pendingWindow());
  // The only port is the worker-owned connection returned by hostPort.
  require('node:vm').runInContext('nativePort.disconnect()', h.sandbox);
  assert.equal((await result).error.code, 4001); assert.equal((await h.decide(view)).error.code, 4001);
  const toolbar = await h.toolbar(); assert.equal(toolbar.info.mode, 'sim'); assert.ok(toolbar.error); assert.equal(toolbar.balance, undefined);
});
