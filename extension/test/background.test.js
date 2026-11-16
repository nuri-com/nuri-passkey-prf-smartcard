const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { createHarness, E } = require('./harness');
function setup(t, options = {}) { const h = createHarness(options); t.after(h.dispose); return h; }
async function connected(t, options = {}) { const h = setup(t, options); const r = await h.rpc('eth_requestAccounts'); assert.ok(r.result, JSON.stringify(r)); h.address = r.result[0]; return h; }
function tx(address, patch = {}) { return { from: address, to: address, value: '0x0', nonce: '0x0', gas: '0x5208', maxFeePerGas: '0xf4240', maxPriorityFeePerGas: '0x3e8', ...patch }; }

test('default Base; unconnected account/sign/switch denied', async (t) => {
  const h = setup(t); assert.equal((await h.rpc('eth_chainId')).result, '0x2105');
  assert.deepEqual((await h.rpc('eth_accounts')).result, []);
  assert.equal((await h.rpc('personal_sign', ['hello'])).error.code, 4100);
  assert.equal((await h.rpc('wallet_switchEthereumChain', [{ chainId: '0x1' }])).error.code, 4100);
});
test('real Python host info + personal/EIP712/EIP1559 on a persistent native sim stream', async (t) => {
  const h = await connected(t, { realHost: true });
  assert.equal(E.getAddress(h.address), h.address);
  const personal = await h.rpc('personal_sign', ['hello', h.address]);
  assert.equal(E.verifyMessage('hello', personal.result), h.address);
  const typed = { types: { Mail: [{ name: 'contents', type: 'string' }] }, primaryType: 'Mail', domain: { name: 'Nuri', chainId: 8453 }, message: { contents: 'hi' } };
  const signed = await h.rpc('eth_signTypedData_v4', [h.address, JSON.stringify(typed)]);
  assert.equal(E.verifyTypedData(typed.domain, typed.types, typed.message, signed.result), h.address);
  const raw = await h.rpc('eth_signTransaction', [tx(h.address)]);
  assert.ok(raw.result, JSON.stringify(raw));
  const parsed = E.Transaction.from(raw.result); assert.equal(parsed.type, 2); assert.equal(parsed.chainId, 8453n); assert.equal(parsed.from, h.address);
  assert.equal(h.calls[0].method, 'info'); assert.ok(h.badges.includes('SIM')); assert.ok(h.badges.includes('#b00020'));
});
test('ETH1 no PIN and every signing approval carries declared mode', async (t) => {
  const h = await connected(t); vm.runInContext('cachedInfo.pin_set = false', h.sandbox);
  const r = await h.rpc('personal_sign', [h.address, 'hello']); assert.equal(E.verifyMessage('hello', r.result), h.address);
  assert.equal(h.calls.at(-1).method, 'sign_hash');
  assert.ok(!h.badges.includes('SIM'));
});
test('ETH2 verifies PIN once, signs approved hash, no PIN in persistent/session state', async (t) => {
  const h = await connected(t, { pin: '2468' });
  const r = await h.rpc('personal_sign', ['protected', h.address]);
  assert.equal(E.verifyMessage('protected', r.result), h.address);
  const attempts = h.calls.filter((c) => c.method === 'verify_pin'); assert.equal(attempts.length, 1);
  assert.equal(attempts[0].params.pin, '2468'); assert.equal(attempts[0].params.hash, E.hashMessage('protected'));
  assert.equal(JSON.stringify(h.storage).includes('2468'), false); assert.deepEqual(h.storage.session, {});
});
// A separate manual harness seeds connected permission to isolate popup controls.
function approvalFixture(t, options = {}) {
  const h = setup(t, { ...options, autoApprove: false, local: { connectedOrigins: { 'https://dapp.test': 1 } } });
  const result = h.rpc('personal_sign', ['displayed message', h.wallet.address]);
  return { h, result };
}
test('approval bound to extension id, exact URL, Chrome document, live window and displayed hash', async (t) => {
  const { h, result } = approvalFixture(t); const id = await h.pendingWindow(), view = await h.open(id);
  const base = { type: 'approval', approvalId: view.approvalId, windowId: id, binding: view.binding, hash: view.hash, approved: true };
  for (const from of [{ ...view.from, id: 'other' }, { ...view.from, url: 'https://dapp.test' }, { ...view.from, documentId: 'orphan' }]) assert.equal((await h.message({ ...base }, from)).error.code, 4001);
  assert.equal((await h.message({ ...base, windowId: id + 1 }, view.from)).error.code, 4001);
  assert.equal((await h.message({ ...base, hash: E.hashMessage('different') }, view.from)).error.code, 4001);
  assert.equal((await h.message({ ...base, binding: E.ZeroHash }, view.from)).error.code, 4001);
  assert.equal(h.calls.filter((c) => c.method !== 'info').length, 0);
  assert.ok((await h.decide(view)).ok); assert.ok((await result).result);
  assert.equal((await h.decide(view)).error.code, 4001); assert.equal(h.calls.filter((c) => c.method === 'sign_hash').length, 1);
});
test('cannot settle before display acknowledgement', async (t) => {
  const { h, result } = approvalFixture(t); const id = await h.pendingWindow();
  const approvalId = new URL(h.windows.get(id).tabs[0].url).searchParams.get('id');
  const r = await h.message({ type: 'approval:get', approvalId, windowId: id }, h.sender(id));
  assert.equal((await h.message({ type: 'approval', approvalId, windowId: id, binding: r.binding, hash: r.request.summary.hash, approved: true }, h.sender(id))).error.code, 4001);
  await h.chrome.windows.remove(id); assert.equal((await result).error.code, 4001);
});
test('different live popup cannot authorize another request even with copied fields', async (t) => {
  const { h, result } = approvalFixture(t); const id = await h.pendingWindow(), a = await h.open(id);
  const second = h.rpc('personal_sign', ['other', h.wallet.address]); const id2 = await h.pendingWindow(), b = await h.open(id2);
  assert.notEqual(a.approvalId, b.approvalId);
  assert.equal((await h.message({ type: 'approval', approvalId: a.approvalId, windowId: id, binding: a.binding, hash: a.hash, approved: true }, b.from)).error.code, 4001);
  await h.decide(a, false); await h.decide(b, false); assert.equal((await result).error.code, 4001); assert.equal((await second).error.code, 4001);
});
test('in-memory summary modification after display fails closed', async (t) => {
  const { h, result } = approvalFixture(t); const view = await h.open(await h.pendingWindow());
  vm.runInContext(`approvals.get(${JSON.stringify(view.approvalId)}).payload.summary.message = 'changed'`, h.sandbox);
  assert.equal((await h.decide(view)).error.code, 4001); assert.equal((await result).error.code, 4001);
  assert.equal(h.calls.filter((c) => c.method === 'sign_hash').length, 0);
});
test('close, explicit reject and timeout cancel without signing', async (t) => {
  for (const action of ['close', 'reject', 'timeout']) {
    const { h, result } = approvalFixture(t); const id = await h.pendingWindow(), view = await h.open(id);
    if (action === 'close') await h.chrome.windows.remove(id);
    else if (action === 'reject') await h.decide(view, false);
    else h.expire();
    assert.equal((await result).error.code, 4001); assert.equal(h.calls.filter((c) => c.method === 'sign_hash').length, 0);
  }
});
test('restart removes orphan popups + legacy session ids; random ids never reused', async (t) => {
  const h = setup(t, { autoApprove: false, session: { 'approval:1': { summary: 'old' } }, windows: [[77, { id: 77, tabs: [{ id: 1, url: 'chrome-extension://test/approve.html?id=1' }] }]] });
  await h.tick(); assert.equal(h.windows.has(77), false); assert.deepEqual(h.storage.session, {});
  assert.equal((await h.message({ type: 'approval', approvalId: '1', windowId: 77, approved: true }, { id: 'test', url: 'chrome-extension://test/approve.html?id=1', documentId: 'old' })).error.code, 4001);
  const request = h.rpc('eth_requestAccounts'); const view = await h.open(await h.pendingWindow()); assert.match(view.approvalId, /^[0-9a-f-]{36}$/); assert.notEqual(view.approvalId, '1'); await h.decide(view, false); await request;
});
test('PIN_REQUIRED prompts trusted popup; wrong PIN preserves same hash, explicit correct retry signs once', async (t) => {
  const { h, result } = approvalFixture(t, { pin: '2468' }); const view = await h.open(await h.pendingWindow());
  assert.equal(view.request.summary.pinRequired, true);
  const needed = await h.decide(view); assert.equal(needed.error.data.code, 'PIN_REQUIRED');
  const wrong = await h.decide(view, true, '0000'); assert.equal(wrong.error.data.code, 'PIN_WRONG'); assert.equal(wrong.error.data.tries_left, 4);
  assert.equal(h.windows.has(view.windowId), true);
  const good = await h.decide(view, true, '2468'); assert.ok(good.ok); assert.ok((await result).result);
  assert.deepEqual(h.calls.filter((c) => c.method === 'verify_pin').map((c) => c.params.hash), [view.hash, view.hash]);
  assert.equal(JSON.stringify(h.storage).includes('2468'), false);
});
test('closing, rejecting or timing out during native signing discards signature and never broadcasts', async (t) => {
  for (const cancellation of ['close', 'reject', 'timeout']) {
  let finish;
  const h = setup(t, { autoApprove: false, local: { connectedOrigins: { 'https://dapp.test': 1 } }, nativeHandler: async (msg, info, wallet) => {
    if (msg.method === 'info') return { result: info };
    await new Promise((resolve) => { finish = resolve; }); const s = wallet.signingKey.sign(msg.params.hash); return { result: { r: s.r, s: s.s, yParity: s.yParity } };
  } });
  const result = h.rpc('eth_sendTransaction', [tx(h.wallet.address)]); const view = await h.open(await h.pendingWindow()); const clicking = h.decide(view);
  await h.tick();
  assert.equal((await h.decide(view)).error.code, 4001); // duplicate while busy never signs twice
  if (cancellation === 'close') await h.chrome.windows.remove(view.windowId);
  else if (cancellation === 'reject') assert.ok((await h.decide(view, false)).ok);
  else h.expire();
  finish(); await clicking;
  assert.equal((await result).error.code, 4001); assert.equal(h.rpcCalls.length, 0);
  assert.equal(h.calls.filter((c) => c.method === 'sign_hash').length, 1);
  }
});
test('unknown/missing host mode and unavailable host never sign or open approvals', async (t) => {
  for (const options of [{ mode: 'unknown' }, { nativeUnavailable: true }]) { const h = setup(t, options); const r = await h.rpc('eth_requestAccounts'); assert.equal(r.error.code, -32603); assert.equal(h.windows.size, 0); assert.equal(h.calls.some((c) => c.method === 'sign_hash'), false); }
});
test('Base send fills live nonce/fees, displays exact EIP1559 fields, broadcasts signed bytes and stores basescan link', async (t) => {
  let raw;
  const h = setup(t, { autoApprove: false, local: { connectedOrigins: { 'https://dapp.test': 1 } }, fetch: async (method, params, url) => {
    assert.equal(url, 'https://mainnet.base.org');
    const values = { eth_getTransactionCount: '0x7', eth_estimateGas: '0x5208', eth_getBlockByNumber: { baseFeePerGas: '0x64' }, eth_maxPriorityFeePerGas: '0x3', eth_getBalance: '0xde0b6b3a7640000' };
    if (method === 'eth_sendRawTransaction') { raw = params[0]; return E.keccak256(raw); }
    assert.ok(Object.hasOwn(values, method), method); return values[method];
  } });
  const req = { from: h.wallet.address, to: h.wallet.address, value: '0x0' };
  const result = h.rpc('eth_sendTransaction', [req]); const view = await h.open(await h.pendingWindow());
  assert.equal(view.request.summary.chain, 'Base'); assert.equal(view.request.summary.tx.chainId, '8453'); assert.equal(view.request.summary.tx.to, h.wallet.address);
  assert.equal(view.request.summary.tx.value, '0.0 ETH'); assert.equal(view.request.summary.tx.nonce, 7); assert.match(view.request.summary.tx.executionFeeCap, /ETH/);
  req.to = E.ZeroAddress; // the page no longer owns the transaction being displayed
  await h.decide(view); const response = await result; assert.equal(response.result, E.keccak256(raw));
  const parsed = E.Transaction.from(raw); assert.equal(parsed.unsignedHash, view.hash); assert.equal(parsed.maxFeePerGas, 203n); assert.equal(parsed.maxPriorityFeePerGas, 3n); assert.equal(parsed.nonce, 7); assert.equal(parsed.to, h.wallet.address); assert.equal(parsed.from, h.wallet.address);
  assert.equal(h.storage.local.lastTx.url, 'https://basescan.org/tx/' + response.result);
  const toolbar = await h.toolbar(); assert.equal(toolbar.balance, '1.0'); assert.equal(toolbar.lastTx.hash, response.result);
});
test('switch supports Ethereum, Base, Base Sepolia; wrong transaction chain/from/type rejected', async (t) => {
  const h = await connected(t);
  for (const chainId of ['0x1', '0x14a34', '0x2105']) { assert.equal((await h.rpc('wallet_switchEthereumChain', [{ chainId }])).result, null); assert.equal((await h.rpc('eth_chainId')).result, chainId); }
  assert.equal((await h.rpc('wallet_switchEthereumChain', [{ chainId: '0x89' }])).error.code, 4902);
  for (const patch of [{ chainId: '0x1' }, { from: E.ZeroAddress }, { gasPrice: '0x1' }, { type: '0x0' }, { maxFeePerGas: '0x1', maxPriorityFeePerGas: '0x2' }]) assert.equal((await h.rpc('eth_signTransaction', [tx(h.address, patch)])).error.code, -32602);
  assert.equal((await h.rpc('eth_sign', [h.address, '0x00'])).error.code, 4200);
});
