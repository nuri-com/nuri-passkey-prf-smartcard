const test = require('node:test');
const assert = require('node:assert/strict');
const { createHarness } = require('./harness');

const CONNECT = { url: 'https://connect.nuri.com/approve/abc' };
const createOpts = { rp: { id: 'nuri.com', name: 'Nuri Wallet' }, user: { id: 'dXNlcg', name: 'emin', displayName: 'emin' }, challenge: 'Y2hhbGxlbmdl', pubKeyCredParams: [{ type: 'public-key', alg: -7 }], extensions: { prf: {} } };
const getOpts = { rpId: 'nuri.com', challenge: 'Y2hhbGxlbmdl', allowCredentials: [{ type: 'public-key', id: 'Y3JlZA' }], extensions: { prf: { eval: { first: 'c2FsdA' } } } };

function setup(t, options = {}) {
  const h = createHarness({
    nativeHandler: async (msg) => {
      if (msg.method === 'webauthn_get' && msg.params.pin !== '2468') return { error: { code: 'PIN_WRONG', message: 'wrong card PIN', tries_left: 7 } };
      if (msg.method.startsWith('webauthn_')) return { result: { id: 'Y3JlZA', type: 'public-key', response: {}, clientExtensionResults: { prf: { results: { first: 'cHJm' } } } } };
      return { error: { code: 'CARD_ERROR', message: 'unexpected ' + msg.method } };
    },
    ...options,
  });
  t.after(h.dispose);
  return h;
}
const rpcFrom = (h, sender, method, params) => h.message({ type: 'rpc', method, params }, sender);

test('card WebAuthn refused for any origin but connect.nuri.com, before host or popup', async (t) => {
  const h = setup(t);
  for (const url of ['https://app.nuri.com/', 'https://dapp.test/', 'https://connect.nuri.com.evil.test/', 'http://connect.nuri.com/']) {
    const r = await rpcFrom(h, { url }, 'nuri_webauthnGet', [getOpts]);
    assert.equal(r.error.code, 4100, url);
  }
  assert.equal(h.calls.length, 0); assert.equal(h.windows.size, 0);
});

test('create: approval popup, PIN forwarded once with Chrome origin, PIN never persisted', async (t) => {
  const h = setup(t, { pin: '2468' });
  const r = await rpcFrom(h, CONNECT, 'nuri_webauthnCreate', [createOpts]);
  assert.equal(r.result.id, 'Y3JlZA');
  const call = h.calls.find((c) => c.method === 'webauthn_create');
  assert.equal(call.params.origin, 'https://connect.nuri.com');
  assert.equal(call.params.pin, '2468');
  assert.deepEqual(call.params.publicKey, createOpts);
  assert.equal(h.calls.some((c) => c.method === 'info'), false, 'no ETH applet read needed');
  assert.equal(JSON.stringify(h.storage).includes('2468'), false);
});

test('get: wrong PIN keeps popup open for retry, then returns PRF result', async (t) => {
  const h = setup(t, { autoApprove: false });
  const pending = rpcFrom(h, CONNECT, 'nuri_webauthnGet', [getOpts]);
  const view = await h.open(await h.pendingWindow());
  assert.equal(view.request.kind, 'webauthn_get');
  assert.equal(view.request.summary.rpId, 'nuri.com');
  assert.equal(view.request.summary.pinRequired, true);
  const bad = await h.decide(view, true, '0000');
  assert.equal(bad.error.data.code, 'PIN_WRONG'); assert.equal(bad.error.data.tries_left, 7);
  assert.equal((await h.decide(view, true, '2468')).ok, true);
  const r = await pending;
  assert.equal(r.result.clientExtensionResults.prf.results.first, 'cHJm');
});

test('reject closes without touching the card', async (t) => {
  const h = setup(t, { autoApprove: () => false });
  const r = await rpcFrom(h, CONNECT, 'nuri_webauthnGet', [getOpts]);
  assert.equal(r.error.code, 4001);
  assert.equal(h.calls.length, 0);
});

test('missing options rejected', async (t) => {
  const h = setup(t);
  assert.equal((await rpcFrom(h, CONNECT, 'nuri_webauthnGet', [])).error.code, -32602);
});
