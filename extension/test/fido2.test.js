const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHarness } = require('./harness');

const EXT = path.resolve(__dirname, '..');

test('generic FIDO2 refused until site is opted in via trusted toolbar', async (t) => {
  const h = createHarness({
    pin: '2468',
    nativeHandler(msg) {
      if (msg.method === 'fido2_create' || msg.method === 'fido2_get') {
        assert.equal(msg.params.pin, '2468');
        return {
          result: {
            id: 'Y3JlZF9naA',
            rawId: 'Y3JlZF9naA',
            type: 'public-key',
            authenticatorAttachment: 'cross-platform',
            response: {
              clientDataJSON: 'e30',
              attestationObject: 'o2NmbXRkbm9uZQ',
              authenticatorData: 'AQID',
              publicKey: 'BAUG',
              publicKeyAlgorithm: -7,
              signature: 'BwgJ',
            },
            clientExtensionResults: {},
          },
        };
      }
      return { error: { code: 'CARD_ERROR', message: 'unexpected ' + msg.method } };
    },
  });
  t.after(h.dispose);

  const gh = { url: 'https://github.com/settings/security' };
  const toolbar = { id: 'test', url: h.chrome.runtime.getURL('popup.html') };
  const createOpts = { rp: { id: 'github.com', name: 'GitHub' }, user: { id: 'dXNlcg', name: 'emin' }, challenge: 'Y2hhbGxlbmdl' };
  const getOpts = { rpId: 'github.com', challenge: 'Y2hhbGxlbmdl', allowCredentials: [{ type: 'public-key', id: 'Y3JlZF9naA' }] };

  const denied = await h.message({ type: 'rpc', method: 'nuri_fidoCreate', params: [createOpts] }, gh);
  assert.equal(denied.error.code, 4100);
  assert.equal(h.calls.length, 0);

  // Untrusted web page cannot enable itself
  const unauth = await h.message({ type: 'popup:fidoToggle', origin: 'https://github.com' }, gh);
  assert.equal(unauth, null);

  // Trusted toolbar opts in https://github.com
  const toggled = await h.message({ type: 'popup:fidoToggle', origin: 'https://github.com' }, toolbar);
  assert.equal(toggled.enabled, true);
  assert.equal((await h.message({ type: 'fido:check' }, gh)).enabled, true);

  const created = await h.message({ type: 'rpc', method: 'nuri_fidoCreate', params: [createOpts] }, gh);
  assert.equal(created.result.id, 'Y3JlZF9naA');
  const got = await h.message({ type: 'rpc', method: 'nuri_fidoGet', params: [getOpts] }, gh);
  assert.equal(got.result.id, 'Y3JlZF9naA');

  // Turning it back off blocks immediately
  const off = await h.message({ type: 'popup:fidoToggle', origin: 'https://github.com' }, toolbar);
  assert.equal(off.enabled, false);
  const deniedAgain = await h.message({ type: 'rpc', method: 'nuri_fidoGet', params: [getOpts] }, gh);
  assert.equal(deniedAgain.error.code, 4100);
});

test('inpage.js intercepts navigator.credentials when enabled and bypasses platform/disabled requests', async () => {
  const listeners = new Map();
  const pagePosts = [];
  const nativeFallbacks = [];
  const windowObj = {
    addEventListener(name, fn) { listeners.set(name, fn); },
    dispatchEvent() {},
    postMessage(data) { pagePosts.push(data); },
  };
  const navigatorObj = {
    credentials: {
      async create(opts) { nativeFallbacks.push({ kind: 'create', opts }); return { native: true }; },
      async get(opts) { nativeFallbacks.push({ kind: 'get', opts }); return { native: true }; },
    },
  };
  class CustomEvent { constructor(type, init) { this.type = type; this.detail = init.detail; } }
  class DOMException extends Error { constructor(msg, name) { super(msg); this.name = name; } }

  vm.runInNewContext(fs.readFileSync(path.join(EXT, 'inpage.js'), 'utf8'), {
    window: windowObj,
    navigator: navigatorObj,
    CustomEvent,
    DOMException,
    crypto: require('node:crypto').webcrypto,
    location: { origin: 'https://github.com' },
  });

  // Disabled initially -> delegates to native browser WebAuthn
  const chal = new Uint8Array([1, 2, 3, 4]).buffer;
  const nativeRes = await navigatorObj.credentials.get({ publicKey: { challenge: chal } });
  assert.equal(nativeRes.native, true);
  assert.equal(nativeFallbacks.length, 1);

  // Enable via content.js event
  listeners.get('message')({ source: windowObj, data: { channel: 'nuri-card:to-page', event: 'nuri:fidoEnabled', args: [true] } });

  // Platform authenticator still bypasses to Touch ID
  await navigatorObj.credentials.create({ publicKey: { challenge: chal, authenticatorSelection: { authenticatorAttachment: 'platform' } } });
  assert.equal(nativeFallbacks.length, 2);

  // Cross-platform create goes through nuri_fidoCreate and returns ArrayBuffer WebAuthn credential
  const p = navigatorObj.credentials.create({
    publicKey: {
      rp: { id: 'github.com', name: 'GitHub' },
      user: { id: new Uint8Array([9, 8, 7]), name: 'emin' },
      challenge: chal,
    },
  });
  const reqMsg = pagePosts.at(-1);
  assert.equal(reqMsg.method, 'nuri_fidoCreate');
  assert.equal(reqMsg.params[0].challenge, 'AQIDBA');
  assert.equal(reqMsg.params[0].user.id, 'CQgH');
  listeners.get('message')({
    source: windowObj,
    data: {
      channel: 'nuri-card:to-page',
      id: reqMsg.id,
      method: 'nuri_fidoCreate',
      result: {
        id: 'AQID',
        rawId: 'AQID',
        type: 'public-key',
        authenticatorAttachment: 'cross-platform',
        response: {
          clientDataJSON: 'BAUG',
          attestationObject: 'BwgJ',
          authenticatorData: 'CgsM',
          publicKey: 'DQ4P',
          publicKeyAlgorithm: -7,
        },
        clientExtensionResults: {},
      },
    },
  });
  const cred = await p;
  assert.equal(cred.id, 'AQID');
  assert.equal(cred.rawId.byteLength, 3);
  assert.equal(cred.response.getAuthenticatorData().byteLength, 3);
  assert.equal(cred.response.getPublicKey().byteLength, 3);
  assert.deepEqual([...cred.response.getTransports()], ['usb', 'nfc']);
});
