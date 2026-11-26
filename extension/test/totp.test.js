const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHarness } = require('./harness');

const EXT = path.resolve(__dirname, '..');

test('untrusted web page cannot invoke popup TOTP actions', async (t) => {
  const h = createHarness({
    nativeHandler: () => ({ result: { code: '123456', remaining: 25, step: 30, digits: 6 } }),
  });
  t.after(h.dispose);
  for (const type of ['popup:totpStatus', 'popup:totpCode', 'popup:totpPut', 'popup:totpFill']) {
    const res = await h.message({ type }, { id: 'test', url: 'https://accounts.hetzner.com/2fa' });
    assert.equal(res, null);
  }
  const rpcRes = await h.rpc('totp_code', []);
  assert.equal(rpcRes.error.code, 4200);
  assert.equal(h.calls.length, 0);
});

test('trusted toolbar can provision TOTP, read code, and trigger active-tab autofill', async (t) => {
  let simStored = false;
  const h = createHarness({
    nativeHandler(msg) {
      if (msg.method === 'totp_status') {
        return { result: { version: '1.0', provisioned: simStored, pin_required: false } };
      }
      if (msg.method === 'totp_put') {
        assert.equal(msg.params.secret, 'JBSWY3DPEHPK3PXP');
        simStored = true;
        return { result: { provisioned: true, version: '1.0' } };
      }
      if (msg.method === 'totp_code') {
        return { result: { code: '482910', remaining: 19, step: 30, digits: 6 } };
      }
      return { error: { code: 'BAD_REQUEST', message: 'unexpected ' + msg.method } };
    },
  });
  t.after(h.dispose);
  const sent = [];
  h.chrome.tabs.query = (_q, cb) => cb([{ id: 77 }]);
  h.chrome.tabs.sendMessage = (tabId, msg, cb) => { sent.push({ tabId, msg }); cb({ filled: true }); };

  const toolbar = { id: 'test', url: h.chrome.runtime.getURL('popup.html') };
  const putReq = { type: 'popup:totpPut', secret: 'JBSWY3DPEHPK3PXP', pin: '' };
  const saved = await h.message(putReq, toolbar);
  assert.equal(saved.result.provisioned, true);
  assert.equal(putReq.secret, '');

  const filled = await h.message({ type: 'popup:totpFill' }, toolbar);
  assert.equal(filled.filled, true);
  assert.equal(filled.totp.code, '482910');
  assert.deepEqual(JSON.parse(JSON.stringify(sent)), [{ tabId: 77, msg: { type: 'nuri:fillTotp', code: '482910' } }]);
});

test('content.js fills visible OTP input on nuri:fillTotp and dispatches input/change', () => {
  const dispatched = [];
  const otpInput = {
    tagName: 'INPUT',
    type: 'text',
    name: 'code',
    id: 'otp',
    placeholder: 'OTP *',
    autocomplete: '',
    disabled: false,
    readOnly: false,
    offsetParent: {},
    value: '',
    focused: false,
    getAttribute: () => null,
    closest: () => null,
    focus() { this.focused = true; },
    dispatchEvent(ev) { dispatched.push(ev.type); },
  };
  const listeners = [];
  const sandbox = {
    window: { addEventListener() {}, postMessage() {} },
    document: {
      activeElement: null,
      querySelectorAll: (sel) => (sel === 'input' ? [otpInput] : []),
      querySelector: () => null,
    },
    HTMLInputElement: { prototype: {} },
    CSS: { escape: (s) => s },
    Event: class { constructor(type) { this.type = type; } },
    chrome: {
      runtime: {
        onMessage: { addListener: (fn) => listeners.push(fn) },
        sendMessage() {},
      },
    },
  };
  vm.runInNewContext(fs.readFileSync(path.join(EXT, 'content.js'), 'utf8'), sandbox);
  let response = null;
  listeners[0]({ type: 'nuri:fillTotp', code: '901234' }, {}, (r) => { response = r; });
  assert.deepEqual(JSON.parse(JSON.stringify(response)), { filled: true });
  assert.equal(otpInput.value, '901234');
  assert.equal(otpInput.focused, true);
  assert.deepEqual(dispatched, ['input', 'change']);
});
