const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const EXT = path.resolve(__dirname, '..');

test('Nuri discovery preserves an existing OKX provider and announces its own identity', () => {
  const okx = { isOkxWallet: true, request() {} };
  const listeners = new Map(), announcements = [];
  const window = {
    ethereum: okx,
    addEventListener(name, fn) { listeners.set(name, fn); },
    dispatchEvent(event) { announcements.push(event); },
  };
  class CustomEvent { constructor(type, init) { this.type = type; this.detail = init.detail; } }
  vm.runInNewContext(fs.readFileSync(path.join(EXT, 'inpage.js'), 'utf8'), {
    window, CustomEvent, crypto: require('node:crypto').webcrypto, location: { origin: 'https://dapp.test' },
  });
  assert.equal(window.ethereum, okx);
  assert.equal(announcements.length, 1);
  const { info, provider } = announcements[0].detail;
  assert.equal(info.rdns, 'com.nuri.card');
  assert.equal(provider.isNuriCard, true);
  assert.notEqual(provider, okx);
  assert.equal(provider.isOkxWallet, undefined);
  assert.deepEqual(Buffer.from(info.icon.split(',')[1], 'base64'), fs.readFileSync(path.join(EXT, 'icon32.png')));
  listeners.get('eip6963:requestProvider')();
  assert.equal(announcements.length, 2);
  assert.equal(announcements[1].detail.provider, provider);
});
