const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHarness, E, tick } = require('./harness');
const EXT = path.resolve(__dirname, '..');
// popup.js reads the shared Bitcoin helpers from the page global, as popup.html does.
const libSandbox = { NuriHashing: { ethers: E } };
vm.createContext(libSandbox);
libSandbox.self = libSandbox;
vm.runInContext(fs.readFileSync(path.join(EXT, 'lib/bitcoin.js'), 'utf8'), libSandbox);
const pageGlobals = { self: { NuriBitcoin: libSandbox.NuriBitcoin } };
function dom() {
  const elements = new Map();
  function element(id) { if (!elements.has(id)) elements.set(id, { hidden: false, disabled: false, value: '', textContent: '', innerHTML: '', focus() {} }); return elements.get(id); }
  const events = {};
  return { elements, element, events, document: { querySelector: (id) => element(id.slice(1)), getElementById: element }, window: { addEventListener: (name, fn) => { events[name] = fn; }, close() { events.closed = true; } } };
}
async function approvalPopup(t, options = {}) {
  const h = createHarness({ ...options, autoApprove: false, local: { connectedOrigins: { 'https://dapp.test': 1 } } }); t.after(h.dispose);
  const result = h.rpc('personal_sign', ['popup message', h.wallet.address]);
  const windowId = await h.pendingWindow(), from = h.sender(windowId), page = dom();
  const chrome = { windows: { getCurrent: async () => ({ id: windowId }) }, runtime: { sendMessage: (msg) => h.message(msg, from) } };
  const context = vm.createContext({ chrome, document: page.document, window: page.window, location: { search: new URL(from.url).search }, URLSearchParams, TextEncoder, ...pageGlobals });
  await vm.runInContext(fs.readFileSync(path.join(EXT, 'approve.js'), 'utf8'), context);
  return { h, result, ...page };
}
test('approval UI labels simulator on every signing popup; legacy PIN field stays hidden', async (t) => {
  const ui = await approvalPopup(t, { mode: 'sim' }); assert.equal(ui.element('sim').hidden, false); assert.equal(ui.element('pinBox').hidden, true);
  assert.match(ui.element('body').innerHTML, /Hash sent to card/); await ui.element('approve').onclick(); assert.ok((await ui.result).result); assert.equal(ui.events.closed, true);
  const css = fs.readFileSync(path.join(EXT, 'ui.css'), 'utf8'); assert.match(css, /\.sim \{ background: #FFE2D6/);
});
test('PIN popup clears input before native use, wrong tries shown, retry has same hash and explicit click', async (t) => {
  const ui = await approvalPopup(t, { pin: '2468' }); assert.equal(ui.element('pinBox').hidden, false); assert.equal(ui.element('sim').hidden, true);
  ui.element('pin').value = '0000'; const wrong = ui.element('approve').onclick(); assert.equal(ui.element('pin').value, ''); await wrong;
  assert.match(ui.element('tries').textContent, /4 PIN tries/); assert.equal(ui.element('approve').disabled, false);
  ui.element('pin').value = '2468'; await ui.element('approve').onclick(); assert.ok((await ui.result).result); assert.equal(ui.element('pin').value, '');
  assert.equal(ui.h.calls.filter((c) => c.method === 'verify_pin').length, 2);
  assert.equal(new Set(ui.h.calls.filter((c) => c.method === 'verify_pin').map((c) => c.params.hash)).size, 1);
});
test('PIN only appears after host PIN_REQUIRED when info did not ask for it', async (t) => {
  const ui = await approvalPopup(t); assert.equal(ui.element('pinBox').hidden, true); ui.h.info.pin_set = true;
  await ui.element('approve').onclick(); assert.equal(ui.element('pinBox').hidden, false); assert.equal(ui.element('pin').value, '');
  await ui.element('reject').onclick(); assert.equal((await ui.result).error.code, 4001);
});
test('pagehide clears PIN and blocked response disables signing', async (t) => {
  const ui = await approvalPopup(t, { pin: '2468' }); ui.element('pin').value = '2468'; ui.events.pagehide(); assert.equal(ui.element('pin').value, '');
  ui.h.info.pin_tries_left = 1; ui.element('pin').value = '0000'; await ui.element('approve').onclick(); assert.equal(ui.element('approve').disabled, true); assert.equal((await ui.result).error.code, 4001);
});
test('toolbar renders SIM badge, ETH balance and full basescan hash link', async () => {
  const page = dom(), hash = '0x' + 'ab'.repeat(32);
  const chrome = { runtime: { sendMessage(_msg, cb) { cb({ info: { mode: 'sim', address: E.ZeroAddress, applet: 'eth1', applet_version: 'sim', reader: 'fake' }, state: { chainId: '0x2105', connectedOrigins: {} }, balance: '1.23', lastTx: { hash, chainId: '0x2105' } }); } } };
  vm.runInNewContext(fs.readFileSync(path.join(EXT, 'popup.js'), 'utf8'), { chrome, document: page.document, ...pageGlobals });
  assert.match(page.element('out').innerHTML, /class="sim"/); assert.match(page.element('out').innerHTML, /1.23 ETH/); assert.ok(page.element('out').innerHTML.includes('https://basescan.org/tx/' + hash));
});
test('toolbar authenticity badge requires exact boolean true from card mode', () => {
  const source = fs.readFileSync(path.join(EXT, 'popup.js'), 'utf8');
  for (const attestation of [undefined, null, {}, { verified: false }, { verified: 'true' },
    { verified: 'false' }, { verified: 1 }, { verified: 0 }, { verified: [] }, { verified: {} },
    { verified: null }, { verified: new Boolean(true) }, { reason: 'verified' }]) {
    const page = dom();
    const chrome = { runtime: { sendMessage(_msg, cb) { cb({ info: { mode: 'card', attestation } }); } } };
    vm.runInNewContext(source, { chrome, document: page.document, ...pageGlobals });
    const rendered = page.element('out').innerHTML;
    assert.doesNotMatch(rendered, /genuine Nuri card/, JSON.stringify(attestation));
    assert.match(rendered, /Card authenticity unverified/);
    assert.match(rendered, /class="attestation unverified"/);
  }
  const page = dom();
  const chrome = { runtime: { sendMessage(_msg, cb) { cb({ info: { mode: 'card', attestation: { verified: true, reason: 'verified' } } }); } } };
  vm.runInNewContext(source, { chrome, document: page.document, ...pageGlobals });
  assert.match(page.element('out').innerHTML, /class="attestation verified">genuine Nuri card<\/div>/);
  assert.doesNotMatch(page.element('out').innerHTML, /Card authenticity unverified/);
});
test('toolbar SIM cannot claim genuineness even with a true flag, and refresh removes an old badge', () => {
  const page = dom();
  let info = { mode: 'card', attestation: { verified: true } };
  const chrome = { runtime: { sendMessage(_msg, cb) { cb({ info }); } } };
  vm.runInNewContext(fs.readFileSync(path.join(EXT, 'popup.js'), 'utf8'), { chrome, document: page.document, ...pageGlobals });
  assert.match(page.element('out').innerHTML, /genuine Nuri card/);
  info = { mode: 'sim', attestation: { verified: true } };
  page.element('refresh').onclick();
  assert.doesNotMatch(page.element('out').innerHTML, /genuine Nuri card/);
  assert.match(page.element('out').innerHTML, /Software simulator · public test key/);
  assert.match(page.element('out').innerHTML, /Card authenticity unverified/);
  info = { mode: 'card', attestation: { verified: false, reason: '<script>genuine Nuri card</script>' } };
  page.element('refresh').onclick();
  assert.doesNotMatch(page.element('out').innerHTML, /genuine Nuri card|<script>/);
  assert.match(page.element('out').innerHTML, /Card authenticity unverified/);
  info = null;
  page.element('refresh').onclick();
  assert.doesNotMatch(page.element('out').innerHTML, /genuine Nuri card/);
});
test('toolbar receives native attestation unchanged through background info', async (t) => {
  for (const verified of [true, false, 'true', undefined]) {
    const h = createHarness({ nativeHandler(msg, info) {
      assert.equal(msg.method, 'info');
      return { result: { ...info, attestation: { verified, reason: 'fixture' } } };
    }, fetch: async () => '0x0' });
    t.after(h.dispose);
    const response = await h.toolbar(), page = dom();
    const chrome = { runtime: { sendMessage(_msg, cb) { cb(response); } } };
    vm.runInNewContext(fs.readFileSync(path.join(EXT, 'popup.js'), 'utf8'), { chrome, document: page.document, ...pageGlobals });
    assert.equal(page.element('out').innerHTML.includes('genuine Nuri card'), verified === true);
    assert.equal(page.element('out').innerHTML.includes('Card authenticity unverified'), verified !== true);
  }
});
test('stage Send 0 ETH button requests Base self-send and exposes a basescan link', async () => {
  const html = fs.readFileSync(path.join(EXT, 'test-dapp.html'), 'utf8'); const inline = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const page = dom(), callbacks = {}, calls = [], address = E.ZeroAddress, hash = '0x' + 'cd'.repeat(32);
  const provider = { on() {}, async request(req) { calls.push(req); if (req.method === 'eth_requestAccounts') return [address]; if (req.method === 'eth_chainId') return '0x2105'; if (req.method === 'eth_sendTransaction') return hash; return null; } };
  page.document.createTextNode = (text) => ({ textContent: text });
  page.element('log').append = (node) => { page.element('log').textContent += node.textContent; };
  page.document.createElement = () => ({}); page.element('sent').replaceChildren = (...children) => { page.events.children = children; };
  vm.runInNewContext(inline, { window: { ethers: E, addEventListener: (name, fn) => { callbacks[name] = fn; }, dispatchEvent() {} }, document: page.document, Event: class {}, Date });
  callbacks['eip6963:announceProvider']({ detail: { info: { rdns: 'com.nuri.card', name: 'Nuri Card', uuid: 'fixture' }, provider } });
  await page.element('connect').onclick(); await page.element('send').onclick();
  assert.deepEqual(JSON.parse(JSON.stringify(calls.find((c) => c.method === 'eth_sendTransaction'))), { method: 'eth_sendTransaction', params: [{ from: address, to: address, value: '0x0' }] });
  assert.equal(calls.find((c) => c.method === 'wallet_switchEthereumChain').params[0].chainId, '0x2105'); assert.equal(page.events.children[1].href, 'https://basescan.org/tx/' + hash);
});

test('account view leads with the total and lists every rail with its address', () => {
  const page = dom();
  const bitcoin = {
    total: 10933,
    rails: [
      { rail: 'Arkade', address: 'ark1valid', sats: 4926 },
      { rail: 'Boarding', address: 'bc1pboard', sats: 0 },
      { rail: 'Onchain (MuSig2 + CSV)', address: 'bc1ponchain', sats: 6007 },
    ],
    wallet: { ark_address: 'ark1valid', boarding_address: 'bc1pboard', onchain_address: 'bc1ponchain' },
  };
  const chrome = { runtime: { sendMessage(_msg, cb) { cb({ info: { mode: 'card', address: E.ZeroAddress, applet: 'eth2', applet_version: 'x', reader: 'r' }, state: { chainId: '0x2105', connectedOrigins: {} }, balance: '0.5', bitcoin }); } } };
  vm.runInNewContext(fs.readFileSync(path.join(EXT, 'popup.js'), 'utf8'), { chrome, document: page.document, ...pageGlobals });
  const html = page.element('out').innerHTML;
  assert.match(html, /0\.00010933 BTC/);
  assert.match(html, /10,933 sats · all rails/);
  assert.match(html, /Onchain \(MuSig2 \+ CSV\)/);
  assert.ok(html.indexOf('Bitcoin') < html.indexOf('Ethereum'), 'Bitcoin leads');
  assert.equal(page.element('receivePanel').hidden, false);
  assert.match(page.element('receive').innerHTML, /bc1pboard/);
});

test('an unread onchain rail says unread and the total no longer pretends to be complete', () => {
  const page = dom();
  const bitcoin = { total: 4926, rails: [{ rail: 'Arkade', address: 'ark1valid', sats: 4926 }, { rail: 'Onchain (MuSig2 + CSV)', address: 'bc1ponchain', sats: null }], onchainError: 'mempool HTTP 502', wallet: {} };
  const chrome = { runtime: { sendMessage(_msg, cb) { cb({ info: { mode: 'card', address: E.ZeroAddress }, state: { chainId: '0x2105', connectedOrigins: {} }, bitcoin }); } } };
  vm.runInNewContext(fs.readFileSync(path.join(EXT, 'popup.js'), 'utf8'), { chrome, document: page.document, ...pageGlobals });
  assert.match(page.element('out').innerHTML, /unread/);
  assert.match(page.element('out').innerHTML, /Onchain rail unread: mempool HTTP 502/);
});

test('the send form hides the amount for invoices and asks for one for names', () => {
  const page = dom();
  const chrome = { runtime: { sendMessage(_msg, cb) { cb({ info: { mode: 'card', address: E.ZeroAddress }, state: { chainId: '0x2105', connectedOrigins: {} } }); } } };
  vm.runInNewContext(fs.readFileSync(path.join(EXT, 'popup.js'), 'utf8'), { chrome, document: page.document, ...pageGlobals });
  assert.equal(page.element('sendAmountBox').hidden, true);
  page.element('sendKind').value = 'nuri';
  page.element('sendKind').onchange();
  assert.equal(page.element('sendAmountBox').hidden, false);
  assert.match(page.element('sendTargetLabel').textContent, /nuri\.eth/);
});

test('a Bitcoin approval popup shows the rail, destination, digest and PIN rules', async (t) => {
  const h = createHarness({ autoApprove: false, local: { connectedOrigins: { 'https://dapp.test': 1 } }, bitcoinPin: '2468' });
  t.after(h.dispose);
  const LN = 'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4js';
  const result = h.rpc('nuri_bitcoinSend', [{ kind: 'lightning', invoice: LN }]);
  const windowId = await h.pendingWindow(), from = h.sender(windowId), page = dom();
  const chrome = { windows: { getCurrent: async () => ({ id: windowId }) }, runtime: { sendMessage: (msg) => h.message(msg, from) } };
  const context = vm.createContext({ chrome, document: page.document, window: page.window, location: { search: new URL(from.url).search }, URLSearchParams, TextEncoder, ...pageGlobals });
  await vm.runInContext(fs.readFileSync(path.join(EXT, 'approve.js'), 'utf8'), context);
  const body = page.element('body').innerHTML;
  assert.match(page.element('kind').textContent, /Send Bitcoin/);
  assert.match(body, /Lightning invoice/);
  assert.match(body, /Transaction digest/);
  assert.match(body, /Payment hash/);
  assert.equal(page.element('pinBox').hidden, false);
  page.element('pin').value = '2468';
  await page.element('approve').onclick();
  assert.ok((await result).result);
});
