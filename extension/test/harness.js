// Fake Chrome + RPC only. Optional real native host uses the explicit public sim.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawn } = require('node:child_process');
const E = require('../third_party/ethers.umd.min.js');
const EXT = path.resolve(__dirname, '..');
const clone = (v) => v === undefined ? undefined : JSON.parse(JSON.stringify(v));
const tick = () => new Promise((resolve) => setImmediate(resolve));
function createHarness(options = {}) {
  const wallet = new E.Wallet('0x' + '02'.repeat(32)); // synthetic fixture only
  const storage = { local: options.local || {}, session: options.session || {} };
  const windows = new Map(options.windows || []);
  const contexts = new Map([...windows.values()].map((win) => ['document-' + win.id, { documentId: 'document-' + win.id, documentUrl: win.tabs[0].url, tabId: win.tabs[0].id, windowId: win.id }]));
  const listeners = { message: [], removed: [] };
  const timers = new Map();
  const calls = [], rpcCalls = [], badges = [];
  const BITCOIN_PK = '03' + '11'.repeat(32);
  const SERVER_PK = '02' + '22'.repeat(32);
  const info = { address: wallet.address, pubkey: wallet.signingKey.compressedPublicKey, applet: options.pin ? 'eth2' : 'eth1', applet_version: 'test', reader: 'FAKE', mode: options.mode || 'card', pin_set: !!options.pin, pin_tries_left: options.pin ? 5 : null };
  let nextWindow = 100, native, child, closed = false;
  // Fake Bitcoin card: the aggregate is the hash of both keys so every identity
  // change is visible in the address and in the approval digest.
  let bitcoinAggregate = '02' + require('node:crypto').createHash('sha256').update(BITCOIN_PK + SERVER_PK).digest('hex').slice(2);
  const bitcoinPreview = (request) => ({
    job_id: 'job-' + (calls.length),
    digest: '0x' + require('node:crypto').createHash('sha256').update(JSON.stringify(request)).digest('hex'),
    summary: {
      kind: request.params.kind,
      destination: request.params.target,
      amount_sats: request.params.amount_sats ?? (request.params.kind === 'lightning' ? 2100 : null),
      payment_hash: request.params.kind === 'lightning' ? 'ab'.repeat(32) : null,
      aggregate_pubkey33: bitcoinAggregate,
      network: 'mainnet',
    },
  });
  const bitcoin = {};
  bitcoin.bitcoinInfo = async () => ({
    status: 'NURI_CARD_BITCOIN_INFO_OK', network: 'mainnet', card_pubkey33: BITCOIN_PK, server_pubkey33: SERVER_PK,
    aggregate_pubkey33: bitcoinAggregate,
    ark_address: 'ark1qzpq904am6clw3pgqwyh4p02708fy4xs0hcpwt7rwfdttuxsjameepfv6ed2mgaw4k2tdts49m4wkk3zqyrjv44sr2gcgxrm47gy7sqnlyjr3x',
    boarding_address: 'bc1p48tcgtk50havqnyq7pswx7hux8szpfjrrv3477z7r6sl4s0vyaxspfzzwu',
    onchain_address: 'bc1pxa43e00wl6a2qqfd7wu8xgmuz8vczauvmn0nt45zff2kuq9u4klsfrz0f5',
    card_applet: '1.17', pin_set: !!options.bitcoinPin, pin_tries_left: options.bitcoinPin ? 5 : null, reader: 'FAKE',
  });
  const pick = (obj, keys) => keys === null ? clone(obj) : Object.fromEntries([].concat(keys).filter((key) => key in obj).map((key) => [key, clone(obj[key])]));
  const chrome = {
    runtime: {
      id: 'test', lastError: null, getURL: (p) => 'chrome-extension://test/' + p,
      onMessage: { addListener: (fn) => listeners.message.push(fn) },
      getContexts: async ({ documentIds }) => documentIds ? documentIds.map((id) => contexts.get(id)).filter(Boolean) : [...contexts.values()],
      connectNative(name) {
        if (options.nativeUnavailable) throw new Error('unavailable');
        if (name !== 'com.nuri.card') throw new Error('unexpected host');
        const messages = [], disconnect = [];
        native = { onMessage: { addListener: (fn) => messages.push(fn) }, onDisconnect: { addListener: (fn) => disconnect.push(fn) }, disconnect() { for (const fn of disconnect) fn(); }, postMessage(request) {
          const msg = clone(request); // Chrome serializes before the caller clears PIN
          calls.push(msg);
          if (child) {
            const body = Buffer.from(JSON.stringify(msg)), size = Buffer.alloc(4); size.writeUInt32LE(body.length);
            child.stdin.write(Buffer.concat([size, body]));
          } else queueMicrotask(async () => {
            let result, error;
            if (options.nativeHandler) ({ result, error } = await options.nativeHandler(msg, info, wallet, bitcoin));
            else if (msg.method === 'info') result = clone(info);
            else if (msg.method === 'bitcoin_info') result = clone(await bitcoin.bitcoinInfo());
            else if (msg.method === 'bitcoin_balance') result = { status: 'NURI_CARD_BITCOIN_BALANCE_OK', vtxo_sats: 4926, boarding_sats: 0, onchain_address: 'bc1pxa43e00wl6a2qqfd7wu8xgmuz8vczauvmn0nt45zff2kuq9u4klsfrz0f5', ark_address: 'ark1x', boarding_address: 'bc1px' };
            else if (msg.method === 'bitcoin_preview') result = bitcoinPreview(msg);
            else if (msg.method === 'bitcoin_sign_partial' && options.bitcoinPin && msg.params.pin !== options.bitcoinPin) { info.bitcoin_tries = (info.bitcoin_tries ?? 5) - 1; error = { code: 'BITCOIN_ERROR', message: `wrong PIN, ${info.bitcoin_tries} tries left` }; }
            else if (msg.method === 'bitcoin_sign_partial') result = options.bitcoinSignResult ? options.bitcoinSignResult(msg) : { status: 'NURI_CARD_BITCOIN_SEND_OK', ark_txid: 'cd'.repeat(32), approved_digest: msg.params.digest };
            else if (msg.method === 'bitcoin_cancel') result = { cancelled: true };
            else if (msg.method === 'bitcoin_invoice') result = { status: 'NURI_CARD_LIGHTNING_INVOICE_CREATED', invoice: 'lnbc21u1pjt8xyzpp5fakeinvoice', amount_sats: msg.params.amount_sats, payment_hash: 'ef'.repeat(32) };
            else if (info.pin_set && msg.method === 'sign_hash') error = { code: 'PIN_REQUIRED', message: 'PIN required', tries_left: info.pin_tries_left };
            else if (msg.method === 'verify_pin' && msg.params.pin !== options.pin) { info.pin_tries_left--; error = { code: 'PIN_WRONG', message: 'Wrong PIN', tries_left: info.pin_tries_left }; }
            else { const sig = wallet.signingKey.sign(msg.params.hash); result = { r: sig.r, s: sig.s, yParity: sig.yParity }; }
            for (const fn of messages) fn(error ? { id: msg.id, ok: false, error } : { id: msg.id, ok: true, result });
          });
        } };
        if (options.realHost) {
          child = spawn(process.env.NURI_HOST_PYTHON || 'python3', [path.resolve(EXT, '../host/nuri_card_host.py')], { env: { ...process.env, NURI_CARD_SIM: '1', NURI_CARD_HOST_LOG: '' }, stdio: ['pipe', 'pipe', 'pipe'] });
          let buffer = Buffer.alloc(0);
          child.stdout.on('data', (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            while (buffer.length >= 4 && buffer.length >= buffer.readUInt32LE(0) + 4) {
              const n = buffer.readUInt32LE(0), response = JSON.parse(buffer.subarray(4, n + 4)); buffer = buffer.subarray(n + 4);
              for (const fn of messages) fn(response);
            }
          });
          child.on('exit', () => { if (!closed) native.disconnect(); });
        }
        return native;
      },
    },
    storage: Object.fromEntries(['local', 'session'].map((area) => [area, { get: async (keys) => pick(storage[area], keys), set: async (obj) => Object.assign(storage[area], clone(obj)), remove: async (keys) => { for (const key of [].concat(keys)) delete storage[area][key]; } }])),
    windows: {
      async create({ url }) {
        const id = nextWindow++, tabId = id + 1000, documentId = 'document-' + id;
        windows.set(id, { id, tabs: [{ id: tabId, url }] });
        contexts.set(documentId, { documentId, documentUrl: url, tabId, windowId: id });
        if (options.windowCreated) await options.windowCreated(id);
        setImmediate(async () => {
          if (options.autoApprove === false || closed) return;
          const approved = typeof options.autoApprove === 'function' ? options.autoApprove() : true;
          const view = await open(id);
          if (view.error) return;
          await decide(view, approved, options.pin);
        });
        return clone(windows.get(id));
      },
      async getAll() { return clone([...windows.values()]); },
      async get(id) { if (!windows.has(id)) throw new Error('no such window'); return clone(windows.get(id)); },
      async remove(id) { windows.delete(id); for (const [key, context] of contexts) if (context.windowId === id) contexts.delete(key); for (const fn of listeners.removed) fn(id); },
      onRemoved: { addListener: (fn) => listeners.removed.push(fn) },
    },
    tabs: { query: (_q, cb) => cb([]), sendMessage: () => {} },
    action: { setBadgeText: async (o) => badges.push(o.text), setBadgeBackgroundColor: async (o) => badges.push(o.color) },
  };
  const sandbox = { chrome, console, URL, TextEncoder, TextDecoder, crypto: require('node:crypto').webcrypto, setTimeout: (fn, ms) => { const id = {}; timers.set(id, fn); return id; }, clearTimeout: (id) => timers.delete(id), fetch: async (url, req) => {
    if (options.httpFetch) return options.httpFetch(url, req);
    const body = JSON.parse(req.body || '{}'); rpcCalls.push({ url, ...body });
    if (!options.fetch) throw new Error('network disabled in test');
    return { ok: true, json: async () => ({ result: await options.fetch(body.method, body.params, url) }) };
  } };
  sandbox.self = sandbox; sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  sandbox.importScripts = (...files) => { for (const file of files) vm.runInContext(fs.readFileSync(path.join(EXT, file), 'utf8'), sandbox, { filename: file }); };
  vm.runInContext(fs.readFileSync(path.join(EXT, 'background.js'), 'utf8'), sandbox);
  function message(msg, sender = { id: 'test', url: 'https://dapp.test/index.html' }) { return new Promise((resolve) => { let handled = false; for (const fn of listeners.message) if (fn(msg, sender, (r) => resolve(clone(r)))) handled = true; if (!handled) resolve(null); }); }
  function sender(id) { const win = windows.get(id); return { id: 'test', url: win?.tabs[0].url, documentId: 'document-' + id }; }
  async function open(id) {
    const win = windows.get(id);
    if (!win) return { error: { code: 4001, message: 'window already closed' } };
    const approvalId = new URL(win.tabs[0].url).searchParams.get('id');
    const from = sender(id), meta = { approvalId, windowId: id };
    const response = await message({ type: 'approval:get', ...meta }, from);
    if (!response?.request) return response;
    const view = { ...meta, ...response, from, hash: response.request.summary.hash || null };
    const shown = await message({ type: 'approval:displayed', ...meta, binding: view.binding, hash: view.hash }, from);
    if (!shown.ok) return shown;
    return view;
  }
  async function decide(view, approved = true, pin) { return message({ type: 'approval', approvalId: view.approvalId, windowId: view.windowId, binding: view.binding, hash: view.hash, approved, ...(pin === undefined ? {} : { pin }) }, view.from); }
  async function pendingWindow() { for (let tries = 0; tries < 100; tries++) { await tick(); const ids = [...windows.keys()]; if (ids.length) return ids.at(-1); } throw new Error('no approval window'); }
  function dispose() { closed = true; child?.kill(); timers.clear(); }
  return { sandbox, chrome, storage, windows, contexts, calls, rpcCalls, badges, info, wallet, message, open, decide, pendingWindow, sender, dispose, tick, expire: () => { for (const fn of [...timers.values()]) fn(); }, rpc: (method, params) => message({ type: 'rpc', method, params }), toolbar: () => message({ type: 'popup:state' }, { id: 'test', url: chrome.runtime.getURL('popup.html') }) };
}
module.exports = { createHarness, clone, tick, E };
