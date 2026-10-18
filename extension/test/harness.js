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
  const info = { address: wallet.address, pubkey: wallet.signingKey.compressedPublicKey, applet: options.pin ? 'eth2' : 'eth1', applet_version: 'test', reader: 'FAKE', mode: options.mode || 'card', pin_set: !!options.pin, pin_tries_left: options.pin ? 5 : null };
  let nextWindow = 100, native, child, closed = false;
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
            if (options.nativeHandler) ({ result, error } = await options.nativeHandler(msg, info, wallet));
            else if (msg.method === 'info') result = clone(info);
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
        setImmediate(async () => {
          if (options.autoApprove === false || closed) return;
          const approved = typeof options.autoApprove === 'function' ? options.autoApprove() : true;
          const view = await open(id);
          if (view.error) throw new Error(JSON.stringify(view.error));
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
    const body = JSON.parse(req.body); rpcCalls.push({ url, ...body });
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
    const approvalId = new URL(windows.get(id).tabs[0].url).searchParams.get('id');
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
