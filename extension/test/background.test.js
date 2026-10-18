// End-to-end (no Chrome, no card): background.js handler logic against the REAL
// python host (host/nuri_card_host.py) in sim mode, via a mocked chrome.* API.
// Run: NURI_HOST_PYTHON=<venv>/bin/python node --test extension/test/background.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const vm = require("node:vm");
const { spawnSync } = require("node:child_process");

const EXT = path.join(__dirname, "..");
const HOST = path.join(EXT, "..", "host", "nuri_card_host.py");
const PY = process.env.NURI_HOST_PYTHON || "python3";

function nativeMessage(msg) {
  const body = Buffer.from(JSON.stringify(msg));
  const len = Buffer.alloc(4);
  len.writeUInt32LE(body.length);
  const r = spawnSync(PY, [HOST, "chrome-extension://test/"], { input: Buffer.concat([len, body]), env: { ...process.env, NURI_CARD_SIM: "1" } });
  if (r.status !== 0) throw new Error("host failed: " + r.stderr.toString());
  const n = r.stdout.readUInt32LE(0);
  return JSON.parse(r.stdout.subarray(4, 4 + n).toString());
}

// ---- mock chrome ----------------------------------------------------------
const storage = { local: {}, session: {} };
const listeners = { onMessage: [], onRemoved: [] };
let autoApprove = true;
const chrome = {
  runtime: {
    lastError: null,
    sendNativeMessage(name, msg, cb) {
      assert.equal(name, "com.nuri.card");
      try { cb(nativeMessage(msg)); } catch (e) { chrome.runtime.lastError = { message: e.message }; cb(undefined); chrome.runtime.lastError = null; }
    },
    getURL: (p) => "chrome-extension://test/" + p,
    onMessage: { addListener: (fn) => listeners.onMessage.push(fn) },
  },
  storage: {
    local: { get: async (keys) => pick(storage.local, keys), set: async (o) => Object.assign(storage.local, o) },
    session: { get: async (keys) => pick(storage.session, keys), set: async (o) => Object.assign(storage.session, o), remove: async (k) => { delete storage.session[k]; } },
  },
  windows: {
    nextId: 100,
    async create() {
      const id = this.nextId++;
      // simulate the user clicking Approve/Reject in approve.html
      setTimeout(() => {
        const approvalId = Number(Object.keys(storage.session).find((k) => k.startsWith("approval:")).split(":")[1]);
        for (const fn of listeners.onMessage) fn({ type: "approval", approvalId, approved: autoApprove }, {}, () => {});
      }, 0);
      return { id };
    },
    remove: async () => {},
    onRemoved: { addListener: (fn) => listeners.onRemoved.push(fn) },
  },
  tabs: { query: (_q, cb) => cb([]), sendMessage: () => {} },
};
function pick(obj, keys) { const o = {}; for (const k of [].concat(keys)) if (k in obj) o[k] = obj[k]; return o; }

const sandbox = { chrome, console, setTimeout, clearTimeout, fetch: async () => { throw new Error("network disabled in test"); }, URL, TextEncoder, TextDecoder, crypto: globalThis.crypto };
sandbox.self = sandbox;
sandbox.globalThis = sandbox;
sandbox.importScripts = (...files) => { for (const f of files) vm.runInContext(fs.readFileSync(path.join(EXT, f), "utf8"), sandbox, { filename: f }); };
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(EXT, "background.js"), "utf8"), sandbox, { filename: "background.js" });

const ORIGIN = "http://dapp.test";
function rpc(method, params) {
  return new Promise((resolve) => {
    // JSON round-trip: the vm context has its own Object prototype, which breaks deepEqual
    for (const fn of listeners.onMessage) fn({ type: "rpc", method, params }, { url: ORIGIN + "/index.html" }, (r) => resolve(JSON.parse(JSON.stringify(r))));
  });
}
const E = sandbox.ethers;
let address;

test("eth_chainId defaults to Base", async () => {
  assert.deepEqual(await rpc("eth_chainId"), { result: "0x2105" });
});

test("eth_accounts is empty before connect; personal_sign is unauthorized", async () => {
  assert.deepEqual(await rpc("eth_accounts"), { result: [] });
  const r = await rpc("personal_sign", ["0x00", "0x0000000000000000000000000000000000000000"]);
  assert.equal(r.error.code, 4100);
});

test("eth_requestAccounts asks approval and returns the sim address from the host", async () => {
  const r = await rpc("eth_requestAccounts");
  assert.ok(r.result, JSON.stringify(r));
  address = r.result[0];
  const info = nativeMessage({ id: 1, method: "info" }).result;
  assert.equal(address, info.address);
  assert.equal(E.getAddress(address), address, "EIP-55");
  assert.deepEqual(await rpc("eth_accounts"), { result: [address] });
});

test("personal_sign via card host recovers to the card address", async () => {
  const msg = "Hello from Nuri Card";
  const r = await rpc("personal_sign", [E.hexlify(E.toUtf8Bytes(msg)), address]);
  assert.ok(r.result, JSON.stringify(r));
  assert.equal(E.verifyMessage(msg, r.result), address);
  // reversed parameter order also works
  const r2 = await rpc("personal_sign", [address, msg]);
  assert.equal(E.verifyMessage(msg, r2.result), address);
});

test("eth_signTypedData_v4 via card host recovers to the card address", async () => {
  const typed = {
    types: {
      EIP712Domain: [{ name: "name", type: "string" }, { name: "chainId", type: "uint256" }],
      Mail: [{ name: "contents", type: "string" }],
    },
    primaryType: "Mail",
    domain: { name: "Nuri", chainId: 8453 },
    message: { contents: "hi" },
  };
  const r = await rpc("eth_signTypedData_v4", [address, JSON.stringify(typed)]);
  assert.ok(r.result, JSON.stringify(r));
  assert.equal(E.verifyTypedData(typed.domain, { Mail: typed.types.Mail }, typed.message, r.result), address);
});

test("eth_signTransaction (explicit fees, no RPC) yields an EIP-1559 tx from the card address", async () => {
  const r = await rpc("eth_signTransaction", [{ from: address, to: "0x000000000000000000000000000000000000dEaD", value: "0x0", nonce: "0x0", gas: "0x5208", maxFeePerGas: "0xf4240", maxPriorityFeePerGas: "0x3e8" }]);
  assert.ok(r.result, JSON.stringify(r));
  const tx = E.Transaction.from(r.result);
  assert.equal(tx.type, 2);
  assert.equal(tx.chainId, 8453n);
  assert.equal(tx.from, address);
  assert.equal(tx.to, "0x000000000000000000000000000000000000dEaD");
});

test("wrong from address is rejected", async () => {
  const r = await rpc("eth_signTransaction", [{ from: "0x000000000000000000000000000000000000dEaD", to: address, nonce: "0x0", gas: "0x5208", maxFeePerGas: "0x1", maxPriorityFeePerGas: "0x1" }]);
  assert.equal(r.error.code, -32602);
});

test("user rejection returns 4001 and nothing is signed", async () => {
  autoApprove = false;
  const r = await rpc("personal_sign", ["0x1234", address]);
  assert.equal(r.error.code, 4001);
  autoApprove = true;
});

test("wallet_switchEthereumChain to Ethereum then unsupported chain", async () => {
  assert.deepEqual(await rpc("wallet_switchEthereumChain", [{ chainId: "0x1" }]), { result: null });
  assert.deepEqual(await rpc("eth_chainId"), { result: "0x1" });
  const r = await rpc("wallet_switchEthereumChain", [{ chainId: "0x89" }]);
  assert.equal(r.error.code, 4902);
  await rpc("wallet_switchEthereumChain", [{ chainId: 8453 }]);
  assert.deepEqual(await rpc("eth_chainId"), { result: "0x2105" });
});

test("eth_sign is refused", async () => {
  const r = await rpc("eth_sign", [address, "0x00"]);
  assert.equal(r.error.code, 4200);
});
