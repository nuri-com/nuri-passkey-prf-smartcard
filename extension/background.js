// MV3 service worker: EIP-1193 request handling, approvals, native host bridge.
importScripts("third_party/ethers.umd.min.js", "lib/hashing.js");

const H = self.NuriHashing;
const NATIVE_HOST = "com.nuri.card";
const DEFAULT_CHAIN = "0x2105"; // Base

// ---------------------------------------------------------------------------
// State (persisted in chrome.storage.session / local because SW can be killed)
// ---------------------------------------------------------------------------
async function getState() {
  const { chainId = DEFAULT_CHAIN, connectedOrigins = {} } = await chrome.storage.local.get(["chainId", "connectedOrigins"]);
  return { chainId, connectedOrigins };
}
async function setState(patch) {
  await chrome.storage.local.set(patch);
}

let cachedInfo = null; // {address, pubkey, applet, applet_version, reader, mode}

// ---------------------------------------------------------------------------
// Native host
// ---------------------------------------------------------------------------
let nextNativeId = 1;
function nativeCall(method, params) {
  const id = nextNativeId++;
  const msg = params ? { id, method, params } : { id, method };
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, msg, (resp) => {
      if (chrome.runtime.lastError) {
        reject(rpcError(-32603, `Nuri Card host unreachable: ${chrome.runtime.lastError.message}. Run host/install-macos.sh.`));
        return;
      }
      if (!resp || resp.id !== id) {
        reject(rpcError(-32603, "Nuri Card host: malformed response"));
        return;
      }
      if (!resp.ok) {
        const code = resp.error?.code || "CARD_ERROR";
        reject(rpcError(code === "BAD_REQUEST" ? -32602 : -32603, `Nuri Card [${code}]: ${resp.error?.message || ""}`, resp.error));
        return;
      }
      resolve(resp.result);
    });
  });
}

async function cardInfo(force = false) {
  if (cachedInfo && !force) return cachedInfo;
  const info = await nativeCall("info");
  info.address = H.getAddress(info.address);
  cachedInfo = info;
  await setState({ lastInfo: info });
  return info;
}

async function signHashOnCard(hash, expectedAddress) {
  const sig = await nativeCall("sign_hash", { hash });
  // Belt and braces: the host already verified; re-check in the extension with ethers.
  const recovered = H.recoverAddress(hash, sig);
  if (recovered.toLowerCase() !== expectedAddress.toLowerCase()) {
    throw rpcError(-32603, `Nuri Card: signature does not recover to ${expectedAddress} (got ${recovered})`);
  }
  return sig;
}

// ---------------------------------------------------------------------------
// Approval popup
// ---------------------------------------------------------------------------
const approvals = new Map(); // approvalId -> {resolve, reject, windowId}
let nextApprovalId = 1;

async function requestApproval(origin, kind, summary) {
  const approvalId = nextApprovalId++;
  const payload = { approvalId, origin, kind, summary, createdAt: Date.now() };
  await chrome.storage.session.set({ ["approval:" + approvalId]: payload });
  const url = chrome.runtime.getURL(`approve.html?id=${approvalId}`);
  const win = await chrome.windows.create({ url, type: "popup", width: 420, height: 560, focused: true });
  return new Promise((resolve, reject) => {
    approvals.set(approvalId, { resolve, reject, windowId: win.id });
  });
}

chrome.windows.onRemoved.addListener((windowId) => {
  for (const [id, a] of approvals) {
    if (a.windowId === windowId) {
      approvals.delete(id);
      chrome.storage.session.remove("approval:" + id);
      a.reject(rpcError(4001, "User rejected the request"));
    }
  }
});

function settleApproval(approvalId, approved) {
  const a = approvals.get(approvalId);
  if (!a) return;
  approvals.delete(approvalId);
  chrome.storage.session.remove("approval:" + approvalId);
  if (approved) a.resolve(true);
  else a.reject(rpcError(4001, "User rejected the request"));
  chrome.windows.remove(a.windowId).catch(() => {});
}

// ---------------------------------------------------------------------------
// RPC passthrough (read-only methods + broadcast)
// ---------------------------------------------------------------------------
async function rpc(chainId, method, params) {
  const chain = H.SUPPORTED_CHAINS[chainId];
  if (!chain) throw rpcError(4901, `Unsupported chain ${chainId}`);
  const res = await fetch(chain.rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw rpcError(body.error.code ?? -32603, body.error.message ?? "rpc error", body.error.data);
  return body.result;
}

function rpcError(code, message, data) {
  return { code, message, data };
}

function originOf(sender) {
  try { return new URL(sender.url || sender.origin || "").origin; } catch { return sender.origin || "unknown"; }
}

// ---------------------------------------------------------------------------
// Method handlers
// ---------------------------------------------------------------------------
async function ensureConnected(origin, state) {
  if (!state.connectedOrigins[origin]) throw rpcError(4100, "Unauthorized: call eth_requestAccounts first");
}

function assertFromIsCard(from, address) {
  if (from && H.getAddress(from).toLowerCase() !== address.toLowerCase()) {
    throw rpcError(-32602, `from ${from} is not the Nuri Card address ${address}`);
  }
}

async function prepareTx(req, chainId, address) {
  if (!req || typeof req !== "object") throw rpcError(-32602, "transaction must be an object");
  assertFromIsCard(req.from, address);
  const filled = {};
  if (req.nonce == null) filled.nonce = Number(await rpc(chainId, "eth_getTransactionCount", [address, "pending"]));
  if (req.gas == null && req.gasLimit == null) {
    filled.gasLimit = BigInt(await rpc(chainId, "eth_estimateGas", [{ from: address, to: req.to, value: req.value, data: req.data || req.input }]));
  }
  if (req.maxFeePerGas == null || req.maxPriorityFeePerGas == null) {
    const block = await rpc(chainId, "eth_getBlockByNumber", ["latest", false]);
    const base = BigInt(block.baseFeePerGas || "0x0");
    let tip = 1_000_000n; // 0.001 gwei default tip (Base is cheap)
    try { tip = BigInt(await rpc(chainId, "eth_maxPriorityFeePerGas", [])); } catch {}
    filled.maxPriorityFeePerGas = tip;
    filled.maxFeePerGas = base * 2n + tip;
  }
  return H.buildUnsignedTx(req, H.SUPPORTED_CHAINS[chainId].chainId, filled);
}

const handlers = {
  async eth_chainId(_p, { state }) { return state.chainId; },
  async net_version(_p, { state }) { return String(H.SUPPORTED_CHAINS[state.chainId].chainId); },

  async eth_accounts(_p, { origin, state }) {
    if (!state.connectedOrigins[origin]) return [];
    return [(await cardInfo()).address];
  },

  async eth_requestAccounts(_p, { origin, state }) {
    const info = await cardInfo();
    if (!state.connectedOrigins[origin]) {
      await requestApproval(origin, "connect", { address: info.address, applet: `${info.applet} v${info.applet_version}`, reader: info.reader, mode: info.mode });
      state.connectedOrigins[origin] = Date.now();
      await setState({ connectedOrigins: state.connectedOrigins });
    }
    return [info.address];
  },

  async wallet_switchEthereumChain(params, { state, origin }) {
    const target = params?.[0]?.chainId;
    if (!target) throw rpcError(-32602, "chainId required");
    const hex = H.toHexChainId(target);
    if (!H.SUPPORTED_CHAINS[hex]) throw rpcError(4902, `Unrecognized chain ${hex}; supported: ${Object.keys(H.SUPPORTED_CHAINS).join(", ")}`);
    if (hex !== state.chainId) {
      await setState({ chainId: hex });
      broadcastEvent("chainChanged", [hex]);
    }
    return null;
  },

  async personal_sign(params, { origin, state }) {
    await ensureConnected(origin, state);
    const info = await cardInfo();
    // MetaMask order: [message, address]; some dapps send [address, message]
    let [message, address] = params || [];
    if (typeof message === "string" && /^0x[0-9a-fA-F]{40}$/.test(message) && !(typeof address === "string" && /^0x[0-9a-fA-F]{40}$/.test(address))) {
      [message, address] = [address, message];
    }
    assertFromIsCard(address, info.address);
    const hash = H.hashPersonalMessage(message);
    await requestApproval(origin, "personal_sign", { address: info.address, message: H.decodePersonalMessage(message), hash });
    const sig = await signHashOnCard(hash, info.address);
    return H.compactSignature(sig);
  },

  async eth_signTypedData_v4(params, { origin, state }) {
    await ensureConnected(origin, state);
    const info = await cardInfo();
    const [address, typedData] = params || [];
    assertFromIsCard(address, info.address);
    const parsed = H.parseTypedData(typedData);
    const hash = H.hashTypedDataV4(typedData);
    await requestApproval(origin, "eth_signTypedData_v4", {
      address: info.address,
      domain: parsed.domain,
      primaryType: parsed.primaryType,
      message: parsed.message,
      hash,
    });
    const sig = await signHashOnCard(hash, info.address);
    return H.compactSignature(sig);
  },

  async eth_signTransaction(params, { origin, state }) {
    await ensureConnected(origin, state);
    const info = await cardInfo();
    const tx = await prepareTx(params?.[0], state.chainId, info.address);
    const hash = H.unsignedTxHash(tx);
    await requestApproval(origin, "eth_signTransaction", { address: info.address, chain: H.SUPPORTED_CHAINS[state.chainId].name, tx: H.txSummary(tx), hash });
    const sig = await signHashOnCard(hash, info.address);
    return H.attachSignature(tx, sig);
  },

  async eth_sendTransaction(params, { origin, state }) {
    await ensureConnected(origin, state);
    const info = await cardInfo();
    const tx = await prepareTx(params?.[0], state.chainId, info.address);
    const hash = H.unsignedTxHash(tx);
    await requestApproval(origin, "eth_sendTransaction", { address: info.address, chain: H.SUPPORTED_CHAINS[state.chainId].name, tx: H.txSummary(tx), hash });
    const sig = await signHashOnCard(hash, info.address);
    const raw = H.attachSignature(tx, sig);
    return rpc(state.chainId, "eth_sendRawTransaction", [raw]);
  },

  async eth_sign() { throw rpcError(4200, "eth_sign is disabled (unsafe); use personal_sign"); },
  async eth_signTypedData() { throw rpcError(4200, "use eth_signTypedData_v4"); },
  async eth_signTypedData_v3() { throw rpcError(4200, "use eth_signTypedData_v4"); },
  async wallet_addEthereumChain() { throw rpcError(4200, "only Base (0x2105) and Ethereum (0x1) are built in"); },
  async wallet_requestPermissions(_p, ctx) { await handlers.eth_requestAccounts(_p, ctx); return [{ parentCapability: "eth_accounts" }]; },
  async wallet_getPermissions(_p, { origin, state }) { return state.connectedOrigins[origin] ? [{ parentCapability: "eth_accounts" }] : []; },
  async wallet_revokePermissions(_p, { origin, state }) {
    delete state.connectedOrigins[origin];
    await setState({ connectedOrigins: state.connectedOrigins });
    return null;
  },
};

const PASSTHROUGH = new Set([
  "eth_blockNumber", "eth_call", "eth_estimateGas", "eth_gasPrice", "eth_getBalance", "eth_getBlockByNumber",
  "eth_getBlockByHash", "eth_getCode", "eth_getLogs", "eth_getTransactionByHash", "eth_getTransactionCount",
  "eth_getTransactionReceipt", "eth_maxPriorityFeePerGas", "eth_feeHistory", "eth_sendRawTransaction",
  "eth_getStorageAt", "web3_clientVersion",
]);

async function handleRequest(method, params, origin) {
  const state = await getState();
  if (handlers[method]) return handlers[method](params, { origin, state });
  if (PASSTHROUGH.has(method)) return rpc(state.chainId, method, params || []);
  throw rpcError(4200, `Unsupported method ${method}`);
}

function broadcastEvent(event, args) {
  chrome.tabs.query({}, (tabs) => {
    for (const t of tabs) chrome.tabs.sendMessage(t.id, { type: "event", event, args }, () => void chrome.runtime.lastError);
  });
}

// ---------------------------------------------------------------------------
// Message router
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== "object") return false;
  if (msg.type === "rpc") {
    const origin = originOf(sender);
    handleRequest(msg.method, msg.params, origin)
      .then((result) => sendResponse({ result: result === undefined ? null : result }))
      .catch((e) => sendResponse({ error: e && e.code !== undefined ? e : { code: -32603, message: String(e?.message || e) } }));
    return true;
  }
  if (msg.type === "approval") {
    settleApproval(msg.approvalId, !!msg.approved);
    sendResponse({ ok: true });
    return false;
  }
  if (msg.type === "popup:info") {
    cardInfo(true).then((info) => sendResponse({ info })).catch((e) => sendResponse({ error: e }));
    return true;
  }
  if (msg.type === "popup:state") {
    getState().then((state) => sendResponse({ state, info: cachedInfo }));
    return true;
  }
  if (msg.type === "popup:disconnectAll") {
    setState({ connectedOrigins: {} }).then(() => { broadcastEvent("accountsChanged", [[]]); sendResponse({ ok: true }); });
    return true;
  }
  return false;
});
