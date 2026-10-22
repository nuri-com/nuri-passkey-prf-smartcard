// MV3 service worker: EIP-1193 request handling, approvals, native host bridge.
importScripts("third_party/ethers.umd.min.js", "lib/hashing.js");

const H = self.NuriHashing;
const NATIVE_HOST = "com.nuri.card";
const DEFAULT_CHAIN = "0x2105"; // Base

// Native Chrome side panel; browser preference controls left/right placement.
chrome.sidePanel?.setPanelBehavior({ openPanelOnActionClick: true }).catch(console.error);

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
let nativePort = null;
const nativePending = new Map();
function hostPort() {
  if (nativePort) return nativePort;
  const port = chrome.runtime.connectNative(NATIVE_HOST);
  nativePort = port;
  port.onMessage.addListener((resp) => {
    const pending = nativePending.get(resp?.id);
    if (!pending) return;
    nativePending.delete(resp.id);
    if (resp.ok) pending.resolve(resp.result);
    else pending.reject(rpcError(resp.error?.code === "BAD_REQUEST" ? -32602 : -32603,
      `Nuri Card [${resp.error?.code || "CARD_ERROR"}]: ${resp.error?.message || "host error"}`, resp.error));
  });
  port.onDisconnect.addListener(() => {
    if (nativePort !== port) return;
    nativePort = null;
    cachedInfo = null;
    for (const pending of nativePending.values()) pending.reject(rpcError(-32603, "Nuri Card host disconnected"));
    nativePending.clear();
    for (const [id] of approvals) cancelApproval(id, "Card connection closed");
  });
  return port;
}
function nativeCall(method, params) {
  const id = nextNativeId++;
  return new Promise((resolve, reject) => {
    try {
      const port = hostPort();
      nativePending.set(id, { resolve, reject });
      port.postMessage(params ? { id, method, params } : { id, method });
    } catch {
      nativePending.delete(id);
      reject(rpcError(-32603, "Nuri Card host unreachable. Run host/install-macos.sh."));
    } finally {
      // postMessage serializes synchronously. Never retain a PIN in this worker.
      if (params && Object.hasOwn(params, "pin")) delete params.pin;
    }
  });
}

async function cardInfo(force = false) {
  if (cachedInfo && !force) return cachedInfo;
  const info = await nativeCall("info");
  if (!info || !["card", "sim"].includes(info.mode)) throw rpcError(-32603, "Host did not declare card/sim mode");
  info.address = H.getAddress(info.address);
  await chrome.action.setBadgeText({ text: info.mode === "sim" ? "SIM" : "" });
  await chrome.action.setBadgeBackgroundColor({ color: "#b00020" });
  cachedInfo = info;
  await setState({ lastInfo: info });
  return info;
}

async function signHashOnCard(hash, expectedAddress, pin) {
  // Only host info on the live native connection authorizes this mode.
  if (!nativePort || !cachedInfo || !["card", "sim"].includes(cachedInfo.mode)) throw rpcError(-32603, "Read the card again before signing");
  let params = pin === undefined ? { hash } : { hash, address: expectedAddress, pin };
  pin = undefined;
  const method = Object.hasOwn(params, "pin") ? "verify_pin" : "sign_hash";
  const pending = nativeCall(method, params);
  params = null;
  const sig = await pending;
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
const approvals = new Map(); // memory only: killed worker = cancelled approval
const APPROVAL_TIMEOUT_MS = 120000;
const approvalBase = chrome.runtime.getURL("approve.html");
// A worker restart must not revive an old popup or persisted resolver id.
const approvalReady = (async () => {
  const saved = await chrome.storage.session.get(null);
  await chrome.storage.session.remove(Object.keys(saved).filter((key) => key.startsWith("approval:")));
  const contexts = await chrome.runtime.getContexts({ contextTypes: ["TAB"] });
  for (const ctx of contexts) {
    if (ctx.documentUrl?.startsWith(approvalBase + "?")) await chrome.windows.remove(ctx.windowId).catch(() => {});
  }
})();
function approvalDigest(payload) {
  return H.ethers.keccak256(H.ethers.toUtf8Bytes(JSON.stringify(payload)));
}
async function requestApproval(origin, kind, summary, action = null) {
  await approvalReady;
  const approvalId = crypto.randomUUID();
  const payload = JSON.parse(JSON.stringify({ approvalId, origin, kind, summary, createdAt: Date.now() }));
  const binding = approvalDigest(payload);
  const url = chrome.runtime.getURL(`approve.html?id=${approvalId}`);
  let resolve, reject;
  const result = new Promise((yes, no) => { resolve = yes; reject = no; });
  const a = { payload, binding, url, action, resolve, reject, windowId: null, documentId: null, displayed: false, busy: false };
  approvals.set(approvalId, a);
  let opened;
  a.ready = new Promise((resolve) => { opened = resolve; });
  a.timer = setTimeout(() => cancelApproval(approvalId, "Approval timed out"), APPROVAL_TIMEOUT_MS);
  // Popup scripts may message before windows.create resolves: wait for its
  // Chrome-assigned id, never treat the caller's claimed id as authority.
  chrome.windows.create({ url, type: "popup", width: 460, height: 680, focused: true }).then(async (win) => {
    a.windowId = win.id;
    if (approvals.get(approvalId) !== a) { await chrome.windows.remove(win.id).catch(() => {}); return; }
    await chrome.windows.get(win.id); // catches a close before onRemoved could bind it
  }).catch(() => cancelApproval(approvalId, "Could not open approval")).finally(opened);
  return result;
}
function cancelApproval(id, message = "User rejected the request") {
  const a = approvals.get(id);
  if (!a) return;
  approvals.delete(id);
  clearTimeout(a.timer);
  a.reject(rpcError(4001, message));
  if (a.windowId !== null) chrome.windows.remove(a.windowId).catch(() => {});
}
chrome.windows.onRemoved.addListener((windowId) => {
  for (const [id, a] of approvals) if (a.windowId === windowId) cancelApproval(id);
});
async function boundApproval(msg, sender) {
  const a = approvals.get(msg.approvalId);
  if (a) await a.ready;
  if (!a || a.windowId === null || sender.id !== chrome.runtime.id || sender.url !== a.url || !sender.documentId) {
    throw rpcError(4001, "Unknown or orphaned approval popup");
  }
  // documentId comes from Chrome, not the popup's claimed windowId.
  const contexts = await chrome.runtime.getContexts({ documentIds: [sender.documentId], contextTypes: ["TAB"] });
  const live = contexts.find((c) => c.windowId === a.windowId && c.documentUrl === a.url && c.documentId === sender.documentId);
  if (!live || msg.windowId !== a.windowId || (a.documentId && a.documentId !== sender.documentId)) throw rpcError(4001, "Approval window does not match");
  const win = await chrome.windows.get(a.windowId, { populate: true });
  if (!win.tabs?.some((t) => t.id === live.tabId)) throw rpcError(4001, "Approval popup is no longer live");
  if (approvals.get(msg.approvalId) !== a || approvalDigest(a.payload) !== a.binding) {
    cancelApproval(msg.approvalId, "Approval changed after display");
    throw rpcError(4001, "Approval changed after display");
  }
  a.documentId = sender.documentId;
  return a;
}
async function approvalMessage(msg, sender) {
  let pin = msg.pin;
  delete msg.pin;
  try {
    const a = await boundApproval(msg, sender);
    if (msg.type === "approval:get") return { request: JSON.parse(JSON.stringify(a.payload)), binding: a.binding };
    if (msg.binding !== a.binding || msg.hash !== (a.payload.summary.hash || null)) throw rpcError(4001, "Displayed request/hash does not match");
    if (msg.type === "approval:displayed") { a.displayed = true; return { ok: true }; }
    if (!a.displayed) throw rpcError(4001, "Approval has not been displayed");
    if (!msg.approved) { cancelApproval(msg.approvalId); return { ok: true }; }
    if (a.busy) throw rpcError(4001, "Approval already used");
    a.busy = true;
    try {
      const pending = a.action ? a.action(pin) : Promise.resolve(true);
      pin = undefined;
      const value = await pending;
      if (approvals.get(msg.approvalId) !== a) throw rpcError(4001, "Approval cancelled while signing");
      approvals.delete(msg.approvalId);
      clearTimeout(a.timer);
      a.resolve(value);
      return { ok: true };
    } catch (e) {
      const code = e?.data?.code;
      if (["PIN_REQUIRED", "PIN_WRONG"].includes(code) && e?.data?.tries_left !== 0 && approvals.get(msg.approvalId) === a) {
        a.busy = false;
        return { error: e }; // same displayed hash; user explicitly retries once per click
      }
      cancelApproval(msg.approvalId, e?.message || "Card signing failed");
      throw e;
    }
  } finally {
    pin = undefined;
  }
}
async function approvedSignature(origin, kind, summary, info) {
  return requestApproval(origin, kind, { ...summary, mode: info.mode, pinRequired: !!info.pin_set, triesLeft: info.pin_tries_left },
    (pin) => signHashOnCard(summary.hash, info.address, pin));
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
  if (!res.ok) throw rpcError(-32603, `RPC HTTP ${res.status}`);
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
  if (req.chainId != null && H.toHexChainId(req.chainId) !== chainId) throw rpcError(-32602, "Transaction chainId does not match selected chain");
  if (req.gasPrice != null || (req.type != null && BigInt(req.type) !== 2n)) throw rpcError(-32602, "Only EIP-1559 (type 2) transactions are supported");
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
    filled.maxFeePerGas = base * 2n + BigInt(req.maxPriorityFeePerGas ?? tip);
  }
  try { return H.buildUnsignedTx(req, H.SUPPORTED_CHAINS[chainId].chainId, filled); }
  catch (e) { throw rpcError(-32602, e.message); }
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
    await ensureConnected(origin, state);
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
    const sig = await approvedSignature(origin, "personal_sign", { address: info.address, message: H.decodePersonalMessage(message), hash }, info);
    return H.compactSignature(sig);
  },

  async eth_signTypedData_v4(params, { origin, state }) {
    await ensureConnected(origin, state);
    const info = await cardInfo();
    const [address, typedData] = params || [];
    assertFromIsCard(address, info.address);
    const parsed = H.parseTypedData(typedData);
    const hash = H.hashTypedDataV4(typedData);
    const sig = await approvedSignature(origin, "eth_signTypedData_v4", {
      address: info.address,
      domain: parsed.domain,
      primaryType: parsed.primaryType,
      types: parsed.types,
      message: parsed.message,
      hash,
    }, info);
    return H.compactSignature(sig);
  },

  async eth_signTransaction(params, { origin, state }) {
    await ensureConnected(origin, state);
    const info = await cardInfo();
    const tx = await prepareTx(JSON.parse(JSON.stringify(params?.[0] || null)), state.chainId, info.address);
    const hash = H.unsignedTxHash(tx);
    const sig = await approvedSignature(origin, "eth_signTransaction", { address: info.address, chain: H.SUPPORTED_CHAINS[state.chainId].name, tx: H.txSummary(tx), hash }, info);
    return H.attachSignature(tx, sig);
  },

  async eth_sendTransaction(params, { origin, state }) {
    await ensureConnected(origin, state);
    const info = await cardInfo();
    const tx = await prepareTx(JSON.parse(JSON.stringify(params?.[0] || null)), state.chainId, info.address);
    const hash = H.unsignedTxHash(tx);
    const sig = await approvedSignature(origin, "eth_sendTransaction", { address: info.address, chain: H.SUPPORTED_CHAINS[state.chainId].name, tx: H.txSummary(tx), hash }, info);
    const raw = H.attachSignature(tx, sig);
    const txHash = await rpc(state.chainId, "eth_sendRawTransaction", [raw]);
    if (txHash !== H.ethers.keccak256(raw)) throw rpcError(-32603, "RPC returned a transaction hash that does not match the signed transaction");
    await setState({ lastTx: { hash: txHash, chainId: state.chainId, url: H.SUPPORTED_CHAINS[state.chainId].explorer + "/tx/" + txHash } });
    return txHash;
  },

  async eth_sign() { throw rpcError(4200, "eth_sign is disabled (unsafe); use personal_sign"); },
  async eth_signTypedData() { throw rpcError(4200, "use eth_signTypedData_v4"); },
  async eth_signTypedData_v3() { throw rpcError(4200, "use eth_signTypedData_v4"); },
  async wallet_addEthereumChain() { throw rpcError(4200, "only Base (0x2105), Ethereum (0x1) and Base Sepolia (0x14a34) are built in"); },
  async wallet_requestPermissions(_p, ctx) { await handlers.eth_requestAccounts(_p, ctx); return [{ parentCapability: "eth_accounts" }]; },
  async wallet_getPermissions(_p, { origin, state }) { return state.connectedOrigins[origin] ? [{ parentCapability: "eth_accounts" }] : []; },
  async wallet_revokePermissions(_p, { origin, state }) {
    delete state.connectedOrigins[origin];
    await setState({ connectedOrigins: state.connectedOrigins });
    return null;
  },

  // Card-backed WebAuthn (FIDO2 + PRF) for Nuri Connect. Origin comes from
  // Chrome's sender URL; the host re-checks origin and rp.id. ETH flows above
  // are untouched and need no ETH applet for these two methods.
  async nuri_webauthnCreate(params, { origin }) { return cardWebAuthn("create", origin, params); },
  async nuri_webauthnGet(params, { origin }) { return cardWebAuthn("get", origin, params); },
};

const WEBAUTHN_ORIGINS = new Set(["https://connect.nuri.com"]);
async function cardWebAuthn(kind, origin, params) {
  if (!WEBAUTHN_ORIGINS.has(origin)) throw rpcError(4100, `Card WebAuthn is not enabled for ${origin}`);
  const publicKey = JSON.parse(JSON.stringify(params?.[0] ?? null));
  if (!publicKey || typeof publicKey !== "object") throw rpcError(-32602, "publicKey options required");
  const summary = kind === "create"
    ? { rpId: publicKey.rp?.id, account: publicKey.user?.name, prf: !!publicKey.extensions?.prf, pinRequired: true }
    : { rpId: publicKey.rpId, credentials: (publicKey.allowCredentials || []).length, prf: !!publicKey.extensions?.prf?.eval, pinRequired: true };
  return requestApproval(origin, `webauthn_${kind}`, summary,
    (pin) => nativeCall(`webauthn_${kind}`, pin === undefined ? { origin, publicKey } : { origin, publicKey, pin }));
}

const PASSTHROUGH = new Set([
  "eth_blockNumber", "eth_call", "eth_estimateGas", "eth_gasPrice", "eth_getBalance", "eth_getBlockByNumber",
  "eth_getBlockByHash", "eth_getCode", "eth_getLogs", "eth_getTransactionByHash", "eth_getTransactionCount",
  "eth_getTransactionReceipt", "eth_maxPriorityFeePerGas", "eth_feeHistory", "eth_sendRawTransaction",
  "eth_getStorageAt", "web3_clientVersion",
]);

async function handleRequest(method, params, origin) {
  if (!/^https?:\/\//.test(origin)) throw rpcError(4100, "Use an HTTP(S) origin (serve test-dapp.html on localhost)");
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
function trustedToolbar(sender) {
  return sender.id === chrome.runtime.id && sender.url === chrome.runtime.getURL("popup.html");
}
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== "object") return false;
  if (msg.type === "rpc") {
    const origin = originOf(sender);
    handleRequest(msg.method, msg.params, origin)
      .then((result) => sendResponse({ result: result === undefined ? null : result }))
      .catch((e) => sendResponse({ error: e && e.code !== undefined ? e : { code: -32603, message: String(e?.message || e) } }));
    return true;
  }
  if (["approval:get", "approval:displayed", "approval"].includes(msg.type)) {
    approvalMessage(msg, sender).then(sendResponse).catch((error) => sendResponse({ error }));
    return true;
  }
  if (!trustedToolbar(sender)) return false;
  if (msg.type === "popup:info") {
    cardInfo(true).then((info) => sendResponse({ info })).catch((e) => sendResponse({ error: e }));
    return true;
  }
  if (msg.type === "popup:state") {
    getState().then(async (state) => {
      const info = await cardInfo(true);
      const { lastTx } = await chrome.storage.local.get("lastTx");
      try {
        const balance = H.formatEther(BigInt(await rpc(state.chainId, "eth_getBalance", [info.address, "latest"])));
        sendResponse({ state, info, balance, lastTx });
      } catch (error) { sendResponse({ state, info, lastTx, error }); }
    }).catch((error) => sendResponse({ error }));
    return true;
  }
  if (msg.type === "popup:disconnectAll") {
    setState({ connectedOrigins: {} }).then(() => { broadcastEvent("accountsChanged", [[]]); sendResponse({ ok: true }); });
    return true;
  }
  return false;
});
