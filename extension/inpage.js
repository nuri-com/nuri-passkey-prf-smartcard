// Runs in the page's MAIN world (manifest content_scripts world: "MAIN").
// Exposes an EIP-1193 provider and announces it via EIP-6963.
// All requests are relayed through content.js (isolated world) -> background.js.
(() => {
  if (globalThis.__nuriCardProviderInstalled) return;
  globalThis.__nuriCardProviderInstalled = true;

  const CHANNEL_TO_CONTENT = "nuri-card:to-content";
  const CHANNEL_TO_PAGE = "nuri-card:to-page";
  const ICON = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAACp0lEQVR4AcXBzWsUZxzA8e/z25md3U0yZjfZxOhGWlLBl8324CsiBQ9FelAo1IOIDaW00Ju3Qj3oRWzRQ9NLoH+AiGfvngQPKr4FxMRqA760Rp3sbnb2bZ6n7GFhWZvZBFbm81H5qYIhQkLEhIgJERMiJkRMCHE0W2Z292sKbpW2QUszu/s1AzFNp8u7/mHMadLpu0mPIyOrhBFCbE002bPJ5+xnyzhiaLGVYd+wjy2GNgUcSldIiaHTzsEauWSTMEIPt7wUBvhx23s+BqGHmlZcWMhyYkuR/FCNfhPW4WHJ4dpLl1+2vyEuhn4S1unPpTQt3096dDNAQysSMU2nRMxQ14owwjrVteLCQpavxsr8n9srCU5uXcFWhpbP3SqFoSp3VhKEsdiA+ZLDlRcup3MrdPvt6SgXd/zL9f1LFJsxMnbAH88yLK7GCaPyUwXDGmwxCFDTijZRkBRNJRAMH9qWbDAQ0zz3bfxA6MUiREMrumkDq4GwliXfZiOEiFmEcC3NoKVp0wbe1C0CwwfSdkAyZui2XI9R14q1WIT4NufxzUSRciC0xJWhYRTnnmS57SXpdObTd3yZLdPthwdbmC85rMWih5vvU5x9PEaLAk7nPH6eWubEnUk6XVwc5dLTEQ5nKvz0yTtO3c3RUtFCGGEDDHCvmGDcCehW1YpyIFS1whhFORDKgaANoSx6mHCaHBsv0eKI4fh4iRtvU/SLRQ9pO+Bg2mfI0uzd5DP3d4arL136xaKH+8UE559kUcDc9CuG7YCGVvSLsE4G+HVxlK83F8kP1ej2RabCTM7jyEiFAUszk/OYyXmMxgPCCCEWVuM8Kjm0Pfdtfv9rhAPDPt0mkw2m3RoDluZ+McG0W2ParZGKacKo/FTBECEhYkLEhIgJERMi9h/NLeDlNbJhXAAAAABJRU5ErkJggg==";

  class ProviderRpcError extends Error {
    constructor(code, message, data) {
      super(message);
      this.code = code;
      if (data !== undefined) this.data = data;
    }
  }

  const pending = new Map();
  let nextId = 1;
  const listeners = new Map();
  let fidoEnabled = false;

  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  function isBinaryBuffer(val) {
    if (!val || typeof val !== "object") return false;
    if (val instanceof ArrayBuffer || ArrayBuffer.isView(val)) return true;
    const tag = Object.prototype.toString.call(val);
    return tag === "[object ArrayBuffer]" || tag === "[object SharedArrayBuffer]";
  }
  function toB64u(buf) {
    const bytes = ArrayBuffer.isView(buf)
      ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
      : new Uint8Array(buf);
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i], b = i + 1 < bytes.length ? bytes[i + 1] : 0, c = i + 2 < bytes.length ? bytes[i + 2] : 0;
      out += B64[a >> 2] + B64[((a & 3) << 4) | (b >> 4)];
      if (i + 1 < bytes.length) out += B64[((b & 15) << 2) | (c >> 6)];
      if (i + 2 < bytes.length) out += B64[c & 63];
    }
    return out;
  }
  function fromB64u(str) {
    const clean = String(str || "").replace(/=+$/, "");
    const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
    let p = 0;
    for (let i = 0; i < clean.length; i += 4) {
      const a = B64.indexOf(clean[i]), b = B64.indexOf(clean[i + 1]);
      const c = i + 2 < clean.length ? B64.indexOf(clean[i + 2]) : -1;
      const d = i + 3 < clean.length ? B64.indexOf(clean[i + 3]) : -1;
      out[p++] = (a << 2) | (b >> 4);
      if (c >= 0) out[p++] = ((b & 15) << 4) | (c >> 2);
      if (d >= 0) out[p++] = ((c & 3) << 6) | d;
    }
    return out.buffer;
  }
  function serializeWebAuthn(val) {
    if (isBinaryBuffer(val)) return toB64u(val);
    if (Array.isArray(val)) return val.map(serializeWebAuthn);
    if (val && typeof val === "object") {
      const out = {};
      for (const k of Object.keys(val)) {
        if (val[k] !== undefined && typeof val[k] !== "function") out[k] = serializeWebAuthn(val[k]);
      }
      return out;
    }
    return val;
  }
  function decodeExtResults(raw) {
    if (!raw || typeof raw !== "object") return {};
    const out = JSON.parse(JSON.stringify(raw));
    if (out.prf?.results) {
      if (out.prf.results.first) out.prf.results.first = fromB64u(out.prf.results.first);
      if (out.prf.results.second) out.prf.results.second = fromB64u(out.prf.results.second);
    }
    return out;
  }
  function asWebAuthnCredential(json, kind) {
    const rawId = fromB64u(json.rawId || json.id);
    const r = json.response || {};
    const ext = decodeExtResults(json.clientExtensionResults);
    const response = kind === "create"
      ? {
          clientDataJSON: fromB64u(r.clientDataJSON),
          attestationObject: fromB64u(r.attestationObject),
          getTransports: () => (Array.isArray(r.transports) ? r.transports : ["usb", "nfc"]),
          getAuthenticatorData: () => (r.authenticatorData ? fromB64u(r.authenticatorData) : new ArrayBuffer(0)),
          getPublicKey: () => (r.publicKey ? fromB64u(r.publicKey) : null),
          getPublicKeyAlgorithm: () => r.publicKeyAlgorithm ?? -7,
        }
      : {
          clientDataJSON: fromB64u(r.clientDataJSON),
          authenticatorData: fromB64u(r.authenticatorData),
          signature: fromB64u(r.signature),
          userHandle: r.userHandle ? fromB64u(r.userHandle) : null,
        };
    return {
      id: json.id,
      rawId,
      type: json.type || "public-key",
      authenticatorAttachment: json.authenticatorAttachment || "cross-platform",
      response,
      getClientExtensionResults: () => ext,
      toJSON: () => json,
    };
  }
  function notAllowed(message) {
    return typeof DOMException === "function"
      ? new DOMException(message, "NotAllowedError")
      : Object.assign(new Error(message), { name: "NotAllowedError" });
  }

  function emit(event, ...args) {
    for (const fn of listeners.get(event) || []) {
      try { fn(...args); } catch (e) { console.error("[Nuri Card] listener error", e); }
    }
  }

  const provider = {
    isNuriCard: true,
    isMetaMask: false,
    chainId: null,
    selectedAddress: null,
    request({ method, params }) {
      if (typeof method !== "string") {
        return Promise.reject(new ProviderRpcError(-32600, "method must be a string"));
      }
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        window.postMessage({ channel: CHANNEL_TO_CONTENT, id, method, params: params ?? [] }, "*");
      });
    },
    on(event, fn) {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event).add(fn);
      return provider;
    },
    removeListener(event, fn) {
      listeners.get(event)?.delete(fn);
      return provider;
    },
    // legacy helpers some dapps still call
    enable() { return provider.request({ method: "eth_requestAccounts" }); },
    isConnected() { return true; },
  };
  provider.addListener = provider.on;
  provider.off = provider.removeListener;

  window.addEventListener("message", (ev) => {
    if (ev.source !== window || !ev.data || ev.data.channel !== CHANNEL_TO_PAGE) return;
    const msg = ev.data;
    if (msg.event) {
      if (msg.event === "nuri:fidoEnabled") { fidoEnabled = Boolean(msg.args?.[0]); return; }
      if (msg.event === "chainChanged") provider.chainId = msg.args[0];
      if (msg.event === "accountsChanged") provider.selectedAddress = msg.args[0]?.[0] ?? null;
      emit(msg.event, ...(msg.args || []));
      return;
    }
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    if (msg.error) {
      p.reject(new ProviderRpcError(msg.error.code ?? -32603, msg.error.message ?? "error", msg.error.data));
    } else {
      if (msg.method === "eth_chainId") provider.chainId = msg.result;
      if (msg.method === "eth_requestAccounts" || msg.method === "eth_accounts") provider.selectedAddress = msg.result[0] ?? null;
      p.resolve(msg.result);
    }
  });

  // EIP-6963 announcement
  const info = Object.freeze({
    uuid: crypto.randomUUID(),
    name: "Nuri Card",
    icon: ICON,
    rdns: "com.nuri.card",
  });
  const detail = Object.freeze({ info, provider });
  const announce = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail }));
  window.addEventListener("eip6963:requestProvider", announce);
  announce();

  // Also expose window.ethereum if nobody else did (non-destructive).
  if (!("ethereum" in window)) {
    try { Object.defineProperty(window, "ethereum", { value: provider, writable: true, configurable: true }); } catch {}
  }
  window.nuriCard = provider;

  if (typeof navigator !== "undefined" && navigator.credentials && typeof navigator.credentials.create === "function" && typeof navigator.credentials.get === "function") {
    const creds = navigator.credentials;
    const origCreate = creds.create.bind(creds);
    const origGet = creds.get.bind(creds);
    const shouldBypass = (options) => (
      !fidoEnabled
      || !options?.publicKey
      || options.mediation === "conditional"
      || options.publicKey?.authenticatorSelection?.authenticatorAttachment === "platform"
    );
    const wrap = (kind, orig) => async (options) => {
      if (shouldBypass(options)) return orig(options);
      const method = kind === "create" ? "nuri_fidoCreate" : "nuri_fidoGet";
      try {
        const json = await provider.request({ method, params: [serializeWebAuthn(options.publicKey)] });
        return asWebAuthnCredential(json, kind);
      } catch (err) {
        const hostCode = err?.data?.code;
        if (hostCode === "NO_CARD" || hostCode === "NO_READER") return orig(options);
        throw notAllowed(err?.message || "Smartcard FIDO2 operation was not allowed.");
      }
    };
    try {
      creds.create = wrap("create", origCreate);
      creds.get = wrap("get", origGet);
    } catch {}
  }
})();
