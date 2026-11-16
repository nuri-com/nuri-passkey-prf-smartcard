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
})();
