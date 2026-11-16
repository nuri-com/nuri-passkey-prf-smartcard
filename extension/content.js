// Isolated-world bridge: page (inpage.js) <-> background service worker.
(() => {
  const CHANNEL_TO_CONTENT = "nuri-card:to-content";
  const CHANNEL_TO_PAGE = "nuri-card:to-page";

  window.addEventListener("message", (ev) => {
    if (ev.source !== window || !ev.data || ev.data.channel !== CHANNEL_TO_CONTENT) return;
    const { id, method, params } = ev.data;
    chrome.runtime.sendMessage({ type: "rpc", method, params }, (resp) => {
      if (chrome.runtime.lastError || !resp) {
        window.postMessage({
          channel: CHANNEL_TO_PAGE, id, method,
          error: { code: -32603, message: chrome.runtime.lastError?.message || "Nuri Card: no response from extension" },
        }, "*");
        return;
      }
      window.postMessage({ channel: CHANNEL_TO_PAGE, id, method, ...resp }, "*");
    });
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "event") {
      window.postMessage({ channel: CHANNEL_TO_PAGE, event: msg.event, args: msg.args }, "*");
    }
  });
})();
