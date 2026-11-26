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

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg && msg.type === "event") {
      window.postMessage({ channel: CHANNEL_TO_PAGE, event: msg.event, args: msg.args }, "*");
      return false;
    }
    if (msg && msg.type === "nuri:fillTotp") {
      const code = String(msg.code || "").trim();
      if (!/^\d{6,8}$/.test(code)) {
        sendResponse({ filled: false, reason: "Invalid TOTP code." });
        return false;
      }
      const isVisible = (el) => {
        if (!el || el.tagName !== "INPUT" || el.disabled || el.readOnly) return false;
        const t = (el.type || "text").toLowerCase();
        if (!["", "text", "tel", "number", "password", "search"].includes(t)) return false;
        const style = typeof getComputedStyle === "function" ? getComputedStyle(el) : null;
        if (style && (style.display === "none" || style.visibility === "hidden")) return false;
        return el.offsetParent !== null || (typeof el.getClientRects === "function" && el.getClientRects().length > 0);
      };
      const inputs = [...document.querySelectorAll("input")].filter(isVisible);
      const hintOf = (el) => {
        const lbl = el.id ? document.querySelector(`label[for="${CSS.escape ? CSS.escape(el.id) : el.id}"]`)?.textContent || "" : "";
        const parentLbl = el.closest("label")?.textContent || "";
        return [el.name, el.id, el.placeholder, el.getAttribute("aria-label"), el.autocomplete, lbl, parentLbl].filter(Boolean).join(" ");
      };
      const otpRx = /\b(otp|totp|2fa|mfa|passcode)\b|two[-_ ]?factor|one[-_ ]?time|auth[-_ ]?code|verification[-_ ]?code/i;
      let target = isVisible(document.activeElement) ? document.activeElement : null;
      if (!target) target = inputs.find((el) => (el.autocomplete || "").toLowerCase() === "one-time-code") || null;
      if (!target) target = inputs.find((el) => otpRx.test(hintOf(el))) || null;
      if (!target && inputs.length === 1) target = inputs[0];
      if (!target) {
        sendResponse({ filled: false, reason: "No OTP input field found on this page — code copied instead." });
        return false;
      }
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
      if (setter) setter.call(target, code);
      else target.value = code;
      if (typeof target.focus === "function") target.focus();
      target.dispatchEvent(new Event("input", { bubbles: true }));
      target.dispatchEvent(new Event("change", { bubbles: true }));
      sendResponse({ filled: true });
      return false;
    }
    return false;
  });
})();
