// Public bootstrap UI. The terminal code is entered by the user, never fetched.
// The server keeps the bearer and session id out of JavaScript (HttpOnly cookie).
(() => {
  'use strict';
  const nativeFetch = window.fetch.bind(window);
  let resolveReady;
  const ready = new Promise((resolve) => { resolveReady = resolve; });
  window.fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, location.href);
    if (url.origin === location.origin && url.pathname.startsWith('/api/')) await ready;
    return nativeFetch(input, init);
  };
  async function start() {
    try {
      const response = await nativeFetch('/api/session', { cache: 'no-store', credentials: 'same-origin' });
      if (response.ok) { resolveReady(); return; }
    } catch { /* Show the pairing form, not a credential-bearing fallback. */ }
    const overlay = document.createElement('dialog');
    overlay.setAttribute('aria-label', 'Pair this browser with the card helper');
    overlay.innerHTML = '<form><h2>Pair this browser</h2><p>Enter the one-time pairing code printed in the helper terminal. No card action happens during pairing.</p><label>Pairing code <input name="code" type="password" autocomplete="off" maxlength="64" required></label><p role="status"></p><button type="submit">Pair browser</button></form>';
    document.body.append(overlay);
    overlay.addEventListener('cancel', (event) => event.preventDefault());
    overlay.showModal();
    const form = overlay.querySelector('form');
    const input = form.elements.code;
    const status = overlay.querySelector('[role="status"]');
    const button = overlay.querySelector('button');
    input.focus();
    form.addEventListener('submit', async (event) => {
      event.preventDefault(); button.disabled = true; status.textContent = '';
      try {
        const response = await nativeFetch('/pair', {
          method: 'POST', credentials: 'same-origin', cache: 'no-store',
          headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: input.value.trim() }),
        });
        input.value = '';
        if (!response.ok) { status.textContent = 'Code invalid or already used. Check the helper terminal for its current code.'; return; }
        overlay.close(); overlay.remove(); resolveReady();
      } catch { status.textContent = 'Helper unavailable. Restart it and use its new terminal code.'; }
      finally { button.disabled = false; }
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
