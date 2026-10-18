(async () => {
  const id = Number(new URLSearchParams(location.search).get("id"));
  const key = "approval:" + id;
  const { [key]: req } = await chrome.storage.session.get(key);
  const $ = (s) => document.querySelector(s);
  if (!req) {
    $("#body").textContent = "Approval request not found (expired).";
    $("#approve").disabled = true;
    return;
  }
  $("#origin").textContent = req.origin;
  const titles = {
    connect: "Connect account",
    personal_sign: "Sign message (personal_sign)",
    eth_signTypedData_v4: "Sign typed data (EIP-712)",
    eth_signTransaction: "Sign transaction (not broadcast)",
    eth_sendTransaction: "SEND transaction",
  };
  $("#kind").textContent = titles[req.kind] || req.kind;
  const s = req.summary || {};
  const rows = [];
  const row = (k, v) => rows.push(`<div class="row"><span class="k">${k}:</span> <code>${escapeHtml(String(v))}</code></div>`);
  if (s.address) row("Card address", s.address);
  if (req.kind === "connect") {
    row("Applet", s.applet);
    row("Reader", s.reader);
    row("Mode", s.mode);
    if (s.mode === "sim") rows.push('<div class="warn">SIMULATOR key, not the card</div>');
  }
  if (req.kind === "personal_sign") {
    rows.push(`<div class="row"><span class="k">Message:</span></div><pre>${escapeHtml(s.message)}</pre>`);
  }
  if (req.kind === "eth_signTypedData_v4") {
    row("Primary type", s.primaryType);
    rows.push(`<div class="row"><span class="k">Domain:</span></div><pre>${escapeHtml(JSON.stringify(s.domain, null, 2))}</pre>`);
    rows.push(`<div class="row"><span class="k">Message:</span></div><pre>${escapeHtml(JSON.stringify(s.message, null, 2))}</pre>`);
  }
  if (req.kind === "eth_signTransaction" || req.kind === "eth_sendTransaction") {
    row("Chain", s.chain);
    if (req.kind === "eth_sendTransaction") rows.push('<div class="warn">This will be broadcast to the network.</div>');
    rows.push(`<pre>${escapeHtml(JSON.stringify(s.tx, null, 2))}</pre>`);
  }
  if (s.hash) row("Hash sent to card", s.hash);
  $("#body").innerHTML = rows.join("");

  const settle = (approved) => {
    chrome.runtime.sendMessage({ type: "approval", approvalId: id, approved }, () => window.close());
  };
  $("#approve").onclick = () => settle(true);
  $("#reject").onclick = () => settle(false);

  function escapeHtml(str) {
    return str.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
})();
