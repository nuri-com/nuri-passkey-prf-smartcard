(async () => {
  const id = new URLSearchParams(location.search).get("id");
  const $ = (s) => document.querySelector(s);
  const windowId = (await chrome.windows.getCurrent()).id;
  const send = (msg) => chrome.runtime.sendMessage({ approvalId: id, windowId, ...msg });
  const fail = (error) => { $("#error").textContent = error?.message || "Approval expired or unavailable"; $("#approve").disabled = true; $("#pin").value = ""; };
  const response = await send({ type: "approval:get" }).catch(() => null);
  if (!response?.request) { fail(response?.error); return; }
  const req = response.request;
  const s = req.summary;
  const binding = response.binding;
  const hash = s.hash || null;
  $("#origin").textContent = req.origin;
  const titles = { connect: "Connect account", personal_sign: "Sign message", eth_signTypedData_v4: "Sign typed data", eth_signTransaction: "Sign transaction · no broadcast", eth_sendTransaction: "Send transaction", webauthn_create: "Create Nuri wallet key on card", webauthn_get: "Unlock Nuri wallet with card", bitcoin_send: "Send Bitcoin · card cosign" };
  $("#kind").textContent = titles[req.kind] || req.kind;
  $("#sim").hidden = s.mode !== "sim";
  const rows = [];
  const esc = (str) => String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const row = (key, value) => rows.push(`<div class="row"><span class="k">${esc(key)}:</span> <code>${esc(value)}</code></div>`);
  if (s.address) row("Card address", s.address);
  if (req.kind.startsWith("webauthn_")) { row("Wallet site", s.rpId); if (s.account) row("Account", s.account); row("Wallet key (PRF)", s.prf ? "yes" : "no"); }
  if (req.kind === "connect") { row("Applet", s.applet); row("Reader", s.reader); row("Mode", s.mode); }
  if (req.kind === "personal_sign") rows.push(`<pre>${esc(s.message)}</pre>`);
  if (req.kind === "eth_signTypedData_v4") {
    row("Primary type", s.primaryType);
    rows.push(`<pre>${esc(JSON.stringify({ domain: s.domain, types: s.types, message: s.message }, null, 2))}</pre>`);
  }
  if (s.tx) {
    row("Chain", s.chain + " (" + s.tx.chainId + ")");
    row("To", s.tx.to); row("Value", s.tx.value); row("Execution fee cap", s.tx.executionFeeCap);
    if (req.kind === "eth_sendTransaction") rows.push('<div class="warn">This will be broadcast to the network and spends gas.</div>');
    rows.push(`<pre>${esc(JSON.stringify(s.tx, null, 2))}</pre>`);
  }
  if (req.kind === "bitcoin_send") {
    const sat = (n) => Number(n || 0).toLocaleString("en-US");
    row("Rail", s.kind === "lightning" ? "Lightning invoice (via Arkade swap)" : "Arkade address");
    row("To", s.destination);
    if (s.destinationSource) row("Resolved from", s.destinationSource);
    row("Amount", s.amountSats ? `${sat(s.amountSats)} sats (${s.amountBtc} BTC)` : "invoice amount");
    if (s.paymentHash) row("Payment hash", s.paymentHash);
    row("Wallet key", s.aggregate);
    rows.push('<div class="warn">The card co-signs with the Nuri server. This broadcasts an Arkade transaction.</div>');
  }
  if (hash) row(req.kind === "bitcoin_send" ? "Transaction digest" : "Hash sent to card", hash);
  $("#body").innerHTML = rows.join("");
  let needsPin = !!s.pinRequired;
  const pinState = (required, tries) => {
    needsPin = required;
    $("#pinBox").hidden = !required;
    $("#tries").textContent = tries == null ? "" : `${tries} PIN tries remaining`;
    if (tries === 0) fail({ message: "PIN blocked. Use the card recovery procedure." });
  };
  pinState(needsPin, s.triesLeft);
  const shown = await send({ type: "approval:displayed", binding, hash });
  if (!shown?.ok) { fail(shown?.error); return; }
  let busy = false;
  const settle = async (approved) => {
    if (busy && approved) return;
    if (approved && needsPin && (new TextEncoder().encode($("#pin").value).length < 4 || new TextEncoder().encode($("#pin").value).length > 16)) {
      $("#error").textContent = "PIN must be 4–16 bytes."; return;
    }
    busy = true;
    $("#approve").disabled = true;
    let msg = { type: "approval", binding, hash, approved };
    if (approved && needsPin) msg.pin = $("#pin").value;
    $("#pin").value = "";
    let pending;
    try { pending = send(msg); } finally { delete msg.pin; msg = null; }
    const result = await pending.catch(() => null);
    if (result?.ok) { window.close(); return; }
    const error = result?.error;
    const code = error?.data?.code;
    $("#error").textContent = error?.message || "Approval no longer available";
    if (["PIN_REQUIRED", "PIN_WRONG"].includes(code) && error?.data?.tries_left !== 0) {
      pinState(true, error.data.tries_left); busy = false; $("#approve").disabled = false; $("#pin").focus();
    } else fail(error);
  };
  $("#approve").onclick = () => settle(true);
  $("#reject").onclick = () => settle(false);
  window.addEventListener("pagehide", () => { $("#pin").value = ""; });
})().catch(() => { document.querySelector("#pin").value = ""; document.querySelector("#approve").disabled = true; document.querySelector("#error").textContent = "Approval unavailable. Request again from the site."; });
