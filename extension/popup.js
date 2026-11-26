const out = document.getElementById("out");
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const B = self.NuriBitcoin;

// The total leads; every rail is then shown with its own full address. A rail
// that could not be read says so instead of silently shrinking the total.
function railRows(bitcoin) {
  const rows = [];
  for (const rail of bitcoin.rails || []) {
    const sats = rail.sats === null || rail.sats === undefined ? "unread" : `${B.formatSats(rail.sats)} sats`;
    rows.push(`<div class="rail"><span class="k">${esc(rail.rail)}</span> <strong>${esc(sats)}</strong><br><code>${esc(rail.address || "")}</code></div>`);
  }
  if (bitcoin.onchainError) rows.push(`<p class="err">Onchain rail unread: ${esc(bitcoin.onchainError)}</p>`);
  return rows;
}

function render({ info, state, error, balance, ethBalance, ethError, bitcoin, bitcoinError, lastTx, loadingBalances }) {
  const rows = [];
  if (error) rows.push(`<p class="err">${esc(error.message || "Wallet unavailable")}</p>`);
  if (info) {
    if (info.mode === "sim") rows.push('<p class="sim">Software simulator · public test key. Do not deposit money.</p>');
    if (bitcoin) {
      rows.push(`<p class="total"><span class="k">Bitcoin</span><br><strong>${esc(B.formatBtc(bitcoin.total))} BTC</strong><br><span class="k">${esc(B.formatSats(bitcoin.total))} sats · all rails</span></p>`);
      rows.push(...railRows(bitcoin));
      document.getElementById("receivePanel").hidden = false;
      document.getElementById("sendPanel").hidden = false;
      document.getElementById("receive").innerHTML = [bitcoin.wallet?.ark_address, bitcoin.wallet?.boarding_address]
        .filter(Boolean)
        .map((address, index) => `<p><span class="k">${index ? "Boarding" : "Arkade"}</span><br><code>${esc(address)}</code></p>`)
        .join("");
    } else if (bitcoinError) {
      rows.push(`<p class="k">Bitcoin</p><p class="err">${esc(bitcoinError)}</p>`);
    } else if (loadingBalances) {
      rows.push('<p><span class="k">Bitcoin</span><br>Loading…</p>');
    }
    const eth = ethBalance ?? balance;
    rows.push(`<p><span class="k">Ethereum</span><br>${eth == null ? (loadingBalances ? "Loading…" : "Balance unavailable") : esc(eth) + " ETH"}</p>`);
    if (ethError) rows.push(`<p class="err">${esc(ethError)}</p>`);
    rows.push(`<p><span class="k">Card address</span><br><code>${esc(info.address)}</code></p>`);
    if (state) {
      const names = { "0x2105": "Base", "0x1": "Ethereum", "0x14a34": "Base Sepolia" };
      rows.push(`<p>${esc(names[state.chainId] || state.chainId)}</p>`);
    }
    const verified = info.mode === "card" && info.attestation?.verified === true;
    rows.push(`<details><summary>Card details</summary><p>${esc(info.applet)} v${esc(info.applet_version)}</p><p>${esc(info.reader)}</p><p>${info.pin_set ? "PIN protected" : "PIN not enabled"}</p>`);
    rows.push(verified ? '<div class="attestation verified">genuine Nuri card</div>' : '<div class="attestation unverified">Card authenticity unverified</div>');
    rows.push("</details>");
  }
  if (state) {
    const origins = Object.keys(state.connectedOrigins || {});
    rows.push(`<details><summary>Connected sites (${origins.length})</summary><p>${origins.length ? origins.map(esc).join("<br>") : "No connected sites"}</p></details>`);
  }
  if (lastTx && /^0x[0-9a-f]{64}$/.test(lastTx.hash)) {
    const explorers = { "0x2105": "https://basescan.org", "0x1": "https://etherscan.io", "0x14a34": "https://sepolia.basescan.org" };
    if (explorers[lastTx.chainId]) rows.push(`<p>Last broadcast (not confirmation)<br><a target="_blank" rel="noopener noreferrer" href="${explorers[lastTx.chainId]}/tx/${lastTx.hash}"><code>${lastTx.hash}</code></a></p>`);
  }
  out.innerHTML = rows.join("");
}
function load() {
  let answered = false;
  let latestInfo = null;
  let timeout = setTimeout(() => {
    if (!answered) render({ info: latestInfo, error: { message: "Wallet balances did not respond. Check the card, then click Refresh." } });
  }, 20000);
  chrome.runtime.sendMessage({ type: "popup:info" }, (first) => {
    const firstError = chrome.runtime.lastError;
    if (firstError || first?.error) {
      answered = true;
      clearTimeout(timeout);
      render({ error: firstError || first.error });
      return;
    }
    if (first?.info) {
      latestInfo = first.info;
      render({ ...first, loadingBalances: true, error: null }); // Show the card before network balances.
    }
    clearTimeout(timeout);
    timeout = setTimeout(() => {
      if (!answered) render({ info: latestInfo, error: { message: "Wallet balances did not respond. Check the card, then click Refresh." } });
    }, 35000);
    chrome.runtime.sendMessage({ type: "popup:account" }, (r) => {
      answered = true;
      clearTimeout(timeout);
      const error = chrome.runtime.lastError;
      render(error ? { info: latestInfo, error: { message: error.message } } : r || { info: latestInfo, error: { message: "Wallet unavailable" } });
    });
  });
}

// --- send form ---------------------------------------------------------------
const kind = document.getElementById("sendKind");
const target = document.getElementById("sendTarget");
const amountBox = document.getElementById("sendAmountBox");
const amount = document.getElementById("sendAmount");
const sendOut = document.getElementById("sendOut");
function syncKind() {
  const value = kind.value;
  document.getElementById("sendTargetLabel").textContent = value === "lightning"
    ? "Invoice (lnbc…)" : value === "ark" ? "Arkade address (ark1…)" : "Username · pays <name>.nuri.eth";
  amountBox.hidden = value !== "ark" && value !== "nuri";
  sendOut.textContent = "";
}
kind.onchange = syncKind;
syncKind();

document.getElementById("sendGo").onclick = () => {
  sendOut.textContent = "";
  const request = { kind: kind.value, target: target.value.trim(), amountSats: Number(amount.value) };
  if (kind.value === "nuri") request.name = target.value.trim();
  chrome.runtime.sendMessage({ type: "popup:bitcoinSend", request }, (r) => {
    if (r?.error) { sendOut.textContent = r.error.message || "Send failed"; return; }
    const result = r?.result || {};
    sendOut.innerHTML = `<p>Broadcast (not settlement)<br><a target="_blank" rel="noopener noreferrer" href="https://arkade.space/tx/${esc(result.ark_txid)}"><code>${esc(result.ark_txid)}</code></a><br><span class="k">Approved digest ${esc(result.approved_digest || "")}</span></p>`;
    load();
  });
};

// --- receive invoice ---------------------------------------------------------
document.getElementById("invoiceMake").onclick = () => {
  const box = document.getElementById("invoiceOut");
  box.textContent = "Creating…";
  const amountSats = Number(document.getElementById("invoiceSats").value);
  const memo = document.getElementById("invoiceMemo").value.trim();
  chrome.runtime.sendMessage({ type: "popup:invoice", amountSats, memo }, (r) => {
    if (r?.error) { box.textContent = r.error.message || "Invoice failed"; return; }
    box.innerHTML = `<code>${esc(r.result.invoice)}</code><br><span class="k">${esc(String(r.result.amount_sats))} sats</span>`;
  });
};

// --- on-card 2FA (TOTP) -----------------------------------------------------
const totpCodeEl = document.getElementById("totpCode");
const totpMetaEl = document.getElementById("totpMeta");
const totpMsgEl = document.getElementById("totpMsg");
const totpPinRow = document.getElementById("totpPinRow");
const totpSecretEl = document.getElementById("totpSecret");
const totpPinEl = document.getElementById("totpPin");
let totpState = { code: "", expiresAt: 0, step: 30, pinRequired: false, provisioned: false };

function fmtTotp(code) {
  return /^\d{6}$/.test(code) ? `${code.slice(0, 3)} ${code.slice(3)}` : (code || "------");
}

function copyText(text) {
  if (!text) return Promise.resolve(false);
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text).then(() => true, () => false);
  }
  return Promise.resolve(false);
}

function renderTotpCountdown() {
  if (!totpMetaEl || !totpState.provisioned || !totpState.expiresAt) return;
  const left = Math.max(0, Math.ceil((totpState.expiresAt - Date.now()) / 1000));
  totpMetaEl.textContent = `${left}s left`;
  if (left === 0) fetchTotpCode();
}

function fetchTotpCode(onDone) {
  chrome.runtime.sendMessage({ type: "popup:totpCode" }, (r) => {
    const err = chrome.runtime.lastError || r?.error;
    if (err || !r?.totp) {
      totpState.code = "";
      totpState.expiresAt = 0;
      totpState.provisioned = false;
      if (totpCodeEl) totpCodeEl.textContent = "------";
      if (totpMetaEl) {
        const msg = err?.code === "NOT_PROVISIONED" || /NOT_PROVISIONED|6985/i.test(err?.message || "")
          ? "No secret stored yet"
          : (err?.message || "Unavailable");
        totpMetaEl.textContent = msg;
      }
      if (onDone) onDone(null, err);
      return;
    }
    const { code, remaining, step } = r.totp;
    totpState.code = code;
    totpState.step = step || 30;
    totpState.expiresAt = Date.now() + Number(remaining || 30) * 1000;
    totpState.provisioned = true;
    if (totpCodeEl) totpCodeEl.textContent = fmtTotp(code);
    renderTotpCountdown();
    if (onDone) onDone(r.totp, null);
  });
}

function loadTotp() {
  chrome.runtime.sendMessage({ type: "popup:totpStatus" }, (r) => {
    const err = chrome.runtime.lastError || r?.error;
    if (err || !r?.status) {
      if (r?.info) return; // Ignore synthetic mock responses in unrelated unit tests.
      if (totpMetaEl) totpMetaEl.textContent = err?.message || "Card TOTP unavailable";
      return;
    }
    totpState.pinRequired = Boolean(r.status.pin_required);
    if (totpPinRow) totpPinRow.hidden = !totpState.pinRequired;
    if (r.status.provisioned === false) {
      totpState.code = "";
      totpState.expiresAt = 0;
      totpState.provisioned = false;
      if (totpCodeEl) totpCodeEl.textContent = "------";
      if (totpMetaEl) totpMetaEl.textContent = "No secret stored yet";
      return;
    }
    fetchTotpCode();
  });
}

const totpRefreshBtn = document.getElementById("totpRefresh");
if (totpRefreshBtn) totpRefreshBtn.onclick = () => { if (totpMsgEl) totpMsgEl.textContent = ""; loadTotp(); };

const totpCopyBtn = document.getElementById("totpCopy");
if (totpCopyBtn) totpCopyBtn.onclick = () => {
  fetchTotpCode(async (totp, err) => {
    if (!totp) { if (totpMsgEl) totpMsgEl.textContent = err?.message || "No code available"; return; }
    const ok = await copyText(totp.code);
    if (totpMsgEl) totpMsgEl.textContent = ok ? `Copied ${totp.code}` : `Code: ${totp.code}`;
  });
};

const totpFillBtn = document.getElementById("totpFill");
if (totpFillBtn) totpFillBtn.onclick = () => {
  if (totpMsgEl) totpMsgEl.textContent = "Reading card…";
  chrome.runtime.sendMessage({ type: "popup:totpFill" }, async (r) => {
    const err = chrome.runtime.lastError || r?.error;
    if (err || !r?.totp) {
      if (totpMsgEl) totpMsgEl.textContent = err?.message || "Could not read TOTP code";
      return;
    }
    totpState.code = r.totp.code;
    totpState.expiresAt = Date.now() + Number(r.totp.remaining || 30) * 1000;
    totpState.provisioned = true;
    if (totpCodeEl) totpCodeEl.textContent = fmtTotp(r.totp.code);
    renderTotpCountdown();
    await copyText(r.totp.code);
    if (totpMsgEl) totpMsgEl.textContent = r.filled ? `Filled ${r.totp.code} in tab` : (r.reason || `Copied ${r.totp.code}`);
  });
};

const totpSaveBtn = document.getElementById("totpSave");
if (totpSaveBtn) totpSaveBtn.onclick = () => {
  const secret = totpSecretEl?.value.trim() || "";
  const pin = totpPinEl?.value || "";
  if (totpSecretEl) totpSecretEl.value = "";
  if (totpPinEl) totpPinEl.value = "";
  if (!secret) { if (totpMsgEl) totpMsgEl.textContent = "Paste Base32 secret or otpauth:// URI first"; return; }
  if (totpMsgEl) totpMsgEl.textContent = "Saving to card…";
  chrome.runtime.sendMessage({ type: "popup:totpPut", secret, pin }, (r) => {
    const err = chrome.runtime.lastError || r?.error;
    if (err || !r?.result) {
      if (totpMsgEl) totpMsgEl.textContent = err?.message || "Save failed";
      return;
    }
    if (totpMsgEl) totpMsgEl.textContent = "Saved on card (secret never stored on host)";
    const details = document.getElementById("totpSetupDetails");
    if (details) details.open = false;
    loadTotp();
  });
};

if (typeof setInterval === "function") setInterval(renderTotpCountdown, 1000);

document.getElementById("refresh").onclick = () => { load(); loadTotp(); };
document.getElementById("disconnect").onclick = () => chrome.runtime.sendMessage({ type: "popup:disconnectAll" }, load);
load();
loadTotp();
