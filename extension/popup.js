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

function render({ info, state, error, balance, ethBalance, bitcoin, bitcoinError, lastTx }) {
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
    }
    const eth = ethBalance !== undefined ? ethBalance : balance;
    rows.push(`<p><span class="k">Ethereum</span><br>${eth === undefined ? "" : esc(eth) + " ETH"}</p>`);
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
function load() { chrome.runtime.sendMessage({ type: "popup:account" }, (r) => render(r || { error: { message: "Wallet unavailable" } })); }

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

document.getElementById("refresh").onclick = load;
document.getElementById("disconnect").onclick = () => chrome.runtime.sendMessage({ type: "popup:disconnectAll" }, load);
load();
