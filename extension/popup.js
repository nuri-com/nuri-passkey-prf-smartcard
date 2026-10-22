const out = document.getElementById("out");
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function render({ info, state, error, balance, lastTx }) {
  const rows = [];
  if (error) rows.push(`<p class="err">${esc(error.message || "Wallet unavailable")}</p>`);
  if (info) {
    if (info.mode === "sim") rows.push('<p class="sim">Software simulator · public test key. Do not deposit money.</p>');
    rows.push(`<p><span class="k">Card address</span><br><code>${esc(info.address)}</code></p>`);
    if (balance !== undefined) rows.push(`<p>${esc(balance)} ETH</p>`);
    if (state) {
      const names = { "0x2105": "Base", "0x1": "Ethereum", "0x14a34": "Base Sepolia" };
      rows.push(`<p>${esc(names[state.chainId] || state.chainId)}</p>`);
    }
    const verified = info.mode === "card" && info.attestation?.verified === true;
    rows.push(`<details><summary>Card details</summary><p>${esc(info.applet)} v${esc(info.applet_version)}</p><p>${esc(info.reader)}</p><p>${info.pin_set ? "PIN protected" : "PIN not enabled"}</p>`);
    rows.push(verified ? '<div class="attestation verified">genuine Nuri card</div>' : '<div class="attestation unverified">Card authenticity unverified</div>');
    rows.push('</details>');
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
function load() { chrome.runtime.sendMessage({ type: "popup:state" }, (r) => render(r || { error: { message: "Wallet unavailable" } })); }
document.getElementById("refresh").onclick = load;
document.getElementById("disconnect").onclick = () => chrome.runtime.sendMessage({ type: "popup:disconnectAll" }, load);
load();
