const out = document.getElementById("out");
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function render({ info, state, error, balance, lastTx }) {
  const rows = [];
  if (error) rows.push(`<div class="err">${esc(error.message || "Wallet unavailable")}</div>`);
  if (info) {
    if (info.mode === "sim") rows.push('<div class="sim">SIM — PUBLIC SOFTWARE KEY. Never fund.</div>');
    rows.push(`<div class="row">Address: <code>${esc(info.address)}</code></div>`);
    rows.push(`<div class="row">${esc(info.applet)} v${esc(info.applet_version)} · ${esc(info.reader)} · ${esc(info.mode)}</div>`);
    rows.push(`<div class="row">${info.pin_set ? "PIN protected" : "No PIN (demo/legacy)"}</div>`);
  }
  if (state) {
    rows.push(`<div class="row">Chain: ${esc(state.chainId)}</div>`);
    rows.push(`<div class="row">Balance: ${balance === undefined ? "unavailable" : esc(balance) + " ETH"}</div>`);
    const origins = Object.keys(state.connectedOrigins || {});
    rows.push(`<div class="row">Connected: ${origins.length ? origins.map(esc).join(", ") : "none"}</div>`);
  }
  if (lastTx && /^0x[0-9a-f]{64}$/.test(lastTx.hash)) {
    const explorers = { "0x2105": "https://basescan.org", "0x1": "https://etherscan.io", "0x14a34": "https://sepolia.basescan.org" };
    if (explorers[lastTx.chainId]) rows.push(`<div class="row">Last broadcast (not confirmation): <a target="_blank" rel="noopener noreferrer" href="${explorers[lastTx.chainId]}/tx/${lastTx.hash}"><code>${lastTx.hash}</code></a></div>`);
  }
  out.innerHTML = rows.join("");
}
function load() { chrome.runtime.sendMessage({ type: "popup:state" }, (r) => render(r || { error: { message: "Wallet unavailable" } })); }
document.getElementById("refresh").onclick = load;
document.getElementById("disconnect").onclick = () => chrome.runtime.sendMessage({ type: "popup:disconnectAll" }, load);
load();
