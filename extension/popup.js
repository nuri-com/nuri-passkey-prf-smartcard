const out = document.getElementById("out");
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function render(info, state, err) {
  const rows = [];
  if (err) rows.push(`<div class="err">${esc(err.message || JSON.stringify(err))}</div>`);
  if (info) {
    rows.push(`<div class="row"><span class="k">Address:</span> <code>${esc(info.address)}</code></div>`);
    rows.push(`<div class="row"><span class="k">Pubkey:</span> <code>${esc(info.pubkey)}</code></div>`);
    rows.push(`<div class="row"><span class="k">Applet:</span> ${esc(info.applet)} v${esc(info.applet_version)} · <span class="k">Reader:</span> ${esc(info.reader)} · <span class="k">Mode:</span> ${esc(info.mode)}</div>`);
  }
  if (state) {
    rows.push(`<div class="row"><span class="k">Chain:</span> ${esc(state.chainId)}</div>`);
    const origins = Object.keys(state.connectedOrigins || {});
    rows.push(`<div class="row"><span class="k">Connected sites:</span> ${origins.length ? origins.map(esc).join(", ") : "none"}</div>`);
  }
  out.innerHTML = rows.join("");
}

function load(force) {
  chrome.runtime.sendMessage({ type: "popup:state" }, (r) => {
    render(r?.info, r?.state);
    if (force || !r?.info) {
      chrome.runtime.sendMessage({ type: "popup:info" }, (ir) => render(ir?.info, r?.state, ir?.error));
    }
  });
}
document.getElementById("refresh").onclick = () => load(true);
document.getElementById("disconnect").onclick = () => chrome.runtime.sendMessage({ type: "popup:disconnectAll" }, () => load(false));
load(false);
