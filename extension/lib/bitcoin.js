// Bitcoin wallet helpers: units, destination validation, ENS <name>.nuri.eth
// resolution and approval summaries. Pure functions; the card never sees them.
(function (root) {
  const E = root.NuriHashing.ethers;

  const SATS = 100000000n;

  function parseSats(text) {
    const raw = String(text == null ? "" : text).trim().replace(/[\s_]/g, "");
    if (!/^\d{1,11}(\.\d{1,8})?$/.test(raw)) throw new Error("Amount must be a number of BTC with up to 8 decimals");
    const [whole, frac = ""] = raw.split(".");
    const sats = BigInt(whole) * SATS + BigInt((frac + "00000000").slice(0, 8));
    if (sats <= 0n) throw new Error("Amount must be greater than zero");
    return Number(sats);
  }

  function formatBtc(sats) {
    const value = BigInt(Math.max(0, Math.trunc(Number(sats) || 0)));
    const whole = value / SATS;
    const frac = (value % SATS).toString().padStart(8, "0").replace(/0+$/, "");
    return frac ? `${whole}.${frac}` : String(whole);
  }

  function formatSats(sats) {
    return Number(sats || 0).toLocaleString("en-US");
  }

  // --- bech32m (BIP-350) for Arkade addresses -------------------------------
  const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  function polymod(values) {
    let chk = 1;
    for (const value of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ value;
      for (let i = 0; i < 5; i += 1) if ((top >> i) & 1) chk ^= GENERATOR[i];
    }
    return chk;
  }
  function hrpExpand(hrp) {
    const out = [];
    for (const ch of hrp) out.push(ch.charCodeAt(0) >> 5);
    out.push(0);
    for (const ch of hrp) out.push(ch.charCodeAt(0) & 31);
    return out;
  }
  function fromWords(words) {
    const out = [];
    let acc = 0, bits = 0;
    for (const word of words) {
      if (word < 0 || word > 31) throw new Error("bad bech32 word");
      acc = (acc << 5) | word;
      bits += 5;
      while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
    }
    if (bits >= 5 || ((acc << (8 - bits)) & 0xff)) throw new Error("bad bech32 padding");
    return out;
  }

  // Mainnet Arkade address = bech32m("ark", version 0 || server pk || output key).
  // The checksum is verified here so a typo is caught before the card signs.
  function isArkAddress(value) {
    const address = String(value || "").trim().toLowerCase();
    if (!address.startsWith("ark1") || address.length < 60 || address.length > 200) return false;
    const hrp = "ark";
    const words = [];
    for (const ch of address.slice(hrp.length + 1)) {
      const index = CHARSET.indexOf(ch);
      if (index === -1) return false;
      words.push(index);
    }
    if (words.length < 7) return false;
    if (polymod([...hrpExpand(hrp), ...words]) !== 0x2bc830a3) return false;
    try {
      const data = fromWords(words.slice(0, -6));
      return data.length === 65 && data[0] === 0;
    } catch { return false; }
  }

  function isLightningInvoice(value) {
    const text = String(value || "").trim().toLowerCase();
    if (!/^lnbc(\d+)?[0-9a-z]*1[0-9a-z]+$/.test(text)) return false;
    // Mainnet only, amount present or amountless, bech32 charset after the split.
    return /^lnbc[0-9]+[munp]?1[02-9ac-hj-np-z]{20,}$/.test(text) || /^lnbc1[02-9ac-hj-np-z]{20,}$/.test(text);
  }

  function isNuriName(value) {
    return /^[a-z0-9][a-z0-9-]{0,62}$/.test(String(value || "").trim().toLowerCase());
  }

  // Text-record keys checked in order. Which key a Nuri registrant writes is not
  // documented in this repository (UNVERIFIED); the addr record is the last
  // resort and we always report which one matched.
  const ENS_TEXT_KEYS = ["ark", "arkade", "btc", "bitcoin", "address"];

  function ensProvider(rpcUrl) {
    return new E.JsonRpcProvider(rpcUrl, 1, { staticNetwork: true });
  }

  async function resolveNuriName(name, rpcUrl) {
    const label = String(name || "").trim().toLowerCase().replace(/\.nuri\.eth$/, "");
    if (!isNuriName(label)) throw new Error("Username must be a single label (a-z, 0-9, -)");
    const full = `${label}.nuri.eth`;
    let resolver;
    try { resolver = await E.EnsResolver.fromName(ensProvider(rpcUrl), full); } catch { resolver = null; }
    if (!resolver?.address) throw new Error(`${full} is not registered`);
    for (const key of ENS_TEXT_KEYS) {
      let text = "";
      try { text = String((await resolver.getText(key)) || "").trim(); } catch { continue; }
      if (isArkAddress(text)) return { address: text.toLowerCase(), source: `text:${key}`, label, kind: "ark" };
      if (isLightningInvoice(text)) return { address: text.toLowerCase(), source: `text:${key}`, label, kind: "lightning" };
    }
    let address = null;
    try { address = await resolver.getAddress(); } catch { address = null; }
    if (address && address !== E.ZeroAddress) return { address, source: "address", label, kind: "evm" };
    throw new Error(`${full} has no Arkade, Lightning or EVM address record`);
  }

  // Onchain rail of the card wallet (mempool.space). A failure is 0, never a guess:
  // the caller shows the rail as unread instead of a wrong total.
  async function onchainSats(address, apiBase) {
    const res = await fetch(`${apiBase}/address/${address}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`mempool HTTP ${res.status}`);
    const body = await res.json();
    const chain = body?.chain_stats || {};
    const mempool = body?.mempool_stats || {};
    return Number(chain.funded_txo_sum || 0) - Number(chain.spent_txo_sum || 0)
      + Number(mempool.funded_txo_sum || 0) - Number(mempool.spent_txo_sum || 0);
  }

  root.NuriBitcoin = { parseSats, formatBtc, formatSats, isArkAddress, isLightningInvoice, isNuriName, resolveNuriName, onchainSats, ENS_TEXT_KEYS };
})(self);
