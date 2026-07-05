# Logbook — session notes

Fast catch-up for whoever picks this up next. For deep dives, follow the linked
docs. Newest session at top.

---

## 2026-06-30 — card-as-wallet, FIDO2 user-presence, hardware/platform findings

### Where things stand

Three physical cards in play (all Feitian; `ICFabricator=4090`, `OS ID=86AA`,
`batch=6200` — same chip family):

| Card | Serial | OS date / ATR | FIDO2 | MuSig2 (BTC) | TOTP | Notes |
|---|---|---|---|---|---|---|
| **Funded** | `8606570B` | 2025-05-14 / `3b:81:80:01:80:80` | v1 (`up:false`) | ✅ key `02b9f705…` | — | holds mainnet wallet `bc1pvmpre4…`; **pending** 7831-sat tx `50bbea9e…` |
| **Do-everything** | `87E5470B` | 2025-05-14 / `3b:81:80:01:80:80` | **`up:true`** | ✅ key `02c65f27…` | ✅ | full Nuri install; **PIN `1996`** |
| **Fresh** | `8786470B` | 2023-03-30 / `3b:80:80:01:01` | `up:true` | ❌ `6A81` | ✅ | no secp256k1 (older OS) |

**Wallet model:** `musig2(client, card)` key-path + client `CSV(52500)` recovery
leaf. Client key = card FIDO2 PRF → `HKDF(app:nuri.com|wallet|v1)` → BIP86
`m/86'/0'/0'/0/0` (PWA-identical). Cosigner = card MuSig2 applet.

### Q&A / decisions

**Q: Can one card be the whole wallet — passkey-PRF client key *and* MuSig2 cosigner?**
A: Yes. Built `web/card-wallet.html` + server `/api/wallet/{address,utxos,spend}`.
Proven end-to-end on **mainnet via the reader path** (address `bc1pvmpre4…`).

**Q: Can the browser create the wallet from the card's passkey PRF (like the PWA)?**
A: **Not on macOS desktop.** Two walls, both *outside* the card:
1. The FIDO2 applet originally advertised `up:false` → browsers require user
   presence → WebAuthn hung. Fixed (see below); Safari now creates passkeys on
   the card.
2. Safari then returns **`prf: null`** for an external security key even though the
   card enabled `hmac-secret` (assertion `authenticatorData` ED flag = **true**).
   Chrome would do PRF but **can't see a PC/SC contact reader**. So browser PRF is
   a macOS dead-end. Evidence: `prf-test.html` registration showed
   `extensionDataIncluded:true` + `prf:null`.
   → PRF paths that work: **native-NFC app**, **Windows Chrome/Edge**, or the
   **reader bridge** (what our wallet uses).

**Q: The FIDO2 `up:false` fix?**
A: One byte — `CannedCBOR.AUTH_INFO_SECOND` `up` `0xF4`→`0xF5`. The applet already
set `UP=1` in every assertion, so advertising `up:true` is consistent.
→ `patches/0002-advertise-user-presence.patch` + `dist/FIDO2-up.cap` (built,
verified `up:true` + `REAL_CARD_WEBAUTHN_PRF_OK` on hardware). v1 `dist/FIDO2.cap`
preserved. ⚠️ Reflashing FIDO2 wipes the PRF credential → wallet address changes,
so **sweep a funded card before reflashing it**. Doc: `docs/fido2-user-presence.md`.

**Q: Why does MuSig2 work on one card but `6A81` on an "identical" card?**
A: Same chip family, **different card OS version**. Keygen computes `pubkey = sk×G`
via `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` (raw point). OS **2025-05-14** exposes
it → works. OS **2023-03-30** only has legacy hashed ECDH → the applet can't
recover the point → throws `SW_FUNC_NOT_SUPPORTED (6A81)`. Traced to
`NuriMuSig2v019.java` keygen path. The card OS is mask-ROM — **not user-updatable**
over GlobalPlatform (only applets are).

**Q: Card sourcing rule?**
A: Buy cards reading **OS `2025-05-14` / ATR `3b:81:80:01:80:80`**. Screen
read-only with `gp -i` (OS date); confirm with `npm run cosign:real-card:keygen`
(expect `REAL_CARD_COSIGN_FLOW_OK`, not `6A81`). Same model number is **not** enough.

**Q: Card PIN?**
A: Cards ship PIN-less (`clientPin:false`, 8 retries). Set the do-everything card's
PIN to **`1996`** (only needed for browser passkey sites). Reader-mode wallet uses
UV-discouraged → never asks for it. Lost PIN → only recovery is a FIDO2 reset
(wipes credentials).

**Q: Remote signing (a VPS reaches the local card)?**
A: Works via `scripts/card-mcp-server.mjs` (card as a remote MCP cosigner); tunnel
with ngrok or Cloudflare Tunnel. Deferred this session.

### Open threads / next steps
- **Sweep** the funded wallet once tx `50bbea9e…` confirms (`web/card-wallet.html`
  → Send → broadcast, funded card `8606570B` in the reader).
- Provision a fresh wallet on the **do-everything card** (`87E5470B`) via reader
  mode to get one self-contained card.
- Browser/PWA PRF: pursue **native-NFC app** (works) or **Windows** for web; macOS
  desktop is out.
- Optional: software EC point-multiply in the MuSig2 applet → would support
  older-OS cards.
- Optional: Cloudflare Tunnel for remote card signing.

### Run the wallet (reader mode)
```bash
npm run cosign:web            # serves http://localhost:8787/wallet
# funded card in the reader, network = mainnet
# Get receive address → Refresh balance → Send (tick broadcast)
```
Endpoints: `POST /api/wallet/{address,utxos,spend}` — reader by default; pass
`prfHex` to use a browser-supplied PRF instead.

### Session reference
- Claude Code session id: **`2b1f4b28-6681-46d2-9474-2597d74a5b72`**
- Full transcript (local, auto-saved, ~3.8 MB):
  `~/.claude/projects/-Users-eminmahrt-Developer-nuri-passkey-prf-smartcard/2b1f4b28-6681-46d2-9474-2597d74a5b72.jsonl`
- Resume / read the whole conversation: `claude --resume 2b1f4b28-6681-46d2-9474-2597d74a5b72`

This logbook is the distilled context; the raw transcript is the fallback if you
need the full reasoning behind a decision. The transcript is intentionally **not**
committed (it's already backed up locally, and it's large/noisy for a public repo).
</content>

---

## 2026-07-05 — gp reader "bug", ETH signer install, SIGN infinite loop

**Q: gp can't connect to the OMNIKEY reader that has the card — every `-r`
value fails. Reader bug? macOS bug?**
A: Neither. The gp in use was a **snapshot build (`f2af9ef`)** with broken
card-present detection in its jnasmartcardio layer — it filtered the reader out
*before* name matching, so no `-r` spelling could ever work. The official
**release v26.06.04 worked on the first try with no `-r` at all**. Upstream had
already fixed the snapshot bug on 2026-06-21 (gp `1ae44dc`), unreleased at the
time. A hand-rolled SCP02 client was attempted before this was found — don't do
that: failed EXTERNAL AUTHs (`6982`) count toward the ISD velocity counter and
can brick the Security Domain. Full write-up:
[`gp-macos-troubleshooting.md`](gp-macos-troubleshooting.md).

**Q: Do the new applets/scripts crash the card? It keeps needing re-seats.**
A: The card never crashed — it survived every re-seat with all applets intact.
Two separate host/applet problems stacked:
1. **ETH applet v1.0's `INS_SIGN` had a guaranteed infinite loop** in its
   software `modInverse` (binary xGCD: termination waited for `v==0` which is
   unreachable; `u` hits 0 and `while(isEven(u))` spins on zero forever). Plus
   two more latent bugs: parity checked on the wrong end of the big-endian
   buffers, and odd-value halving lost its `+n` (`addMod(x,n)` is a no-op).
   SELECT/VERSION/KEYGEN/GET_PUBKEY were all fine — only SIGN hung.
2. **macOS PC/SC does not recover from a stalled APDU**: once SIGN went mute,
   every later `SCardConnect` hung system-wide (even `opensc-tool`), which
   *looked like* the card dying. Only re-seating the card clears it.
Fixed in **v1.1** (new xGCD verified off-card against `pow(a,-1,n)`, 5000+
cases, before flashing; iteration cap now throws `6988` instead of hanging).

**Q: Why did the test script fail with `0x80100016` even when the stack was healthy?**
A: The OMNIKEY 5422 contact slot + this card fail **T=1** transmits; force
**T=0** (`conn.connect(CardConnection.T0_protocol)` — now in
`scripts/card-eth-test.py`).

### State
- Card: FIDO2/MuSig2/OATH untouched; ETH applet **v1.0** installed via gp
  v26.06.04 (KEYGEN works, pubkey
  `0266ee75…9a05`); **v1.1 CAP built + verified, flash pending** (needs one
  more card re-seat, then `gp --delete 4E55524945544801 --delete 4E555249455448
  && gp --install dist/nuri-eth-signer.cap`).
- Host: `~/bin/gp.jar` is now release v26.06.04 (snapshot kept as `.bak`).

### Next steps
- Re-seat card → flash v1.1 → run `python3 scripts/card-eth-test.py`
  (expects VERSION `01 01`, then SIGN + ecrecover green).
- Wire the signer into an ethers.js `Signer` (per `docs/eth-signing-spec.md`).
