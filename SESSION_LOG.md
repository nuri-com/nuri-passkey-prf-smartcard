## 2026-07-05 — gp reader bug + ETH applet install

**Goal:** ETH-Signer CAP auf die Karte bringen; gp konnte den "Reader 01" nicht ansprechen.
**Decisions:**
1. Ursache: gp-Build f2af9ef (Snapshot) hat kaputte Reader-/Card-Present-Erkennung (jnasmartcardio); Fix-Commit im Upstream vom 2026-06-21 ist noch unreleased.
2. Offizielles Release v26.06.04 funktioniert out-of-the-box — kein eigener SCP02-Client nötig.
3. ~/bin/gp.jar durch v26.06.04 ersetzt (Backup: gp.jar.f2af9ef.bak).
**State:** Alte ETH-App gelöscht, dist/nuri-eth-signer.cap installiert; gp -l zeigt PKG 4E555249455448 v1.0 LOADED, Applet 4E55524945544801 SELECTABLE. Danach ist der PC/SC-Slot durch abgebrochene Test-Prozesse verklemmt (SCardConnect hängt).
**Next steps:**
1. Reader ab- und wieder anstecken (oder sudo killall usbsmartcardreaderd).
2. python3 scripts/card-eth-test.py als Smoke-Test laufen lassen.
**Open questions:**
1. Keine.

### Addendum (same day, later)
1. Smoke-Test fand den echten Karten-Killer: `INS_SIGN` hing zu 100% — Endlosschleife in `modInverse` des ETH-Applets (dazu: Parität am falschen Buffer-Ende geprüft, Halbierung verlor das `+n`).
2. Fix als v1.1 gebaut (off-card gegen `pow(a,-1,n)` mit 5000+ Fällen verifiziert, CAP-Verifier 0 Fehler). Flash steht aus — braucht ein Karten-Re-Seat (SIGN-Hänger verklemmt macOS-PC/SC systemweit).
3. Alles dokumentiert: `docs/gp-macos-troubleshooting.md` (Post-Mortem), README-Status, CHANGELOG, Logbook.
4. Merksätze: nur gp-Release-Jars; nie SCP02 selbst bauen (ISD-Brick-Gefahr); T=0 am OMNIKEY-Kontaktslot; nie Prozesse mid-APDU killen; Karten-Krypto erst off-card verifizieren, dann flashen.

## 2026-07-07 — checkout real broadcast + cake.cash merchant

**Goal:** real broadcast at end of merchant checkout; clean UX; card-friendly profile.
**Decisions:**
1. Kept the existing `paid_demo` proof (card signs a `paymentPackage` JSON, BIP340 verified) — that part was right. The "broadcast" we needed is the *existing* receive-side `claimVHTLC` flow running after the proof. Same card, same applet, real on-chain broadcast.
2. Honest scope: the merchant invoice is a *new* LNURL-pay from `nuri@cake.cash`; the VHTLC we claim is the card's existing receive. Preimage hashes don't match, so the demo isn't a real merchant payment — it's a real chain broadcast. Documented in code comment; documented as not-the-full-send in `docs/tap-to-pay-concept.md` step 6.
3. Skipped: card-presence endpoint, profile UI polish, PIN gate, full Boltz send path (intent + forfeit + ephemeral session keys + ASP round). All out of scope for "minimal real broadcast". User explicitly OK'd skipping the PIN gate.
4. Skipped: also need to skip the full presence-gating UI; user only wanted the send at the end, not the broader UX rework.
**State:**
- Merchant target: `nuri@cake.cash` (LNURL-pay, min 1 sat, max 40 000 sats — verified).
- `handleCheckoutConfirm` now: signs proof → calls `claimReceiveVHTLCs()` → surfaces `session.broadcast` in the public view.
- Factored per-claim logic into `buildClaimCfg()` + `claimReceiveVHTLCs()` helpers; `handleCardLightningClaim` reuses them.
- Checkout page renders the broadcast state alongside the proof state.
- `FIDO2_BACKUP_PIN` not set on this host yet — server returns `broadcast.skipped='pin-not-set'` cleanly (no crash).
- Simulated backend end-to-end test: BOLT11 from cake.cash, proof signed with BIP340 verify=true, broadcast skipped (no PIN). Shape is correct.
**Next steps:**
1. Run with `FIDO2_BACKUP_PIN=<pin>` and a card in the reader: terminal → forward → tap → confirm → expect `broadcast.claimed_ok: 1`, `ark_address: bc1p…`, settled balance went up by 2330 sats.
2. Decide whether the full Boltz *send* path is on the roadmap (tap-to-pay-concept.md step 6, 3–5 days). That gets the merchant paid; current state just makes the card's existing receive settle on-chain.
3. Decide whether to do the profile/terminal UI rework later (presence pill, button gating, polished empty states).
**Open questions:**
1. None blocking. The send path is the big open question — want it built?

## 2026-07-07 — Bitcoin debit card: real Nuri Lightning send + pure-Arkade wallet + Visa-style terminal

**Goal:** Make the card a working Bitcoin debit card — not just receive/claim, but *send* Lightning from the card's Ark balance, plus a second pure-Arkade wallet, on a real card terminal UX.

**Decisions:**
1. The send never worked because it reused the receive-*claim* endpoint (`receive/claim/approve`). The real path is Nuri's native send: `swap-intent/create → send/prepare → card FIDO2 UV → send/cosign (MuSig2) → send/complete`. No Nuri server change needed — it already existed (`server-arkade-v4/scripts/test-api-send.mjs` is the reference).
2. Checkpoint txs cosign as follow-ups under one `challenge_token` with `route_scope: "direct_send_session"` (funding cosign is strict).
3. Optimistic send (`waitFor: "funded"`) per request — returns on funding, Boltz settles after.
4. Two accounts, same card key: **Nuri** = `musig2(card, Nuri-server)` (recoverable, has `card@nuri.com` LNURL); **Pure Arkade** = `musig2(card, local key we hold)`, zero Nuri.
5. Checkout page restyled to match the light POS terminal, PIN numpad → tap card.

**State:** Proven on mainnet. `card@nuri.com` registered + funded (auto-claimed 4520 sats). Card-signed send to `emin@nuri.com` succeeded 3× incl. through the terminal (`NURI_CARD_ARKADE_SEND_OK`, `ark_txid e6af75b5…`). Balance 2330→5038 over the session. Profile page has an account dropdown; terminal + checkout end-to-end.

**Next steps:**
1. Reconcile the ~997-sat Boltz lockup from the first pre-fix attempt (auto-refunds after timeout, or already paid emin).
2. Fund + demo a real pure-Arkade send (wallet works, currently 0 balance).
3. Optional: PIN/UV-gate the on-card MuSig2 nonce/sign APDUs (roadmap hardening).

**Open questions:**
1. None blocking — the core (card-signed Lightning send) works end-to-end.
