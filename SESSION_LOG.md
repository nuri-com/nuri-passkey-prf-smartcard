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
