# The Nuri Card Challenge

> **Every phone becomes a card reader. Tap the card, claim funds. Tap the
> card, broadcast a real transaction. One prompt, one build, one score.**

> **Outcome update (2026-07-10):** Android NFC now reads the physical card,
> completes PIN-authorized FIDO assertions, produces valid card+Nuri MuSig2
> signatures, and broadcasts an Ark transaction returned by the live indexer.
> The last post-broadcast ordering change still needs a fresh real payment for
> `send/complete`, funded-status, and merchant-settlement proof. Full incident
> report: [`docs/expo-web-parity-incident-2026-07-10.md`](docs/expo-web-parity-incident-2026-07-10.md).

## The vision

You hold a Bitcoin smartcard. You tap it to any phone (iOS or Android,
running Expo). The phone is a dumb terminal: it provides NFC transport,
internet, and UI. The card holds the keys and signs. The phone holds nothing.

Today this works over a USB PC/SC reader on a laptop. The challenge: make it
work over **NFC on a phone**, so anyone can tap the card and pay. The phone
replaces the reader. Every phone becomes a Nuri terminal.

## What exists already (you build on top of this)

### The card (ready, do not modify)

A Feitian fingerprint Java Card with two applets installed and proven:

| Applet | AID | APDUs | What it does |
|---|---|---|---|
| MuSig2 signer | `4E5552494D554701` | `GET_PUBKEY` (INS `0x03`), `GET_NONCES` (INS `0x40`), `FINALIZE` (INS `0x41`) | On-card secp256k1 key, non-exportable. Returns 33-byte pubkey, 66-byte pub nonce, 32-byte MuSig2 partial. |
| FIDO2 / passkey | `A0000006472F0001` | CTAP2 `authenticatorInfo`, `clientPin` (getPinToken), `getAssertion` with `hmac-secret` | Card-presence + PIN verification (UV assertion). Does **not** export any secret. |

You do **not** modify or reflash the card. The applets are as-is.

### The existing NFC probe (your starting point)

`mobile/expo-nfc-prf-probe/` is a working Expo app that already:
- Speaks **ISO-DEP NFC** to the card via `react-native-nfc-manager`
- Selects the FIDO2 AID, sends CTAP2 commands, does the `clientPin` ECDH
  handshake, derives PRF over NFC
- Runs on Android (APK built and tested) and iOS (builds, needs device test)
- Uses Expo SDK 57, React Native 0.86

The probe now selects both the FIDO2 and **MuSig2 AID**, sends MuSig2 APDUs,
and is wired to the Arkade SDK, Nuri cosigner, and Boltz swap flow.

### The ASP (live, you talk to it)

| Endpoint | Method | Purpose |
|---|---|---|
| `/arkade/info?client_pk33=…` | GET | Server pubkey, recovery config |
| `/arkade/auth` | POST | Card-presence challenge → auth token |
| `/arkade/sign` | POST | ASP MuSig2 partial (needs approval token) |
| `/api/arkade/receive/invoice` | POST | Create a Lightning receive invoice |
| `/api/arkade/receive/sync` | POST | List claimable/pendable receives |
| `/api/arkade/receive/claim/approve` | POST | Approve a claim with card UV assertion |

Base URL: `https://arkade.nuri.com/v4`. Ark node: `https://arkade.computer`.
Boltz (mainnet): `https://api.boltz.exchange`.

### The SDK (you use it, don't reinvent it)

- `@arkade-os/sdk` — `Wallet`, `RestArkProvider`, `RestIndexerProvider`, `InMemoryWalletRepository`, `InMemoryContractRepository`
- `@arkade-os/boltz-swap` — `ArkadeSwaps`, `BoltzSwapProvider`, `InMemorySwapRepository`
- `@scure/btc-signer` — Bitcoin tx + MuSig2 (`/musig2.js`)
- `@noble/curves` — secp256k1, schnorr

### The reference PC/SC implementation (your spec, not your target)

The repo has a complete working implementation over PC/SC (USB reader on a
laptop). Your Expo app must do the same thing the PC/SC code does, but over
NFC on a phone:

- `scripts/card-arkade-claim.mjs` — the full claim + send runner using the SDK
- `scripts/card-arkade-claim-signer.py` — the card MuSig2 round (Python + pyscard)
- `scripts/real-card-arkade-signer-proof.py` — the card APDU proof
- `scripts/local-card-cosign-server.mjs` — the full localhost server (all routes)

Read these. They are the contract. Your code must produce the same APDU
sequence and the same MuSig2 session math, just over NFC instead of PC/SC.

## The MuSig2 signing round (the core of everything)

```
Card (MuSig2 applet)              ASP (arkade.nuri.com)           Phone (Expo)
  client sk (never leaves)          ASP sk (never leaves)           holds nothing
      │                                │                              │
      │  1. NFC: GET_PUBKEY → pk33     │                              │
      │──────────────────────────────────────────────────────────────→│ register with ASP
      │                                │                              │
      │  2. NFC: GET_NONCES → nonce66  │                              │
      │←─────────── aggregate_xonly, msg32 ──────────────────────────│ relay from ASP
      │──→ pub_nonce ───────────────────────────────────────────────→│ relay to ASP
      │                                │                              │
      │  3. NFC: FINALIZE(a_i, b, parity, e) │                        │
      │←────────── ASP nonce + ASP partial ──────────────────────────│ relay from ASP
      │  s = k + e·a·sk                 │                              │
      │──→ card partial ───────────────┐│                              │
      │                                ↓↓                              │
      │                    aggregate → BIP340 sig → verify → submit   │
      │                                │                              │
      │                                │   Boltz swap → Lightning → merchant
```

The APDU sequence is identical over NFC and PC/SC. Only the transport
changes. The existing probe already does ISO-DEP + CTAP2 over NFC. You need
to select the MuSig2 AID (`4E5552494D554701`) and send the MuSig2 APDUs
instead of CTAP2.

## The two tests (the entire goal)

We are test-driven. There are exactly two tests. Both must pass on a real
phone with the real card tapped over NFC.

### Test 1: Tap card and claim funds

```
1. Open the app on a phone (iOS or Android)
2. Tap the card to the phone NFC
3. App reads card MuSig2 pubkey over NFC
4. App registers with the ASP, shows the card's Ark address + balance
5. App creates a Lightning invoice (receive), shows it as a QR
6. Test runner pays the invoice over Lightning
7. App detects the payment (poll or push), claims the VHTLC
   → card MuSig2 signs over NFC, ASP cosigns, SDK submits
8. Card's settled Ark balance goes up
```

**Pass condition**: after tapping the card, the balance increases by the
invoice amount. The card signed over NFC. No PC/SC, no laptop, no USB reader.

### Test 2: Tap card and broadcast a real transaction

```
1. Open the app on a phone
2. Enter a merchant Lightning address or BOLT11 invoice + amount
3. Tap the card to the phone NFC
4. Enter card PIN (terminal-style, on the phone screen)
5. Card MuSig2 signs the VTXO spend over NFC
6. ASP cosigns, SDK builds the offchain tx, Boltz pays the merchant invoice
7. Merchant sees the payment
```

**Current result**: card signing over NFC and Ark broadcast pass. Merchant
Lightning settlement after the final monitor/complete ordering change remains
the outstanding pass condition. No PC/SC or laptop participates in the phone
signing run.

## Constraints

- **Card key never leaves the card.** No PRF-derived spend key in the app.
  The card is the MuSig2 client signer; the ASP is the cosigner.
  (Model A in `docs/signing-architecture.md`.)
- **Phone holds no key material.** It is a relay: NFC to the card, HTTP to
  the ASP, SDK for tx building.
- **Do not modify or reflash the card.** The applets are as-is.
- **Latest Expo.** Use Expo SDK 55+ (the probe already does). The app
  must run on iOS and Android.
- **One prompt, one build.** No iterative "let me try another approach."
  Ask your clarifying questions upfront, then build.
- **The MuSig2 applet has no PIN gate.** `INS_PARTIAL_SIGN` signs whatever
  it is sent. The FIDO2 `clientPin` UV assertion is the card-presence check.
  This is a known limitation. Document it honestly.

## Scoring

| # | Test | Points |
|---|---|---|
| 1 | Tap card → claim funds (NFC, real card, real ASP, balance goes up) | 35 |
| 2 | Tap card → broadcast real tx (NFC, card signs, merchant invoice paid) | 35 |
| 3 | No key export (app source has no card private key, no PRF spend key) | 10 |
| 4 | Cross-platform (works on iOS AND Android, not just one) | 10 |
| 5 | Clean code (readable, matches the reference repo's style) | 5 |
| 6 | Honest about limitations (documents the PIN gate gap, side-channel caveat) | 5 |

**Total: 100.** Bonus (up to 10 extra, capped at 100): the app is a reusable
Expo package that any other app can import as a Nuri card terminal SDK.

## Before you build: the 5-10 questions you must ask

Before writing any code, ask 5-10 clarifying questions. Each must be
multiple-choice with suggested answers. This proves you understand the
problem before you build. Topics you should cover:

1. **Transport**: NFC over `react-native-nfc-manager` (ISO-DEP), or is there
   another NFC library? What about iOS CoreNFC limitations?
2. **APDU framing**: How do you wrap the MuSig2 APDUs (CLA 0x80, AID
   `4E5552494D554701`) in ISO-DEP? How does the existing probe do it for FIDO2?
3. **MuSig2 session math**: The card returns a raw partial. How does the
   host compute `a_i`, `b`, `parity`, `e` from the BIP327 session? Which
   `@scure/btc-signer/musig2.js` functions do you call?
4. **ASP approval flow**: How does the card UV assertion become an approval
   token? (`/arkade/auth` → card signs challenge → `/api/arkade/receive/claim/approve` → token → `/arkade/sign`)
5. **SDK identity**: The `Wallet.create()` needs an `Identity` that
   implements `sign()`, `compressedPublicKey()`, `xOnlyPublicKey()`. How do
   you implement `CardBackedAggregateIdentity` for NFC? (See
   `scripts/card-arkade-claim.mjs` for the PC/SC version.)
6. **`claimVHTLC` vs `sendLightningPayment`**: Both use the same identity.
   What's the difference in the SDK call? Which one is receive, which is send?
7. **Network**: Mainnet or signet? (Answer: mainnet, Boltz mainnet.)
8. **PIN source**: Env variable, user entry on the phone, or both?
9. **What if the card is not present?**: How does the app handle a missing
   card gracefully (no crash, show "tap card")?
10. **Expo compatibility**: Can `@arkade-os/sdk` + `@scure/btc-signer` run
    in React Native? Any polyfills needed (`Buffer`, `EventSource`)?

If you don't ask, you fail the understanding bar and we stop.

## Reference material in this repo

Read these first. They are the spec. The code is the contract.

**Architecture:**
- `docs/signing-architecture.md` — Model A (card = client signer, ASP = cosigner)
- `docs/tap-to-pay-concept.md` — UX flows, PIN security model, hardware limits
- `docs/musig2-card-extension.md` — the MuSig2 APDU spec (INS, AID, state rules)
- `docs/arkade-card-signer-proof.md` — the clean app-facing signer contract
- `docs/arkade-lightning.md` — how Arkade + Boltz fit together

**Working code (PC/SC reference, your spec):**
- `scripts/card-arkade-claim.mjs` — the full claim + send runner using the SDK
- `scripts/card-arkade-claim-signer.py` — the card MuSig2 round (Python + pyscard)
- `scripts/real-card-arkade-signer-proof.py` — the card APDU proof
- `scripts/local-card-cosign-server.mjs` — the full localhost server (all routes)

**Existing NFC probe (your starting point):**
- `mobile/expo-nfc-prf-probe/` — working ISO-DEP NFC + CTAP2 to the card
- `mobile/expo-nfc-prf-probe/src/ctapPrf.ts` — ISO-DEP, AID select, APDU exchange, CTAP2 CBOR
- `mobile/expo-nfc-prf-probe/App.tsx` — the probe UI
- `mobile/expo-nfc-prf-probe/package.json` — Expo SDK 55, react-native-nfc-manager

**Dependencies:**
- `package.json` — exact versions of `@arkade-os/sdk`, `@arkade-os/boltz-swap`, `@scure/btc-signer`, `@noble/curves`

## The environment

```
# The card (already on the reader, or tap to phone NFC)
# MuSig2 AID: 4E5552494D554701
# FIDO2 AID:  A0000006472F0001

# ASP
https://arkade.nuri.com/v4

# Ark node
https://arkade.computer

# Boltz (mainnet)
https://api.boltz.exchange

# Existing NFC probe (run it to verify the phone sees the card)
cd mobile/expo-nfc-prf-probe
npm run android   # or npm run ios -- --device
```

## Honest limits (don't pretend past these)

- The card can't broadcast. The phone is the network endpoint.
- The card can't parse transactions. It signs a 32-byte hash. Amount limits
  are phone-enforced, not card-enforced.
- The MuSig2 applet has no PIN gate. The FIDO2 `clientPin` is the
  card-presence check. A compromised app could ask the card to sign
  malicious hashes until the PIN gate is added on-card.
- The card's scalar arithmetic is Satochip-derived software, not
  hardware-hardened. Don't claim side-channel resistance for real funds.
- iOS CoreNFC has session-time limits (~60 seconds). The MuSig2 round
  (nonce → ASP → finalize) must complete within one NFC session, or the
  app must keep the session alive across the network round-trip.
- `react-native-nfc-manager` on iOS requires a native entitlement. The
  existing probe handles this; your app must too.

If you pretend past these, you lose points. Honesty is scored.

## Good luck.

Build the Expo app. Ask your questions first. Then build it in one shot. We
run the two tests on a real phone with the real card. We score you. The card
is in your hand. Go.
