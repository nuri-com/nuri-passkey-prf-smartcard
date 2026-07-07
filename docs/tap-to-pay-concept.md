# Tap-to-pay: concept & implementation plan

> **⚡ Status update (2026-07-07): the core is now BUILT and PROVEN ON MAINNET.**
> The tap-to-pay Lightning **send** path, the Visa-style `/checkout` terminal, the
> `card@nuri.com` receive/auto-claim, and the two wallets on one card key all work
> — a card-signed payment settled real Lightning value (`NURI_CARD_ARKADE_SEND_OK`).
> For the plain-English end-to-end walkthrough see
> [`how-it-works.md`](how-it-works.md) and the main README's
> [Bitcoin debit card](../README.md#bitcoin-debit-card-tap-to-pay-lightning-arkade--nuri)
> section. This document is kept as the deeper design/APDU reference and the
> record of the hardware boundary; treat its "buildable today / not built"
> framing below as the historical planning view. The genuinely remaining open
> items are the *phone-optional standalone* POS terminal (Scenario B) and
> PIN-gating the MuSig2 sign APDU on the applet itself.

> The vision: hold a Bitcoin debit card up to a phone or a Bitcoin POS terminal
> and pay — backed by your own keys, self-custody, no seed phrase, no custodian.
> This document is honest about which parts of that vision are buildable today,
> which are a research direction, and which are impossible on this hardware.

## Table of contents

- [The hardware boundary — read first](#the-hardware-boundary--read-first)
- [Two real scenarios](#two-real-scenarios)
- [Scenario C — phone as a dumb terminal (buildable today)](#scenario-c--phone-as-a-dumb-terminal-buildable-today)
- [Scenario B — custom Bitcoin POS terminal (the vision)](#scenario-b--custom-bitcoin-pos-terminal-the-vision)
- [Security model — card-side PIN](#security-model--card-side-pin)
- [What is built vs what is missing](#what-is-built-vs-what-is-missing)
- [Implementation order](#implementation-order)
- [What we cannot do — honest limits](#what-we-cannot-do--honest-limits)

---

## The hardware boundary — read first

The Feitian BioCARD is a JavaCard secure element with a contactless
ISO-14443 interface. It can hold keys, sign, and run small applets. It
**cannot**:

- connect to the internet (no WiFi, no cellular, no Bluetooth),
- display anything (no screen, no LEDs the host can drive),
- accept user input directly (no keypad),
- broadcast a transaction,
- read the Bitcoin mempool,
- open a Lightning channel,
- talk to an Arkade ASP.

That is not a software bug we can fix; it is the hardware. Every hardware
wallet has the same shape — a Ledger signs but your computer broadcasts;
a Trezor signs but your phone broadcasts. The card is the signer, never
the network endpoint.

**Implication for "card alone at a terminal":** the card alone is enough
to *sign*, but it is never enough to *pay*. Paying needs an internet-connected
device that can fetch an invoice, build a transaction, get a signature from
the card, and broadcast. The only question is *whose* device that is:

- **yours** (your phone in your pocket) — Scenario C below, or
- **the merchant's** (a Bitcoin POS terminal at the counter) — Scenario B.

There is no Scenario "card and nothing else." That is physics, not software.

A Boltcard avoids this by being custodial: the card holds no keys, only a
static URL. The terminal reads the URL and the custodian pays. Self-custody
+ card-only + no-internet-device is structurally impossible on every
hardware class that exists today.

---

## Two real scenarios

| | Scenario C (today) | Scenario B (the vision) |
|---|---|---|
| Whose device is involved | your phone (or anyone's phone running our app) | the merchant's POS terminal (running our firmware) |
| Card alone? | no — needs a phone | yes — the terminal is the merchant's, not yours |
| Internet | the phone has it | the terminal has it |
| Buildable today | yes — every primitive proven | no — needs a reference terminal implementation |
| "At any POS" | everywhere a phone is | only at merchants running our terminal software |
| Self-custody | yes (card holds the key, phone holds nothing) | yes |

Both scenarios use the **same card** and the **same on-card applets**. The
difference is purely what the other end of the NFC link is.

---

## Scenario C — phone as a dumb terminal (buildable today)

You tap your card to a phone running the Nuri app. The phone is a dumb
terminal: it provides NFC transport, internet, UI, and Lightning plumbing.
It holds **no keys**. The card is the client signer; the Arkade ASP is the
cosigner. No PRF, no derived key in phone RAM. (See
[`docs/signing-architecture.md`](signing-architecture.md) Model A for why
this is simpler and stronger than the PRF path.)

### UX flow

```
┌─────────────┐   NFC (ISO-DEP)    ┌──────────────┐    internet    ┌────────────┐
│   your card │ ←────────────────→ │  phone (app) │ ←────────────→ │  Arkade ASP│
│  (client sk)│                    │  (no keys)   │                │  (ASP sk)  │
└─────────────┘                    └──────────────┘                └────────────┘

1. Tap card → phone reads card MuSig2 pubkey over NFC (no PIN) →
   registers with the ASP → shows your BTC address + balance.
   Read-only, harmless.

2. You (or the merchant) enter a Lightning invoice / amount on the phone.

3. Tap 2 → phone sends CTAP2 clientPin APDU → you type the card PIN on
   the phone → card verifies PIN (card-enforced) → card is now authorized
   to sign for this session.

4. Phone relays the MuSig2 exchange: card INS_NONCE_GEN → pub nonce →
   ASP; ASP returns (a, b, e); card INS_PARTIAL_SIGN → partial; ASP
   partial → aggregate → BIP340 sig. Card's sk never leaves the card;
   phone holds no key material at any point.

5. Phone drives the Boltz submarine swap (on-chain → Lightning) with the
   signed transaction → pays the invoice.

6. Card forgets the session. Done.
```

### Who does what

| Step | Card (client signer) | Phone (dumb terminal) | Arkade ASP / Boltz |
|---|---|---|---|
| NFC transport | responds to APDUs | opens ISO-DEP session | — |
| Key material | client sk, never leaves | **holds none** | ASP sk, never leaves |
| Pubkey / balance | `INS_GET_INDIVIDUAL_PUBKEY` | displays address, fetches VTXO state | ASP serves VTXO state |
| Amount policy | none (blind signing) | enforces "above X → require PIN" | — |
| PIN gate | CTAP2 `clientPin` — card-enforced | sends `pinAuth`, cannot bypass | — |
| Signing | MuSig2 partial `s = k + e·a·sk` (sk never leaves) | relays partials both ways, aggregates + BIP340 verify | ASP partial |
| Lightning | nothing | builds Boltz swap tx, pays invoice | ASP round + Boltz swap |

The card holds the client signing key. The phone holds nothing. The ASP
holds the cosigner key. To sign a transaction you need both the card's
partial AND the ASP's partial — 2-of-2, real self-custody. A compromised
phone cannot steal funds (it has no key and cannot forge the card's
partial). A stolen card cannot steal funds (it has no ASP partial).

### Why this is the realistic path today

Every primitive in the table above is already proven on a real card in this
repo:

- ISO-DEP NFC + CTAP2 transport — `mobile/expo-nfc-prf-probe/`
  (Android APK, verified). The probe already speaks ISO-DEP and CTAP2;
  switching the AID to the MuSig2 applet (`4E5552494D554701`) and wrapping
  the MuSig2 APDUs is plumbing, not new research.
- CTAP2 `clientPin` PIN protocol — `scripts/manage-fido2-pin.py` (set /
  change / verify / get_pin_token, all proven over PC/SC; the NFC probe
  already does the `getKeyAgreement` ECDH step).
- MuSig2 partial signing — `dist/nuri-musig2-v20-keygen.cap`, on-chain
  proven (Signet tx `c85a73fa…`). The card as *client signer* (Model A)
  uses the exact same protocol as the card as *cosigner* (Model B) — only
  the role changes, not the APDUs.
- Arkade ASP + Boltz swap — wired in `nuri-expo` (`@arkade-os/sdk`,
  `@arkade-os/boltz-swap`). The ASP expects a client pubkey + partial;
  the card produces both. The registration flow needs to accept a
  card-generated pubkey instead of a phone-derived one.
- Boltz-swap-ready tx building — `scripts/card-cosign-tweaked.py`,
  `scripts/nuri-card-wallet.mjs` (receive/spend/broadcast over PC/SC).

What is missing is wiring these together in the mobile app, and moving the
MuSig2 APDU exchange from PC/SC to NFC. Both are plumbing, not research.

---

## Scenario B — custom Bitcoin POS terminal (the vision)

You walk into a merchant. The merchant has a Bitcoin POS terminal (could be
a phone running our terminal firmware, could be a dedicated device). You tap
your card. The terminal reads the invoice, gets a signature from your card,
pays, and the merchant sees the payment confirmed. You carried only your
card.

This is the debit-card UX. It is also the hardest thing to build, because
no existing Bitcoin POS terminal speaks our APDUs.

### UX flow

```
┌─────────────┐   NFC (ISO-DEP)    ┌──────────────────┐    internet    ┌────────────┐
│   your card │ ←────────────────→ │ merchant POS    │ ←────────────→ │ ASP/Boltz  │
│  (keys)     │                    │ (our firmware)   │                │ /mempool   │
└─────────────┘                    └──────────────────┘                └────────────┘

1. Merchant enters amount on the terminal → terminal generates or fetches
   a Lightning invoice.

2. You tap the card → terminal sends `INS_GET_INDIVIDUAL_PUBKEY` (AID
   4E5552494D554701) → card returns the secp256k1 pubkey.

3. Terminal sends CTAP2 `clientPin` APDU on the FIDO2 AID → you type the
   PIN on the terminal's keypad → card verifies PIN → `pinAuth` established.

4. Terminal sends `INS_NONCE_GEN` then `INS_PARTIAL_SIGN` with the
   BIP341 sighash of the Boltz swap transaction → card returns partial.

5. Terminal aggregates, BIP340-verifies, drives the Boltz swap, broadcasts,
   pays the Lightning invoice, shows "paid".

6. Card forgets everything.
```

### What this requires

1. **A reference terminal implementation.** Open-source software that runs
   on a cheap Android phone (or a Raspberry Pi + NFC HAT) and speaks:
   - ISO-DEP NFC as the reader side,
   - our MuSig2 APDU set (AID `4E5552494D554701`, see below),
   - CTAP2 `clientPin` for the card-side PIN,
   - a Lightning node / Boltz client / Arkade ASP client,
   - a merchant UI (amount, invoice, confirm, paid).
2. **The card-side PIN gate on the MuSig2 applet.** Today the MuSig2 applet
   does not enforce a PIN — `INS_PARTIAL_SIGN` signs whatever it is sent.
   For a terminal flow this must change: the applet should refuse to sign
   until a `pinAuth` has been established in the session. See the security
   model section below.
3. **A published APDU spec** so terminal builders can implement against it.
   The spec already exists in this repo at
   [`docs/musig2-card-extension.md`](musig2-card-extension.md) — it just
   needs the PIN gate added and a "terminal integration" companion doc.

### APDU reference (existing, from `docs/musig2-card-extension.md`)

CLA `0x80`, AID `4E 55 52 49 4D 55 47 32 01` ("NURIMU2\x01"):

| INS | Name | Input | Output |
|---|---|---|---|
| `0x01` | GET_VERSION | — | version / build |
| `0x10` | GET_INDIVIDUAL_PUBKEY | key slot | 33-byte compressed pubkey |
| `0x20` | NONCE_GEN | key slot, aggregate x-only pubkey, msg32, session id | 66-byte public nonce |
| `0x30` | PARTIAL_SIGN | key slot, aggregate nonce, signer coefficient context, msg32, session id | 32-byte partial signature |
| `0x40` | RESET_SESSION | session id | — |

For Scenario B, the terminal implements the reader side of this table. The
card side is unchanged from what is already flashed. The only on-card work
needed for Scenario B is the PIN gate (see below).

### Why this is not "tap at any existing Boltcard POS"

Boltcard terminals expect an LNURLW QR / NFC payload — a static URL the
terminal fetches, and a custodian pays on the card's behalf. The card holds
no keys. Our card holds the keys and signs real transactions; that is a
different protocol. A merchant running a Boltcard-only terminal cannot
accept our card. A merchant running our terminal firmware can accept our
card and could also accept Boltcards if the terminal speaks both protocols
— but the card side is not Boltcard-compatible by design, because
Boltcard-compatible means custodial.

---

## Security model — card-side PIN

The single most important property of a debit card is that it refuses to
pay without a PIN the card itself verifies. A PIN the phone checks is
worthless if the phone is compromised; a PIN the card checks is enforced
by the secure element.

### CTAP2 `clientPin` — what is already built

The card already speaks the FIDO2 CTAP2 clientPin protocol. The Python
tool `scripts/manage-fido2-pin.py` proves the full flow over PC/SC:

```bash
npm run card:pin:status    # is a PIN set?
npm run card:pin:set       # set the first PIN (CTAP2 set_pin)
npm run card:pin:change    # change PIN (needs old PIN)
npm run card:pin:verify    # verify PIN → get_pin_token
```

Under the hood (CTAP2 command `0x06`, pinProtocol=1):

| subCommand | name | CBOR map keys |
|---|---|---|
| `1` | `getRetries` | `{1: 1}` |
| `2` | `getKeyAgreementValue` | `{1: 1, 2: 2}` → returns P-256 pubkey at key `1` |
| `3` | `setPin` | `{1: 1, 2: 3, 3: newPinEnc, 4: pinAuth, 5: 2}` |
| `5` | `getPinToken` | `{1: 1, 2: 5, 3: keyAgreement, 4: pinHashEnc}` → returns `pinToken` at key `2` |
| `6` | `changePin` | `{1: 1, 2: 6, 3: newPinEnc, 4: pinAuth, 5: 2, 6: oldPinHashEnc}` |
| `7` | `getPinUvAuthToken` | like `5` but returns a UV token |

The ECDH flow:

```
phone/terminal                                 card
─────────────                                  ────
1. subCommand 2 → getKeyAgreementValue    →   returns card P-256 pubkey
2. phone generates ephemeral P-256 keypair
3. ECDH(ephemeral, card_pub) → sharedPoint
4. sha256(sharedPoint[1:33]) → sharedSecret
5. pinHash = sha256(pin UTF-8)
6. pinHashEnc = AES-CBC-256(sharedSecret, IV=0, pinHash)
7. subCommand 5 {keyAgreement, pinHashEnc} →  card decrypts, compares, returns pinToken
                                               (or increments retry counter on mismatch;
                                                too many mismatches brick the PIN)
```

The mobile NFC probe already does steps 1-4 (the ECDH establishment) for
the `hmac-secret` path. Adding PIN verification is `subCommand 5` on the
same transport — a few hours of work, not a new protocol.

### What the PIN protects today vs what it should protect

Today the card-side PIN protects the **FIDO2 path**: a `getAssertion`
with `hmac-secret` (the PRF) refuses to return the PRF without `pinAuth`
once a PIN is set. The MuSig2 applet is a **separate applet** with its own
AID and **no PIN gate at all** — `INS_PARTIAL_SIGN` signs whatever it is
sent. That is the gap.

**What needs to be built on-card:** the MuSig2 applet should refuse
`INS_NONCE_GEN` and `INS_PARTIAL_SIGN` until a `pinAuth` has been presented
in the current session. The cleanest implementation is to share the PIN
token with the FIDO2 applet (the card already has it), or to add a small
`INS_AUTHORIZE` to the MuSig2 applet that takes a `pinAuth` produced by
the FIDO2 clientPin command. Either way the secure element enforces the
PIN — the phone/terminal cannot bypass it.

This is the most important on-card work for the tap-to-pay vision. It is
also the only on-card change required for Scenario B; everything else is
terminal-side software.

### Amount limits

The card signs an opaque 32-byte hash. It cannot see the amount, the
recipient, or the fee. So the card cannot enforce "do not sign more than X
sats" — that has to be a phone/terminal policy.

**But the PIN gate gives us the debit-card equivalent.** The phone/terminal
policy is:

- below threshold X: no PIN prompt, phone just signs and pays (small
  friction, like contactless debit cards below €50),
- above threshold X: phone/terminal must send `clientPin` to the card;
  card refuses to sign without it.

The threshold lives in the phone/terminal, so a compromised phone could lie
about the amount to skip the PIN. That is a real risk. The mitigations are:
(a) the user confirms the amount on the phone screen before the sign,
(b) the card's PIN retry counter limits PIN-guessing attacks, and
(c) for large payments, require the card-side PIN unconditionally
(threshold = 0). The hardware limit — card cannot parse txs — is
permanent; the policy is the best we can do without on-chain tx parsing
on-card, which is a much larger project and not in scope here.

### Biometric unlock

The Feitian BioCARD has a match-on-card fingerprint sensor. Feitian
confirms a Java applet can call the match-on-card fingerprint API to gate a
private-key operation. The SDK is **NDA-gated** — we cannot integrate it
into our own applet without an NDA with Feitian. Until then:

- the FIDO2 applet (Feitian's own, preloaded) can use fingerprint,
- our MuSig2 / ETH applet uses CTAP2 PIN,
- the phone can additionally require FaceID/TouchID before sending the
  sign APDU — phone-enforced, not card-enforced, but good UX.

Long term, the NDA path is the real fingerprint-on-card story.

---

## What is built vs what is missing

| Component | Status | File |
|---|---|---|
| ISO-DEP NFC + CTAP2 transport | ✅ proven (Android APK) | `mobile/expo-nfc-prf-probe/src/ctapPrf.ts` |
| CTAP2 `hmac-secret` PRF over NFC | ✅ proven | same |
| CTAP2 `clientPin` PIN set/change/verify | ✅ proven over PC/SC | `scripts/manage-fido2-pin.py` |
| CTAP2 `clientPin` `getKeyAgreement` ECDH | ✅ in the NFC probe | `mobile/expo-nfc-prf-probe/src/ctapPrf.ts:242` |
| CTAP2 `clientPin` `getPinToken` over NFC | ⚙️ ECDH done, `subCommand 5` not wired | same file |
| MuSig2 applet (on-card keygen + partial sign) | ✅ proven on-chain | `dist/nuri-musig2-v20-keygen.cap` |
| MuSig2 APDU exchange over NFC | ⚙️ probe speaks ISO-DEP, AID switch + APDU wrap not done | `mobile/expo-nfc-prf-probe/` |
| MuSig2 applet PIN gate (`INS_PARTIAL_SIGN` refuses without `pinAuth`) | ❌ not built | `card/eth/NuriEcdsaSigner.java` (pattern), MuSig2 source not in repo |
| PRF → BIP86 client key | ✅ proven | `scripts/card-arkade-identity.mjs` |
| Boltz submarine swap tx building | ✅ proven over PC/SC | `scripts/card-cosign-tweaked.py`, `scripts/nuri-card-wallet.mjs` |
| Boltz swap in the mobile app | ❌ not wired | needs `@arkade-os/boltz-swap` in the Expo app |
| Arkade ASP client in the mobile app | ❌ not wired | needs `@arkade-os/sdk` |
| Reference POS terminal (Scenario B) | ❌ not built | new project |
| ETH / EVM signer over NFC | ⚙️ applet proven over PC/SC, NFC path same as MuSig2 | `card/eth/NuriEcdsaSigner.java` |

---

## Implementation order

Numbered by dependency, smallest first. Each step is independently
verifiable.

1. **CTAP2 `getPinToken` over NFC** — add `subCommand 5` to
   `mobile/expo-nfc-prf-probe/src/ctapPrf.ts`, verify a known PIN returns
   a `pinToken`, wrong PIN increments the retry counter. ~1-2 days.
   Unblocks every signing flow that needs a card-side PIN.

2. **MVP: tap → address + balance via NFC (read-only).** Extend the mobile
   probe: tap → `hmac-secret` PRF (with PIN if set) → HKDF → BIP86 → BTC
   address → fetch UTXOs from mempool.space → display address + balance.
   No signing. Proves the NFC-wallet path end-to-end. ~1 day.

3. **MuSig2 APDUs over NFC.** The probe already speaks ISO-DEP; switch AID
   to `4E5552494D554701` and wrap `INS_GET_INDIVIDUAL_PUBKEY` /
   `INS_NONCE_GEN` / `INS_PARTIAL_SIGN`. Verify a partial over NFC matches
   a partial over PC/SC for the same key. ~2-3 days.

4. **Testnet on-chain tap-to-pay (Scenario C, on-chain only).** Tap →
   enter amount → MuSig2 sign over NFC → aggregate → broadcast →
   signet explorer. Proves Scenario C end-to-end without Lightning. ~1 day.

5. **MuSig2 applet PIN gate (on-card).** `INS_NONCE_GEN` and
   `INS_PARTIAL_SIGN` refuse until a `pinAuth` has been presented in the
   session. This is the single most important on-card change for the
   debit-card UX. Requires the MuSig2 applet source (not currently in
   this repo — only the built CAP is). ~2-3 days once source is available.

6. **Boltz Lightning integration in the mobile app.** Pull in
   `@arkade-os/boltz-swap`, build a submarine swap tx in the app, sign
   with the card over NFC, broadcast, pay a real Lightning invoice.
   ~3-5 days.

7. **Arkade ASP integration in the mobile app.** `@arkade-os/sdk`,
   `TreeSignerSession`, live boarding round against `arkade.computer`
   with the card in the reader. ~3-5 days.

8. **Reference POS terminal (Scenario B, vision).** Open-source terminal
   firmware (Android or Raspberry Pi + NFC HAT) that speaks our APDUs,
   CTAP2 PIN, Boltz, and a merchant UI. Research project, not in scope
   for this repo today.

---

## What we cannot do — honest limits

- **Card alone with no internet device anywhere.** The card cannot
  broadcast. No hardware wallet can. The "card alone" UX requires a
  terminal with internet (Scenario B); the "card + your phone" UX
  requires your phone (Scenario C).
- **Card parses the transaction to enforce amount limits.** The card sees
  only a 32-byte hash. Amount limits are a phone/terminal policy, not
  card-enforced. The card-enforced part is the PIN gate.
- **Biometric unlock in our own applet.** Feitian SDK is NDA-gated. Long
  term path. Today: CTAP2 PIN on the card, optionally FaceID/TouchID on
  the phone as a UX layer.
- **Tap at any existing Boltcard POS.** Boltcard terminals expect LNURLW
  (custodial, no keys on card). Our card holds the keys and signs real
  transactions — a different protocol. A merchant needs our terminal
  firmware (Scenario B), or a phone running our app (Scenario C).
- **Browser WebAuthn PRF on macOS/mobile.** Safari returns `prf:null` for
  external security keys; Chrome cannot see a PC/SC contact reader. This
  is why the tap-to-pay path is a **native mobile app**, not a web page.
  The mobile NFC probe (`mobile/expo-nfc-prf-probe/`) is native ISO-DEP
  precisely for this reason.
- **Production-grade side-channel resistance on the on-card bignum.** The
  ETH signer's hand-rolled `modInverse` is variable-time. The MuSig2
  applet uses the card's native EC point math (hardware-hardened) for
  `k·G`, but its scalar arithmetic is Satochip-derived software. For real
  funds, see the [Security model & caveats](../README.md#security-model--caveats--read-this-before-trusting-the-card-with-real-funds)
  section of the main README.

---

## Provenance

This document is the concept spec for the tap-to-pay north-star described
in the main README's Roadmap track 4. It is honest about the hardware
boundary because pretending otherwise would cost real money later. The
primitives are all proven in this repo; the missing piece is wiring them
together in a mobile app and (for Scenario B) a reference terminal.

Related files:

- `mobile/expo-nfc-prf-probe/` — the native NFC PRF probe (Scenario C
  foundation).
- `docs/musig2-card-extension.md` — the APDU spec both scenarios use.
- `docs/arkade-lightning.md` — how Arkade + Boltz fit in (Scenario C
  Lightning path).
- `scripts/manage-fido2-pin.py` — CTAP2 PIN proof (card-side PIN gate).
- `scripts/card-arkade-identity.mjs` — PRF → client key derivation.
- `scripts/nuri-card-wallet.mjs` — receive / spend / broadcast (the
  wallet flow to port to mobile).