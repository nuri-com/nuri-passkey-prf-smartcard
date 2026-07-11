# How it works — a Bitcoin debit card you can actually tap

> A smartcard that pays Lightning invoices from a Bitcoin balance, with the same
> tap‑a‑card‑and‑enter‑a‑PIN experience as a Visa terminal — except no bank is
> holding your money, and the key that authorizes every payment physically never
> leaves the card.

This document explains the whole thing end to end: what the card is, what it can
do, how the merchant terminal works, how the profile wallet works, why it was
hard to build, and why the result is genuinely new.

> **2026-07-10 correction:** the current product path exposes the inserted
> card's live Nuri-cosigned account only. It does not substitute `card@nuri.com`,
> an old card key, a local "Pure Arkade" account, zero balances, or empty receive
> lists. The complete regression timeline and current proof boundary are in
> [`expo-web-parity-incident-2026-07-10.md`](expo-web-parity-incident-2026-07-10.md).

---

## 1. The one‑sentence version

You walk up to a terminal, it shows "400 sats", you put your card on the reader
and type your PIN, and the card signs the Ark transaction. The terminal reports
Ark broadcast and swap funding separately; it may say **Paid** only after the
merchant confirms Lightning settlement. The authorization came from a chip in
the card, with no custodian holding the card key.

That's a **self‑custodial contactless Bitcoin card**. As far as we know, that
combination — hardware‑secured key + tap‑to‑pay UX + Lightning + no custodian —
did not exist as a working thing before this.

---

## 2. What the card is

It's a Java Card smartcard (tested on a Feitian sample) running custom applets.
The one that matters here is a **MuSig2 co‑signer**: it generates a secp256k1
key *on the card* and will produce Schnorr/MuSig2 partial signatures, but it will
**never export the private key**. There is no API to read the secret out. The key
is born on the card and dies on the card.

Around it sits a FIDO2/WebAuthn applet (the same standard behind passkeys), which
gives us two things for free:

- **Presence** — the card has to be physically on the reader to do anything.
- **PIN** — a user‑verification (UV) assertion that proves the right PIN was
  entered, enforced by the chip, with a retry counter that locks the card after
  too many wrong guesses (just like a SIM).

So every payment is gated by *something you have* (the card) and *something you
know* (the PIN) — the exact two factors a bank card uses, but here they authorize
a cryptographic signature instead of a message to a bank.

### What the card can do (capabilities)

- Generate a non‑exportable secp256k1 key on‑card and return only the public key.
- Produce MuSig2 nonces (`GET_NONCES`) and partial signatures (`FINALIZE`) — the
  building blocks of a 2‑of‑2 Bitcoin signature.
- Produce WebAuthn/FIDO2 assertions (presence + PIN) over a challenge.
- Keep a FIDO credential and a separate non-exportable MuSig2 wallet key on the
  same physical card; the live server verifies their explicit mapping.
- (Other applets on the same card: SSH login key, OATH‑TOTP 2FA, an ETH/EVM
  ECDSA signer — all documented in the main README.)

The card does **not**: parse transactions, know amounts or recipients, hold any
balance itself, or ever reveal a secret. It is a signing oracle with a PIN.

---

## 3. The money lives on Arkade (Bitcoin, instant, cheap)

The card's balance isn't a bank ledger — it's Bitcoin held on **Arkade**, an Ark
network. Ark lets you hold Bitcoin in "virtual UTXOs" (VTXOs) that move instantly
and cheaply off‑chain while remaining backed by real on‑chain Bitcoin, with a
unilateral exit path so you're never trapped. `arkade.computer` is the Ark
operator that runs the shared signing rounds.

A VTXO is owned by a taproot key. Here that key is a **2‑of‑2 MuSig2** — the card
plus a second signer — so spending needs *both* signatures. That's the whole
security model in one line: **the card alone can't move the money, and the second
signer alone can't either.**

Paying Lightning from an Ark balance uses a **Boltz submarine swap**: you lock
the sats into a swap contract on Ark, Boltz pays the Lightning invoice, and takes
the locked sats. The card signs the spend that funds the swap.

---

## 4. The live card account

The wallet is `musig2(card, Nuri server)`. The physical card supplies the
non-exportable client key and Nuri supplies the second partial after a
PIN-authorized FIDO assertion. The profile obtains its username through an
authenticated live request.

The FIDO credential and MuSig2 key are separate applet identities. The server
maps them explicitly. A credential hit in the database does not prove that the
inserted card still has the MuSig2 key previously associated with it.

---

## 5. How the terminal works (tap‑to‑pay)

```
Merchant terminal (/terminal)                 Customer approval (/checkout)
┌───────────────────────────┐                 ┌───────────────────────────┐
│  Nuri Coffee              │                 │  Nuri Coffee   400 sats   │
│  merchant + LN + memo     │    forwards     │  ENTER CARD PIN  • • • •  │
│  [ numpad to enter amount]│  ───────────▶   │  [ numpad ]               │
│  [ Charge ]               │                 │        ◯ 21s scanning…    │
└───────────────────────────┘                 └───────────────────────────┘
```

1. The merchant enters an amount on the numpad and hits **Charge**. The server
   resolves the merchant's Lightning address into a real BOLT11 invoice and makes
   a checkout session, then forwards to the approval screen.
2. The customer types a **4‑digit PIN** on the numpad. As soon
   as the 4th digit lands — no button press — a **countdown ring** starts and the
   terminal begins **scanning for the card for 21 seconds**. This is the nice
   detail: if the card isn't on the reader yet, it doesn't fail — it keeps trying,
   so you can demo "nothing happens… now I place the card… approved."
3. Under the hood the browser polls a fast card probe every ~1s. Three outcomes:
   - **Card present + right PIN** → it runs the real payment.
   - **Card present + wrong PIN** → "🔒 Wrong PIN", back to the PIN pad.
   - **No card within 21s** → "😔 No card detected", back to the PIN pad.
4. After the Ark transaction is broadcast, the app separately requires Nuri's
   `send/complete` response and the Boltz funded event. The UI must not call the
   merchant paid until Lightning settlement is confirmed.

**Fast-funds handling:** before paying, the terminal checks the balance. Missing
or malformed balance data is an error, never zero. If the available balance is
short, the payment fails visibly; the live flow does not silently claim or
substitute another source of funds.

---

## 6. How the payment is actually authorized (the hard part)

This is the part that had never been wired up before. Because the funds are
locked to `musig2(card, second‑key)`, spending needs a real two‑party signing
round, and for the Nuri card the second party is a server that must be convinced,
by the card, that this exact payment is authorized:

```
Pay a merchant Lightning invoice:
  1. Boltz: create a submarine swap        → an Ark lockup address to fund
  2. Nuri: create a send intent            → a server-side record of "this payment"
  3. Build the funding spend (Arkade SDK); to sign it the card must:
       a. Nuri send/prepare (the exact spend + its sighashes)  → a challenge
       b. ONE FIDO2 assertion: card present + PIN, over that challenge
       c. per input:  card MuSig2 nonce → Nuri send/cosign (server partial)
                      → card FINALIZE  → combine into one Bitcoin signature
  4. Nuri send/complete → Boltz sees the funded swap → pays the invoice
```

The server re‑derives every sighash from the actual spend and only cosigns those
exact bytes — so its signature is worthless for any other transaction. The card
only ever does two kinds of operation: a FIDO2 presence+PIN assertion, and MuSig2
nonce/finalize. It never sees the amount, the recipient, or the transaction.

The monitor subscribes before broadcast. The app records `send/complete` and
requires a funded status; it does not silently convert a monitor or completion
failure into approval.

---

## 7. How the profile (wallet) works

The profile page (`/profile`) is the cardholder's wallet view:

- **Identity** — card key, username, and Lightning address come from the inserted
  card and authenticated live server responses.
- **Receive** — mint a BOLT11 QR for the authenticated Lightning account.
- **Auto‑claim** — incoming Lightning payments arrive as reverse swaps that must
  be *claimed* (the card co‑signs a claim). The page watches for them and claims
  automatically, so money just "shows up" as spendable balance.
- **Balance** — the real Ark balance for that account, live.

Everything the profile does with the card — claiming, receiving, showing the
balance — is the same card + MuSig2 machinery the terminal uses to pay.

---

## 8. Why this was hard (the journey / learnings)

A few things we learned building it, because they explain why a working version
didn't already exist:

- **Sending is not receiving.** The receive/claim path worked first, and the send
  path was mistakenly wired to the *claim* approval endpoint — which validates a
  receive record and returns "not claimable" for a spend. Sending needed a
  different, dedicated server flow (`send/prepare → cosign → complete`). Once we
  stopped knocking on the claim door, it worked.
- **The funds are cryptographically bound to the co‑signer.** You can't "just
  skip the server" for the Nuri card — the money is locked to `musig2(card,
  server)`. That's a feature (recovery, no server custody), not a bug, but it
  means the server *must* participate in every spend from this live account.
- **A smartcard can be the client half of a MuSig2 wallet.** The card produces
  nonces and partials over exactly the right sighash so the aggregate signature
  is valid for a real VTXO spend. Proven on mainnet, not a simulation.
- **The terminal shouldn't fail fast.** Real card UX means "keep trying while I
  fumble for the card," so the scan polls for 21 seconds instead of erroring the
  instant no card is found.
- **Do not maintain two session transcripts in one client.** Expo previously
  verified the server with `@scure/btc-signer` but independently calculated the
  card transcript with custom point arithmetic. JavaScript negative remainder
  behavior made that transcript diverge from Python/BIP327. The custom helper
  was deleted.

---

## 9. Why it's amazing

- **Self‑custody that feels like a debit card.** Tap, PIN, approved. No app to
  open, no seed phrase at the till, no custodian who can freeze you.
- **No single party can move your money.** Not the card if it's stolen (no PIN,
  and it's only half the key). Not the server (it's only the other half, and only
  cosigns what the card approves). Not a thief who phishes the server.
- **The private key never leaves the chip.** Same guarantee as a hardware wallet,
  in a form factor you can put in a wallet next to your Visa.
- **Real Bitcoin, mainnet.** Historical desktop runs settled Lightning value;
  the 2026-07-10 Android run independently proves NFC signing and indexed Ark
  broadcast. Its final Lightning settlement remains a separate proof step.
- **No invented account state** — the UI shows the physical card and the live
  account mapping or an explicit error.

A Visa card is a message to a bank asking it to move money it holds for you. This
card is a **signature you produce**, that moves money **only you can move**, with
the ergonomics of the thing it replaces.

---

*Reproduce all of this — including flashing the card — from the
[README](../README.md#bitcoin-debit-card-tap-to-pay-lightning-arkade--nuri).*
