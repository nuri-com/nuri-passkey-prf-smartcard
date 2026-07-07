# How it works — a Bitcoin debit card you can actually tap

> A smartcard that pays Lightning invoices from a Bitcoin balance, with the same
> tap‑a‑card‑and‑enter‑a‑PIN experience as a Visa terminal — except no bank is
> holding your money, and the key that authorizes every payment physically never
> leaves the card.

This document explains the whole thing end to end: what the card is, what it can
do, how the merchant terminal works, how the profile wallet works, why it was
hard to build, and why the result is genuinely new.

---

## 1. The one‑sentence version

You walk up to a terminal, it shows "400 sats", you put your card on the reader
and type your PIN, a green ring spins for a moment, and it says **Approved**. A
real Lightning payment just went to the merchant — signed by a chip in the card,
settled on Bitcoin, with no custodian in the middle who could freeze or redirect
the money.

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
- Derive a stable wallet identity from a passkey PRF output — the *same* identity
  the Nuri phone app derives, so the card and the app are the same wallet.
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

## 4. Two wallets on one card

Same physical card key, aggregated with a different second key:

### Nuri card — `card@nuri.com`
The second MuSig2 key is the **Nuri server**. This gives you a *recoverable*
wallet (server‑assisted recovery, plus a unilateral card‑exit path after a
timelock) and a real **Lightning address** — anyone can pay `card@nuri.com` and
the sats land on your card. The server is a **co‑signer, not a custodian**: it
holds one key of the 2‑of‑2 and can never move funds alone, and it only cosigns a
specific payment after the card proves presence + PIN over *that* payment.

### Pure Arkade — no Nuri at all
The second key is one **you hold locally**. Now both halves of the 2‑of‑2 are in
your hands (card + your key), `arkade.computer` runs the round, and **no Nuri
server is involved in any way**. Maximum self‑custody, no Lightning username.

You pick which card to pay with using a selector on the terminal and a dropdown
on the profile page. The card signing is byte‑for‑byte identical; only the second
signer differs.

---

## 5. How the terminal works (tap‑to‑pay)

```
Merchant terminal (/terminal)                 Customer approval (/checkout)
┌───────────────────────────┐                 ┌───────────────────────────┐
│  Nuri Coffee              │                 │  Nuri Coffee   400 sats   │
│  4 0 0   sats             │    forwards     │  [Nuri card] [Pure Arkade]│
│  [ numpad to enter amount]│  ───────────▶   │  ENTER CARD PIN  • • • •   │
│  [ Charge ]               │                 │  [ numpad ]               │
└───────────────────────────┘                 │        ◯ 21s scanning…    │
                                              └───────────────────────────┘
```

1. The merchant enters an amount on the numpad and hits **Charge**. The server
   resolves the merchant's Lightning address into a real BOLT11 invoice and makes
   a checkout session, then forwards to the approval screen.
2. The customer picks a card and types a **4‑digit PIN** on the numpad. As soon
   as the 4th digit lands — no button press — a **countdown ring** starts and the
   terminal begins **scanning for the card for 21 seconds**. This is the nice
   detail: if the card isn't on the reader yet, it doesn't fail — it keeps trying,
   so you can demo "nothing happens… now I place the card… approved."
3. Under the hood the browser polls a fast card probe every ~1s. Three outcomes:
   - **Card present + right PIN** → it runs the real payment.
   - **Card present + wrong PIN** → "🔒 Wrong PIN", back to the PIN pad.
   - **No card within 21s** → "😔 No card detected", back to the PIN pad.
4. On success: a green ✅, **Approved — payment broadcast**, and a receipt with
   the amount and the Ark transaction id. The merchant is paid over Lightning.

**Fast‑funds handling:** before paying, the terminal checks the balance. If it
already covers the amount, it pays immediately and quietly claims any newly
arrived money afterward. If it's short, it first claims pending incoming
payments, then pays — so a payment never fails just because a recent top‑up
wasn't claimed yet.

---

## 6. How the payment is actually authorized (the hard part)

This is the part that had never been wired up before. Because the funds are
locked to `musig2(card, second‑key)`, spending needs a real two‑party signing
round, and for the Nuri card the second party is a server that must be convinced,
by the card, that this exact payment is authorized:

```
Pay 400 sats to card@nuri.com's merchant:
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

The payment is **optimistic**: the terminal returns as soon as the spend is
funded, without waiting for the Lightning leg to fully settle — so it feels
instant, like a card tap should.

The **Pure Arkade** card does the same dance but computes the second signature
locally with your own key — no server round trip at all.

---

## 7. How the profile (wallet) works

The profile page (`/profile`) is the cardholder's wallet view:

- **Account dropdown** — switch between the Nuri card and the Pure Arkade card;
  balance and address update for the selected one.
- **Receive** — the Nuri card has `card@nuri.com`; it also mints a BOLT11 QR to
  receive a specific amount. Pay it from any Lightning wallet.
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
  means the server *must* participate in every spend. The Pure Arkade card is the
  answer for people who want zero server involvement.
- **A smartcard can be the client half of a MuSig2 wallet.** The card produces
  nonces and partials over exactly the right sighash so the aggregate signature
  is valid for a real VTXO spend. Proven on mainnet, not a simulation.
- **The terminal shouldn't fail fast.** Real card UX means "keep trying while I
  fumble for the card," so the scan polls for 21 seconds instead of erroring the
  instant no card is found.

---

## 9. Why it's amazing

- **Self‑custody that feels like a debit card.** Tap, PIN, approved. No app to
  open, no seed phrase at the till, no custodian who can freeze you.
- **No single party can move your money.** Not the card if it's stolen (no PIN,
  and it's only half the key). Not the server (it's only the other half, and only
  cosigns what the card approves). Not a thief who phishes the server.
- **The private key never leaves the chip.** Same guarantee as a hardware wallet,
  in a form factor you can put in a wallet next to your Visa.
- **Real Bitcoin, real Lightning, mainnet.** Not a testnet toy — actual sats went
  to `emin@nuri.com` and `card@nuri.com`, signed by the card.
- **Two modes on one card** — a recoverable, username‑enabled Nuri card *and* a
  no‑server pure‑Arkade card — so it fits both "I want recovery" and "I trust no
  one" users.

A Visa card is a message to a bank asking it to move money it holds for you. This
card is a **signature you produce**, that moves money **only you can move**, with
the ergonomics of the thing it replaces.

---

*Reproduce all of this — including flashing the card — from the
[README](../README.md#bitcoin-debit-card-tap-to-pay-lightning-arkade--nuri).*
