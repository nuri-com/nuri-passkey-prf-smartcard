# Signing architecture — which key lives where, and who actually signs

> The tap-to-pay concept doc said "the card signs, no keys leave." That was
> underspecified and overcomplicated. This doc is the precise, simpler
> version. The card can hold a raw secp256k1 key and sign directly — no PRF,
> no derived key in the phone. The phone is just a dumb terminal.

## Table of contents

- [The simple model — card + ASP, phone is a terminal](#the-simple-model--card--asp-phone-is-a-terminal)
- [Why the PRF path exists at all (and why the card doesn't need it)](#why-the-prf-path-exists-at-all-and-why-the-card-doesnt-need-it)
- [The full model table](#the-full-model-table)
- [Model A — Card as client signer + ASP cosigner (the simple one)](#model-a--card-as-client-signer--asp-cosigner)
- [Model B — Card as MuSig2 cosigner + phone holds client key (standalone)](#model-b--card-as-musig2-cosigner--phone-holds-client-key-standalone)
- [Model C — Card as PRF root (browser Arkade path)](#model-c--card-as-prf-root-browser-arkade-path)
- [Model D — Card as sole ECDSA signer (ETH)](#model-d--card-as-sole-ecdsa-signer-eth)
- [Recommendation for tap-to-pay](#recommendation-for-tap-to-pay)

---

## The simple model — card + ASP, phone is a terminal

```
Card (MuSig2 applet)        Arkade ASP              Phone (dumb terminal)
  client sk                   ASP sk                   holds nothing
  never leaves                never leaves             no keys, ever
      │                           │                       │
      │  MuSig2 2-of-2: card + ASP                       │
      │                           │                       │
  INS_KEYGEN → pubkey ──────────────────────────→ register with ASP
      │                           │                       │
      │  INS_NONCE_GEN ◀──── aggregate x-only, msg32 ──── relay from ASP
      │  ──→ pub nonce ──────────────────────────→ relay to ASP
      │                           │                       │
      │  INS_PARTIAL_SIGN ◀──── (a, b, e) ──────────── relay from ASP
      │  s = k + e·a·sk            │                       │
      │  ──→ partial ─────────────┐ │                      │
      │                           ↓ ↓                      │
      │                   ASP partial ──→ aggregate → BIP340 sig
      │                           │                       │
      │                           │           Boltz swap → Lightning → merchant
```

- **Card** = the client signer. Key generated on-card via `INS_KEYGEN`,
  non-exportable. Produces MuSig2 partials via `INS_PARTIAL_SIGN`.
- **ASP** = the cosigner. The other MuSig2 party. Already built in Arkade.
- **Phone** = relay terminal. Sends APDUs to the card, sends partials to the
  ASP, aggregates the final signature, drives the Boltz swap. **Holds no
  key material — none, ever.**
- **No PRF. No FIDO2 applet needed for this path. No derived key in phone
  RAM.** The card's secp256k1 key is the client key. The phone just relays.

**Why this works with Arkade:** Arkade's boarding/forfeit rounds are 2-of-2
MuSig2 between a client and the ASP. The "client" is just whoever holds a
secp256k1 key and registers its pubkey with the ASP. The card's MuSig2
applet already does exactly this. The ASP doesn't care that the client is a
card instead of a phone — it sees a pubkey and a partial. This is **already
proven on Signet** (tx `c85a73fa…` block 308804); the only difference is
that in that proof the phone held the client key and the card was the
cosigner. Swap the roles: the card is the client, the ASP is the cosigner.
Same MuSig2 protocol, same applet, no new on-card code.

**Security:**
- Compromised phone → **no funds gone.** The phone holds no key. It can
  relay APDUs but cannot sign without the card.
- Stolen card → **no funds gone.** The card has the client key but no ASP
  partial. Without the ASP, no signature.
- Both the card AND the ASP needed → true 2-of-2, self-custody, no single
  point of failure.

---

## Why the PRF path exists at all (and why the card doesn't need it)

The PRF path exists because **browsers can't hold a secp256k1 key**. WebAuthn
only exposes `hmac-secret` (PRF) — a 32-byte derivation output. So the browser
wallet path *had* to derive a Bitcoin key from PRF and sign in JavaScript
inside the browser. That's a browser limitation, not a card limitation.

**The card can hold a raw secp256k1 key and sign directly.** The MuSig2
applet already does this: `INS_KEYGEN` generates the key, `INS_PARTIAL_SIGN`
signs. No PRF, no derivation, no key in phone RAM.

I carried the browser limitation into the card path by mistake. For the
card-as-signer path, PRF is unnecessary. The card's own secp256k1 key is the
wallet key. The phone is just a terminal.

---

## The full model table

| | Model A: card signs | Model B: card cosigns | Model C: PRF root | Model D: sole ECDSA |
|---|---|---|---|---|
| Card applets | MuSig2 (or any secp256k1) | FIDO2 + MuSig2 | FIDO2 | ETH |
| Card holds | client sk (never leaves) | FIDO2 sk + cosigner sk | FIDO2 sk | ETH sk |
| Who signs | **card** + ASP | phone (client sk) + **card** | phone (client sk) + ASP | **card** alone |
| Phone holds a key? | **no** | yes (client sk from PRF) | yes (client sk from PRF) | no |
| PRF needed? | **no** | yes (for client key) | yes (for client key) | no |
| Compromised phone → funds gone? | **no** | no (missing card partial) | **yes** (ASP cosigns) | n/a |
| Stolen card → funds gone? | no (no ASP) | no (no client key) | no | yes if no PIN |
| Instant Lightning | **yes** (Boltz on Arkade VTXO) | no (on-chain) | yes | n/a |
| Needs ASP online | yes | no | yes | no |
| On-chain proof | Signet tx `c85a73fa…` (card as cosigner; card-as-client is the same protocol) | same tx | PRF→client key proven | 5/5 ecrecover |

**Model A is what you're asking for.** Card signs, ASP cosigns, phone is a
terminal, no keys leave the card, instant Lightning via Arkade+Boltz. The
rest are variations for other constraints (browser path needs PRF, ETH
needs ECDSA, standalone no-ASP wallet needs card-as-cosigner).

---

## Model A — Card as client signer + ASP cosigner

See the diagram above. This is the simple model. The card is the MuSig2
client, the ASP is the cosigner, the phone relays.

**What exists:** the MuSig2 applet (`dist/nuri-musig2-v20-keygen.cap`) with
`INS_KEYGEN`, `INS_NONCE_GEN`, `INS_PARTIAL_SIGN` — all proven on a real
card. The Arkade ASP exists in `nuri-expo` / `@arkade-os/sdk`. The Boltz
swap path exists in `nuri-expo` / `@arkade-os/boltz-swap`.

**What's missing:**
1. Register the card's MuSig2 pubkey with the Arkade ASP (currently the ASP
   expects a phone-derived client key; the registration flow needs to accept
   a card-generated pubkey).
2. Mobile app that relays MuSig2 APDUs between the card and the ASP over
   NFC. The mobile NFC probe (`mobile/expo-nfc-prf-probe/`) already speaks
   ISO-DEP — switching the AID to `4E5552494D554701` and wrapping the MuSig2
   APDUs is plumbing.
3. Card-side PIN gate on the MuSig2 applet (see
   `tap-to-pay-concept.md` security model) so the card refuses to sign
   without a PIN the card verifies.

**Why no new on-card code is needed for the signing itself:** the MuSig2
applet's `INS_PARTIAL_SIGN` computes `s = k + e·a·sk` where `sk` is the
card's key. Whether the *other* MuSig2 party is a phone (standalone wallet)
or an ASP (Arkade) is invisible to the card — it just receives `(a, b, e)`
and returns a partial. The protocol is the same.

---

## Model B — Card as MuSig2 cosigner + phone holds client key (standalone)

This is the standalone `musig2(client, card)` wallet, already proven on
Signet. The phone holds a client key (derived from PRF), the card holds a
separate cosigner key. Both partials needed to sign.

**Why this exists:** server-independent, no ASP needed. But the phone holds
a key (from PRF), so it's weaker than Model A against a compromised phone —
except that the card's partial is still required, so a compromised phone
alone still cannot sign.

**When to use this:** large self-custody payments where you don't want to
depend on the ASP being online. Slower (on-chain confirmation, or a direct
Boltz swap from on-chain UTXOs).

---

## Model C — Card as PRF root (browser Arkade path)

This is the browser path: the card emits PRF, the browser derives a client
key from it, the ASP cosigns. Exists because browsers can't hold keys. See
`docs/arkade-lightning.md` for the full details.

**When this is the right model:** only when the client is a browser (no
native NFC app). On mobile with a native app, use Model A instead — the card
signs directly, no PRF, stronger security.

---

## Model D — Card as sole ECDSA signer (ETH)

Single-key ECDSA for Ethereum. The card's key never leaves. No second
factor. Card-side PIN via CTAP2 is the protection. See the ETH signer
section of the main README.

---

## Recommendation for tap-to-pay

**Model A.** Card is the client signer, ASP is the cosigner, phone is a
dumb terminal. No PRF, no keys in the phone, instant Lightning via
Arkade+Boltz. This is the simple, secure architecture you're asking for.

The card holds the key. The card signs. No keys leave the card. The phone
is just a terminal with internet. The ASP provides the second half of the
2-of-2 so the card alone cannot sign, and so Lightning works.

One card, two payment modes, both self-custody:

- **Instant (Model A):** card + ASP + Boltz swap → Lightning. Small
  payments, instant, low fee. Card is the client signer.
- **Self-custody offline (Model B):** card + phone (client key from PRF) →
  on-chain or direct Boltz. Large payments, no ASP dependency. Card is the
  cosigner.

The app picks the model per payment based on amount and whether the ASP is
reachable. The card holds the same MuSig2 key in both — it just plays client
(Model A) or cosigner (Model B) depending on what the other party is.

---

## Provenance

- Model A signing protocol: proven on Signet tx `c85a73fa…` (block 308804)
  — the card produced a valid MuSig2 partial; only the *role* (client vs
  cosigner) changes from what was tested, not the protocol.
- Model B: the same Signet tx, with the card as cosigner and the phone
  holding the client key.
- Model C PRF → client key: `scripts/card-arkade-identity.mjs`
  (`CARD_ARKADE_IDENTITY_STABLE_OK`).
- Model D: `dist/nuri-eth-signer.cap` v1.3, 5/5 ecrecover via `python-ecdsa`.

Related:
- `docs/tap-to-pay-concept.md` — UX flows, CTAP2 PIN security model,
  Scenario C (phone) vs Scenario B (POS terminal).
- `docs/arkade-lightning.md` — Arkade + Boltz specifics.
- `docs/musig2-card-extension.md` — the MuSig2 APDU spec Model A/B use.