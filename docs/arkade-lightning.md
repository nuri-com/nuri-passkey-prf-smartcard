# Arkade / Lightning Card Paths

> **Status update (2026-07-10):** Android NFC produced two verified card/server
> MuSig2 rounds and broadcast an Ark transaction returned by the live indexer.
> The profile now uses the authenticated username for the inserted
> credential/card pair; it does not substitute an older username or local
> account. The final monitor/`send/complete` ordering requires the next real
> payment for completion and Lightning-settlement proof. See
> [`expo-web-parity-incident-2026-07-10.md`](expo-web-parity-incident-2026-07-10.md).

This file is a map, not the source of truth. For the implemented card-client
signer proof, use [`arkade-card-signer-proof.md`](arkade-card-signer-proof.md)
and the code it references.

## Recommended Signing Model

The simple secure model is:

```text
card MuSig2 key = Arkade client signer
Arkade ASP key = second MuSig2 signer
phone/app = relay, verifier, transaction builder, and Lightning/Boltz driver
```

The phone does not receive a PRF-derived spend key in this model. It receives
only public keys, public nonces, and partial signatures, then verifies and
aggregates with the same `@scure/btc-signer` MuSig2 semantics used by Arkade.

Proof commands in this repo:

```bash
npm run card:arkade:signer:sim   # local scure-compatible proof, no hardware
npm run card:arkade:signer:real  # PC/SC proof with the current MuSig2 applet
```

Both untweaked MuSig2 signing and Arkade-style x-only Taproot tweak signing are
covered by the proof path.

## Current Real-Card APDU

The installed card applet currently exposes a reduced APDU flow:

```text
GET_PUBKEY
GET_NONCES
FINALIZE(a_i, b, parity, e)
```

`scripts/real-card-arkade-signer-proof.py` adapts that to the clean app role:
the card is labelled as `card_client_pk33`, the local software signer simulates
the ASP, and the host verifies both partials plus the final BIP340 signature.

This is still proof/dev until the card applet enforces PIN or UV before nonce
generation and signing.

## PRF Compatibility

The older PRF path remains useful, but it is a different model:

```bash
npm run card:arkade:key
npm run card:arkade:identity
```

Those commands prove the card FIDO2 PRF can derive the same app-compatible
client key material. That can support login, pairing, migration, recovery, or
browser fallback. It is not the preferred spend-signing path when the card can
hold and use the Arkade client MuSig2 key directly.

## App integration

The Expo probe now implements the card-backed identity directly over NFC. It
uses the Arkade SDK for transaction construction, the live Nuri server for the
second partial, and one pinned `@scure/btc-signer` session for card inputs,
partial verification, aggregation, and final BIP340 verification.

The FIDO credential and MuSig2 applet key remain separate identities. The app
must verify their server mapping before displaying account data or signing.

The Lightning path remains Arkade plus Boltz. The card changes who supplies the
client MuSig2 partial; it does not replace Arkade, the ASP, or the Boltz payment
flow.
