# Arkade Card Client Signer Proof

This note is derived from the proof code added in this repo, not from the older
concept docs. The model under test is:

```text
card = Arkade client signer
ASP/server = second MuSig2 signer and Lightning/payment infrastructure
phone/app = transaction builder, verifier, relay, and UI
```

The card stores the client MuSig2 private key and never exports it. PRF can still
exist for login, pairing, or compatibility, but it is not the spend signer in
this model.

## Code Anchors

- Clean host-side contract and simulator proof:
  `src/musig2/arkade-client-signer.js`
- Simulator and negative tests:
  `test/arkade-client-signer.test.js`
- Simulator proof CLI:
  `scripts/arkade-card-signer-proof.mjs`
- Real-card PC/SC proof adapter:
  `scripts/real-card-arkade-signer-proof.py`

## Clean App Contract

The app-facing signer shape is:

```ts
type ArkadeClientSigner = {
  kind: "software-passkey" | "card";
  getClientPk33(): Promise<string>;
  beginSign(input: {
    sessionId: string;
    msg32: string;
    aggregatedXonly32: string;
  }): Promise<{ clientPubNonce66: string }>;
  partialSign(input: {
    sessionId: string;
    msg32: string;
    sortedPubkeys33: string[];
    aggregateNonce66: string;
    tweak32?: string;
  }): Promise<{ clientPartial32: string }>;
};
```

`software-passkey` wraps the current app-style private-key flow. `card` exposes
only pubkey, pub nonce, and partial signature. The simulator enforces sequential
card sessions and burns the nonce after one partial signature.

Production card mode is blocked until nonce/sign commands are protected by a
card-side PIN or UV gate. Until then, card signer mode is proof/dev only.

## Current Real-Card APDU

The current MuSig2 applet is lower-level than the clean interface. The PC/SC
proof adapts the clean role assignment to today’s APDUs:

```text
GET_PUBKEY -> card_client_pk33
GET_NONCES -> card_client_pub_nonce66
FINALIZE(a_i, b, parity, e) -> card_client_partial32
```

The host computes the scure/BIP327 session values, verifies the ASP partial,
asks the card for the client partial, verifies the card partial, and aggregates
the final BIP340 signature. The card still never exports its private key or
secret nonce.

Run the real-card adapter when the card and PC/SC environment are present:

```bash
npm run card:arkade:signer:real
```

It produces both cases:

- untweaked MuSig2 signing;
- Arkade-style x-only Taproot tweak signing from a VTXO `scriptRoot32`.

## Simulator Proof

Run the local proof without hardware:

```bash
npm run card:arkade:signer:sim
npm run card:arkade:signer:sim -- --json
```

The proof returns:

- card/client pubkey and ASP pubkey;
- sorted participant keys and aggregate key;
- card and ASP public nonces;
- ASP partial, card partial, and final aggregate signature;
- verification booleans for both partials and the final BIP340 signature.

The tests also cover rejection for wrong `msg32`, wrong ASP nonce, wrong tweak,
nonce reuse, and wrong client pubkey.

## PRF Compatibility Path

These commands are still useful, but they are not the secure spend-signing model
described above:

```bash
npm run card:arkade:key
npm run card:arkade:identity
```

They prove a card FIDO2 PRF can derive the same Nuri/Arkade client key material
as the app’s passkey path. That is compatibility and migration tooling. It means
PRF may still be useful for login, pairing, recovery, or browser fallback, but
the stronger card-signer model does not export a spend key to the phone.

## App Integration Boundary

In the app, `ArkadeRemoteIdentity` should depend on `ArkadeClientSigner` instead
of reading a private key directly:

1. get `clientPk33` from the active signer;
2. ask the signer for `clientPubNonce66`;
3. call the ASP/server cosign route with `msg32`, `client_pk33`,
   `client_pub_nonce`, and optional `tweak32`;
4. verify the ASP partial;
5. ask the signer for `clientPartial32`;
6. verify the card/client partial;
7. aggregate the final signature;
8. continue the existing wallet send or Boltz Lightning path.

The existing software passkey signer should remain the default. Card signer mode
should stay behind an explicit feature flag until onboarding, migration, and
PIN/UV-gated signing are ready.
