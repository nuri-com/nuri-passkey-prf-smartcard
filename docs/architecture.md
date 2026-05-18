# Architecture

## Goal

Build the smallest practical Java Card path that can be tested locally before buying cards:

- FIDO2 passkey authentication.
- WebAuthn PRF support via CTAP2 `hmac-secret`.
- Optional Taproot/MuSig2 partial signing with an internal card key.

## Split Applet Model

Use two applets or two AIDs:

- FIDO2 applet: passkey authentication, client PIN / UV, resident credentials, `hmac-secret`.
- MuSig2 applet: Bitcoin-only internal-key and nonce state, partial signature output.

This is intentionally simpler than one large combined applet. The FIDO2 applet can stay close to upstream and remain testable with FIDO tooling. The MuSig2 applet has a narrow APDU surface and can be tested against `@scure/btc-signer`.

## Browser PRF

Browsers expose WebAuthn `prf`. Authenticators expose CTAP2 `hmac-secret`. The client/browser layer transforms PRF inputs into hmac-secret salts and returns PRF outputs in `clientExtensionResults`.

Implication: the authenticator should implement and advertise `hmac-secret`. Advertising a separate CTAP extension named `prf` is unnecessary and can break clients that parse GetInfo strictly.

## Minimal FIDO2 Surface

Keep:

- `authenticatorGetInfo`
- `authenticatorMakeCredential`
- `authenticatorGetAssertion`
- `authenticatorClientPIN` / `pinUvAuth`
- resident credentials
- `hmac-secret`
- reset

Avoid in the first build:

- IDEX biometric integration
- MuSig2 inside FIDO2 code paths
- custom PRF CTAP extension
- large blobs and enterprise attestation unless needed by target clients

## MuSig2 Surface

The MuSig2 card stores one or more internal secp256k1 keys and one active secret nonce per signing session. The host performs transaction construction, key aggregation, taproot tweak handling, aggregate nonce/session creation, final signature aggregation, and final verification.

The card only needs:

- expose individual public key
- generate and return public nonce
- return one partial signature for a specific session
- burn nonce after signing

That is the smallest security boundary for a useful hardware co-signer.

## Test Strategy

FIDO2:

- Java compile and jCardSim smoke tests.
- `python-fido2` hmac-secret tests against jCardSim.
- Later: CTAP bridge or real NFC/HID browser test.

MuSig2:

- Node simulator using `@scure/btc-signer/musig2.js`.
- Host/card round trip with aggregate key, public nonces, partial signatures, aggregate signature verification.
- APDU-level simulator with the same command contract and nonce replay rejection.
