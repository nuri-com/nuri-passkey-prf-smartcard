# Nuri Arkade Card Cosigner Plan

> Current direction, 2026-07-06: do not treat this historical option map as the
> source of truth. The implemented proof is now the simpler model where the card
> is the Arkade **client signer** and the Arkade ASP/server remains the second
> MuSig2 signer plus Lightning/payment infrastructure. See
> [`arkade-card-signer-proof.md`](arkade-card-signer-proof.md) for the code-backed
> contract, simulator proof, and real-card PC/SC adapter.

This document maps the current Nuri Arkade MuSig2 signing flow to a smartcard
cosigner. It is based on the local sibling checkouts inspected on 2026-06-13:

- `../nuri-expo` branch `arkade-debug-ui-ux-and-migration-fixes-emino-jun13th`,
  commit `7d0f41d90b5405a48278577dbd0d866b4941f2cf`, dirty working tree.
- `../server-arkade-v4` branch `security/receive-claim-approval`, commit
  `68700b376e36084fb54de587a7054dcaa969e355`, dirty working tree.
- GitHub remote check: `nuri-expo` `main` is
  `ba37e633b561c86931c5dfa335c93240ff0333d3`; the local app branch is not the
  remote `main` commit. `server-arkade-v4` remote `main` is
  `68700b376e36084fb54de587a7054dcaa969e355`.

## Current Libraries

Both sides use `@scure/btc-signer` and its MuSig2 module:

| Repo | Package | Version |
| --- | --- | --- |
| `nuri-expo` | `@scure/btc-signer` | `2.0.1` |
| `nuri-expo` | `@noble/curves` | `2.0.0` |
| `nuri-expo` | `@noble/hashes` | `2.0.0` |
| `server-arkade-v4` | `@scure/btc-signer` | `2.0.1` |
| `server-arkade-v4` | `@noble/curves` | `2.0.0` |
| `server-arkade-v4` | `@noble/hashes` | `2.0.1` |
| `server-arkade-v4` | `@noble/secp256k1` | `^3.0.0` |

The app contract config currently says:

```json
{
  "nuri_server_api": "v4",
  "nuri_server_version": "nuri-server-api-v4.2.0-one-server-test",
  "nuri_contract_version": "nuri-client-recovery-v1",
  "nuri_contract_type": "nuri_client_recovery_v1",
  "arkade_sdk_version": "0.4.23",
  "bitcoin_tx_version": "2"
}
```

## Current Nuri Signing Flow

The app obtains the server public key, sorts the client and server keys, and
derives the aggregate MuSig2 key using `musig2.sortKeys`, `musig2.keyAggregate`,
and `musig2.keyAggExport` in
`../nuri-expo/services/arkade/ArkadeRemoteIdentity.ts`.

During signing, the app:

1. Loads the client signing key from the passkey PRF/key vault.
2. Creates a client MuSig2 nonce with `musig2.nonceGen(clientPk, clientPriv,
   aggregatedXonly, msg32)`.
3. Sends `msg32`, `client_pk33`, `client_pub_nonce`, and optional `tweak32` to
   the Arkade signer server.
4. Receives `server_pub_nonce66` and `server_partial32`.
5. Reconstructs `musig2.Session(aggNonce, sortedKeys, msg32, tweaks, tweakModes)`.
6. Verifies the server partial with `session.partialSigVerify`.
7. Creates the client partial with `session.sign(secretNonce, clientPriv)`.
8. Aggregates with `session.partialSigAgg([clientPartial, serverPartial])`.

The relevant current app path is
`ArkadeRemoteIdentity.signMsg32WithCosigner`.

The server imports the same MuSig2 primitives from
`@scure/btc-signer/musig2.js` in `../server-arkade-v4/src/ArkadeServer.js`.
For the tree-session path, it:

1. Creates a short-lived tree session.
2. Derives the server cosigner key for the app's `client_pk33`.
3. Creates the server nonce with `nonceGen(serverPub, serverPriv,
   innerAggXonly, msg32)`.
4. Stores the 97-byte secret nonce server-side.
5. On `/arkade/tree/sign`, checks the nonce context has not changed.
6. Builds the same `Session`.
7. Computes `session.sign(serverSecNonce97, serverPriv)`.
8. Verifies its own partial before returning it.
9. Deletes and zeroes the secret nonce.

This is the best place to substitute a hardware cosigner because nonce
generation and partial signing are already separated.

## Why Server And Card Are Not Automatically Interchangeable

A MuSig2 partial signature is bound to one individual public key. Today the
wallet policy is effectively:

```text
taproot_musig2_with_csv_client_exit
cooperative path: musig2(client_pubkey, server_pubkey)
recovery path: client key after Nuri CSV delay
```

The server public key is derived from `COSIGNER_SEED_V4` in
`../server-arkade-v4/src/ArkadeDerive.js`. The derived `server_pubkey` is part
of the aggregate key and therefore part of the wallet address/policy.

Implication:

- A card with a different pubkey cannot sign for an existing
  `musig2(client_pubkey, server_pubkey)` address.
- To make the card sign the existing server-backed wallet, the card must hold
  the same derived cosigner private key, or the same account secret/chain-code
  derivation logic. That duplicates the server cosigner secret and is only
  acceptable for a controlled demo or a deliberate production key-custody
  decision.
- The clean production path is a new wallet/policy whose cooperative key is
  `musig2(client_pubkey, card_pubkey)`, or a larger policy that explicitly
  contains both server and card alternatives.

## Product Options

### Option A: Card Replaces Server For A New Wallet

Create a new card-backed Arkade wallet where the aggregate key is:

```text
musig2(client_pubkey, card_pubkey)
```

The app uses the same `@scure/btc-signer` host flow, but calls the card instead
of `/arkade/tree/nonce` and `/arkade/tree/sign`.

This is the smallest clean production design. It does not require importing the
server's cosigner key into the card, but it creates a different wallet address
from the current server-backed wallet.

### Option B: Card Signs As The Existing Server Cosigner

Install the same derived server cosigner key into the card, or install an
account key and implement the same `nuri-btc-cosigner-v4` derivation in the
card.

This lets the card produce partial signatures for the current
`musig2(client_pubkey, server_pubkey)` policy. It is useful for a demonstration,
but it has a serious key-management question: the same cosigner secret now
exists in both server infrastructure and card hardware.

### Option C: Server-Or-Card Policy

Define a new policy that explicitly supports both:

```text
path 1: musig2(client_pubkey, server_pubkey)
path 2: musig2(client_pubkey, card_pubkey)
path 3: delayed client recovery path
```

This is the best "either server or card" product model, but it is not a drop-in
replacement for the current two-key aggregate. It requires address/policy
migration and PSBT/taproot tree updates.

### Option D: PRF Hack

Use passkey PRF / CTAP2 `hmac-secret` to derive an app-side backup signing
secret, then sign in the app with `@scure/btc-signer`.

This can work as an offline backup/unlock mechanism, especially through the
native Android/iOS NFC probe when mobile browsers do not expose PRF. It is not
equivalent to a hardware signer, because the PRF output leaves the card and the
app can derive/use the secret.

### Option E: Server-Attached Card / HSM Mode

Attach a smartcard reader to the Nuri Arkade server and make the server routes
call the card for MuSig2 nonce generation and partial signing.

This is theoretically viable and is the closest model to a small HSM:

```text
nuri-expo app
  -> existing /arkade/tree/session-init, /arkade/tree/nonce, /arkade/tree/sign
  -> server verifies approval/session policy
  -> server sends APDUs to local smartcard
  -> smartcard returns server_pub_nonce66 and server_partial32
  -> server never sees/export the card private key
```

What this improves:

- The Arkade server process no longer holds the raw cosigner private key in RAM.
- A server backup/database leak does not leak the cosigner key.
- The existing app protocol can remain mostly unchanged if the card public key
  is the same key that the wallet policy expects.

What this does not solve by itself:

- A compromised server could still ask the attached card to sign malicious
  `msg32` values unless server-side approval/policy checks remain correct, or
  the card itself validates a richer transaction policy.
- If the card has a different pubkey than the current server cosigner key,
  existing wallet addresses still cannot use it without migration.
- This is not the same product as a user-held card tapped on a phone. It is
  server-side hardware key isolation.

Server-attached mode is an excellent first real-card test because the app can
stay on the current server API while the server-side signer backend changes
from software to card.

## Required Card Cosigner API

The card must not parse Bitcoin transactions. The host already has `scure` and
can build the exact session. The card should expose only this minimum API:

```ts
type CardCosigner = {
  getIndividualPubkey(): Promise<Uint8Array>; // 33-byte compressed secp256k1 key
  nonceGen(input: {
    sessionId: Uint8Array;        // 16 or 32 bytes
    aggregateXonly32: Uint8Array; // scure keyAggExport x-only form
    msg32: Uint8Array;            // BIP341 sighash
  }): Promise<Uint8Array>;        // 66-byte public nonce
  partialSign(input: {
    sessionId: Uint8Array;
    aggregateNonce66: Uint8Array;
    sortedPubkeys33: Uint8Array[];
    msg32: Uint8Array;
    tweak32?: Uint8Array;
    tweakIsXonly?: boolean;
  }): Promise<Uint8Array>;        // 32-byte MuSig2 partial signature
}
```

Security rules:

- `nonceGen` stores a secret nonce internally or returns an encrypted opaque
  secnonce blob that only the card can open later.
- `partialSign` consumes the nonce exactly once.
- The nonce must be bound to `sessionId`, key slot, aggregate key, message,
  public nonce, and protocol version.
- The host must verify the returned partial with `session.partialSigVerify`
  before aggregating.
- FIDO2 PRF key material and MuSig2 signing keys must stay in separate key slots
  or separate applets.

## Private Key Lifecycle On The Card

There are three realistic ways to get a cosigner private key onto the card.

### Preferred: Generate The Key On-Card

The card generates a secp256k1 private key internally and never exports it.

Provisioning flow:

1. Host selects the MuSig2 applet AID.
2. Host sends `KEYGEN` for a named slot, for example `arkade-cosigner-0`.
3. Card generates `sk_card` using card RNG.
4. Card stores `sk_card` in persistent card memory with an access policy:
   PIN, fingerprint, or both.
5. Card returns only `card_pubkey33`.
6. Server stores `card_pubkey33`, card serial/slot id, and optional attestation.
7. App/wallet policy is created with `musig2(client_pubkey, card_pubkey33)`.

This is the safest production model. The server never sees the private key.
It also means existing server-backed wallet addresses cannot use this card key
unless they migrate to a new card-backed policy.

### Migration/Demo: Import A Server-Compatible Key

For a controlled proof or migration, the server-derived cosigner key can be
loaded into the card once. After import, signing happens only on the card.

Provisioning flow:

1. Server derives the existing `nuri-btc-cosigner-v4` child key for a test
   `client_pubkey`, or derives/imports an account-level card key.
2. Host opens a secure GlobalPlatform/SCP channel or manufacturer-secure loader.
3. Host sends `IMPORT_KEY` to the MuSig2 applet.
4. Card stores the key as non-exportable.
5. Host deletes/zeroes the import material and disables software signing for
   that key slot.

This can make the card sign for a policy that already expects the server
pubkey. It is not the cleanest long-term model because the same secret existed
outside the card during provisioning.

### PRF-Derived App Key

The card can return a stable WebAuthn PRF output and the app/server derives a
software key from it.

This is useful as an offline backup or recovery mechanism, but it is not a
hardware signer. The derived key exists outside the card after PRF output.

## Minimal Server-Attached Test Plan

The first server-side proof does not need a real Java Card MuSig2 applet. It
should prove the backend boundary first:

```text
software backend
  -> same result as current server
card-sim backend
  -> same server API, but secret operation behind CardCosigner interface
apdu-sim backend
  -> same flow over APDU-shaped calls
real card backend
  -> same APDU contract after a MuSig2 applet is installed
```

The current CLI smoke script proves the first three modes:

```bash
npm run server:cosigner:software
npm run server:cosigner:card-sim
npm run server:cosigner:apdu-sim
npm run cli:e2e
```

Use `REAL_CARD=1 npm run cli:e2e` to include the real FIDO2 PRF PC/SC tests.
That proves the current physical FIDO2 card can be reached and returns PRF.

On 2026-06-14, the standalone Nuri MuSig2 applet was also installed on the
same Feitian sample:

```bash
gp -r 2 --load dist/nuri-musig2-v20-keygen.cap
gp -r 2 --package 4E5552494D5547 --applet 4E5552494D554701 --create 4E5552494D554701
npm run cosign:real-card:keygen
npm run card:musig2:test
```

The applet selected successfully at `4E5552494D554701` and the Python real-card
suite passed `6/6`. `npm run cosign:real-card:keygen` also passed with on-card
long-term key generation and final aggregate BIP340 signature verification.
That is a real device proof for the standalone APDU signer.
It is not yet the final Arkade signer backend because the server route still
needs to call this card API, bind nonce/session state to the current
`@scure/btc-signer` flow, and verify returned partials before aggregation.

There is now also a local HTTP/web proof for the final product shape:

```bash
npm run cosign:demo
npm run cosign:web
npm run cosign:web:real-card
```

`npm run cosign:demo` returns `NURI_CARD_COSIGN_FLOW_OK` with
`final_signature_verified=true`. `npm run cosign:web` serves
`http://127.0.0.1:8787/cosign-demo.html`, where a browser-triggered request
calls a local cosign server and receives a valid aggregate MuSig2/BIP340
signature. This proof uses `simulated-on-card-keygen`: the backend generates the
card key internally and returns only pubkey, nonce, and partial signature.

`npm run cosign:web:real-card` serves the same page with a real PC/SC card
backend. First use creates `.nuri-card-musig2/browser-real-card.json`, runs
`INS_KEYGEN` on the card, and saves the public wallet identity plus a local
demo client secret. Later browser-triggered signatures reuse the existing
non-exportable card key through `GET_PUBKEY` and fail if the public key no
longer matches the saved profile.

`npm run cosign:real-card:keygen` is the explicit keygen proof. It uses the
v1.10/KGEN applet `INS_KEYGEN` command, so the cosigner key is generated inside
the card and only `card_pubkey33` leaves the card. `npm run cosign:real-card`
uses the existing non-exportable card key and does not reprovision.

## Fit With This Repo

This repo already has the right host-side proof shape:

- `src/musig2/card-sim.js` proves a card-like object can generate nonce,
  partial-sign, and aggregate with `@scure/btc-signer/musig2.js`.
- `src/musig2/apdu-sim.js` proves the APDU framing and nonce replay rejection.
- `docs/musig2-card-extension.md` defines the current APDU concept.

Current limitation: the APDU simulator still uses a host-side `Session` object
registry for `PARTIAL_SIGN`. A real Java Card will not have that object. The
next implementation step is to replace that simulator shortcut with either:

1. a reduced Satochip-style input such as `a_i(32) || b(32) || parity(1) ||
   e(32)`, plus any tweak/global coefficient values required by the current
   `@scure/btc-signer@2.0.1` session; or
2. the upstream Satochip `musig2-support` APDU flow, where the card returns an
   encrypted secnonce and later signs using the host-provided BIP327 session
   context.

## Satochip Path

The upstream branch to use for real Java Card MuSig2 work is:

```text
https://github.com/Toporin/SatochipApplet/tree/musig2-support
```

That branch is newer than the old debug branch and includes nonce-reuse
protection. It is AGPL-licensed upstream, so code cannot be copied into this
MIT repo without a deliberate licensing decision. The clean path is to keep
Satochip as a reference/upstream dependency or obtain/rewrite the required
minimal MuSig2 applet code under compatible terms.

## Integration Point In `nuri-expo`

For the current Arkade path, introduce a small cosigner abstraction:

```ts
type ArkadeCosignerBackend = "server" | "card";

type ArkadeCosigner = {
  publicKey33(): Promise<string>;
  nonce(input: SignPayloadFields & { txid?: string }): Promise<{
    cosigner_pub_nonce66: string;
  }>;
  sign(input: SignPayloadFields & {
    cosigner_pub_nonce66: string;
    txid?: string;
  }): Promise<{
    cosigner_partial32: string;
    cosigner_pub_nonce66: string;
    cosigner_pubkey: string;
  }>;
};
```

The existing server implementation wraps:

- `arkadeTreeNonce`
- `arkadeTreeSign`
- existing approval-token checks

The card implementation wraps:

- NFC/PCSC APDUs
- local user presence / PIN / fingerprint where available
- no server-side cosigner private key

`ArkadeRemoteIdentity.signMsg32WithCosigner` can then verify and aggregate
against `cosigner_pubkey` instead of assuming it is always `serverPk33`.

## Next Concrete Work

1. Add a `CardCosigner` host adapter in this repo that uses the same values as
   `ArkadeRemoteIdentity.signMsg32WithCosigner`.
2. Remove the host-side `Session` registry shortcut from the APDU simulator and
   replace it with reduced session-context bytes that a Java Card can verify
   and sign.
3. Re-run `npm test` and `npm run musig2:demo`.
4. Port the APDU contract to Java Card, preferably by narrowing the Satochip
   `musig2-support` branch or a clean-room minimal signer.
5. Add a server-side prototype in `server-arkade-v4` behind
   `ARKADE_COSIGNER_BACKEND=software|card-sim|card-pcsc`.
6. Add an app-side prototype in `nuri-expo` behind a `card` cosigner flag.
7. For existing wallets, decide explicitly between:
   - same server cosigner key on card, demo only unless accepted; or
   - new card-backed wallet/policy; or
   - new server-or-card taproot policy and migration.
