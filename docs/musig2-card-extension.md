# MuSig2 Card Extension

## Compatibility Target

The host-side compatibility target is `@scure/btc-signer/musig2.js`, which exposes BIP327-style helpers:

- `IndividualPubkey(secretKey)`
- `sortKeys(pubkeys)`
- `keyAggregate(sortedPubkeys)`
- `keyAggExport(context)`
- `nonceGen(individualPubkey, secretKey, aggregatePubkey, msg)`
- `nonceAggregate(publicNonces)`
- `new Session(aggregateNonce, sortedPubkeys, msg)`
- `session.sign(secretNonce, secretKey)`
- `session.partialSigAgg(partialSignatures)`

The card does not need to construct Bitcoin transactions or PSBTs. It only needs to participate as one signer.

This repo includes a method-level simulator in `src/musig2/card-sim.js` and an APDU framing simulator in `src/musig2/apdu-sim.js`. They prove compatibility with `@scure/btc-signer/musig2.js` before any Java Card implementation work starts.

## APDU Contract

Dedicated AID:

```text
4E 55 52 49 4D 55 53 49 47 32 01
```

Commands use CLA `0x80`.

| INS | Name | Input | Output |
| --- | --- | --- | --- |
| `0x01` | GET_VERSION | empty | version/build bytes |
| `0x10` | GET_INDIVIDUAL_PUBKEY | key slot | individual pubkey, scure-compatible |
| `0x20` | NONCE_GEN | key slot, aggregate x-only pubkey, msg32, session id | public nonce |
| `0x30` | PARTIAL_SIGN | key slot, aggregate nonce, sorted pubkeys hash or explicit signer coefficient context, msg32, session id | partial signature |
| `0x40` | RESET_SESSION | session id | empty |

For the smallest first Java Card implementation, `PARTIAL_SIGN` can use the existing Satochip-style reduced input:

```text
a_i(32) || b(32) || parity(1) || e(32)
```

and return:

```text
s_i(32)
```

The host computes aggregation context using `@scure/btc-signer/musig2.js`, then verifies the partial signature before final aggregation. This keeps expensive parsing and transaction policy off-card.

## State Rules

- Each `NONCE_GEN` creates one secret nonce pair and one session id.
- `PARTIAL_SIGN` consumes and clears that nonce.
- A second `PARTIAL_SIGN` for the same session must fail.
- Session ids must bind at least: key slot, aggregate pubkey, msg32, public nonce, and protocol version.
- The card must never export secret nonces or internal private keys.

## Taproot Internal Key

For Taproot key-path signing, the host should:

1. Aggregate individual MuSig2 pubkeys with scure.
2. Treat the aggregate x-only key as the Taproot internal key.
3. Apply the TapTweak on host, or use scure's taproot transaction signing path around the MuSig2 result.
4. Ask the card only for its MuSig2 partial signature over the BIP341 sighash message.

That makes the card compatible with scure while keeping Taproot script/PSBT policy host-side.

## Security Notes

- Deterministic nonce generation is acceptable only if it includes private key, aggregate key, message, session id, and high-quality card randomness. Prefer randomized BIP327 nonce generation.
- Never allow caller-supplied raw nonce secrets.
- Verify all input lengths exactly.
- Return partial signatures only once per nonce.
- Keep the FIDO2 PRF key material separate from Bitcoin signing keys.
