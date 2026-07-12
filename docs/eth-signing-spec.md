# Nuri Card Ethereum Signing — Specification & Integration Plan

> Current status: implemented and real-card proven as applet v1.3. The complete
> source is `card/eth/`, the reproducible CAP is `dist/nuri-eth-signer.cap`, and
> the safe existing-key acceptance command is `python3 scripts/card-eth-test.py`.
> The implementation-plan sections below are retained as design history; use
> `docs/card-v1-release.md` and `docs/card-v1-acceptance.md` operationally.

Add standard secp256k1 ECDSA signing to the Nuri smartcard so it becomes a
**hardware Ethereum/EVM wallet** alongside its existing Bitcoin, SSH, and TOTP
capabilities. The private key is generated on-card and never leaves the secure
element — same security model as Bitcoin MuSig2 and FIDO2 SSH.

---

## Table of contents

- [What it does](#what-it-does)
- [Why this works (the card already has the hard part)](#why-this-works-the-card-already-has-the-hard-part)
- [Architecture: phone + card flow](#architecture-phone--card-flow)
- [Applet specification](#applet-specification)
- [Host-side ethers.js signer](#host-side-ethersjs-signer)
- [APDU reference](#apdu-reference)
- [Security model](#security-model)
- [Historical implementation plan](#historical-implementation-plan-completed)
- [Testing](#testing)
- [Future: on-card keccak256](#future-on-card-keccak256)

---

## What it does

The card becomes a hardware Ethereum wallet:

- **Key generation on-card.** A secp256k1 private key is generated inside the
  card's secure element. The card returns only the 33-byte compressed public
  key. The private key never leaves — no export APDU exists.
- **Transaction signing on-card.** The phone/computer hashes the Ethereum
  transaction with keccak256 (standard — `ethers` / `@noble/hashes` does this),
  sends the 32-byte hash to the card, the card computes the ECDSA signature
  `(r, s, v)`, and the phone broadcasts the signed transaction.
- **Same card, more chains.** One card does SSH + Bitcoin (MuSig2) + Ethereum
  (ECDSA) + TOTP + passkey login — all with independent keys in one secure
  element.

---

## Why this works (the card already has the hard part)

The card's MuSig2 applet already proves these primitives work on this exact
hardware (Feitian JCOP, OS 2025-05-14):

| Primitive (secp256k1) | Proven by | ECDSA needs it? |
|---|---|---|
| Key generation (`KeyPair.genKeyPair()` on secp256k1) | ✅ MuSig2 `INS_KEYGEN` | ✅ yes — same |
| EC point multiply (`ALG_EC_SVDP_DH_PLAIN_XY`) | ✅ MuSig2 nonce gen | ✅ yes — for `r = (k·G).x mod n` |
| Scalar arithmetic on-card | ✅ MuSig2 partial sign (`s = k + e·a·sk`) | ✅ yes — for `s = k⁻¹(z + r·d) mod n` |

Standard ECDSA is **simpler than MuSig2**:
- MuSig2: `s = k + e·a·sk` (coefficient `a`, aggregate key, nonce aggregation)
- ECDSA: `s = k⁻¹(z + r·d) mod n` (single key, modular inverse)

The only new operation is **modular inverse** (`k⁻¹ mod n`), which is a
~30-line extended-GCD implementation in Java Card. No new hardware primitive
needed — the card already does everything else.

**keccak256 stays on the host.** This is how every hardware wallet does
Ethereum (Ledger, Trezor, GridPlus). The card signs a 32-byte hash; it never
needs to understand Ethereum, RLP, gas, or keccak. This keeps the applet tiny
and the audit surface minimal.

---

## Architecture: phone + card flow

```
┌──────────────┐
│  Phone /     │  ethers.js / @noble/hashes
│  Computer    │
└──────┬───────┘
       │ 1. Build Ethereum transaction (legacy or EIP-1559)
       │ 2. keccak256(RLP-encoded tx) → 32-byte hash z
       │
       ▼
┌──────────────┐     NFC tap or PC/SC reader
│  Card reader │     (user taps card = user presence)
└──────┬───────┘
       │ 3. APDU: ECDSA_SIGN(z, key_slot)
       ▼
┌──────────────┐
│  Nuri card   │  secp256k1 ECDSA on-card
│  ECDSA applet│
│              │  4. Generate random nonce k (TRNG)
│              │  5. r = (k·G).x mod n
│              │  6. s = k⁻¹(z + r·d) mod n
│              │  7. v = 27 + parity(k·G.y)  [for EIP-155: v = 0/1]
│              │  (private key d never leaves)
└──────┬───────┘
       │ 8. Card returns: r(32) || s(32) || v(1)
       ▼
┌──────────────┐
│  Phone /     │  9.  Assemble signed tx: rawTx + (r, s, v)
│  Computer    │  10. Broadcast to Ethereum network
└──────────────┘
```

---

## Applet specification

### AID

```text
4E 55 52 49 45 54 48 01    ("NURIETH1")
```

### Java Card class: `com.nuri.eth.NuriEcdsaSigner`

A minimal applet (~200 lines) that:

1. **Generates** a secp256k1 key pair on-card (one-time, at provisioning).
2. **Stores** the private key in the card's protected key store.
3. **Signs** a 32-byte hash with ECDSA, returning `(r, s, v)`.
4. **Returns** the public key on request (for address derivation on the host).

### Key storage

| Key | Type | Storage |
|---|---|---|
| secp256k1 private key | `ECPrivateKey` (secp256k1 parameters) | Card key store, non-exportable |
| secp256k1 public key | `ECPublicKey` | Derived from private key, returned to host on request |

The applet uses `KeyBuilder.TYPE_EC_F2M_PRIVATE` or
`KeyBuilder.TYPE_EC_FP_PRIVATE` with secp256k1 domain parameters, same as the
MuSig2 applet. The key is generated via `KeyPair.genKeyPair()` — same call that
MuSig2 `INS_KEYGEN` uses and that is already proven on this card.

### Modular inverse

Java Card does not have a built-in modular inverse for the secp256k1 order `n`.
The applet implements it with the extended Euclidean algorithm (~30 lines):

```java
// Modular inverse via extended GCD: a^-1 mod n
// n = secp256k1 order: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
private static byte[] modInverse(byte[] a, byte[] n) {
    // Extended Euclidean algorithm, 256-bit operands
    // Returns a^-1 mod n as 32-byte big-endian
    // ... ~30 lines of BigInteger-free arithmetic on byte arrays
}
```

Alternatively, use `javacardx.crypto.BigInteger` if the card supports it
(JC 3.0.5+ — this card is JC 3.0.5). That makes it a one-liner:

```java
BigInteger inv = BigInteger.valueOf(a).modInverse(BigInteger.valueOf(n));
```

### User presence (tap)

Every `ECDSA_SIGN` command requires user presence. The applet checks a
presence flag set by the card's physical interface (same mechanism FIDO2
uses). On the Feitian BioCARD, this is the NFC tap or the contact pad.

---

## Host-side ethers.js signer

A custom `ethers.Signer` subclass that routes signing through the card:

```typescript
// src/eth/NuriCardSigner.ts
import { ethers } from "ethers";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import { NuriCardTransport } from "./transport"; // PC/SC or NFC bridge

export class NuriCardSigner extends ethers.Signer {
  readonly transport: NuriCardTransport;
  readonly keySlot: number;
  private _address: string | null = null;

  constructor(transport: NuriCardTransport, provider?: ethers.Provider, keySlot = 0) {
    super();
    this.transport = transport;
    this.keySlot = keySlot;
    if (provider) this.provider = provider;
  }

  // Get the Ethereum address (keccak256(pubkey)[12:])
  async getAddress(): Promise<string> {
    if (this._address) return this._address;
    const pubKey = await this.transport.ecdsaGetPubkey(this.keySlot); // 33 bytes compressed
    const uncompressed = secp256k1.getPublicKey(pubKey).slice(1); // 64 bytes (x||y)
    const hash = keccak_256(uncompressed);
    this._address = ethers.getAddress("0x" + Buffer.from(hash.slice(12)).toString("hex"));
    return this._address;
  }

  // Sign a transaction (ethers calls this)
  async signTransaction(tx: ethers.TransactionRequest): Promise<string> {
    const txObj = await this.populateCall(tx);
    const unsignedTx = ethers.Transaction.from(txObj);
    const rawTxHex = unsignedTx.unsignedSerialized;
    const msgHash = keccak_256(Buffer.from(rawTxHex.slice(2), "hex")); // host hashes
    const sig = await this.transport.ecdsaSign(this.keySlot, msgHash); // card signs
    const signedTx = unsignedTx.addSignature(sig.r, sig.s, sig.v);
    return signedTx.serialized;
  }

  // Sign a message (EIP-191 personal_sign)
  async signMessage(message: ethers.Message): Promise<string> {
    const msgBytes = typeof message === "string" && !message.startsWith("0x")
      ? Buffer.from(message) : Buffer.from(message.slice(2), "hex");
    const prefixed = Buffer.concat([
      Buffer.from("\x19Ethereum Signed Message:\n"),
      Buffer.from(msgBytes.length.toString()),
      msgBytes,
    ]);
    const msgHash = keccak_256(prefixed);
    const sig = await this.transport.ecdsaSign(this.keySlot, msgHash);
    return ethers.Signature.from({
      r: "0x" + sig.r.toString(16).padStart(64, "0"),
      s: "0x" + sig.s.toString(16).padStart(64, "0"),
      v: 27 + sig.v,
    }).serialized;
  }

  // Sign typed data (EIP-712 signTypedData)
  async signTypedData(domain: ethers.TypedDataDomain, types: ethers.TypedDataTypes, value: Record<string, any>): Promise<string> {
    const msgHash = ethers.TypedDataEncoder.hash(domain, types, value);
    const sig = await this.transport.ecdsaSign(this.keySlot, Buffer.from(msgHash.slice(2), "hex"));
    return ethers.Signature.from({
      r: "0x" + sig.r.toString(16).padStart(64, "0"),
      s: "0x" + sig.s.toString(16).padStart(64, "0"),
      v: 27 + sig.v,
    }).serialized;
  }
}
```

### Transport (PC/SC or NFC)

The transport layer sends the APDU and parses the response. On desktop it
uses the same Python `fido2` + `pyscard` stack as the SSH provider. On phone it
uses the native NFC ISO-DEP path (same as the existing mobile PRF probe).

```typescript
// src/eth/NuriCardTransport.ts
export interface NuriCardTransport {
  ecdsaGetPubkey(slot: number): Promise<Uint8Array>; // 33 bytes compressed
  ecdsaSign(slot: number, hash: Uint8Array): Promise<{ r: Uint8Array; s: Uint8Array; v: number }>;
}

export class NuriCardPcscTransport implements NuriCardTransport {
  // Calls the Python helper over PC/SC — same pattern as ssh-pcsc-sk-helper.py
  async ecdsaGetPubkey(slot: number): Promise<Uint8Array> {
    // APDU: SELECT NURIETH1 AID, then INS_GET_PUBKEY
    // Returns 33-byte compressed pubkey
  }
  async ecdsaSign(slot: number, hash: Uint8Array): Promise<{r: Uint8Array; s: Uint8Array; v: number}> {
    // APDU: SELECT NURIETH1 AID, then INS_SIGN with hash
    // Tap card when prompted
    // Returns r(32) || s(32) || v(1)
  }
}
```

---

## APDU reference

All commands use **CLA `0x00`** (matching the MuSig2 applet's convention).

### SELECT

```text
CLA=00 A4 04 00 08  4E 55 52 49 45 54 48 01
SW=9000 on success
```

### INS_GET_VERSION (`0x01`)

Returns applet version + build.

```text
Command:  00 01 00 00 00
Response: [version_major(1)] [version_minor(1)] [build(4)]  9000
```

### INS_GET_PUBKEY (`0x02`)

Returns the on-card secp256k1 public key (compressed, 33 bytes). The host
derives the Ethereum address from it: `keccak256(uncompressed_pubkey)[12:]`.

```text
Command:  00 02 00 00 01 [slot]  00
Response: [pubkey_33_bytes]  9000
```

### INS_KEYGEN (`0x03`)

Generates a new secp256k1 key pair on-card. Overwrites any existing key in
the slot. Returns the compressed public key. The private key never leaves.

```text
Command:  00 03 00 00 01 [slot]  00
Response: [pubkey_33_bytes]  9000
```

If the slot already has a key and overwrite is not allowed, returns
`SW=6985` (conditions not satisfied). Set P1=1 to force overwrite:
`00 03 01 00 01 [slot] 00`.

### INS_SIGN (`0x04`)

Signs a 32-byte hash with ECDSA. **Requires user presence** (card tap).

```text
Command:  00 04 00 00 21 [slot] [hash_32_bytes]  00
          └── Lc=0x21 (33 bytes: 1 slot + 32 hash) ──┘

Response: [r_32_bytes] [s_32_bytes] [v_1_byte]  9000
          └── 65 bytes total ─────────────────────────┘

v = 0 or 1 (EIP-155 compatible; host adds 27 for legacy, or uses as-is for EIP-155)
```

If user presence is not satisfied (no tap within timeout), returns
`SW=6985` (conditions not satisfied).

If the slot has no key, returns `SW=6A81` (function not supported).

### INS_DERIVE_ADDRESS (`0x05`, optional)

Returns the Ethereum address (20 bytes) computed on-card. This requires
keccak256 on-card (see [Future: on-card keccak256](#future-on-card-keccak256)).
If keccak is not available on-card, the host derives the address instead and
this INS returns `SW=6D00` (INS not supported).

---

## Security model

| Property | How |
|---|---|
| Private key never leaves card | Generated on-card via `KeyPair.genKeyPair()`; no export APDU |
| Every signature requires a tap | `INS_SIGN` checks user presence flag (same as FIDO2 UP) |
| Nonce is random, never reused | TRNG generates k per sign; applet clears k immediately after use |
| Key is sequestered from other applets | Separate AID from FIDO2 and MuSig2; applet isolation enforced by the card OS |
| Host cannot extract key | The applet only accepts `INS_SIGN` (hash in, signature out) and `INS_GET_PUBKEY` (public only) |
| Replay resistance | ECDSA nonce is random per signature; same hash → different signature each time (unlike HMAC which is deterministic) |

### Nonce policy (critical)

ECDSA is **far more sensitive to nonce reuse than MuSig2**. If the same `k` is
ever used for two different hashes, the private key can be recovered
algebraically. The applet MUST:

1. Use the card's TRNG for `k` (not deterministic derivation).
2. Clear `k` from RAM immediately after computing `(r, s)`.
3. Reject a second `INS_SIGN` for the same session until a new nonce is
   generated (one-shot per sign call — each call generates fresh `k`).
4. Never accept a host-supplied nonce.

This is the same one-shot pattern the MuSig2 applet uses (`PARTIAL_SIGN`
consumes and clears the nonce).

---

## Historical implementation plan (completed)

### Phase 1: Applet (Java Card)

1. **Write `NuriEcdsaSigner.java`** following the `card/totp/NuriOathTotp.java`
   pattern:
   - `install()` → register with AID `4E55524945544801`
   - `process()` → dispatch on `OFFSET_INS`
   - `INS_KEYGEN` → `KeyPair.genKeyPair()` on secp256k1, return compressed pubkey
   - `INS_GET_PUBKEY` → return stored compressed pubkey
   - `INS_SIGN` → ECDSA sign: generate `k` via TRNG, compute `r = (k·G).x mod n`,
     `s = k⁻¹(z + r·d) mod n`, return `r || s || v`
   - Modular inverse: extended GCD on byte arrays, or `javacardx.crypto.BigInteger`
   - secp256k1 domain parameters: same constants as the MuSig2 applet uses

2. **Build** with the portable `card/eth/build.xml` target:
   ```xml
   <javacard jckit="${jckit.path}">
     <cap aid="4E555249455448" version="1.0" output="../dist/nuri-eth-signer.cap"
          sources="." jca="3.0.4">
       <applet class="com.nuri.eth.NuriEcdsaSigner" aid="4E55524945544801"/>
     </cap>
   </javacard>
   ```

3. **Install** on the card:
   ```bash
   npm run card:eth:install   # or: gp -install dist/nuri-eth-signer.cap
   ```

### Phase 2: Host bridge (Python + ethers.js)

4. **Python helper** (`scripts/card-eth-sign.py`): PC/SC APDU bridge — same
   pattern as `scripts/real-card-cosign-proof.py`. Sends `INS_SIGN`, parses
   `r || s || v`.

5. **ethers.js signer** (`src/eth/NuriCardSigner.ts`): the `ethers.Signer`
   subclass above. Wraps the Python bridge or talks NFC directly on mobile.

6. **Integration test**: generate a key on the card, derive the Ethereum
   address, sign a transaction on a testnet, broadcast, verify on-chain.

### Phase 3: Mobile (NFC)

7. **Extend the mobile NFC probe** (`mobile/expo-nfc-prf-probe/`) to send
   `INS_SIGN` over ISO-DEP. Same NFC path the PRF probe already uses.

8. **Wallet UI**: a phone screen that shows the card's Ethereum address and
   prompts "tap card to sign" for each transaction.

---

## Testing

### Unit tests (host-side, no card)

```typescript
// test/eth-signer.test.ts
// 1. Mock transport returns deterministic (r, s, v)
// 2. Verify ethers can parse the signature
// 3. Verify ecrecover recovers the card's address
```

### Real-card tests

```bash
# 1. Install the applet
npm run card:eth:install

# 2. Generate a key on the card → get Ethereum address
npm run card:eth:keygen   # prints: pubkey 0x..., address 0x...

# 3. Sign a test hash and verify
npm run card:eth:sign:test   # signs a known hash, verifies ecrecover

# 4. Sign a real Sepolia testnet transaction and broadcast
npm run card:eth:sign:tx -- --to=0x... --value=0.001 --network=sepolia

# 5. Verify on Etherscan
# → https://sepolia.etherscan.io/tx/...
```

### ECDSA nonce test (critical security check)

```bash
# Sign the same hash twice → MUST get different (r, s) each time
# (proves nonce is random, not reused)
npm run card:eth:nonce:test
# Expected: r1 != r2 (random nonce each time)
```

---

## Future: on-card keccak256

If the card later supports keccak256 (either via a Feitian vendor API or a
pure-Java Keccak implementation), the applet can add `INS_DERIVE_ADDRESS` and
`INS_SIGN_TX` (raw transaction in, signed tx out) so the card hashes
internally. This would mean:

- The card validates what it's signing (not just a blind hash).
- The host never sees the pre-image (stronger privacy).
- EIP-712 typed data could be verified on-card before signing.

But this is **not required** for a working Ethereum hardware wallet. Every
existing hardware wallet (Ledger, Trezor) hashes on the host and signs a
pre-computed hash. The security trade-off is standard and acceptable: the
card protects the *key*, the host computes the *hash*. If the host is
compromised it could sign a malicious tx, but it can't steal the key — and
the tap-to-sign requirement means the user must consciously approve each
transaction.

---

## Dependencies

| Library | Already in repo? | Purpose |
|---|---|---|
| `@noble/curves` (secp256k1) | ✅ (`package.json`) | Public key handling, address derivation |
| `@noble/hashes` (keccak256) | ✅ (transitive dep of `@noble/curves`) | Host-side transaction hashing |
| `ethers` | ❌ — add as dev dep | Ethereum transaction encoding, signing interface |
| `pyscard` / `fido2` | ✅ (in venv) | PC/SC transport |
| Java Card SDK (JC 3.0.4) | ✅ pinned by the Card V1 builder | Applet compilation |

---

## Provenance

This specification is based on:

- The MuSig2 applet's proven secp256k1 keygen + sign (confirmed on this card,
  block `308802` Bitcoin signet transaction).
- The OATH-TOTP applet's pattern (`card/totp/NuriOathTotp.java` — shows
  the minimal Java Card applet structure).
- The FIDO2 applet's user-presence mechanism (card tap = `UP=1`).
- The existing `@noble/curves` secp256k1 and `@noble/hashes` keccak256
  already in `package.json`.
