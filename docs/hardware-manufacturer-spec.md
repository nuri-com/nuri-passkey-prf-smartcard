# Hardware Manufacturer Test Specification

## Summary

We need a low-cost Java Card or equivalent secure element that can run a FIDO2 CTAP2 applet with passkey authentication and browser PRF support. Browser PRF is implemented by WebAuthn clients on top of the CTAP2 `hmac-secret` authenticator extension, so `hmac-secret` is the required card-side primitive.

Secondary, optional work is a separate Taproot/MuSig2 partial-signing applet. This is not required for the first card qualification.

## Priority

1. FIDO2 passkey authentication.
2. CTAP2 `hmac-secret`, exposed to browsers as WebAuthn `prf`.
3. Resident/discoverable credentials.
4. PIN or user-verification support compatible with CTAP2 client PIN / PIN-UV auth.
5. Optional second AID for secp256k1 MuSig2 partial signing.

## Applet Baseline

The FIDO2 baseline is the Bryan Jacobs FIDO2Applet lineage:

- Source: `https://github.com/BryanJacobs/FIDO2Applet`
- Tested ref in this harness: `fb827954cd091a1810163ce51d2f86d42d0b8e20`
- Package AID: `A000000647`
- Applet AID: `A0000006472F0001`

The local harness builds this baseline in jCardSim and runs the CTAP2 hmac-secret tests plus a custom browser PRF mapping test.

## Required Card Capabilities

Minimum for FIDO2/PRF:

- Java Card Classic 3.0.4 or newer, or a compatible vendor profile.
- GlobalPlatform install and delete support, preferably SCP03.
- Contact ISO/IEC 7816 T=1 and/or contactless ISO/IEC 14443 Type A.
- P-256 key generation.
- ECDSA with SHA-256.
- ECDH plain shared-secret output.
- SHA-256.
- AES-256 CBC no padding.
- Secure random/TRNG.
- Transient memory support for request buffers and PIN/UV tokens.
- Persistent storage for resident credentials and hmac-secret credential secrets.
- APDU buffer compatible with short APDUs; extended APDU/chaining support is useful.

Recommended memory target:

- At least 100 KB user EEPROM/NVM for the FIDO2 applet and credentials.
- At least 2.5 KB RAM.
- More NVM is better if resident credentials are expected.

## Candidate Cards

Likely first test cards:

- NXP JCOP3 J3H145 class: Java Card 3.0.4 Classic, GlobalPlatform 2.2.1, dual interface, P-256/ECDSA class ECC, AES-256, SHA-256, TRNG, around 144 KB EEPROM advertised by suppliers.
- NXP JCOP4 J3R180 class: Java Card 3.0.5 Classic, GlobalPlatform 2.3, JCOP4, AES-256, SHA-2, ECC over GF(p) up to 521 bits, around 180 KB advertised flash/NVM.

Cheapest cards seen during research:

- J3H145: about EUR 29.99 from MoTechno, with volume discounts; CardLogix listing showed USD 9.78 but out of stock during research.
- J3R180: around USD 14-17 from low-cost online sellers, but provenance and default GlobalPlatform keys must be verified.

For a serious manufacturer quote, prefer a vendor who can provide JCAlgTest output, GlobalPlatform key information, and sample cards with documented SCP settings.

## Optional MuSig2 Extension

Use a separate applet/AID:

- Proposed AID: `4E5552494D555349473201`
- CLA: `0x80`
- `GET_VERSION` (`0x01`)
- `GET_INDIVIDUAL_PUBKEY` (`0x10`)
- `NONCE_GEN` (`0x20`)
- `PARTIAL_SIGN` (`0x30`)
- `RESET_SESSION` (`0x40`)

Requirements:

- secp256k1 scalar arithmetic.
- secp256k1 base-point multiplication.
- SHA-256 and BIP340/BIP327 tagged-hash compatibility.
- Secret nonce never exported.
- Partial signing consumes and clears the nonce.

If the card Java Card API does not expose secp256k1 or generic EC arithmetic, MuSig2 should remain a host-side simulation or require a vendor native library. Do not block FIDO2/PRF card selection on MuSig2.

## Acceptance Tests

Simulator acceptance:

```bash
npm install
npm test
npm run fido2:test-prf
```

Browser smoke test:

```bash
npm run web:prf
```

Open `http://localhost:8765/prf-test.html`, register a passkey, then authenticate with PRF. This tests browser WebAuthn PRF only with authenticators the browser can see. A PC/SC card in a reader is not automatically a browser roaming authenticator unless the platform/browser has a usable NFC path or CTAP bridge.

Physical card acceptance:

1. Manufacturer confirms the algorithms and memory above.
2. Install the FIDO2Applet CAP under AID `A0000006472F0001`.
3. Run `fido2-token -L` or equivalent libfido2/Python enumeration through the selected transport.
4. Register a discoverable credential.
5. Authenticate with CTAP2 `hmac-secret`.
6. Use the localhost PRF page to confirm browser PRF if the card is browser-visible.

## Questions For Manufacturer

- Exact chip and OS name/version?
- Java Card version and GlobalPlatform version?
- Supported SCP variant and default key provisioning flow?
- Can you provide JCAlgTest output for the exact card batch?
- Does ECC include P-256 with ECDSA SHA-256 and ECDH plain output?
- Does the card support AES-256 CBC no padding and SHA-256?
- How much user NVM, RAM, and commit capacity is available after OS options?
- Does contactless mode support ISO 14443-4 APDUs for this applet?
- Are extended APDUs or command chaining supported?
- Can you preload CAP files and inject per-card attestation material?
- Can you provide unlocked development samples with known GlobalPlatform keys?
- What is the lowest MOQ and sample lead time?

## References

- WebAuthn Level 3 PRF extension: `https://www.w3.org/TR/webauthn-3/`
- FIDO CTAP2.1 hmac-secret extension: `https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html`
- Bryan Jacobs FIDO2Applet: `https://github.com/BryanJacobs/FIDO2Applet`
- scure MuSig2 API: `https://github.com/paulmillr/scure-btc-signer#musig2`
- BIP327 MuSig2: `https://bips.dev/327/`
