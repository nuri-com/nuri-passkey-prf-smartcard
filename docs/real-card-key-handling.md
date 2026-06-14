# Real Card Key Handling

This file is intentionally non-secret. Do not commit GlobalPlatform/SCP keys, Feitian vendor keys, exported development keys, attestation private keys, PINs, or card seed material to this repository.

## Current Target Cards

Keep these categories separate during testing:

| Category | Meaning | Current state |
| --- | --- | --- |
| Feitian fingerprint/FIDO2 sample | The card currently being tested by PC/SC and phone NFC. | Active target for FIDO2 PIN, auth, and PRF. Fingerprint integration is not implemented in the clean CAP yet. |
| J3R150/J3R180/J3R200/J3H145 Java Cards | Blank or unfused JavaCard buy candidates for loading this CAP. | Not the same as the Feitian fingerprint card unless a seller explicitly says so. Need GP/SCP keys and algorithm confirmation. |
| MuSig2/Satochip work | Optional second applet/AID for Taproot partial signing. | Installed and tested on the current sample as `4E5552494D554701`; still not audited or fingerprint-gated. |

## When Keys Are Needed

No GlobalPlatform keys are needed for these operations:

- PC/SC reader inventory.
- CTAP/FIDO2 `getInfo`.
- FIDO2 makeCredential/getAssertion tests.
- CTAP/FIDO2 reset through `npm run card:reset`.
- FIDO2 PIN status, set, change, and verify through CTAP `clientPin`.

GlobalPlatform/SCP keys are needed for these operations:

- Listing applets with authenticated GP access on a non-default-key card.
- Deleting applets/packages.
- Installing `dist/FIDO2.cap`.
- Loading a fingerprint integration applet or Satochip/MuSig2 applet.
- Changing card manager keys.

The current contact sample observed on 2026-05-20 accepted the GlobalPlatformPro default development key and used SCP02 DES3 keys. Do not assume other samples do the same.

## Current Reader Mapping

Observed with HID Global OMNIKEY 5422:

| Physical card | PC/SC/OpenSC reader | GlobalPlatformPro reader | Current status |
| --- | --- | --- | --- |
| Feitian fingerprint/FIDO2 contact sample | `opensc-tool -r 1 ...` | `gp -r2 ...` or `GP_READER_INDEX=2` | Present, ATR `3B:80:80:01:01`, OpenSC name `MuscleApplet`, GP applet list accessible with default development key. |
| Feitian fingerprint/FIDO2 over phone NFC | Native Apple/browser NFC prompt | Not controlled by GP tooling here | Recognized by phone and asks for PIN, but the phone-side PIN setup loop must be diagnosed with the browser test page and PC/SC PIN status. |

Use exactly one active card while testing, and label command output with the physical sample.

On 2026-05-20, macOS `system_profiler SPSmartCardsDataType` reported:

- `HID Global OMNIKEY 5422 Smartcard Reader 01`: no card present.
- `HID Global OMNIKEY 5422 Smartcard Reader`: ATR `3B80800101`.

After CTAP reset on the original preinstalled contact sample, direct CTAP `hmac-secret` worked only with `up=false`. Normal user-presence (`up=true`) assertions still failed with CTAP `0x27 OPERATION_DENIED`.

After deleting package `A0000006472F` and reinstalling this repo's clean `dist/FIDO2.cap`, the contact card passed `npm run card:test` with `REAL_CARD_WEBAUTHN_PRF_OK`. The installed package is now `A000000647` version `0.4` with applet `A0000006472F0001`.

After loading `dist/nuri-musig2-v20-keygen.cap`, the same card also has the Nuri MuSig2 applet installed:

- package `4E5552494D5547`, version `1.9`
- applet `4E5552494D554701`
- applet-reported version `1.10`, build `KGEN`
- on-card key generation command `INS_KEYGEN = 0x04`
- `npm run card:musig2:test` passed with `Result: 6/6 tests passed`
- `npm run cosign:real-card` passed with `REAL_CARD_COSIGN_FLOW_OK`

Current MuSig2 status: v1.10/KGEN signs on the real card and creates the long-term cosigner key on-card. The key is non-exportable at the applet API level: the host receives only the compressed public key, nonces, and partial signatures.

Current `getInfo` after clean CAP install:

- `versions`: `FIDO_2_0`, `FIDO_2_1`, `FIDO_2_1_PRE`
- `extensions`: `uvm`, `credBlob`, `credProtect`, `hmac-secret`, `largeBlobKey`, `minPinLength`
- `clientPin`: `false`
- `pin_uv_protocols`: `[2, 1]`
- `min_pin_length`: `4`
- `max_pin_length`: `63`
- `makeCredUvNotRqd`: `true`

`clientPin: false` means the card supports CTAP client PIN and no PIN is currently set. It does not mean a fixed factory PIN exists.

## PIN Workflow

The FIDO2 PIN lives on the card. A production card should be shipped without a shared preset PIN; the first user sets it through CTAP `clientPin setPin`.

For deterministic development, use the PC/SC path first:

```bash
npm run card:pin:status
npm run card:pin:set
npm run card:pin:verify
npm run card:test
```

Expected state transition:

1. Before setting: `clientPin: false`.
2. After `card:pin:set`: `FIDO2_PIN_SET_OK` and `clientPin: true`.
3. After `card:pin:verify`: `FIDO2_PIN_VERIFY_OK`.
4. `npm run card:test` should still print `REAL_CARD_WEBAUTHN_PRF_OK`.
5. `npm run card:test:pin` should prompt for the PIN and still print `REAL_CARD_WEBAUTHN_PRF_OK`.

If the phone loops while asking to enter the new PIN twice, check the PC/SC status immediately. If `clientPin` is still `false`, the phone did not complete CTAP `setPin`. If `clientPin` changed to `true`, the phone may be failing later during registration or PRF and the browser page output matters.

Do not paste PINs into chat, commit logs, environment files, or npm arguments.

## Browser/NFC Workflow

Start the local test page:

```bash
npm run web:prf
```

For phone testing, expose it through HTTPS, for example with ngrok:

```bash
ngrok http 8765
```

Open the HTTPS tunnel URL ending in `/prf-test.html` on the phone.

Test in this order:

1. `User verification = discouraged`, `Resident key = required`, then `Register Passkey`.
2. If registration succeeds, tap `Authenticate + PRF` and confirm that `firstHex` and `secondHex` are present.
3. If no-UV succeeds, retry `User verification = preferred`.
4. Only after a PIN is set and verified through PC/SC, retry `User verification = required`.

This separates a normal PRF/passkey failure from a PIN/UV failure. The page logs the request settings and browser error name/message.

The existing `bitcoinlightning` app intentionally uses `residentKey: "required"` and `userVerification: "required"` when creating and restoring the wallet passkey. That is appropriate for a wallet but it forces the browser/platform into a UV path. On the current clean CAP, UV means CTAP client PIN because Feitian fingerprint UV is not integrated yet.

If browser authentication succeeds but the page prints `prf: null`, the browser completed normal WebAuthn but did not return PRF extension output. The diagnostic signal is `authenticatorData.flags.extensionDataIncluded: false` or a 37-byte assertion authenticator-data value. That can happen even when the card supports CTAP2 `hmac-secret`; iOS/iPadOS currently have known limitations passing WebAuthn extension data to external/roaming NFC authenticators.

Clear the local credential and register again after page changes:

```text
Clear Local Credential -> Register Passkey -> Authenticate + PRF
```

The page now requests `extensions: { prf: {} }` during registration, then requests concrete PRF outputs during authentication. That is the compatibility path recommended by Yubico's WebAuthn PRF guide.

## Feitian Fingerprint State

The current clean CAP does not use the Feitian fingerprint sensor. Passing `npm run card:test` only proves FIDO2 auth plus CTAP2 `hmac-secret` PRF through the contact PC/SC path.

To support fingerprint UV cleanly, Feitian or the card supplier must provide documentation for:

- Whether fingerprint enrollment and matching are exposed to custom Java Card applets.
- The Java Card API, shareable interface, or APDU service AID for fingerprint verification.
- Whether the FIDO2 applet can receive a trusted on-card UV result.
- Enrollment/reset lifecycle.
- Security boundaries, retry counters, lockout behavior, and sample code.

Until that is implemented and tested, the product path is PIN-backed FIDO2 PRF/auth, not fingerprint-backed UV.

## What To Ask Vendors

For Feitian fingerprint/FIDO2 samples:

- Exact card model, chip, Java Card version, and GlobalPlatform version.
- Whether custom CAP loading is supported on the fingerprint card.
- SCP mode: SCP02 or SCP03.
- ISD AID.
- GP key version and key IDs.
- ENC/MAC/DEK keys, or the single master/TK key if that is what the vendor provides.
- Fingerprint API documentation for custom applets, if available.
- Whether FIDO2 PIN and fingerprint UV are handled by vendor firmware, a Java Card applet, or both.

For AliExpress/Alibaba/eBay Java Cards:

- Exact chip and OS name.
- Whether it is unfused/unlocked.
- SCP mode: SCP02 or SCP03.
- ISD AID.
- GP key version and key IDs.
- ENC/MAC/DEK keys, or the single master/TK key if that is what the seller provides.
- Confirmation that custom CAP loading is allowed.

Search email or vendor files for:

- `Feitian`
- `Fingerprint`
- `FIDO2`
- `SCP03`
- `SCP02`
- `KENC`
- `KMAC`
- `KDEK`
- `GlobalPlatform`
- `Card Manager`
- `ISD`
- `transport key`
- `TK value`
- `development card`
- `unlocked sample`

## FIDO2-First Acceptance Order

1. Make the clean FIDO2 applet pass `npm run card:test` on the real card.
2. Set and verify a FIDO2 PIN through `npm run card:pin:set` and `npm run card:pin:verify`.
3. Confirm browser WebAuthn PRF with the diagnostic page over HTTPS/NFC.
4. Only then add Feitian fingerprint UV if the vendor provides enough API documentation to implement it cleanly.
