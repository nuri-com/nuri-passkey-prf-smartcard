# Real Card Key Handling

This file is intentionally non-secret. Do not commit GlobalPlatform/SCP keys, IDEX vendor keys, exported development keys, attestation private keys, or card seed material to this repository.

## When Keys Are Needed

No GlobalPlatform keys are needed for these operations:

- PC/SC reader inventory.
- CTAP/FIDO2 `getInfo`.
- FIDO2 makeCredential/getAssertion tests.
- CTAP/FIDO2 reset through `npm run card:reset`.

GlobalPlatform/SCP keys are needed for these operations:

- Listing applets with authenticated GP access on a non-default-key card.
- Deleting applets/packages.
- Installing `dist/FIDO2.cap`.
- Loading an IDEX IBA/fingerprint applet or Satochip/MuSig2 applet.
- Changing card manager keys.

The current contact sample observed on 2026-05-20 accepted the GlobalPlatformPro default development key and used SCP02 DES3 keys. Do not assume other samples do the same.

## Current Reader Mapping

Observed with HID Global OMNIKEY 5422:

| Physical card | PC/SC/OpenSC reader | GlobalPlatformPro reader | Current status |
| --- | --- | --- | --- |
| Contact card, likely Feitian sample | `opensc-tool -r 1 ...` | `gp -r2 ...` or `GP_READER_INDEX=2` | Present, ATR `3B:80:80:01:01`, OpenSC name `MuscleApplet`, GP applet list accessible with default development key. |
| Contactless/NFC IDEX card | `opensc-tool -r 0 ...` | likely `gp -r1 ...` or `GP_READER_INDEX=1` | Not connected during the last probe. Reposition the card on the OMNIKEY contactless antenna until `opensc-tool -r 0 -a` returns an ATR. |

Use exactly one card per slot while testing, and label command output with the physical card/sample.

On 2026-05-20, macOS `system_profiler SPSmartCardsDataType` reported:

- `HID Global OMNIKEY 5422 Smartcard Reader 01`: no card present.
- `HID Global OMNIKEY 5422 Smartcard Reader`: ATR `3B80800101`.

That means the IDEX NFC card was not yet close enough or not being polled successfully, even though the reader itself exists.

## Local IDEX Material Already Found

The following sibling-folder files look relevant. They contain or reference development card keys or IDEX procedures; treat them as local secrets and do not copy their key values into this repo:

- `../FIDO2Applet-working-idex/SatochipApplet/SCP03_KEYS.md`
- `../FIDO2Applet-working-idex/satochip/applet/SCP03_KEYS.md`
- `../FIDO2Applet-working-idex/satochip/keys/CARD_KEYS.md`
- `../FIDO2Applet-working-idex/satochip/nuri-musig2/CARD_KEYS.md`
- `../FIDO2Applet-working-idex/satochip/nuri-musig2/GET_CARD_KEYS.md`
- `../FIDO2Applet-working-idex/satochip/.env`
- `../FIDO2Applet-working-idex/satochip/CARD_STATUS_REPORT.md`
- `../FIDO2Applet-working-idex/satochip/SUCCESS_CARD_UNLOCKED.md`
- `../FIDO2Applet-working-idex/COMPLETE_MUSIG2_GUIDE.md`
- `../0502-nuri-idex/idex-downloads/Enrollment_Guidance-240917-371-13647/IDEX_Enrollment_Guide.pdf`
- `../0502-nuri-idex/idex-downloads/IBA_Release_v1_7 V2/`

The local notes mention an IDEX/IBA service AID family beginning with `A000000905`, including `A00000090501000101` for the IBA service and `A00000090501000301` for an IBA client/test applet. They also mention development APDUs that return ENC/MAC/DEK material for test cards. Do not use those mechanisms on production cards unless the manufacturer explicitly documents them for development samples.

## How To Use Existing Keys Safely

Load keys through shell environment variables only for the current terminal session:

```bash
set -a
source ../FIDO2Applet-working-idex/satochip/.env
set +a
gp -r1 --key-enc "$SCP03_ENC" --key-mac "$SCP03_MAC" --key-dek "$SCP03_DEK" -l
GP_READER_INDEX=1 npm run card:install
```

The install script accepts either `GP_KEY_ENC`/`GP_KEY_MAC`/`GP_KEY_DEK` or the existing local aliases `SCP03_ENC`/`SCP03_MAC`/`SCP03_DEK`.

For cards with one default/master key:

```bash
GP_READER_INDEX=2 GP_KEY="404142434445464748494A4B4C4D4E4F" npm run card:install
```

Only use `GP_FORCE=YES` on a development sample when the local card notes or vendor explicitly say installation is allowed but GlobalPlatformPro is blocking a development-card operation:

```bash
GP_FORCE=YES GP_READER_INDEX=1 npm run card:install
```

## What To Search For In Email Or Vendor Files

Search for these terms:

- `IDEX`
- `IDX56`
- `IBA`
- `Enrollment Guide`
- `IBA Release`
- `SCP03`
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
- `A00000090501000101`

For Feitian/AliExpress/Alibaba-style Java Cards, ask for:

- Exact chip and OS name.
- Whether it is unfused/unlocked.
- SCP mode: SCP02 or SCP03.
- ISD AID.
- GP key version and key IDs.
- ENC/MAC/DEK keys, or the single master/TK key if that is what the seller provides.
- Confirmation that custom CAP loading is allowed.

## IDEX/FIDO2 Product Direction

For the FIDO2-first product, IDEX biometric support should be optional. The minimal PRF/passkey requirement is still CTAP2 `hmac-secret` plus resident credentials. IDEX IBA can later provide on-card user verification, but it increases the build and audit surface because the applet must compile against IDEX shareable-interface exports and call the IBA service AID.

Acceptance order:

1. Make the clean FIDO2 applet pass `npm run card:test` on a real card.
2. Confirm browser WebAuthn PRF with `npm run web:prf`.
3. Only then add IDEX fingerprint UV behind a build flag and test it on the IDEX sample.
