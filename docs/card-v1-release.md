# Nuri Card V1 reproducible release

This document is the source-of-truth release contract for rebuilding the card,
host tooling, and native Expo terminal from a fresh checkout. It distinguishes
source reproducibility, card provisioning, card-specific secrets, and live
service configuration.

## Release contents

Card V1 consists of four independent Java Card applets:

| Capability | Source | CAP | Applet AID |
| --- | --- | --- | --- |
| FIDO2/passkey/PRF | `third_party/fido2-applet/` + patches | `dist/FIDO2-up.cap` | `A0000006472F0001` |
| Bitcoin/Arkade MuSig2 signer | `card/musig2/` | `dist/nuri-musig2-v20-keygen.cap` | `4E5552494D554701` |
| OATH-TOTP | `card/totp/` | `dist/nuri-oath-totp.cap` | `4E555249544F5450` |
| Ethereum/EVM signer | `card/eth/` | `dist/nuri-eth-signer.cap` | `4E55524945544801` |

The corresponding host proofs, APDU clients, Arkade/Lightning flows, PC/SC SSH
bridge, and Expo NFC app are versioned in this repository. `dist/SHA256SUMS`
covers every flashable CAP.

## Fresh-checkout rebuild

Required host tools:

- Git
- Node.js 20 or newer; CI uses Node.js 22
- Python 3.10 or newer
- JDK 8 for CAP compilation
- JDK 17 for Android native builds
- Ant, `patch`, `rsync`, and `shasum`
- GlobalPlatformPro for physical-card installation

Run:

```bash
git clone https://github.com/nuri-com/nuri-passkey-prf-smartcard.git
cd nuri-passkey-prf-smartcard
npm ci
npm run card:release:verify
```

Real-card commands use `scripts/run-card-python.sh`, which creates
`.build/card-v1-python` from the pinned `requirements-card-v1.txt`. No
machine-specific virtual-environment path is required.

The build performs these checks automatically:

1. Verify the checked-in `ant-javacard` tool hash.
2. Fetch and detach the Java Card SDK repository at exact commit
   `e2df471e04d86f33de69a947f44766fbef1d9d69`.
3. Copy the vendored FIDO2 base into an isolated build tree.
4. Apply the versioned Nuri patches.
5. Compile and verify all five CAP artifacts: the historical and current FIDO2
   variants plus MuSig2, TOTP, and ETH.
6. Normalize container timestamps and the informational CAP creation time.
7. Verify all internal CAP components and deterministic outer hashes against
   `dist/`.

Expected final marker:

```text
CARD_V1_RELEASE_VERIFIED
```

## Why normalization is safe

A CAP is a ZIP container of Java Card components. The Java Card converter adds
wall-clock timestamps to the ZIP and manifest. Those fields make byte hashes
change without changing executable components. `scripts/normalize-cap.py`
rewrites only ZIP metadata and the manifest creation-time line. The release
verifier separately compares every uncompressed component to ensure the
normalized artifact contains the proven applet bytecode.

## Source and license boundaries

- The FIDO2 snapshot is MIT and includes its upstream license.
- MuSig2 and ETH include Satochip/OV-chip `Biginteger` code under
  GPL-2.0-or-later. Their corresponding source is included in full.
- The rest of the repository is MIT unless a file says otherwise.
- The Oracle Java Card SDK is fetched separately under its own terms.
- No confidential FEITIAN/IDEX SDK or biometric service binary is part of V1.

See `THIRD_PARTY_NOTICES.md` before redistributing CAPs.

## What cannot be backed up from a card

The applet source and installable CAPs are reproducible. A provisioned card's
private state is intentionally not cloneable:

- FIDO2 credential private keys
- MuSig2 long-term private key
- ETH private key
- PIN state and retry counters
- TOTP secret through the public applet API

A replacement card is a new identity and must be enrolled separately. Public
account mappings and recovery policy must authorize that new card. Never treat
a source/CAP backup as a private-key backup.

## Expo app boundary

The Expo application source, lockfile, Android/iOS prebuild configuration, NFC
logic, send/receive/claim flows, and design-system conformance check are under
`mobile/expo-nfc-prf-probe/`.

The application currently consumes `@nuri/rn` and `@nuri/spec` from the private
`nuri-design-system` repository. A fully public clean-room Expo build therefore
requires either:

1. publishing/licensing those packages, or
2. an authenticated checkout of that exact design-system commit.

Do not replace those packages with app-authored visual components: every
visible screen must continue to use the Nuri design system.

For an authorized checkout:

```bash
npm run mobile:verify:v1
EXPO_NATIVE_ANDROID=YES npm run mobile:verify:v1
```

The first command performs a clean install, the design-system UI guard,
TypeScript checking, and an Android Metro export. The second additionally builds
the arm64 native debug APK with JDK 17 and the Android SDK. The source
verification does not require a card; live NFC acceptance does.

## V1 qualification evidence

The 2026-07-12 release candidate passed:

- all 14 host Node tests, the MuSig2 demo, cosign demo, and TOTP self-check
- a fresh build and Java Card verification of all five CAP artifacts
- component and deterministic SHA-256 equality against `dist/`
- the Expo design-system guard across all four visible screen modules
- TypeScript, Android Metro export, and an arm64 native Android build
- installation of the resulting 49 MB debug APK on the connected Samsung

The release CAPs are component-identical to the artifacts used by the earlier
real-card proofs. The current V1 acceptance rerun could not reach the card
because only the Android phone was attached over USB and macOS exposed no PC/SC
reader. Consequently `REAL_CARD_V1_ACCEPTANCE_OK` is deliberately not claimed
for this checkout. Re-run `CARD_REAL_TESTS=YES scripts/accept-card-v1.sh` with a
PC/SC reader attached before qualifying a newly provisioned physical card.
