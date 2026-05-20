# Nuri Passkey PRF Smartcard

MIT-licensed flash-and-test package for a small Java Card FIDO2 passkey applet with browser PRF support, plus a separate Taproot/MuSig2 partial-signing simulator.

The core conclusion is simple: browser passkey PRF is not a separate card-side CTAP extension. Browsers expose WebAuthn `prf`, and authenticators implement CTAP2 `hmac-secret`. A viable smartcard applet should therefore implement and advertise `hmac-secret`, keep normal FIDO2 authentication working, and avoid adding a non-standard CTAP `"prf"` string unless a specific client requires it.

## What Is In This Repo

- A reproducible build/test flow that clones the public Bryan Jacobs FIDO2Applet baseline and runs Java Card simulator tests.
- A custom end-to-end PRF mapping test: browser-style PRF salts become CTAP2 `hmac-secret` salts, then a discoverable passkey assertion is verified.
- A small MuSig2 card simulator compatible with `@scure/btc-signer/musig2.js`.
- An APDU-level MuSig2 transport simulator with nonce replay rejection.
- A localhost WebAuthn PRF smoke-test page for real browser/passkey testing.
- A manufacturer-facing card requirements spec.

This repo does not vendor the FIDO2Applet source. It clones the baseline into `vendor/FIDO2Applet-clean`, which is ignored by git.

## Quick Start

Requirements:

- Node.js 20 or newer.
- Java 17 for the FIDO2 simulator path.
- Python 3.10 or newer.
- Git.

Fast checks:

```bash
npm install
npm test
npm run musig2:demo
```

Full local end-to-end run:

```bash
npm run fido2:prepare
npm run fido2:test-prf
```

Or run all checks:

```bash
npm run e2e
```

The FIDO2 script clones `https://github.com/BryanJacobs/FIDO2Applet.git` at ref `fb827954cd091a1810163ce51d2f86d42d0b8e20`, initializes the Java Card SDK submodule, builds the simulator jars, installs the Python requirements from the cloned baseline, runs upstream hmac-secret tests, then runs `test/fido2_prf_e2e.py`.

## Browser PRF Smoke Test

Start the local page:

```bash
npm run web:prf
```

Open:

```text
http://localhost:8765/prf-test.html
```

Use `Register Passkey`, then `Authenticate + PRF`. A successful PRF-capable authenticator returns 32-byte `firstHex` and `secondHex` values.

Important limitation: a smartcard in a PC/SC reader is not automatically visible to Chrome, Firefox, or Safari as a roaming WebAuthn authenticator. The page works with whatever authenticator the browser exposes, for example platform passkeys, a USB/NFC security key, or this smartcard later if the OS/browser can reach it through NFC or a CTAP bridge.

If authentication succeeds but `prf` is `null`, the selected browser/authenticator path did not return WebAuthn PRF extension output. On iOS/iPadOS, external NFC authenticators can authenticate successfully while PRF extension data is not passed through. In that case the card can still pass the repo's PC/SC `hmac-secret` test, but browser PRF over phone NFC is blocked by the platform path.

## PIN, Feitian Fingerprint, And First Use

Do not ship cards with a shared preset FIDO2 PIN. The intended production state is no FIDO2 PIN set; the first user sets their own PIN through CTAP `clientPin setPin`, and the PIN verifier/retry state lives on the card.

The current active target is the Feitian fingerprint/FIDO2 smartcard sample. The clean CAP supports FIDO2 PIN capability but does not integrate the Feitian fingerprint sensor yet. Current real-card `getInfo` after clean CAP install showed `clientPin: false`, `min_pin_length: 4`, `pin_uv_protocols: [2, 1]`, and `makeCredUvNotRqd: true`.

The real-card CLI PRF test intentionally sets WebAuthn user verification to `discouraged`. That is why it can pass without a PIN:

- FIDO2 authentication and CTAP2 `hmac-secret` PRF can work without PIN when the relying party does not require user verification.
- A browser or relying party may still require PIN/UV for a discoverable passkey, account policy, or PRF flow.
- Fingerprint-based UV is a separate integration step: the applet must use Feitian-documented fingerprint enrollment/verification APIs and advertise internal UV only when that path is working.

If a phone loops during first-use PIN setup, that is not a valid product state. It likely means the phone/browser/NFC path is not completing CTAP PIN setup cleanly, or the page requested a UV mode the current applet cannot satisfy through that transport. For development, set a PIN through the working PC/SC path and retry the phone. For production, either first-use PIN setup over the intended transport must work reliably, or Feitian fingerprint UV must be implemented and verified on that exact card family.

Inspect the current card PIN state:

```bash
npm run card:pin:status
```

Set the first FIDO2 PIN on the card through PC/SC:

```bash
npm run card:pin:set
```

Verify or change it later:

```bash
npm run card:pin:verify
npm run card:pin:change
```

The PIN script uses `getpass`, so the PIN is not placed in shell history or npm arguments.

## Flashing A Real Card

This repo includes a prebuilt CAP at `dist/FIDO2.cap`. Rebuild it locally:

```bash
npm run card:build
```

Install it with the GlobalPlatform key supplied by the card seller:

```bash
GP_READER="your reader name" GP_KEY="your card key" npm run card:install
```

Some reader stacks work better by numeric GlobalPlatformPro index:

```bash
GP_READER_INDEX=2 GP_KEY="your card key" npm run card:install
```

Cards with separate SCP03 keys can use:

```bash
GP_READER_INDEX=1 GP_KEY_ENC="..." GP_KEY_MAC="..." GP_KEY_DEK="..." npm run card:install
```

Delete an existing FIDO2 package/app instance and reinstall the clean CAP on a test card:

```bash
FIDO2_REINSTALL_CONFIRM=YES GP_READER_INDEX=2 npm run card:reinstall
```

Run the real-card WebAuthn PRF test:

```bash
npm run card:test
```

Run the same real-card WebAuthn PRF test with FIDO2 PIN/user verification required:

```bash
npm run card:test:pin
```

Reset only the FIDO2 authenticator state on an inserted card:

```bash
FIDO2_RESET_CONFIRM=YES npm run card:reset
npm run card:test
```

Use this reset before reinstalling the applet. It wipes FIDO2 credentials and authenticator state on the card, but does not remove Java Card packages through GlobalPlatform. If reset does not make `card:test` pass, the next step is a GlobalPlatform delete/reinstall of the FIDO2 applet, which is more destructive and should only be done on a test sample.

Exact install arguments depend on the card, SCP mode, default keys, and whether the manufacturer pre-personalizes the card. The applet is not a finished production product until it passes `card:install` and `card:test` on the exact card batch.

### Current Real-Card Reset Notes

Observed on 2026-05-20 with an HID Global OMNIKEY 5422 reader and one inserted sample:

- PC/SC ATR: `3B:80:80:01:01`
- OpenSC name: `MuscleApplet`
- FIDO2 smartcard path detected through Python `fido2.pcsc`
- CTAP versions: `U2F_V2`, `FIDO_2_0`, `FIDO_2_1_PRE`
- CTAP extensions: `credProtect`, `hmac-secret`
- CTAP options included `rk: true`, `uv: true`, `clientPin: false`
- Basic non-resident FIDO2 makeCredential worked
- Resident/passkey and `hmac-secret` makeCredential returned CTAP `0x27 OPERATION_DENIED`
- GlobalPlatformPro access worked on reader index `2` with the default development key on this sample

After `FIDO2_RESET_CONFIRM=YES npm run card:reset` on the same preinstalled sample:

- CTAP reset completed successfully.
- `uv` changed from `true` to `false`.
- Direct CTAP `makeCredential` works for a basic credential.
- Direct CTAP `getAssertion` succeeds only when sent with `options: {"up": false}`.
- Direct CTAP `hmac-secret`/PRF returns two 32-byte outputs only when sent with `options: {"up": false}`.
- Normal WebAuthn-style auth/PRF with default user presence (`up=true`) still returns CTAP `0x27 OPERATION_DENIED`.

That preinstalled applet/state was useful for proving the PRF primitive, but it was not acceptable as a browser passkey because browser/WebAuthn clients require user presence.

After deleting the old package `A0000006472F` and reinstalling this repo's clean `dist/FIDO2.cap`:

- GlobalPlatform registry shows package `A000000647` version `0.4` with applet `A0000006472F0001`.
- `npm run card:test` passes on the real contact card.
- `npm run card:test:pin` passes with FIDO2 PIN/user verification required.
- The passing marker is `REAL_CARD_WEBAUTHN_PRF_OK`.
- The real-card PRF test produced two 32-byte WebAuthn PRF outputs through CTAP2 `hmac-secret`.

The current contact-card state is therefore good for CLI-level FIDO2 auth + passkey PRF validation. Browser validation still depends on whether the OS/browser can expose this PC/SC smartcard as a WebAuthn authenticator.

For a failing or preinstalled sample, use this recovery order:

```bash
# non-destructive inventory
opensc-tool --list-readers
opensc-tool -r 1 -a
gp -r2 -i
gp -r2 -l

# destructive only to FIDO2 authenticator state
FIDO2_RESET_CONFIRM=YES npm run card:reset
npm run card:test

# if reset does not fix hmac-secret/rk, reinstall the CAP on a test sample
FIDO2_REINSTALL_CONFIRM=YES GP_READER_INDEX=2 npm run card:reinstall
npm run card:test
```

Only do a GlobalPlatform delete/reinstall on a card that is explicitly allowed to be wiped. Keep exactly one test card inserted or on the reader during these commands, and record the physical sample label/photo beside the command output.

If more than one PC/SC FIDO2 card is visible, set `FIDO2_PCSC_INDEX=0`, `1`, etc. The reset script refuses to choose automatically when multiple PC/SC FIDO2 devices are present.

## Card Shopping Matrix

Prices and availability change quickly. The key requirement is not just the chip name; the card must be **unfused/unlocked** and the seller must provide the **GlobalPlatform/SCP transport keys** so we can install `dist/FIDO2.cap`.

Buy a few different cards and run the same commands against each one:

```bash
gp -list
GP_READER="reader name" GP_KEY="seller key" npm run card:install
npm run card:test
```

Recommended order:

| Priority | Target | Why | Risk | Example/search |
| --- | --- | --- | --- | --- |
| 1 | **J3R180 / JCOP4 / 180K** | Best cheap technical target: newer JCOP4, Java Card 3.0.5, more memory headroom. | Seller must provide keys; some listings are bulk/MOQ. | Alibaba Feitian sample: `https://www.alibaba.com/product-detail/JCOP4-P71-SeclD-Payment-Contactless-Support_1600188735991.html`; search `J3R180 JCOP4 JavaCard 180K unfused`. |
| 2 | **J3H145 / JCOP3 / 145K** | Already listed by upstream FIDO2Applet as working. Strong first reliable target. | Often more expensive than random eBay/AliExpress stock. | Search `J3H145 JCOP3 JavaCard 145K unlocked`; MoTechno/CardLogix/Smartcard Focus style vendors. |
| 3 | **J3R150 / JCOP4 / 150K** | Your eBay listing is the right family: “not fused / TK value provided” is a good sign, and 150K may be enough. | Not explicitly in upstream tested list; seller quality varies. Treat as a cheap test card, not the only card. | eBay example from screenshot/text: `https://www.ebay.de/itm/317918355556`; search exact title `J3R150 JCOP Smart Card Dual Interface 150k Speicher not fused TK value provided`. |
| 4 | **J3H081 / J2D081 / 80K cards** | Cheap experiment only. | Likely too small or missing required algorithms. Do not rely on this for the product path. | Search only if you want a throwaway failure/compatibility data point. |

Avoid cards described only as `J2A040`, `J2A081`, `Java blank card`, `EMV card`, or `ATM card` unless the seller explicitly confirms Java Card 3.0.4+, the crypto algorithms, enough memory, and install keys. Marketing text about EMV, magnetic stripe, ID cards, or ATM support is irrelevant for this project.

Crypto expectation for J3R150/J3R180/J3R200:

- JCOP4/P71 class public specs and seller listings commonly advertise Java Card 3.0.5 Classic, GlobalPlatform 2.3, SHA-256/SHA-384/SHA-512, ECC GF(p) up to 521 bits, and AES-256.
- The exact FIDO2 applet needs P-256 key generation, ECDSA SHA-256, ECDH plain/shared secret, SHA-256, and AES-256 CBC no padding.
- Public evidence says this card family should support the needed algorithms. The seller question is mainly to confirm the exact SKU, that the algorithms are exposed through Java Card APIs on that batch, and that the card is installable with provided keys.

Minimum seller confirmation before buying:

```text
I need unlocked JavaCard samples for loading my own CAP file.

Please confirm:
- Exact chip: J3R180, J3R150, or J3H145
- Java Card Classic 3.0.4+ / 3.0.5 preferred
- GlobalPlatform keys / TK / SCP keys are provided
- Card is not fused/locked and accepts custom CAP install
- This exact batch exposes P-256 ECC, ECDSA SHA-256, ECDH, SHA-256, and AES-256 to Java Card applets
- User NVM and RAM available after OS
- Contact ISO7816 T=1 works with PC/SC readers
```

Recommended first order:

- 2x **J3R180 JCOP4** samples if you can get them cheap.
- 1x **J3H145 JCOP3** from a more reliable smartcard vendor.
- 1x **J3R150 JCOP4 150K** eBay-style card like the screenshot, because it is cheap and may work.
- 1x **ACS ACR39U/ACR39U-N1** contact PC/SC reader for flashing and CLI tests.
- Optional: **ACS ACR122U** NFC reader for APDU/NFC experiments, but browser WebAuthn PRF through NFC is not guaranteed.

## Repo Layout

- `docs/architecture.md`: minimal split-app design.
- `docs/fido2-prf-baseline.md`: FIDO2 PRF baseline and simulator notes.
- `docs/fido2-card-research.md`: online card research and buying/test matrix.
- `docs/hardware-manufacturer-spec.md`: card requirements and acceptance tests to send to suppliers.
- `docs/real-card-key-handling.md`: non-secret key-handling and current Feitian sample notes.
- `docs/musig2-card-extension.md`: optional MuSig2 APDU contract.
- `src/musig2/`: MuSig2 method-level and APDU-level simulators.
- `test/`: Node MuSig2 tests and Python FIDO2 PRF mapping test.
- `web/prf-test.html`: self-hosted browser WebAuthn PRF test page.

## Current Recommendation

Use Bryan Jacobs' FIDO2Applet as the first passkey base, keep the applet focused on FIDO2 + CTAP2 `hmac-secret`, and keep MuSig2 behind a separate AID. That gives a small audit surface for PRF/auth and leaves Taproot/MuSig2 as an optional second phase.

Candidate cards to ask suppliers about first: JCOP3 J3H145-class or JCOP4 J3R180-class cards with Java Card Classic 3.0.4+, P-256, ECDSA SHA-256, ECDH plain, AES-256-CBC, SHA-256, secure RNG, enough NVM for resident credentials, and documented SCP03/GlobalPlatform access.

Useful card references:

- J3R150 JCOP4 Java Card 3.0.5, AES-256, ECC GF(p) 521, SHA-256 listing: https://www.motechno.com/product/j3r150-dual-interface/
- J3R180/J3R200 JCOP4/P71 listing with SHA-256 and ECC521: https://www.alibaba.com/product-detail/JCOP4-P71-SeclD-Payment-Contactless-Support_1600188735991.html
- JCOP4 P71 certificate algorithm list includes ECDSA SHA-256, AES-256 lengths, EC FP 256, SHA-256, and EC DH plain variants: https://sec-certs.org/cc/f29f88756682e034/
- JCAlgTest J3R180 runtime results include EC FP 256 keypair / ECDSA tests: https://www.fi.muni.cz/~xsvenda/jcalgtest/run_time/NXPJCOP4J3R180SECIDP71.html

## References

- WebAuthn Level 3 PRF extension: https://www.w3.org/TR/webauthn-3/
- FIDO CTAP2.1 hmac-secret extension: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
- Bryan Jacobs FIDO2Applet: https://github.com/BryanJacobs/FIDO2Applet
- scure MuSig2: https://github.com/paulmillr/scure-btc-signer#musig2
- BIP327 MuSig2: https://bips.dev/327/
