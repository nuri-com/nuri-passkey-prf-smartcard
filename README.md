# Nuri Passkey PRF Smartcard

MIT-licensed flash-and-test package for a small Java Card FIDO2 passkey applet with browser PRF support, plus a separate Taproot/MuSig2 partial-signing applet/test path.

The core conclusion is simple: browser passkey PRF is not a separate card-side CTAP extension. Browsers expose WebAuthn `prf`, and authenticators implement CTAP2 `hmac-secret`. A viable smartcard applet should therefore implement and advertise `hmac-secret`, keep normal FIDO2 authentication working, and avoid adding a non-standard CTAP `"prf"` string unless a specific client requires it.

## Current State, June 2026

This repo is a working research and test package for three related tracks:

1. **FIDO2 auth + WebAuthn PRF / CTAP2 hmac-secret**
2. **Feitian FT-JCOS BioCARD fingerprint card qualification**
3. **Optional Bitcoin Taproot/MuSig2 partial signing**

The first track is the product priority. MuSig2 is deliberately separate so a FIDO2/passkey failure cannot compromise or complicate the Bitcoin signer.

For the Nuri app/server integration target, see
[`docs/nuri-arkade-card-cosigner-plan.md`](docs/nuri-arkade-card-cosigner-plan.md).
It maps the current `nuri-expo` + `server-arkade-v4` MuSig2 flow to a card
cosigner and explains why "server or card" needs an explicit key/policy choice.

For the immediate Chrome, CLI, Android, and card-install order, see
[`docs/current-test-next-steps.md`](docs/current-test-next-steps.md).

For the confirmed real-card Signet transaction, verbose terminal proof commands,
and Mermaid signing flow, see
[`docs/real-card-signet-proof.md`](docs/real-card-signet-proof.md).

For a sendable report with online explorer links, transaction ledger, live
broadcast transcript, and Mermaid diagrams, see
[`docs/nuri-card-wallet-proof-report.md`](docs/nuri-card-wallet-proof-report.md).

### Can The Nuri Server Signer Be Replaced By The Card?

Yes, for a server-attached HSM-style deployment. The Arkade server would keep
the existing approval, policy, transaction, and session checks, but the private
cosigner operation would move from server RAM to the smartcard:

```text
current:
  server derives/holds serverPriv -> musig2.nonceGen/sign in process memory

card-backed:
  server verifies request/policy -> sends APDU to card -> card returns nonce/partial signature
```

The important MuSig2 constraint is that the cosigner public key is part of the
aggregate Taproot/MuSig2 key. Therefore a random new card key cannot sign for an
existing `musig2(client_pubkey, server_pubkey)` wallet.

There are three workable modes:

1. **Demo or migration:** import the same server cosigner key into the card once,
   then disable software signing for that slot. Existing server-backed wallets
   can keep working, but the secret existed outside the card during
   provisioning.
2. **Clean production:** generate the card cosigner key on-card and create new
   wallets/policies using `musig2(client_pubkey, card_pubkey)`. The server never
   sees the private key, but existing addresses need migration.
3. **Server-or-card policy:** create a new Taproot policy with explicit
   alternatives, for example server path, card path, and delayed client recovery.
   This is the most flexible product model, but it is not a drop-in replacement
   for the current two-key aggregate address.

The current real-card MuSig2 proof shows that a card can produce valid partial
signatures. The remaining product work is wiring the Arkade server backend to
PC/SC/APDU, binding nonce state to the exact `@scure/btc-signer` session, and
verifying every returned partial before aggregation.

### What Is Already Proven

- The repo has passing local MuSig2 compatibility tests against `@scure/btc-signer`.
- The repo has server-cosigner smoke tests for `software`, `card-sim`, and `apdu-sim` backends. These model the Arkade server calling a card-like signer for nonce generation and partial signatures.
- The inserted Feitian BioCARD sample now has two selectable custom applets installed side by side:
  - FIDO2 applet: `A0000006472F0001`
  - Nuri MuSig2 applet: `4E5552494D554701`
- The repo has a real browser PRF test page at `web/prf-test.html`.
- The browser PRF page also has a localhost PC/SC bridge for desktop Chrome testing of the real reader/card outside browser-native WebAuthn.
- The repo has a PC/SC CLI path for real FIDO2 cards using CTAP2 `hmac-secret`.
- The repo has a native Android/iOS NFC probe app that talks ISO-DEP directly to the FIDO applet and can request `hmac-secret` without relying on mobile browser WebAuthn routing.
- A previously flashed clean FIDO2 CAP in this repo passed real-card CLI auth + PRF with marker `REAL_CARD_WEBAUTHN_PRF_OK`.
- The currently inserted Feitian BioCARD sample was converted from the vendor preloaded FIDO2 applet to the local `dist/FIDO2.cap` applet under the standard FIDO2 PC/SC AID `A0000006472F0001`.
- The local applet advertises `hmac-secret`, `rk`, `clientPin`, CTAP2.0, CTAP2.1, and PIN/UV protocols 1 and 2 through `npm run card:prf:info`.
- The same card was then loaded with `dist/nuri-musig2-v20-keygen.cap`. The real-card MuSig2 proof selected AID `4E5552494D554701`, generated the cosigner key on-card, returned only `card_pubkey33`, produced a real card partial signature, and verified the final aggregate BIP340/MuSig2 signature.
- A real Signet Taproot transaction was co-signed by the physical card, broadcast, and confirmed in block `308802`: `d9ecca378bd015f2bd39d3113d3dadc65e6b6f29b72c1d1e6a7d73f246994c38`. It sends `1337` sats, includes `OP_RETURN "Nuri.com"`, returns change to the card aggregate address, and is documented in [`docs/real-card-signet-proof.md`](docs/real-card-signet-proof.md).
- A second live proof run was co-signed by the physical card, broadcast, and confirmed in block `308804`: `c85a73fab75f8649852123d1fff336df2f098792554086a290433ce0999c3e81`. The full transcript is committed at [`docs/logs/real-card-live-broadcast-proof-2026-06-14.md`](docs/logs/real-card-live-broadcast-proof-2026-06-14.md), and the sendable summary is [`docs/nuri-card-wallet-proof-report.md`](docs/nuri-card-wallet-proof-report.md).

Current verification commands that passed in this checkout:

```bash
npm test
npm run musig2:demo
npm run cosign:demo
npm run cli:e2e
REAL_CARD=1 npm run cli:e2e
npm run card:prf:info
npm run card:test
npm run card:musig2:test
npm run cosign:real-card
npm run cosign:real-card:keygen
npm run cosign:web:real-card:selftest
```

`npm test` passed all MuSig2 simulator tests. `npm run musig2:demo` produced `verified=true`. `npm run cosign:demo` produced `NURI_CARD_COSIGN_FLOW_OK` with `final_signature_verified=true`. `npm run cli:e2e` passed the software, card-sim, and APDU-sim server-cosigner flow and ended with `CLI_E2E_OK`. `REAL_CARD=1 npm run cli:e2e` additionally passed real PC/SC FIDO2 PRF info + selftest and ended with `CLI_E2E_OK`. `npm run card:test` printed `REAL_CARD_WEBAUTHN_PRF_OK`. `npm run card:musig2:test` passed the real-card MuSig2 Python host suite with `Result: 6/6 tests passed`. `npm run cosign:real-card:keygen` printed `REAL_CARD_COSIGN_FLOW_OK` with `key_origin: on_card_keygen_non_exportable`, `card_partial_verified: true`, and `final_signature_verified: true`. `npm run cosign:web:real-card:selftest` passed twice: first with `key_origin: on_card_keygen_non_exportable` and then with `key_origin: existing_on_card_non_exportable` while preserving the same `card_pk33` and `aggregate_xonly32`. `npm run cosign:real-card` now signs with the existing card key instead of reprovisioning it.

Before reinstalling the local applet, the vendor preloaded FIDO2 instance returned CTAP `0x27 OPERATION_DENIED` for `makeCredential`, even with PRF disabled and with PIN/UV attempts. The working fix was:

```bash
FIDO2_RESET_CONFIRM=YES npm run card:reset
gp -r 2 --load dist/FIDO2.cap
gp -r 2 -f --delete A0000006472F
gp -r 2 --package A000000647 --applet A0000006472F0001 --create A0000006472F0001
```

After that, `npm run card:prf:info`, `npm run card:test`, the ngrok PC/SC bridge selftest, and `REAL_CARD=1 npm run cli:e2e` all pass.

The successful MuSig2 real-card install/test sequence was:

```bash
gp -r 2 --load dist/nuri-musig2-v20-keygen.cap
gp -r 2 --package 4E5552494D5547 --applet 4E5552494D554701 --create 4E5552494D554701
npm run cosign:real-card:keygen
npm run card:musig2:test
scripts/card-prf-backup.sh selftest --profile after-musig2-install-prf --force --resident-key discouraged --user-verification discouraged --registration-prf prf --salt 'nuri browser prf first input'
npm run card:test
```

The MuSig2 CAP is committed at `dist/nuri-musig2-v20-keygen.cap`. The wrappers `npm run card:musig2:install` and `npm run card:musig2:test` use the committed CAP/test defaults and can be pointed at another CAP/tool with `MUSIG2_CAP=...` and `MUSIG2_TEST_TOOL=...`.

### What We Can Do Now

- **Browser PRF on desktop Chrome:** use `npm run web:prf` and open `http://localhost:8765/prf-test.html`. When sharing the test to phones or another browser, run the fixed ngrok tunnel and use `https://regular-jointly-cheetah.ngrok-free.app/prf-test.html`. This works with authenticators exposed by Chrome WebAuthn, for example platform passkeys or USB/NFC security keys. A PC/SC smartcard in a reader is not automatically visible to Chrome as a WebAuthn roaming authenticator.
- **Desktop Chrome PC/SC bridge:** the same local page has `PC/SC Card Info`, `PC/SC PRF Selftest`, and `PC/SC PRF Derive` buttons. These call the local Node helper, not browser-native WebAuthn.
- **Local card-cosign web demo:** use `npm run cosign:web` for the simulator or `npm run cosign:web:real-card` for the real PC/SC card backend, then open `http://127.0.0.1:8787/cosign-demo.html`. The real-card mode creates `.nuri-card-musig2/browser-real-card.json` on first use, provisions the card key with `INS_KEYGEN`, and then reuses the same non-exportable card key for later browser-triggered signatures.
- **Server-cosigner CLI:** use `npm run server:cosigner:software`, `npm run server:cosigner:card-sim`, `npm run server:cosigner:apdu-sim`, or `npm run cli:e2e`. These prove the Arkade server-side card/HSM boundary and remain useful even now that the standalone real-card MuSig2 applet has passed its own host suite.
- **Real-card MuSig2 applet:** use `npm run card:musig2:install` to install `dist/nuri-musig2-v20-keygen.cap` on a sacrificial developer card, then `npm run cosign:real-card:keygen` to prove on-card keygen + real card partial + final verified aggregate signature. Use `npm run cosign:real-card` after provisioning to sign with the existing non-exportable card key. `npm run card:musig2:test` remains the broader legacy APDU suite. The tested applet AID is `4E5552494D554701`.
- **Real card PRF in CLI:** use `npm run card:prf:info`, `npm run card:prf:enroll`, `npm run card:prf:derive`, and `npm run card:prf:selftest`. Run only one PC/SC command at a time.
- **Real card PRF on Android native NFC:** use `npm run mobile:android`, then the Expo NFC probe app. This is the cleanest phone-tap path when browser NFC/WebAuthn routing does not return PRF.
- **Feitian fingerprint enrollment:** use Feitian's manager app, Windows Security Key settings, or the offline sleeve. This enrolls fingerprints into the Feitian biometric stack.
- **MuSig2 without fingerprint:** continue today with the simulator and, as a separate second phase, a Satochip-derived Java Card applet protected by PIN.

### What We Cannot Claim Yet

- We cannot claim mobile Safari or Android Chrome NFC browser PRF works for this card. The browser path is OS/browser-routed, while the native NFC app talks directly to ISO-DEP.
- We cannot claim Feitian fingerprint unlock is integrated into our custom Java Card applet yet. Feitian confirmed the API exists, but the SDK/API is NDA-gated.
- We cannot claim the current MuSig2 Java Card applet is audited or production-ready. We can claim the local v1.10/KGEN applet was installed on the current Feitian sample, generated the long-term cosigner key on-card, returned only the public key, produced a valid real-card partial signature, and verified the final aggregate BIP340/MuSig2 signature. A product signer still needs a reviewed nonce policy, PIN/fingerprint policy, and a final host flow verified against the exact Nuri Arkade `@scure/btc-signer` session.
- We can claim the inserted Feitian sample now enrolls and derives PRF credentials via desktop PC/SC after replacing the vendor FIDO2 applet with the local `dist/FIDO2.cap`.
- We should not publish local sample GlobalPlatform/SCP keys from old working folders in a public MIT repo. Keep those in local secret notes or a private vault.

## Feitian BioCARD Findings

The local Feitian folder contains:

- `docs/feitian/Datasheet FT_JCOS BioCard E076.pdf`
- `docs/feitian/Manual FP Card 076.pdf`
- `docs/feitian/Manual FT-JCOS BioCARD V1.2EN (2209).pdf`
- `docs/feitian/Datasheet FTSleeve.pdf`
- `docs/feitian/Gmail - Re_ Inquiry - Fingerprint Card.pdf`

The Feitian datasheet says the FT-JCOS BioCARD is a Java Card fingerprint smartcard with:

- Java Card 3.0.5
- GlobalPlatform 2.3.1
- ISO/IEC 7816 and ISO/IEC 14443 Type A
- 13.56 MHz contactless
- 300K user NVM and 6K RAM
- match-on-secure-element fingerprint module
- RSA 2048, AES, SHA-1, SHA-256, SHA-384, SHA-512, MD5, 3DES, HMAC, and ECC FP_192/FP_224/FP_384 listed

Important crypto caveat: the datasheet does not explicitly list P-256/FP_256, ECDSA P-256, ECDH P-256, or AES-256. Live tests and/or Feitian confirmation are still required for exact Java Card API exposure on a given batch.

The manuals confirm:

- The card has a preloaded FIDO2 applet.
- A biometric API can be invoked by applets.
- Fingerprints can be enrolled by mobile NFC, Windows Security Key settings, Bluetooth reader, or offline sleeve.
- Windows enrollment requires Windows 10 version 1903 or later.
- FIDO2 PIN must be set before Windows fingerprint setup.
- FIDO2 PIN length is 4 to 63 characters.
- The demo maximum is 2 fingerprints.
- The v1.2/v1.1 manual says the documented enrollment methods are for demonstration purposes.

The Feitian email thread confirms:

- Feitian has FIDO+Fingerprint and EMV/Mastercard+Fingerprint product lines.
- Feitian said a FIDO2-verified fingerprint card exists.
- Feitian said the first BioCard samples already had a FIDO2 applet installed.
- Feitian said newer EMV+FIDO2 BioCard samples still support fingerprint enrollment by sleeve and had remaining space for an additional applet such as a Bitcoin applet.
- Feitian said FIDO2+Fingerprint has remaining space for other applets.
- Feitian said custom applets can be loaded/installed, but they need to confirm algorithms.
- Feitian said a Java applet can use fingerprint APIs, but the applet SDK requires an NDA.
- Feitian said production with our applet + FIDO2 applet + possibly EMV applet is possible after we have loaded and fully tested our applet on the BioCard and meet MOQ.

Practical conclusion: Feitian is a viable manufacturer path, but a clean fingerprint-gated custom applet requires the Feitian BioCARD fingerprint SDK under NDA. Until then, use FIDO2 PIN/UV or Feitian's preloaded FIDO2 biometric stack, and keep our custom Bitcoin/MuSig2 path PIN-gated.

## Fingerprint Path

There are two separate fingerprint questions:

1. **Can we enroll a fingerprint on the Feitian card?** Yes, according to Feitian docs. Use one of:
   - Feitian FT-JCOS BioCARD Manager over NFC.
   - Windows 10/11 Security Key settings: set FIDO2 PIN first, then enroll fingerprint.
   - Feitian offline sleeve.
2. **Can our own Java applet use the fingerprint instead of a PIN?** Not yet in this public repo. Feitian says it is possible, but we need the NDA SDK/API.

Recommended immediate flow:

```text
Card A: keep as Feitian preloaded/reference card.
Card B: FIDO2 PRF development card, OK to reset/reinstall.
Card C: future Satochip/MuSig2 development card, OK to reset/reinstall.
```

Do not mix these roles until every card is physically labeled and its current applets are recorded with `gp -l` and `npm run card:prf:info`.

## Satochip And MuSig2 Status

The upstream Satochip branches were verified on 2026-06-13:

- `musig2-support`: `3aa97fdc32c3fe3afade3cd5eb7cd9d0d4bd197c`, committed 2025-06-16, tagged `v0.15-0.1`, commit message `Increase version to v0.15-0.1: MuSig2 with nonce reuse check (beta)`.
- `musig2-debug-test`: `e8af0f28818adfea56f98dddc947e7b0ed85c8a0`, committed 2025-05-20, commit message `DEBUG MuSig2 (TESTING ONLY)`.
- `master`: `8cbaa1d6531df7e20c7a3d47d95766db51d9a136`, committed 2024-06-20.

Use `musig2-support` as the base for product research. Treat `musig2-debug-test` as historical debug code only.

The Satochip `musig2-support` changelog says MuSig2 is experimental and implements the private-key parts of BIP327:

- `NonceGen(sk, pk, aggpk, m, extra_in)`
- `Sign(secnonce, sk, session_ctx)`
- encrypted exported secnonce
- internal randomness in nonce generation
- nonce reuse protection in `v0.15-0.1`
- partial signature output `psig`

The applet exposes MuSig2 commands in `CardEdge.java`:

- `INS_MUSIG2_GENERATE_NONCE = 0x7E`
- `INS_MUSIG2_SIGN_HASH = 0x7F`

The wallet/host still preprocesses part of the session context. That fits our intended architecture: phone/app computes aggregation context and Taproot transaction logic; the card only protects the private key and returns a partial signature.

Local sibling folders:

- `../FIDO2Applet-working-idex` contains an older combined workbench with FIDO2 PRF support notes, IDEX biometric experiments, Satochip tools, and local MuSig2 notes. Its README says WebAuthn PRF is supported via CTAP `hmac-secret`, but CTAP bio-stuff is not implemented.
- `../nuri-smartcard-musig2` contains the standalone Java Card MuSig2 implementation (`NuriMuSig2v019.java`, CAP, Python tool, Expo NFC app). On 2026-06-14 it was extended with `INS_KEYGEN` and rebuilt as `dist/nuri-musig2-v20-keygen.cap`. That CAP was loaded onto the same Feitian sample as the local FIDO2 applet and passed the real-card cosign proof. This repo's `src/musig2` simulator is still the minimal scure-compatible server contract; the real applet is the APDU/device proof.

License warning: upstream SatochipApplet is AGPL-3.0. This repo is MIT. Do not copy Satochip Java code into this repo without making an explicit license decision. For a clean MIT product, keep this repo as protocol/test harness and either depend on Satochip separately, get permission, or write a clean-room applet.

## Recommended Next Steps

1. **Stabilize FIDO2 PRF proof again**
   - Use only one card command at a time.
   - Run `npm run card:prf:info`.
   - Run `npm run card:prf:selftest`.
   - Run `npm run card:test`.
   - If Python PC/SC reports `Service not available`, unplug/replug the OMNIKEY reader or restart the macOS smartcard services before retesting.

2. **Start Chrome localhost PRF test**
   - Run `npm run web:prf`.
   - Open `http://localhost:8765/prf-test.html` in desktop Chrome.
   - For a shared HTTPS test URL, run `ngrok http --domain=regular-jointly-cheetah.ngrok-free.app 8765` with the auth token supplied from your shell environment, then open `https://regular-jointly-cheetah.ngrok-free.app/prf-test.html`.
   - Test platform passkey, USB security key, and any browser-visible roaming authenticator.
   - Do not expect a contact PC/SC card reader alone to appear as a Chrome WebAuthn authenticator.

3. **Fingerprint enrollment demo**
   - Use the Feitian Manager app or Windows Security Key settings to enroll two fingerprints.
   - Record which physical card was enrolled.
   - Re-run `npm run card:prf:info` and note `bioEnroll`, `uv`, `clientPin`, and `uv_modality`.

4. **Ask Feitian for the missing SDK package**
   - NDA for BioCARD applet fingerprint SDK/API.
   - Java package/class names or shareable interface.
   - Sample applet showing fingerprint verify -> allow private-key operation.
   - GP/SCP keys and install process for the sample batch.
   - Confirmation of P-256, ECDSA SHA-256, ECDH, AES-256, SHA-256 exposed to Java Card APIs.

5. **MuSig2 product phase**
   - Keep it separate from FIDO2, even if both applets are on the same card.
   - Use the now-installed `NuriMuSig2v019` v1.10/KGEN applet as the first real-card APDU proof.
   - Continue using Satochip `musig2-support` as the reference behavior for nonce reuse protection and BIP327 host/card boundaries.
   - Add a final Nuri Arkade host test that signs the exact `@scure/btc-signer` session used by `nuri-expo` and `server-arkade-v4`.
   - Only after that, decide whether to integrate Feitian fingerprint API instead of PIN.

## What Is In This Repo

- A reproducible build/test flow that clones the public Bryan Jacobs FIDO2Applet baseline and runs Java Card simulator tests.
- A custom end-to-end PRF mapping test: browser-style PRF salts become CTAP2 `hmac-secret` salts, then a discoverable passkey assertion is verified.
- A small MuSig2 card simulator compatible with `@scure/btc-signer/musig2.js`.
- An APDU-level MuSig2 transport simulator with nonce replay rejection.
- Real-card MuSig2 install/test wrappers for the local `../nuri-smartcard-musig2` CAP/tool.
- A localhost WebAuthn PRF smoke-test page for real browser/passkey testing.
- A manufacturer-facing card requirements spec.

This repo does not vendor the FIDO2Applet source. It clones the baseline into `vendor/FIDO2Applet-clean`, which is ignored by git.

## nuricard Console App

`nuricard` is one installable console command that fronts every smartcard
function in this repo. It does not reimplement anything; it forwards to the
npm scripts, so there is nothing to keep in sync.

Install once (makes the global `nuricard` command):

```bash
npm link
```

Run with no arguments for a walk-through, idiot-proof menu:

```bash
nuricard
```

The menu exposes every smartcard function, grouped by area:

```text
   nuricard — Nuri Smartcard
  TOTP  (2FA codes, e.g. Hetzner)
    show code / store secret / install + build the TOTP applet
  FIDO2 / Passkey
    PRF card test, PIN status/set/change/verify, reset, build/install/reinstall,
    CTAP makeCredential matrix, HID transport test
  WebAuthn PRF  (offline backup)
    card info, enroll, derive, stability selftest
  Bitcoin / MuSig2  (card cosigner)
    address, UTXOs, build+sign spend, tx status, MuSig2 install/test,
    real-card cosign + keygen proofs
  Simulators / server cosigner
    MuSig2 sim, cosign sim, server cosigner (software/card-sim/apdu-sim),
    full CLI e2e, unit tests
  Web / Mobile PRF
    serve browser PRF page, ngrok tunnel, Android/iOS NFC PRF probe
  Card maintenance
    list installed applets, show all raw npm commands
```

Destructive actions (FIDO2 reset/reinstall) require typing `YES` to confirm.

Power users can skip the menu and call any function directly. Every npm
script is a subcommand:

```bash
nuricard totp                 # current 6-digit TOTP code from the card
nuricard totp put "BASE32"     # store a TOTP secret on the card
nuricard card:pin:status
nuricard bitcoin:card:address
nuricard help                 # list every command
```

The contact reader index defaults to `GP_READER=2`; override it in the
environment if your reader differs.

### On-Card OATH-TOTP

The repo includes a small Java Card OATH-TOTP applet so a 2FA secret (for
example a Hetzner "Authenticator app" setup key) is stored on the card and the
`HMAC-SHA1` is computed on-card. The card has no clock, so the host sends the
time counter and the card never returns the secret.

- Applet source: `card/NuriOathTotp.java` (AID `4E555249544F5450`)
- Build: `npm run card:totp:build` (JDK 8 + Java Card SDK) -> `dist/nuri-oath-totp.cap`
- Install: `npm run card:totp:install`
- Use: `nuricard totp put "HETZNER_BASE32"` then `nuricard totp`

The code is verified against the RFC 6238 test vector
(`python3 scripts/card-totp.py --selfcheck`) and was matched live against an
independent host TOTP on the real card. The applet stores a single secret and
is not PIN-gated; both are marked as `ponytail:` upgrade points in the source.

## Smartcard MCP Cosigner

`scripts/card-mcp-server.mjs` exposes the physical card as a remote MCP cosigner.
It mirrors the Nuri MCP shape (`initialize` / `tools/list` / `tools/call`) but the
signer is the card on this machine over PC/SC — no browser, no `sign.nuri.com`.
Tunnel it with ngrok to let a remote agent call it.

```bash
npm run card:mcp            # serve http://127.0.0.1:8799/mcp  (+ /healthz)
npm run card:mcp:tunnel     # ngrok http 8799  (public /mcp URL for an agent)
npm run card:mcp:selftest   # JSON-RPC path + one real card signature
```

Tools:

```text
nuri_card_info     public card pubkey, aggregate key, applet version
nuri_card_cosign   sign a 32-byte msg (or text) -> verified BIP340 signature
```

Verified end-to-end over HTTP: `tools/call nuri_card_cosign` returns
`final_signature_verified: true` from the real card. All PC/SC access is
serialized so two card commands never overlap.

Known gap (honest): the installed MuSig2 applet does plain MuSig2 (even-y, no
tweak input). It is **not yet byte-compatible** with `sign.nuri.com`'s tweaked
BIP327 session (`tweak32` + `musig2.Session(..., [tweak32], [true])`). Making the
card a drop-in cosigner for an existing Nuri wallet needs the applet to apply the
Taproot tweak — a separate applet change, not just this wrapper.

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

Expose the same page over HTTPS for Android Chrome or another phone:

```bash
npm run web:tunnel
```

The current development tunnel is:

```text
https://7b8b-90-187-235-105.ngrok-free.app/prf-test.html?v=android7&preset=android-noprf
```

Use `Register Passkey`, then `Authenticate + PRF`. A successful PRF-capable authenticator returns 32-byte `firstHex` and `secondHex` values.

Important limitation: a smartcard in a PC/SC reader is not automatically visible to Chrome, Firefox, or Safari as a roaming WebAuthn authenticator. The page works with whatever authenticator the browser exposes, for example platform passkeys, a USB/NFC security key, or this smartcard later if the OS/browser can reach it through NFC or a CTAP bridge.

If authentication succeeds but `prf` is `null`, the selected browser/authenticator path did not return WebAuthn PRF extension output. On iOS/iPadOS, external NFC authenticators can authenticate successfully while PRF extension data is not passed through. In that case the card can still pass the repo's PC/SC `hmac-secret` test, but browser PRF over phone NFC is blocked by the platform path.

Android is a separate moving target. Google Play services v26.03 announced CTAP2 account authentication over NFC security keys, but current PRF-specific guidance still treats Android Chrome roaming-key PRF as USB-supported and NFC-unsupported. Test basic NFC registration with PRF disabled first, then test PRF; those are two different signals.

Observed Android Chrome NFC result on 2026-05-22: the no-PRF diagnostic still failed with `NotReadableError` after the phone scanned the card. That means this Android browser/device path is failing basic roaming NFC WebAuthn before PRF or PIN policy is relevant. Continue with native NFC ISO-DEP and USB security-key comparison tests.

## Server Cosigner CLI

These scripts model the future server-attached-card/HSM mode. The host keeps
`@scure/btc-signer` for key aggregation, session construction, partial
verification, and final signature aggregation. The cosigner backend is the only
part that owns the cosigner secret and returns `cosigner_pub_nonce66` plus
`cosigner_partial32`.

```bash
npm run server:cosigner:software
npm run server:cosigner:card-sim
npm run server:cosigner:apdu-sim
npm run cli:e2e
```

All three backends should print `SERVER_CARD_COSIGNER_SMOKE_OK` with
`cosigner_partial_verified=true` and `final_signature_verified=true`.

`REAL_CARD=1 npm run cli:e2e` additionally runs the real PC/SC FIDO2 PRF info
and selftest path. For the currently inserted Feitian card with the local
FIDO2 CAP, fresh credential creation and PRF derivation over PC/SC pass.

## Local Card-Cosign Web Demo

Run:

```bash
npm run cosign:web
```

For the physical card backend, run:

```bash
npm run cosign:web:real-card
```

Open:

```text
http://127.0.0.1:8787/cosign-demo.html
```

Click `Create Valid MuSig2 Signature`. The page calls the local cosign server,
which uses the same high-level product boundary we want for Arkade:

```text
browser/client request
  -> local cosign server
  -> card backend returns pubkey, nonce, and partial signature
  -> host verifies card partial
  -> client partial is aggregated
  -> final BIP340 signature verifies against aggregate x-only pubkey
```

`npm run cosign:web` uses `simulated-on-card-keygen`: the card object generates
its own key internally and never returns the private key.

`npm run cosign:web:real-card` uses the physical card through the local PC/SC
reader. On first use it creates `.nuri-card-musig2/browser-real-card.json`,
runs card-side `INS_KEYGEN`, stores the public wallet identity plus a local
demo client secret, and returns a verified aggregate BIP340/MuSig2 signature.
Later requests use `GET_PUBKEY` and fail if the card public key no longer
matches the saved profile.

For CLI-only physical-card proof, run:

```bash
npm run cosign:real-card
npm run cosign:real-card:keygen
npm run cosign:web:real-card:selftest
```

Expected real-card markers:

- `status: REAL_CARD_COSIGN_FLOW_OK`
- first run: `key_origin: on_card_keygen_non_exportable`
- later stable-profile runs: `key_origin: existing_on_card_non_exportable`
- `card_partial_verified: true`
- `final_signature_verified: true`

The output field `final_signature64` is a valid BIP340 Schnorr signature for
`msg32` and `aggregate_xonly32`. To broadcast Bitcoin, `msg32` must be the real
Taproot sighash for a funded transaction and `final_signature64` must be
inserted as the Taproot witness signature.

## Real Bitcoin Signet Demo

The current physical-card wallet identity derives this signet Taproot address:

```bash
npm run bitcoin:card:address
```

Current address:

```text
tb1pywzzgk3p7a5zhhkpqn548pm0xpqqfvzl4jylev522glcjy5npc4sckt9fa
```

It is a key-path Taproot output for the card/client MuSig2 aggregate key:

```text
aggregate_xonly32 = 2384245a21f7682bdec104e953876f304004b05fac89fcb28a523f8912930e2b
scriptPubKey      = 51202384245a21f7682bdec104e953876f304004b05fac89fcb28a523f8912930e2b
```

Check funding:

```bash
npm run bitcoin:card:utxos
```

Build and sign a real self-spend transaction after funding:

```bash
npm run bitcoin:card:spend -- --fee-sats=500
```

That command does not broadcast. It builds a real Taproot key-path transaction,
computes the BIP341 sighash, asks the physical card for the MuSig2 partial,
aggregates the final BIP340 signature, inserts it into the witness, and prints
`raw_tx_hex`.

For a faucet UTXO that is still unconfirmed:

```bash
npm run bitcoin:card:spend -- --include-unconfirmed --fee-sats=500
```

Broadcast is explicit and should only be used after reviewing the printed
transaction:

```bash
npm run bitcoin:card:spend -- --include-unconfirmed --fee-sats=500 --broadcast
```

The CLI can also print human-readable signing progress while keeping stdout as
JSON:

```bash
npm run bitcoin:card:spend -- --amount-sats=1337 --op-return=Nuri.com --fee-sats=500 --verbose
```

The first confirmed physical-card broadcast was:

```text
txid        = d9ecca378bd015f2bd39d3113d3dadc65e6b6f29b72c1d1e6a7d73f246994c38
block       = 308802
block_hash  = 000000130e5278bfe9045681c1cbc23fe3a23dc78d2d570b271730c7ba84ad29
outputs     = 1337 sats to the card address, OP_RETURN "Nuri.com", change to the card address
```

Check the proof transaction:

```bash
npm run bitcoin:card:status -- --txid=d9ecca378bd015f2bd39d3113d3dadc65e6b6f29b72c1d1e6a7d73f246994c38 --verbose
```

For local smoke testing only, a dummy UTXO can be passed manually. This proves
transaction construction and card signing, but it is not broadcastable unless
the outpoint is real:

```bash
npm run bitcoin:card:spend -- --utxo=<txid:vout:value> --fee-sats=500
```

## Offline Backup PRF CLI

For an offline backup use case, the card can derive a stable 32-byte secret without being a wallet signer. This uses the same WebAuthn PRF mapping as browsers: the user salt is transformed as `SHA-256("WebAuthn PRF\0" || salt)` and sent through CTAP2 `hmac-secret`.

On this macOS workstation the card CLI prefers `/opt/homebrew/bin/python3.13` when available. Homebrew `python3` currently points to Python 3.14, which showed intermittent `pyscard` PC/SC context failures with this reader.

Enroll one credential profile on the card:

```bash
npm run card:prf:enroll
```

Or run the full stability proof:

```bash
npm run card:prf:selftest
```

That command enrolls `.nuri-card-prf/default.json` if missing, derives the default salt twice, derives a different salt once, and only passes if:

- same card credential + same salt returns the same PRF;
- same card credential + different salt returns a different PRF;
- the card returns a real 32-byte WebAuthn PRF result.

Derive the default backup secret later:

```bash
npm run card:prf:derive
```

Print only the hex secret:

```bash
npm run card:prf:derive -- --raw
```

Use a different context salt:

```bash
npm run card:prf:derive -- --salt "nuri-wallet-backup-v1:alice"
```

The profile JSON is not the PRF secret, but keep a backup of it. It contains the RP ID and credential ID needed to ask the same card credential for the same PRF. If a production profile should require a FIDO2 PIN, enroll and derive with user verification:

```bash
npm run card:prf:enroll -- --profile pin-backup --user-verification required --pin-prompt
npm run card:prf:derive -- --profile pin-backup --user-verification required --pin-prompt
```

Never run two PC/SC card commands against the same reader at the same time; the reader can reset the card mid-APDU.

## Native Mobile NFC PRF Probe

There is now a minimal Expo SDK 55 app in `mobile/expo-nfc-prf-probe`.

It is intentionally not a PWA and not a WebAuthn wrapper. It talks ISO-DEP NFC directly:

1. select FIDO AID `A0000006472F0001`;
2. run CTAP2 `authenticatorGetInfo`;
3. run CTAP2 `authenticatorClientPIN/getKeyAgreement`;
4. run CTAP2 `authenticatorGetAssertion` with `hmac-secret`;
5. decrypt the extension output and display the 32-byte PRF.

Prepare a desktop profile first:

```bash
npm run card:prf:selftest
cat .nuri-card-prf/default.json
```

Then install the mobile app dependencies:

```bash
cd mobile/expo-nfc-prf-probe
npm install
npm run typecheck
```

Paste the `credential_id` from `.nuri-card-prf/default.json` into the app. Keep `RP ID` as `nuri.local` and `PRF Salt` as `nuri-offline-backup-v1` if you want the phone result to match:

```bash
npm run card:prf:derive -- --raw
```

Android is the easiest real-device path without an Apple developer account:

```bash
npm run mobile:android
```

That reads `.nuri-card-prf/default.json`, injects the saved RP ID and credential ID into the app through Expo public env vars, then builds and installs a native Android development build. It needs Android Studio/SDK and a USB-debugging-enabled Android phone. NFC testing needs a physical Android phone, not an emulator. After installation, run `npm run mobile:start` for later JS iterations.

The wrapper uses the Homebrew Android SDK path `/opt/homebrew/share/android-commandlinetools` when present and forces JDK 17 on macOS, because Java 24 breaks the native CMake build. The verified debug APK output is:

```text
mobile/expo-nfc-prf-probe/android/app/build/outputs/apk/debug/app-debug.apk
```

In the app, tap `Read Card Info` first. If it lists `hmac-secret`, tap `Derive PRF` and compare the `prfHex` result with:

```bash
npm run card:prf:derive -- --raw
```

iOS needs a native build with NFC Tag Reading capability. The app config includes the NFC plugin, the TAG entitlement, and the ISO7816 select identifier, but the local toolchain still has to sign a physical iPhone build with that capability:

```bash
cd mobile/expo-nfc-prf-probe
npm run prebuild -- --platform ios
npm run ios
```

This does not run in Expo Go because `react-native-nfc-manager` requires custom native code. On this machine, `expo-doctor` passed all project checks except local Xcode compatibility: Expo SDK 55 requires Xcode `>=26.0.0`, while the installed Xcode is `16.4.0`. Use Android first or upgrade Xcode before trying the iOS NFC build.

The shorter profile-injected iOS command is:

```bash
npm run mobile:ios
```

That uses the same `.nuri-card-prf/default.json` profile as Android and passes `--device` so Expo targets a physical iPhone. The iOS path uses CoreNFC ISO7816 APDUs through `react-native-nfc-manager`; it is a native app test, not mobile Safari/WebAuthn PRF.

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
- `mobile/expo-nfc-prf-probe/`: native NFC PRF probe app for Android/iOS development builds.

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
- Google System Services release notes, Play services v26.03 NFC CTAP2 note: https://support.google.com/product-documentation/answer/14343500
- Yubico PRF developer guide and platform support matrix: https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html
- Expo SDK 55 reference: https://docs.expo.dev/versions/v55.0.0
- Expo iOS capabilities and entitlements: https://docs.expo.dev/build-reference/ios-capabilities/
- react-native-nfc-manager Expo/development-build note: https://github.com/revtel/react-native-nfc-manager/wiki/Expo-Go
- Android ISO-DEP transceive API: https://developer.android.com/reference/android/nfc/tech/IsoDep
- Apple Core NFC ISO7816 tag API: https://developer.apple.com/documentation/corenfc/nfciso7816tag
- Bryan Jacobs FIDO2Applet: https://github.com/BryanJacobs/FIDO2Applet
- scure MuSig2: https://github.com/paulmillr/scure-btc-signer#musig2
- BIP327 MuSig2: https://bips.dev/327/
