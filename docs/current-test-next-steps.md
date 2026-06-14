# Current Test Next Steps

Date: 2026-06-13

Update: 2026-06-14

## Current Starting Point

- Local Chrome test server is `http://127.0.0.1:8765/prf-test.html`.
- Preferred shared HTTPS tunnel for phone/desktop browser tests is
  `https://regular-jointly-cheetah.ngrok-free.app/prf-test.html`.
- Local PC/SC bridge is enabled on the same server under `/api/pcsc/*`.
- `npm run card:prf:info` sees the current Feitian/FIDO2 card through
  `HID Global OMNIKEY 5422 Smartcard Reader`.
- The current card now runs the local `dist/FIDO2.cap` applet at
  `A0000006472F0001`. It advertises `hmac-secret`, `rk`,
  `clientPin=false`, CTAP2.0, CTAP2.1, and PIN/UV protocols 1 and 2.
- The same card also now runs the Nuri MuSig2 v1.10/KGEN applet at
  `4E5552494D554701`, loaded from
  `dist/nuri-musig2-v20-keygen.cap`.
- Server-cosigner CLI tests pass for `software`, `card-sim`, and `apdu-sim`.
- Fresh FIDO2 credential creation and PRF derivation now pass on the inserted
  Feitian sample over desktop PC/SC.
- After plugging the OMNIKEY reader directly into the Mac on 2026-06-14,
  sandboxed PC/SC sometimes returned `SCARD_E_NO_SERVICE`, but the same scripts
  worked outside the sandbox. For real-card PC/SC tests from Codex, run the card
  scripts with host permissions.
- The vendor preloaded FIDO2 applet returned `CTAP 0x27 OPERATION_DENIED` for
  `makeCredential`, even with PRF disabled, PIN set and verified, direct
  `pinUvAuthParam`, and direct internal UV token. That was fixed by replacing
  the vendor FIDO2 package with the local CAP.
- `npm run card:test`, the ngrok PC/SC selftest, and
  `REAL_CARD=1 npm run cli:e2e` now pass with real-card PRF.
- `npm run card:musig2:test` now passes against the real card with the MuSig2
  Python suite: `Result: 6/6 tests passed`.
- `npm run cosign:real-card` now passes against the real card with on-card
  keygen and final aggregate BIP340 signature verification.
- `npm run cosign:demo` now proves the intended local card-cosigner product
  boundary in simulation: card-generated key in the backend, local cosign
  server request, card partial signature, client partial signature, and a final
  aggregate BIP340/MuSig2 signature with `final_signature_verified=true`.

## Working Real-Card Install Sequence

The successful FIDO2 sequence on 2026-06-14 was:

```bash
FIDO2_RESET_CONFIRM=YES npm run card:reset
gp -r 2 --load dist/FIDO2.cap
gp -r 2 -f --delete A0000006472F
gp -r 2 --package A000000647 --applet A0000006472F0001 --create A0000006472F0001
```

Notes:

- `gp -r 2 -l` showed two OMNIKEY reader slots; reader index 2 was the direct
  contact slot.
- The vendor FIDO2 applet instance `A0000006472F0001` could not be deleted
  directly while its package `A0000006472F` was present.
- Deleting package `A0000006472F` removed the broken vendor FIDO2 instance.
- The local package `A000000647` then created a new standard FIDO2 instance at
  `A0000006472F0001`.
- The local applet reports `up: false`, which is expected for this PC/SC contact
  flow and avoids the vendor applet's `OPERATION_DENIED` user-presence behavior.

The successful MuSig2 add-on sequence on the same card was:

```bash
gp -r 2 --load dist/nuri-musig2-v20-keygen.cap
gp -r 2 --package 4E5552494D5547 --applet 4E5552494D554701 --create 4E5552494D554701
npm run cosign:real-card
npm run card:musig2:test
scripts/card-prf-backup.sh selftest --profile after-musig2-install-prf --force --resident-key discouraged --user-verification discouraged --registration-prf prf --salt 'nuri browser prf first input'
npm run card:test
```

Observed results:

- `gp -r 2 -l` shows `APP: A0000006472F0001` and
  `APP: 4E5552494D554701` as selectable.
- `npm run card:musig2:test` selected the MuSig2 applet and passed card info,
  basic operations, parity handling, single-signer MuSig2, random signatures,
  and multi-party simulation.
- `npm run cosign:real-card` returned `REAL_CARD_COSIGN_FLOW_OK` with
  `key_origin: on_card_keygen_non_exportable`, `card_partial_verified: true`,
  and `final_signature_verified: true`.
- The post-install FIDO2 PRF selftest returned `CARD_PRF_STABLE_OK`.
- The post-install FIDO2 auth+PRF test returned `REAL_CARD_WEBAUTHN_PRF_OK`.

## Step 1: Chrome Desktop Test

Open:

```text
http://127.0.0.1:8765/prf-test.html?run=20260613-chrome-pcsc
```

Or, when the fixed ngrok tunnel is running:

```text
https://regular-jointly-cheetah.ngrok-free.app/prf-test.html?run=20260613-ngrok
```

Start the fixed tunnel without writing the auth token into the repo:

```bash
NGROK_AUTHTOKEN=... ngrok http --domain=regular-jointly-cheetah.ngrok-free.app 8765
```

Test in this order:

1. Click `Diagnostics`.
2. Click `PC/SC Card Info`.
   - Expected: JSON response with `ok: true` and `hmac-secret` in extensions.
3. Click `PC/SC PRF Selftest`.
   - Expected now: JSON response with `ok: true` and
     `CARD_PRF_STABLE_OK` in stdout.
4. Test browser-native WebAuthn:
   - Click `Register Passkey`.
   - If Chrome does not show the smartcard/reader, that is expected for a PC/SC
     reader on macOS. Chrome usually sees platform passkeys and CTAP-HID
     security keys, not this contact smartcard reader.

Interpretation:

- `PC/SC Card Info` passing proves the local machine can talk to the real card.
- Browser-native registration not seeing the reader does not prove the card is
  bad; it means Chrome did not expose this PC/SC reader as WebAuthn transport.
- `OPERATION_DENIED` on PC/SC selftest means the FIDO2 applet/card policy is
  refusing new credential creation on this path. That was the vendor applet
  behavior before the local CAP was installed.
- The ngrok URL is useful for browser/WebAuthn tests from other devices, but
  the `PC/SC *` buttons only work when the request reaches this local machine,
  because they call the local reader bridge connected to the OMNIKEY reader.

## Step 2: CLI Proof

Run:

```bash
npm run cli:e2e
npm run card:prf:info
```

Expected:

- `npm run cli:e2e` ends with `CLI_E2E_OK`.
- `npm run card:prf:info` shows the Feitian/FIDO2 card and `hmac-secret`.
- `npm run card:test` ends with `REAL_CARD_WEBAUTHN_PRF_OK`.
- `REAL_CARD=1 npm run cli:e2e` ends with `CLI_E2E_OK` and includes
  `CARD_PRF_STABLE_OK`.

Optional real-card path:

```bash
REAL_CARD=1 npm run cli:e2e
```

Current expected result: server-cosigner simulator tests pass, real-card info
passes, and real-card PRF selftest passes with `CARD_PRF_STABLE_OK`.

Direct diagnostic commands used on 2026-06-14:

```bash
scripts/card-prf-backup.sh info
scripts/manage-fido2-pin.sh status
scripts/card-prf-backup.sh selftest --profile diag-noprf --force --resident-key discouraged --user-verification discouraged --registration-prf disabled
scripts/card-prf-backup.sh selftest --profile diag-noprf-uv-required --force --resident-key discouraged --user-verification required --registration-prf disabled
scripts/card-prf-backup.sh selftest --profile diag-noprf-rk-required --force --resident-key required --user-verification discouraged --registration-prf disabled
```

Observed vendor-app result before reinstall: `info` and PIN status passed, but
all three credential-create diagnostics returned `OPERATION_DENIED`.

## Step 3: Android Test Phone

If Chrome desktop cannot use the card natively, use the Android ISO-DEP test
app next:

```bash
npm run mobile:android
```

That app talks NFC ISO-DEP directly instead of using browser WebAuthn. It is the
right phone test for cards that the mobile browser path does not expose cleanly.

## Step 4: Local Card-Cosign Web Proof

Run:

```bash
npm run cosign:web
```

Open:

```text
http://127.0.0.1:8787/cosign-demo.html
```

Click `Create Valid MuSig2 Signature`.

Expected:

- `status: NURI_CARD_COSIGN_FLOW_OK`
- `key_origin: card-generated-non-exportable-in-backend`
- `card_partial_verified: true`
- `final_signature_verified: true`
- `final_signature64` is a valid BIP340 signature over `msg32` for
  `aggregate_xonly32`

The browser demo is still backed by the simulator, but the same product shape is
now proven on the real card with:

```bash
npm run cosign:real-card
```

That command uses `INS_KEYGEN` on the installed card applet, so the long-term
cosigner key is generated on-card and never exported.

## Step 5: Card Installation Work

Do not overwrite the current Feitian reference card until it is physically
labeled and its applets are recorded.

Before installing another applet on any other card, collect:

```bash
gp -l
npm run card:prf:info
```

For this card, MuSig2 installation is already proven. For another card,
installation is only possible after we have:

1. A built MuSig2 Java Card CAP.
2. A sacrificial Java Card selected for flashing.
3. GlobalPlatform/SCP install keys for that card, or an unlocked developer card.
4. A host PC/SC APDU test that can replace or complement the current APDU
   simulator backend.

The current repo now proves both the host/server/APDU shape and a standalone
real-card MuSig2 applet test. It still does not prove the final Nuri Arkade
production signer until we bind the card flow to the exact app/server
`@scure/btc-signer` session and finish key lifecycle/policy decisions.
