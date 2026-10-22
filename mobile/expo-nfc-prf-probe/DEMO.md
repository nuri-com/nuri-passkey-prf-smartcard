# Android card wallet demo

Solarized Light wallet for the S21. First open shows the Nuri card and Scan card. Scanning shows the card and “Hold your Nuri card to the phone”. Home has the official Nuri logo, @username, formatted balance, Receive and Send. Long-press balance (or the initial card) for the signing demo and software-card toggle. Tap balance to reopen/refresh. Release APK embeds JavaScript; Metro is not needed.

Typography is 17px with a single 28px heading size. Buttons are full-width, 56px minimum, with primary blue and secondary outlined treatments. Back is text-only. No phone installation or device access is part of this polish build.

## Implemented and phone-tested

- Software-card registration with live exact-pair readback.
- Recovery-contract Ark and Bitcoin boarding addresses, selectable text and Copy, no QR.
- Live operator VTXO, boarding UTXO, and direct MuSig2+CSV on-chain balances; Home shows their single combined total, including unconfirmed on-chain UTXOs. The direct address is derived from the runtime card key, live Nuri server key and validated CSV policy, matching the server's tapscript leaf. Arkade spendability remains separate for send preflight. Failed discovery never becomes a fake zero.
- Software signing with exact 231-byte FINALIZE protocol and aggregate BIP340 verification.
- Send preflight refresh, address/amount validation, insufficient-funds rejection.
- Runtime card GET_PUBKEY, AID3 default (`4E5552494D55473301`), optional `EXPO_PUBLIC_NURI_CARD_AID`, reader mode NFC_A + SKIP_NDEF_CHECK, 15-second transceive timeout. No KEYGEN.

## Not complete

No broadcast or money movement: funded sends fail closed. Live Nuri co-sign approval integration is not connected. `cardWalletApproval.ts` and `cardAutoClaim.ts` are adapters, not proof of completed auto-claim. The signer-only `/info` query returns null username even for the separately claimed card. The wallet now passes `client_pk33` plus the known public `cred_id_b64u` hint; live readback returns `arkade`. AsyncStorage is absent, so the public known-card map is an in-memory constant. This hint is not an authentication credential. No automatic real-card claim was executed. Name remains unavailable unless the live response identifies it. Fresh PIN/UV token after makeCredential and explicit non-resident allowList are mandatory for later approval work.

The public known-card lookup key and credential hint are bundled; signing keys and wallet addresses are never hardcoded. The independently claimed name and exact final-card addresses must be verified with the user's live NFC tap. Software credentials are throwaway and volatile. Do not fund the software wallet.

```mermaid
sequenceDiagram
  participant U as User
  participant A as Android wallet
  participant C as AID3 card
  participant N as Nuri API
  participant O as Ark operator and chain API
  U->>A: Open / tap balance
  A->>C: SELECT; GET_PUBKEY
  C-->>A: Runtime public key
  A->>N: Read recovery policy and derived server key
  A->>O: Read operator policy
  A->>A: Derive recovery-contract addresses
  A->>O: Read VTXOs and boarding UTXOs
  A-->>U: Balance / Receive / Copy
  U->>A: Send address + sats
  A->>O: Refresh balances (read only)
  A-->>U: Insufficient funds, or fail closed
  Note over A,O: No broadcast or settlement endpoint
```

## Build and install

```sh
npm run typecheck
npm run check:design-system
node scripts/test-software-card.mjs
node scripts/test-card-demo-transport.mjs
export JAVA_HOME=$(/usr/libexec/java_home -v 17)
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
cd android
./gradlew :app:assembleRelease -PreactNativeArchitectures=arm64-v8a --console=plain
adb -s R5CR701K92J install -r app/build/outputs/apk/release/app-release.apk
adb -s R5CR701K92J shell am start -n com.nuri.passkeyprfprobe/.MainActivity
```

Release variant uses the existing demo debug signing configuration, not production signing. PIN strings cannot be guaranteed erased by JavaScript; input and byte buffers are cleared best-effort, never logged. Read-only card discovery does not VERIFY or consume PIN tries.
