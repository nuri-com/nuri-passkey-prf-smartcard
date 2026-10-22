# Android card signature demo

Offline, non-payment demonstration of 2-of-2 MuSig2 (BIP327) and BIP340.
The card retains its existing key. The second signer is a **demo cosigner in app
memory, not Nuri server**. No Boltz, LNURL, profile, network request, or environment
configuration is used by the demo entry point. Legacy payment screens remain in
source but are not imported by the app.

## Use

1. Open **Nuri Card · Demo**. Edit the message (default `Nuri card demo`).
2. Enter the existing card PIN. Press **Tap card and sign**.
3. Hold the card against the phone's NFC antenna until verification finishes.
4. Read the card key, aggregate x-only key, SHA-256 message digest, 64-byte
   signature and **Valid BIP340 signature: yes**.

The PIN is hidden, cleared from the field when signing starts, never logged or
persisted, and best-effort cleared from byte buffers. JavaScript strings and
library copies cannot be guaranteed erased. A wrong PIN displays remaining tries
from SW `63Cx`; there is no automatic retry. Do not guess PINs.

```mermaid
sequenceDiagram
  participant U as User
  participant A as Android app
  participant C as PIN2 card
  U->>A: Message + PIN, Tap card and sign
  A->>A: SHA-256(message)
  A->>C: ISO-DEP SELECT 4E5552494D55473201
  A->>C: VERIFY (20), GET_PUBKEY (03)
  A->>C: GET_NONCES (40)
  C-->>A: K1 || K2 || session token (70 bytes)
  A->>A: Ephemeral demo cosigner + BIP327 session
  A->>C: FINALIZE (41), 231 bytes, Le=32
  C-->>A: Card partial signature (32 bytes)
  A->>A: Verify card partial; local partial; aggregate
  A->>A: Verify BIP340 signature, display result
  A-->>C: Close ISO-DEP
```

PIN2 FINALIZE is `a32 || b32 || parity1 || e32 || token4 || R65 || Q65`.
R is the session aggregate nonce **before** parity negation. Q is the signing
aggregate point. Key coefficients include the BIP327 parity/gAcc fold. The demo
matches the real-card reference by normalizing the local key and retrying until
Q has even y; it requires the currently provisioned even-y card key. It never
sends KEYGEN, changes the PIN, installs applets or rekeys the card. Each signing
attempt obtains fresh nonces. Card partials must verify before aggregation.

## Check, build, install

From `mobile/expo-nfc-prf-probe` (dependencies and the read-only local
`../../.build/nuri-design-system` must already be present):

```sh
npm run typecheck
npm run check:design-system
node scripts/test-card-demo.mjs
node scripts/test-card-demo-transport.mjs
export JAVA_HOME=$(/usr/libexec/java_home -v 17)
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"
# If android/ is absent, generate it from app.json:
npx expo prebuild --platform android --no-install
cd android
./gradlew :app:assembleRelease -PreactNativeArchitectures=arm64-v8a --console=plain
cd ..
adb -s R5CR701K92J install -r android/app/build/outputs/apk/release/app-release.apk
adb -s R5CR701K92J shell monkey -p com.nuri.passkeyprfprobe 1
shasum -a 256 android/app/build/outputs/apk/release/app-release.apk
```

Expo's generated release configuration signs this **demo only** APK using its
debug keystore. The release variant embeds the JS bundle: no Metro is required.
This is not production signing or a production wallet.

The software fake-card test independently evaluates the applet's scalar formula,
including both nonce parities, validates the 231-byte payload and verifies the
final signature. It also rejects malformed inputs, tampered partials, consumed
sessions and a wrong message. The transport mock checks SELECT AID, VERIFY,
GET RESPONSE, FINALIZE length/Le, wrong-PIN tries and session cleanup. These tests
do not replace the user's physical NFC card-signing acceptance test.
