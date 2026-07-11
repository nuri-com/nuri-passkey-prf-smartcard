# Nuri Card Terminal

Native Expo development app for the Nuri NFC card. It provides a Lightning
point-of-sale terminal and an authenticated card profile over ISO-DEP NFC.

The app uses the Nuri React Native design system (`@nuri/rn`) for every visible
screen element. Business logic remains in the app; visual components, spacing,
typography, lists, alerts, fields, and buttons come from the design system.

## Current user flow

### Terminal

1. The Lightning address is prefilled with `smartcard@nuri.com` and can be
   changed with the design-system `Edit` action.
2. The merchant enters the amount in sats with the embedded design-system
   keypad.
3. `Charge` resolves the Lightning address and opens payment confirmation.
4. The customer enters the four-digit card PIN with the same keypad and presses
   `Confirm`.
5. The app reads the card, creates and funds the Arkade/Boltz payment, waits for
   funded status, and shows a human-readable success or error state.
6. `New payment` returns to the terminal.

Merchant name and memo are not user inputs. The app supplies the internal
values `Nuri Terminal` and `Nuri Terminal charge` to the existing payment flow.

### Profile

1. The user enters the four-digit card PIN with the embedded design-system
   keypad and presses `Read card`.
2. The PIN keypad is replaced by one card-reading alert and one disabled
   `Reading card…` action. Transient NFC transport loss retries automatically
   within a 21-second read window; PIN, authentication, and server failures do
   not retry.
3. One NFC session authenticates the physical card and registered FIDO
   credential, reads the Lightning account, derives the Ark address, loads the
   balance, and synchronizes incoming payments.
4. Claimable incoming payments start automatically. Receive claims use the
   dedicated `/api/arkade/receive/claim/approve` approval flow and
   approval-token signing through `/arkade/sign`; they do not use outgoing
   `send/prepare` state.
5. The loaded profile shows the balance first and a full-width design-system
   list for the
   Lightning address, wallet address, card status, and card reference.
6. Address/reference rows copy their complete value through `expo-clipboard`.
7. The screen always exposes one primary action: `Read card`, a disabled busy
   state, `Refresh profile`, or `Try incoming payment again`.

Status, copy confirmation, and errors use design-system `Alert` components.
Raw protocol logs remain in the development console and are not displayed to
users.

## Required configuration

This app requires an existing credential profile for the inserted card and live
Arkade endpoints:

```bash
export NURI_PRF_PROFILE=/absolute/path/to/the-card-profile.json
export EXPO_PUBLIC_ASP_BASE=https://your-live-arkade-v4.example/v4
export EXPO_PUBLIC_NODE_URL=https://your-live-ark-node.example
```

The launcher reads the RP ID, origin, credential ID, and credential public key
from the selected profile. Do not paste credential data into the UI and do not
replace an existing credential during normal app startup.

## Install and run

The NFC module requires a native development build; Expo Go is not supported.

```bash
cd mobile/expo-nfc-prf-probe
npm install
npm run android:profile
```

After the native app is installed, JavaScript-only iterations can use:

```bash
npm run start:profile -- --port 8081 --clear
adb reverse tcp:8081 tcp:8081
```

On this Mac, the wrapper selects JDK 17 and the Android SDK at
`/opt/homebrew/share/android-commandlinetools`. NFC testing requires a physical
Android phone. iOS testing similarly requires a physical iPhone and a signing
profile with NFC Tag Reading entitlement:

```bash
npm run ios:profile
```

## Verification

Bundle the complete Android JavaScript path:

```bash
EXPO_PUBLIC_ASP_BASE=https://example.com/v4 \
EXPO_PUBLIC_NODE_URL=https://example.com \
EXPO_PUBLIC_NURI_RP_ID=example.com \
EXPO_PUBLIC_NURI_ORIGIN=https://example.com \
EXPO_PUBLIC_NURI_CREDENTIAL_ID=test \
EXPO_PUBLIC_NURI_CREDENTIAL_PUBLIC_KEY=test \
npx expo export --platform android --output-dir /tmp/nuri-card-terminal
```

Build the native Android app with JDK 17:

```bash
cd android
JAVA_HOME=$(/usr/libexec/java_home -v 17) \
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools \
ANDROID_SDK_ROOT=/opt/homebrew/share/android-commandlinetools \
NODE_ENV=development \
./gradlew app:assembleDebug
```

The full TypeScript check currently traverses the linked design-system source
package and reports its external peer-resolution errors. Android Metro export
and the native Gradle build are the authoritative app compile checks until that
package-level TypeScript setup is corrected.

The receive-claim routing change has been compiled and exercised through app
startup, but a fresh claimable payment was not available for a new physical-card
end-to-end claim in this change. Do not describe the claim repair as live-proven
until that card-backed run completes successfully.

## Security boundaries

- The phone holds no MuSig2 private key; the card supplies the client signing
  partial and the ASP supplies the server partial.
- The four-digit PIN authorizes the FIDO2 assertion used by send/claim approval.
- Card credential profiles and PRF output must not be committed. PRF output is
  secret.
- A successful local build is not proof of a completed Lightning payment. The
  payment screen reports success only after Ark broadcast, server completion,
  and funded status succeed.
