# Android PRF Test Plan

Date: 2026-05-22

## Goal

Prove which Android path can produce a PRF from the Feitian/Java Card FIDO2 applet:

1. browser WebAuthn PRF over Android Chrome;
2. installed PWA using the same WebAuthn API;
3. native NFC APDU over ISO-DEP using the Expo test app;
4. desktop/CLI PCSC as the known-good baseline.

## Current Evidence

The card and applet already pass the real-card CLI baseline:

```bash
npm run card:test
npm run card:prf:selftest
```

`card:test` proves WebAuthn-style PRF through Python `fido2` with CTAP2 `hmac-secret`. `card:prf:selftest` proves a stable offline-backup PRF: same credential and salt return the same 32-byte output.

Observed browser/NFC behavior:

- iOS browser + NFC card can register and authenticate, and reports transport `nfc`, but PRF is `null` and authenticator data does not include extension data.
- Android Chrome + NFC card currently fails during registration with `NotReadableError` from Android Credential Manager, even with `residentKey: discouraged`.
- Android Chrome + NFC card also fails the no-PRF diagnostic with `registrationPrf: disabled` and `authenticationPrf: disabled`. The phone scans the card, then Android Credential Manager returns `NotReadableError` before any PIN prompt.
- The Android error maps to AndroidX Credential Manager's `NotReadableError`, documented as an authenticator response exception indicating an I/O read operation failed during public-key credential creation.

Important diagnostic detail: if the page output still shows `registrationPrf: enabled`, the Android no-PRF diagnostic was not applied. Use `Android No-PRF Diagnostic` to test basic Android NFC WebAuthn without PRF.

Current platform nuance, verified 2026-05-22:

- Google System Services release notes say Google Play services v26.03, released 2026-01-26, allows account authentication through NFC security keys that support CTAP2.
- That is broader than PRF. It means Android's NFC CTAP2 path may now be rolling out or partially available for authentication/PIN/passkeys on some devices.
- Yubico's PRF-specific developer guide still lists Android Chrome roaming authenticator PRF as `USB: yes, NFC: no`.
- Therefore a No-PRF NFC registration can become possible before PRF over NFC becomes possible. Treat these as separate tests.

## Browser/PWA Android Path

The browser page is:

```text
https://7b8b-90-187-235-105.ngrok-free.app/prf-test.html?v=android7&preset=android-noprf
```

Start or restart the tunnel with:

```bash
npm run web:tunnel
```

The page is PWA-installable. PWA install does not grant raw NFC APDU access; it still uses WebAuthn. This is useful to test Android Chrome's WebAuthn behavior, not to bypass Chrome/Android authenticator routing.

Suggested Android Chrome settings:

- Authenticator: `cross-platform`
- User verification: `discouraged` first, then `preferred`
- Resident key: `discouraged` for roaming-key compatibility; then test `required`
- PRF input mode: `eval`

Expected interpretation:

- If `prf.results.firstHex` is present, Android browser path works for that selected authenticator.
- If authentication works but `prf` is `{}` or `null`, the browser/authenticator path did not return PRF extension output.
- If Google Password Manager works but NFC card does not, the browser PRF implementation is fine and Android NFC roaming-key routing is the blocker.
- If USB security key works but NFC card does not, that matches Yubico's published Android matrix: Chrome Android supports roaming PRF over USB but not NFC.
- If the No-PRF diagnostic works but PRF registration or authentication fails, Android NFC CTAP2 auth works on that device, but WebAuthn PRF/CTAP2 `hmac-secret` is not being exposed through the Android browser NFC path.

As of Yubico's PRF developer guide, PRF support is platform-chain dependent. Their table lists Android Chrome as supporting PRF for Google Password Manager, and for roaming authenticators as `USB: yes, NFC: no`. This matches the browser test direction: the card can be correct and still fail through the Android browser NFC path.

Chrome's Web NFC API does not solve this. Web NFC is limited to NDEF records and explicitly does not expose low-level ISO-DEP/APDU I/O. Browser FIDO/WebAuthn NFC goes through Android's credential/FIDO stack, not through JavaScript-accessible NFC.

## Native Android NFC Path

The Expo app is in:

```text
mobile/expo-nfc-prf-probe
```

It does not use WebAuthn. It uses `react-native-nfc-manager` to open `IsoDep`, SELECTs FIDO AID `A0000006472F0001`, and sends CTAP2 CBOR APDUs. Android's `IsoDep.transceive()` API is the correct primitive for raw ISO-DEP command/response.

This is why the CLI works while Android browser NFC may fail:

- CLI/PCSC path: our code directly selects the FIDO applet and sends CTAP2 APDUs. It can set the exact CTAP options and extension inputs, and it is not mediated by Android Credential Manager.
- Browser/PWA path: JavaScript only calls WebAuthn. Chrome delegates to Android/Google Play Services/Credential Manager. The site cannot force the platform to send CTAP2 `hmac-secret` over NFC.
- Native Android path: the app can use ISO-DEP `transceive()` and implement the CTAP2 NFC framing itself, like the CLI does.

Yubico's Android PRF sample uses YubiKit-Android for exactly this class of native flow. Their sample describes PRF as WebAuthn `prf` mapped through CTAP `hmac-secret`, and uses SDK code that abstracts NFC/USB differences.

Token2's FIDO Bridge/Authnkey is another practical workaround. It installs as an Android credential provider and exists specifically to bridge Android's limited native NFC CTAP2 support for security keys. It is useful to test with commercial keys, but for this project a small native app gives us more control and avoids depending on a third-party credential provider.

Run:

```bash
npm run mobile:android
```

`npm run mobile:android` reads `.nuri-card-prf/default.json`, injects the saved RP ID and credential ID into the app through Expo public env vars, then uses `expo run:android`. It builds a native development app because the NFC module requires custom native code. NFC testing requires a physical Android phone.

The Android native project and debug APK build were verified on this Mac after installing Android command-line SDK packages and forcing JDK 17. The APK path is:

```text
mobile/expo-nfc-prf-probe/android/app/build/outputs/apk/debug/app-debug.apk
```

The app expects a profile created on desktop:

```bash
npm run card:prf:selftest
cat .nuri-card-prf/default.json
```

Paste `credential_id` into the app. Keep:

```text
RP ID: nuri.local
PRF Salt: nuri-offline-backup-v1
```

The Android native app result should match:

```bash
npm run card:prf:derive -- --raw
```

## What Would Count As Success

> **Historical probe criteria:** this section describes the original standalone
> PRF diagnostic UI. The current Expo app is the Nuri Card Terminal documented
> in `mobile/expo-nfc-prf-probe/README.md`; it no longer exposes the two buttons
> named below.

Minimum Android success:

- Native app `Read Card Info` returns versions/extensions including `hmac-secret`.
- Native app `Derive PRF` returns a 32-byte hex string.
- The native app PRF equals `npm run card:prf:derive -- --raw` for the same credential and salt.

Browser success:

- Android Chrome page registration reports `prf.enabled: true`.
- Android Chrome authentication reports `prf.results.firstHex`.

If native works and browser NFC does not, the product can still support Android phone-tap PRF through a native app, but not as a pure browser/PWA NFC card flow.

## References

- Yubico PRF developer guide and support matrix: https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html
- MDN WebAuthn PRF extension semantics: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions#prf
- Google passkey support on Android and Chrome: https://developers.google.com/identity/passkeys/supported-environments
- Android Credential Manager `NotReadableError`: https://developer.android.com/reference/androidx/credentials/exceptions/domerrors/NotReadableError
- Chrome Web NFC limitation to NDEF/no ISO-DEP: https://developer.chrome.com/docs/capabilities/nfc
- Android `IsoDep.transceive()` API: https://developer.android.com/reference/android/nfc/tech/IsoDep#transceive(byte%5B%5D)
- react-native-nfc-manager Expo note: https://github.com/revtel/react-native-nfc-manager/wiki/Expo-Go
- YubicoLabs Android PRF sample: https://github.com/YubicoLabs/android-prf-sample
- Token2 FIDO Bridge/Authnkey manual: https://www.token2.eu/site/page/fido-bridge-for-android-user-manual
