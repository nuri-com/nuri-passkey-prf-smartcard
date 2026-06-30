# FIDO2 user-presence fix — make the card usable as a browser/web passkey

## Problem

Browser WebAuthn against the card hangs at macOS "insert and activate your
security key", then fails with `NotAllowedError`. This blocks:

- desktop Safari/Chrome passkey + PRF (our `web/card-wallet.html` browser mode, filekey.app, any WebAuthn site)
- **phone web / PWA + NFC tap** PRF (the future "tap card, browser derives the wallet" UX)

It does **not** block: the PC/SC reader path (our wallet) or a phone **native**
app reading PRF over ISO-DEP NFC directly.

## Root cause

The applet's CTAP2 `authenticatorGetInfo` options map advertises `up: false`:

```
CannedCBOR.AUTH_INFO_SECOND:  "up" -> 0xF4 (false)
```

…but the applet **always** asserts user presence in every response:

```
FIDO2Applet.java:4087   final byte flag_byte = 0x01; // User always present
FIDO2Applet.java:4651   // Presence not really implemented - user always considered present
```

So the *advertised capability* contradicts the *actual behavior*. Platforms
(macOS/Safari, and by extension phone-web NFC) refuse a roaming authenticator
that claims it cannot test user presence.

## Fix

One byte: advertise `up: true`. Recorded as
[`patches/0002-advertise-user-presence.patch`](../patches/0002-advertise-user-presence.patch).

```
CannedCBOR.AUTH_INFO_SECOND:  "up" -> 0xF5 (true)
```

Card presence (insert / NFC tap) is the user-presence signal — which is the
correct semantics for a tap-to-pay card. No assertion-path change is needed
because the applet already returns UP=1.

Build (offline, no card):

```bash
npm run card:build        # rebuilds dist/FIDO2.cap with the patch applied
# (during this work we built a side artifact dist/FIDO2-up.cap to avoid
#  touching the installed dist/FIDO2.cap before flashing)
```

## Transport matrix (why the fix matters)

| Path | Card PRF in… | Before | After fix |
|---|---|---|---|
| Desktop browser + reader | Safari/Chrome WebAuthn | ❌ `up:false` | ✅ |
| Phone **web / PWA** + NFC tap | mobile browser WebAuthn | ❌ `up:false` | ✅ (expected) |
| Phone **native** app + NFC tap | ISO-DEP CTAP direct | ✅ | ✅ |
| Desktop **reader** (our wallet) | local PC/SC bridge | ✅ | ✅ |

## Flash + verify plan — LATER, NOT NOW

⚠️ Reflashing the FIDO2 applet **wipes the `wallet-client` PRF credential**, so
the card wallet address (currently funded on mainnet) **changes**. Order:

1. **First:** let the funded mainnet tx settle and **sweep** the card wallet
   (`web/card-wallet.html` → Send → self/your address → broadcast).
2. Reflash the user-presence CAP (test card OK to wipe):
   ```bash
   FIDO2_REINSTALL_CONFIRM=YES GP_READER_INDEX=2 npm run card:reinstall   # uses dist/FIDO2.cap
   ```
3. Verify the capability flipped:
   ```bash
   npm run card:prf:info        # expect options.up == true
   ```
4. Re-test browser PRF: Safari/Chrome on `http://localhost:8787/wallet`
   (switch the page back to WebAuthn mode), filekey.app, and a phone-web NFC tap.
5. Re-enroll the wallet PRF credential and re-provision the address (it will be
   a new address — fund the new one).

## Honest caveat

Advertising `up:true` is **necessary** and the most likely sufficient fix. macOS
may still impose additional security-key requirements; if browser PRF still
fails after the flash, the native-NFC path already works today and is the
fallback for the phone product. We can only confirm browser acceptance after the
flash (step 4), which is deferred until the wallet is swept.
</content>
