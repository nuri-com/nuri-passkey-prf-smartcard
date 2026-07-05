# Nuri Smartcard — What It Can and Cannot Do

A plain-English summary for hardware suppliers and manufacturers.

---

## What the card is

A Java Card secure element (e.g. Feitian FT-JCOS BioCARD) running **three
independent applets** side by side, each behind its own AID:

| Applet | AID | What it does |
|---|---|---|
| FIDO2 / Passkey | `A0000006472F0001` | WebAuthn authenticator + CTAP2 `hmac-secret` (PRF). Also acts as a hardware SSH key via OpenSSH. |
| MuSig2 cosigner | `4E5552494D554701` | On-card secp256k1 key generation, returns only the public key, signs MuSig2 partials. The private key never leaves the card. |
| OATH-TOTP | `4E555249544F5450` | Stores a 2FA secret, computes HMAC-SHA1 on-card. The secret is written in and never read back. |

All three applets are open-source (MIT) and prebuilt as `.cap` files in
`dist/`. The card must be **unfused/unlocked** with **GlobalPlatform/SCP
transport keys** provided by the seller so the buyer can install these.

---

## What the card CAN do

### 1. SSH hardware key (proven on a real Hetzner server, 2026-07-05)

The card acts as an OpenSSH `sk-ecdsa-sha2-nistp256` hardware key:

- `ssh-keygen -t ecdsa-sk` generates a key pair **on the card**. The private key
  stays in the secure element. Only the public key + a credential ID come back.
- Every SSH login requires the card in a PC/SC reader and a **physical tap**
  (user presence). Without the tap, no signature, no login.
- The "private key" file on disk (`~/.ssh/id_nuri_pcsc_sk`) contains **no
  secret** — just the public key and a credential ID (a reference telling the
  card which credential to use). Copying this file to another machine is
  useless without the physical card.
- Works on any computer after a one-time install of a small provider bridge
  (`nuri-pcsc-sk-provider.so` + Python helper) that translates OpenSSH's FIDO
  calls into PC/SC CTAP2 calls to the card. The provider does no crypto and
  holds no key — it's a wire.
- **Proven:** real login to `root@89.167.91.99` (Hetzner Ubuntu server) with
  two independent cards. Both work. Private key never left the card.

### 2. Passkey / WebAuthn login (proven)

- The card is a CTAP2.1 authenticator: `makeCredential` / `getAssertion` work
  over PC/SC and native NFC.
- Supports `hmac-secret` (PRF extension) — same card + same salt → same 32-byte
  output, forever. This is what ties the card to the Nuri app wallet.
- Verified on hardware: `REAL_CARD_WEBAUTHN_PRF_OK`.

### 3. Bitcoin signer (proven on signet, confirmed in blocks)

- The MuSig2 applet generates a secp256k1 cosigner key **on the card** via
  `INS_KEYGEN` and returns only the 33-byte public key. There is no APDU to
  read the private key out.
- Signs MuSig2 partial signatures. The host builds the transaction; the card
  only protects keys and returns a partial.
- **Proven:** co-signed a live Bitcoin Signet transaction, broadcast and
  confirmed in block `308802`.

### 4. 2FA / TOTP (proven, RFC 6238 verified)

- The OATH-TOTP applet stores a secret, computes HMAC-SHA1 on-card, returns
  the 6-digit code. The secret never leaves the card after being written.
- Verified against the RFC 6238 test vector.

### 5. Same wallet as the Nuri phone app

- The card's FIDO2 PRF output, run through the same HKDF derivation as the
  Nuri app, produces the **byte-identical** wallet/identity key. The card is
  a drop-in for the phone passkey.

---

## What the card CANNOT do (yet)

| Limitation | Why | Status |
|---|---|---|
| **FIDO2 credential cloning** | The private key is generated inside the secure element and there is no APDU to read it out. This is the core security guarantee — if you could clone it, an attacker who steals one card would have everything. | By design, not a bug. Backup = a second independent card. |
| **Browser PRF on macOS** | The card enables `hmac-secret`, but Safari returns `prf:null` for external security keys and Chrome can't see a PC/SC contact reader. This is a **platform limitation** (macOS browser), not a card limitation. Browser PRF works via native NFC app or Windows. | Platform issue. Card works; browser doesn't pass it through. |
| **Fingerprint unlock in our own applet** | Feitian confirms a Java applet can call the match-on-card fingerprint API to gate a private-key operation, but the BioCARD SDK is **NDA-gated**. Today: PIN/UV, or Feitian's own preloaded biometric FIDO2 stack. | Needs NDA SDK. Hardware path identified. |
| **MuSig2 on older OS cards** | secp256k1 EC point-multiply (`ALG_EC_SVDP_DH_PLAIN_XY`) is only available on cards with OS **`2025-05-14`** (ATR `3b:81:80:01:80:80`). The `2023-03-30` OS lacks it → keygen returns `6A81`. The OS is mask-ROM, **not user-updatable**. | Silicon-gated. Must screen each batch with `gp -i`. |
| **NFC tap-to-pay / POS** | The contactless interface works for CTAP2, but a Bitcoin tap-to-pay / POS terminal flow is not built yet. This is the north-star vision, not current capability. | Vision, not built. |
| **Production tamper resistance** | Dev cards are not EAL-certified. Production needs an EAL-certified chip with documented keys. | Hardware decision, not software. |
| **MuSig2 applet audit** | The applet is a proven device primitive, not a reviewed production signer. Nonce policy, PIN/fingerprint policy, and final host-flow hardening are still needed before production use. | Research-grade, not production. |

---

## Hardware requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| Java Card Classic | 3.0.4+ | 3.0.5 |
| GlobalPlatform | install/delete (SCP03 preferred) | SCP03 |
| P-256 keygen | yes | yes |
| ECDSA-SHA256 | yes | yes |
| ECDH plain | yes | yes |
| SHA-256 | yes | yes |
| AES-256-CBC no-pad | yes | yes |
| TRNG | yes | yes |
| NVM | ~100KB+ | 180K+ |
| secp256k1 (`ALG_EC_SVDP_DH_PLAIN_XY`) | needed for MuSig2/Bitcoin | needed for full capability |
| Match-on-card fingerprint API | optional (NDA SDK) | needed for biometric unlock |

**Critical for suppliers:** the card must be **unfused/unlocked** and the
**GlobalPlatform/SCP transport keys** must be provided to the buyer. Without
these, the buyer cannot install the applets. Same model number is not enough
— the OS date matters for secp256k1 support. Screen each batch with
`gp -i` to confirm the OS date is `2025-05-14` or newer.

---

## How SSH works with the card (simple explanation)

Three pieces:

1. **The card** holds the private key. It was generated *inside* the card's
   secure element. There is no command to read it out. The card does the
   actual signing. Without the card, nothing can sign.

2. **Two files on the computer** (`~/.ssh/id_nuri_pcsc_sk` and `.pub`):
   - The `.pub` file is the **public key** — safe to share, goes in the
     server's `authorized_keys`.
   - The "private" key file looks like a normal SSH key but **contains no
     secret**. It holds the public key + a credential ID (a name tag telling
     the card "use credential #X"). Without the physical card, this file is
     useless.

3. **The provider** (`nuri-pcsc-sk-provider.so` + Python helper) is a
   **translator**. OpenSSH has built-in support for hardware SSH keys, but it
   only talks to USB security keys (YubiKey-style). This card is a smartcard
   reached through a PC/SC reader, not USB. The provider sits in between:

   ```
   ssh says "sign this" → provider .so → python helper → PC/SC reader → card signs
   ```

   The provider does no crypto and holds no key. It's a wire. Every computer
   needs it installed **once**. After that, `ssh user@host` works normally.

**Security model:**
- Private key never leaves the card (non-exportable by design).
- Every signature requires a **physical tap** (user presence).
- The key file on disk is inert without the card.
- A stolen laptop + stolen key file = useless without the card.
- A stolen card = useless if you remove its public key from the server.

---

## Backup strategy

You **cannot clone** a FIDO2 credential — the private key is non-exportable.
The backup is a **second independent card** with its own key, both authorized
on the same server:

```
card A (pocket)    → public key A → authorized_keys line 1
card B (home safe) → public key B → authorized_keys line 2
```

- Both cards log into the same server independently.
- If card A is lost/stolen, log in with card B and **remove public key A**
  from `authorized_keys`. The stolen card is now useless.
- This is **stronger than a clone**: a stolen card does not compromise the
  backup.

---

## Proven on real hardware (2026-07-05)

| What | Result |
|---|---|
| Card A logs into `root@89.167.91.99` via SSH | ✅ `OK_FROM_REAL_SERVER` |
| Card B (backup) logs into same server | ✅ `OK_FROM_BACKUP_CARD` |
| Private key never left either card | ✅ by design (no export APDU) |
| Every login required a tap | ✅ user presence enforced |
| Card co-signed live Bitcoin Signet tx | ✅ confirmed in block `308802` |
| Card derives same wallet key as Nuri phone app | ✅ byte-identical |
| Card computes TOTP (RFC 6238) | ✅ verified |

---

## Open source

MIT-licensed. Full source, prebuilt applets, host toolkit, and documentation:
`https://github.com/nuri-com/nuri-passkey-prf-smartcard`