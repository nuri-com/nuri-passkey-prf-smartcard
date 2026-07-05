# SSH with the Nuri Smartcard

Use the Nuri smartcard as a **hardware SSH key**: the private key is generated
inside the card's secure element and never leaves it. No key file on disk can be
stolen — the card *is* the key. Every SSH authentication requires the card to be
in the reader and (by default) a tap on the card to prove user presence.

This document is the complete, reproducible guide: what it is, how it works,
how to set it up on any machine, how to add a backup card, and the design
decisions behind it.

---

## Table of contents

- [What it does](#what-it-does)
- [How it works (architecture)](#how-it-works-architecture)
- [Requirements](#requirements)
- [One-command setup on a new machine](#one-command-setup-on-a-new-machine)
- [Enrolling a new SSH key on the card](#enrolling-a-new-ssh-key-on-the-card)
- [Authorizing the key on your server](#authorizing-the-key-on-your-server)
- [Logging in](#logging-in)
- [Adding a backup card](#adding-a-backup-card)
- [Using it on another machine](#using-it-on-another-machine)
- [Tap vs. always-plugged-in](#tap-vs-always-plugged-in)
- [Decision log (why this design)](#decision-log-why-this-design)
- [Troubleshooting](#troubleshooting)
- [What lives where (file reference)](#what-lives-where-file-reference)

---

## What it does

- **The card is your SSH key.** A FIDO2 credential is generated on the card's
  secure element via CTAP2 `makeCredential`. The private key never leaves the
  card — there is no APDU to read it out.
- **Tap to sign.** Every SSH authentication calls CTAP2 `getAssertion` with the
  `up` (user presence) flag. The card blinks / you tap it, and the signature is
  produced. Without the tap, no signature, no login.
- **Nothing stealable on disk.** The "private key" file on disk
  (`~/.ssh/id_nuri_pcsc_sk`) contains only the **public key** and the
  **credential ID (key handle)** — a reference, not the secret. Copying that
  file to another machine does not let anyone sign without the physical card.
- **Works on any machine after a one-time setup.** The card speaks PC/SC
  (smartcard), not USB CTAP-HID. Stock OpenSSH only looks for USB FIDO devices,
  so a small **provider bridge** (`nuri-pcsc-sk-provider.so`) must be installed
  on each host machine to translate OpenSSH's FIDO calls into PC/SC CTAP2 calls
  to the card. After that one-time setup, it's just `ssh user@host` + tap.

---

## How it works (architecture)

```
┌─────────────┐     OpenSSH (ssh-keygen / ssh / ssh-agent)
│  your mac   │           │
│  or Linux   │           ▼
│  box        │   ┌──────────────────────┐
└─────────────┘   │ nuri-pcsc-sk-        │  OpenSSH FIDO SecurityKeyProvider
                  │ provider.so         │  (dlopen'd by ssh-keygen/ssh)
                  │  (C shim)            │
                  └────────┬───────────┘
                           │ exec()
                           ▼
                  ┌──────────────────────┐
                  │ ssh-pcsc-sk-helper.py│  Python: python-fido2 + pyscard
                  │  (enroll / sign)     │  CTAP2 over PC/SC
                  └────────┬───────────┘
                           │ PC/SC APDUs
                           ▼
                  ┌──────────────────────┐
                  │  PC/SC reader        │  e.g. HID OMNIKEY 5422
                  │  (contact or NFC)    │
                  └────────┬───────────┘
                           │ ISO 7816 / ISO 14443
                           ▼
                  ┌──────────────────────┐
                  │  Nuri smartcard      │  Java Card secure element
                  │  FIDO2 applet        │  AID A0000006472F0001
                  │  (key lives here)     │  private key NEVER leaves
                  └──────────────────────┘
```

**The flow for each SSH login:**

1. `ssh user@host` → OpenSSH loads `~/.ssh/id_nuri_pcsc_sk` (public key + key
   handle only).
2. Server sends a challenge.
3. OpenSSH calls `sk_sign()` in the provider `.so`.
4. The provider shells out to `ssh-pcsc-sk-helper.py`, which sends a CTAP2
   `getAssertion` APDU to the card over PC/SC.
5. **You tap the card** (user presence). The card signs the challenge.
6. The signature goes back to OpenSSH → server verifies against the public key
   in `authorized_keys`.

The private key is never on the host, never on the wire, never in the reader.
It is in the card's secure element, period.

---

## Requirements

**On the host machine (your laptop / workstation):**

| Requirement | macOS | Linux |
|---|---|---|
| C compiler (clang/gcc) | Xcode CLI | `gcc` |
| Python 3.10+ | `brew install python` | system or pyenv |
| OpenSSH (with FIDO support) | `brew install openssh` | `apt install openssh-client` |
| PC/SC daemon | built into macOS | `apt install pcscd && systemctl start pcscd` |
| PC/SC reader | any PC/SC-compatible reader (ACS ACR39U, HID OMNIKEY 5422, ACR122U) | same |
| The Nuri smartcard | inserted in the reader (contact slot or NFC surface) | same |

**On the card:**
- The FIDO2 applet must be installed (AID `A0000006472F0001`). The repo's
  `dist/FIDO2.cap` is the prebuilt applet; install with `npm run card:install`.

---

## One-command setup on a new machine

```bash
git clone https://github.com/nuri-com/nuri-passkey-prf-smartcard.git
cd nuri-passkey-prf-smartcard
bash scripts/install-ssh-card-host.sh
```

This does four things:
1. Builds `dist/nuri-pcsc-sk-provider.so` (the OpenSSH FIDO provider bridge).
2. Sets up a Python venv with `fido2` + `pyscard` (the provider calls it).
3. Writes an ssh_config snippet into `~/.ssh/config` (edit the HostName/User).
4. Checks if an SSH key file already exists at `~/.ssh/id_nuri_pcsc_sk`.

After it finishes, **edit `~/.ssh/config`** and replace
`REPLACE_ME.example.com` with your server's hostname/IP, and set the right
`User`.

If you already have a key file (`~/.ssh/id_nuri_pcsc_sk`) from a previous
enrollment, you're done — skip to [Logging in](#logging-in).

If you **don't** have a key yet (first time, or a new card), enroll one:

---

## Enrolling a new SSH key on the card

This creates a new FIDO2 credential *on the card*. The card generates the
private key inside its secure element; you get back only the public key + a
credential ID (key handle).

```bash
cd /path/to/nuri-passkey-prf-smartcard
PROVIDER=$(pwd)/dist/nuri-pcsc-sk-provider.so

# Use homebrew OpenSSH on macOS (stock /usr/bin/ssh-keygen lacks FIDO support)
SSH_KEYGEN=ssh-keygen
command -v /opt/homebrew/bin/ssh-keygen >/dev/null 2>&1 && SSH_KEYGEN=/opt/homebrew/bin/ssh-keygen

$SSH_KEYGEN -t ecdsa-sk \
  -w "$PROVIDER" \
  -f ~/.ssh/id_nuri_pcsc_sk \
  -C "nuri-card"
```

You'll see:
```
Generating public/private ecdsa-sk key pair.
You may need to touch your authenticator to authorize key generation.
Your identification has been saved in /Users/you/.ssh/id_nuri_pcsc_sk
Your public key has been saved in /Users/you/.ssh/id_nuri_pcsc_sk.pub
```

**Tap the card** when prompted. The card generates the key pair and returns
only the public portion + the credential ID. The private key stays inside the
secure element.

> **Note:** `ssh-keygen -t ecdsa-sk` (not `sk-ecdsa-sk`). OpenSSH's naming is
> `ecdsa-sk` / `ed25519-sk`, but the wire algorithm is
> `sk-ecdsa-sha2-nistp256@openssh.com`.

### Verifying the key works

```bash
# Sign a test message
echo "hello" > /tmp/test.txt
SSH_SK_PROVIDER=$PROVIDER $SSH_KEYGEN -Y sign -f ~/.ssh/id_nuri_pcsc_sk -n file /tmp/test.txt

# Verify it
echo "nuri-card $(cat ~/.ssh/id_nuri_pcsc_sk.pub)" > /tmp/allowed_signers
$SSH_KEYGEN -Y verify -f /tmp/allowed_signers -I nuri-card -n file -s /tmp/test.txt.sig < /tmp/test.txt
# → Good "file" signature for nuri-card with ECDSA-SK key SHA256:...
```

---

## Authorizing the key on your server

Copy the **public key** to your server's `~/.ssh/authorized_keys`. The public
key is safe to share — it's just the card's public half.

```bash
# On the host machine:
cat ~/.ssh/id_nuri_pcsc_sk.pub
# → sk-ecdsa-sha2-nistp256@openssh.com AAAA... nuri-card

# Add it to the server (using an existing key to get in):
PUBKEY=$(cat ~/.ssh/id_nuri_pcsc_sk.pub)
ssh -i ~/.ssh/hetzner_short_key root@YOUR_SERVER "echo '$PUBKEY' >> ~/.ssh/authorized_keys"
```

Or use `ssh-copy-id` (it won't work with the card directly, but you can use
any existing working key to add the card's public key):

```bash
ssh-copy-id -i ~/.ssh/id_nuri_pcsc_sk -o "IdentityFile=~/.ssh/hetzner_short_key" root@YOUR_SERVER
```

---

## Logging in

Once the key is authorized and `~/.ssh/config` has the alias:

```bash
ssh nuri-card-host
# or directly:
ssh -i ~/.ssh/id_nuri_pcsc_sk \
    -o SecurityKeyProvider=/path/to/nuri-pcsc-sk-provider.so \
    root@YOUR_SERVER
```

**Tap the card** when you see:
```
Confirm user presence for key ECDSA-SK SHA256:...
```

You're in. The private key never left the card.

---

## Adding a backup card

### Why you cannot clone the card

**A FIDO2 credential cannot be cloned.** This is the core security guarantee of
the FIDO2 / WebAuthn standard. The private key is generated *inside* the
card's secure element via CTAP2 `makeCredential`. There is no APDU, no command,
no API to read the private key out — by design. If you could clone it, anyone
who steals one card would have your SSH access forever. The non-exportability
*is* the security.

### The right backup pattern: a second independent card

The correct backup is **a second card with its own independent key**, both
authorized on the same server:

```
card A (pocket)     → pubkey A → authorized_keys line 1
card B (home safe)  → pubkey B → authorized_keys line 2
```

- Both cards can log into the same server independently.
- If card A is lost/stolen, you log in with card B and **remove pubkey A** from
  `authorized_keys`. The stolen card is now useless.
- If card B is destroyed, card A still works. Enroll a new card C, add its
  pubkey, remove B.

This is strictly **stronger** than a clone:
- A clone means if one is stolen, both are compromised (same key).
- Two independent keys means a stolen card does not compromise the backup.

### How to set up the backup card

1. **Insert the second card** into the reader.
2. **Enroll a new SSH key on it** (different filename so you keep both):
   ```bash
   $SSH_KEYGEN -t ecdsa-sk \
     -w "$PROVIDER" \
     -f ~/.ssh/id_nuri_pcsc_sk_backup \
     -C "nuri-card-backup"
   ```
   Tap the **second** card when prompted.
3. **Add its public key to the server**:
   ```bash
   PUBKEY_B=$(cat ~/.ssh/id_nuri_pcsc_sk_backup.pub)
   ssh root@YOUR_SERVER "echo '$PUBKEY_B' >> ~/.ssh/authorized_keys"
   ```
4. **Test it**: insert card B, log in with `ssh -i ~/.ssh/id_nuri_pcsc_sk_backup ...`.
5. **Store card B safely** (home, safe, etc.). Store the backup key file
   somewhere accessible but it's not secret — it only has the public key +
   credential ID, not the private key.

### If a card is lost

```bash
# Log in with the backup card
ssh -i ~/.ssh/id_nuri_pcsc_sk_backup root@YOUR_SERVER

# Remove the lost card's public key
ssh -i ~/.ssh/id_nuri_pcsc_sk_backup root@YOUR_SERVER \
  "sed -i '/nuri-card$/d' ~/.ssh/authorized_keys && echo 'nuri-card removed'"
# Or more precisely, remove by the lost card's fingerprint
```

---

## Using it on another machine

To use the card on a **different computer** (e.g. your laptop at a friend's
office, or a second workstation):

```bash
# 1. Clone the repo (or copy it from a USB stick)
git clone https://github.com/nuri-com/nuri-passkey-prf-smartcard.git
cd nuri-passkey-prf-smartcard

# 2. Run the one-command installer
bash scripts/install-ssh-card-host.sh

# 3. Copy your existing key file from the first machine
#    (the key file only has the public key + credential ID — safe to copy)
scp first-machine:~/.ssh/id_nuri_pcsc_sk ~/.ssh/id_nuri_pcsc_sk
scp first-machine:~/.ssh/id_nuri_pcsc_sk.pub ~/.ssh/id_nuri_pcsc_sk.pub

# 4. Edit ~/.ssh/config → set your server's HostName/User

# 5. Plug in the reader + card, and:
ssh nuri-card-host
```

> **The key file is safe to copy.** It contains the public key and the
> credential ID (a reference to which credential on the card to use). It does
> **not** contain the private key. Without the physical card, the key file is
> useless.

> **Why can't this be zero-install?** OpenSSH's built-in FIDO support
> (`ecdsa-sk`) only talks to **USB CTAP-HID** devices (YubiKey, Feitian ePass).
> A PC/SC smartcard reader is not a CTAP-HID device — it's a smartcard
> interface. The `nuri-pcsc-sk-provider.so` bridge translates between OpenSSH's
> FIDO API and the card's PC/SC CTAP2 protocol. This is the one-time cost of
> using a smartcard instead of a USB security key.

---

## Tap vs. always-plugged-in

Two behaviors, both supported:

| Mode | How | Security |
|---|---|---|
| **Tap every time** (default) | Default enrollment (UP flag set). Each SSH auth, you tap the card. | Strongest — proves you're present for *this* sign. |
| **Auto while plugged in** | Enroll with `-O no-touch-required` and add `no-touch-required` to `authorized_keys`. | Weaker — any process on your laptop can SSH while the card is in the reader. |

**Recommendation: keep tap-every-time.** This is exactly the "show I'm here"
model you described. The whole point of moving off stealable disk keys is that
a signature requires *you + the card*, not just *the card sitting there*.

### Switching to no-touch (not recommended)

```bash
# Re-enroll with no-touch-required:
$SSH_KEYGEN -t ecdsa-sk -w "$PROVIDER" -O no-touch-required \
  -f ~/.ssh/id_nuri_pcsc_sk_notouch -C "nuri-card-notouch"

# On the server, add to authorized_keys:
# (prepend no-touch-required to the key)
echo "no-touch-required $(cat ~/.ssh/id_nuri_pcsc_sk_notouch.pub)" >> \
  server:~/.ssh/authorized_keys
```

---

## Decision log (why this design)

### Why use the smartcard and not a USB FIDO key (YubiKey)?

**Decision: the card, only the card.**

The user's goal: one device that is the SSH key, the Bitcoin signer, the 2FA
device, and the wallet identity. The Nuri card already does all of this — it
has the FIDO2 applet, the MuSig2 cosigner applet, and the OATH-TOTP applet. A
separate USB FIDO key would only do SSH/login, and would be a second device to
carry, lose, and buy. The card is the bet: one thing in your pocket.

### Why a provider bridge instead of native OpenSSH FIDO?

**Decision: provider bridge, because the card is PC/SC, not USB CTAP-HID.**

OpenSSH's `ecdsa-sk` / `ed25519-sk` support is built on **libfido2**, which
only discovers **USB CTAP-HID** devices. A Java Card in a PC/SC reader is not
a CTAP-HID device — it's a smartcard reached over ISO 7816 / ISO 14443. There
is no way to make stock OpenSSH see the card without a bridge.

The bridge (`nuri-pcsc-sk-provider.so`) implements the OpenSSH
`SecurityKeyProvider` interface (the `sk_enroll` / `sk_sign` C API) and
translates each call into a CTAP2 APDU exchange over PC/SC, via a Python helper
that uses the `python-fido2` library. This is the minimal, clean translation
layer — it adds no crypto of its own.

The cost: each host machine needs a one-time install of the `.so`, the Python
helper, and the `fido2` library. This is unavoidable for a PC/SC smartcard and
is the trade-off for having the key on a card that also does Bitcoin and TOTP.

### Why tap-every-time (UP required)?

**Decision: user presence required on every sign.**

The user explicitly wanted "tap the card to show I am there, to sign stuff."
This is the CTAP2 `up` (user presence) flag. Every `getAssertion` call includes
`up: true`, which means the card requires a physical touch before it will
produce a signature. This is stronger than "auto-sign while plugged in"
because:
- A stolen laptop + card → still can't SSH without you tapping.
- A malware process on the laptop → can't silently SSH while you're away.
- You must consciously authorize *each* login.

### Why not clone the card for backup?

**Decision: two independent cards, not a clone.**

FIDO2 credentials are non-exportable by design — there is no APDU to read the
private key out of the secure element. A clone would require exporting the
key, which would defeat the entire security model (if you could clone it, so
could an attacker who briefly has the card).

The correct backup is a **second, independent card** with its own key, both
authorized on the same server. If card A is lost, card B logs in and removes
A's public key from `authorized_keys`. This is strictly stronger than a clone:
a stolen card does not compromise the backup.

### Why `ecdsa-sk` and not `ed25519-sk`?

**Current state: `ecdsa-sk`, because the card's FIDO2 applet supports ES256
(P-256 ECDSA).**

The card's CTAP2 `getInfo` advertises ES256 (`alg: -7`, `ecdsa-sha2-nistp256`).
`ed25519-sk` requires Ed25519 support (`alg: -8`), which the current FIDO2
applet does not expose. ES256 is fully supported by OpenSSH and is the
standard FIDO2 algorithm. If a future applet version adds Ed25519, switching is
just re-enrolling with `-t ed25519-sk`.

### Why not ssh-agent (yet)?

**Current state: direct key file (`-i ~/.ssh/id_nuri_pcsc_sk`), not the agent.**

The `ssh-agent` from Homebrew on macOS refuses SK sign operations even when
the provider is loaded, due to its provider allowlist (`-P`) not matching our
custom `.so`. The direct key-file path (`ssh -i ~/.ssh/id_nuri_pcsc_sk -o
SecurityKeyProvider=...`) works reliably and is what the `~/.ssh/config`
alias uses. Fixing the agent is a nice-to-have but not required — the config
alias makes it transparent (`ssh nuri-card-host`).

---

## Troubleshooting

### "device not found"

- **Card not in the reader.** Insert the card (contact slot or NFC surface).
- **Reader not visible to PC/SC.** Check: `opensc-tool -l` (should list the
  reader with "Yes" in the Card column).
- **Wrong reader index.** The helper defaults to reader 0. If your card is on
  a different index, set `FIDO2_PCSC_INDEX=1` (or whichever) in the
  environment.
- **Python venv missing fido2.** Re-run `bash scripts/install-ssh-card-host.sh`.

### "invalid format" when signing

- **The key file doesn't match the card.** The card was reset or re-flashed
  since the key was enrolled, wiping the credential. Re-enroll a new key:
  ```bash
  $SSH_KEYGEN -t ecdsa-sk -w "$PROVIDER" -f ~/.ssh/id_nuri_pcsc_sk -C nuri-card
  ```
  Then add the new public key to your server's `authorized_keys` and remove the
  old one.

### "agent refused operation"

- **ssh-agent doesn't know about the provider.** The agent needs to be started
  with `-P` allowing the provider path, or you bypass the agent by using `-i`
  directly (which is what the `~/.ssh/config` alias does).
- **Fix:** Don't use the agent. Use the config alias:
  ```bash
  ssh nuri-card-host
  ```
  which passes `IdentityFile` + `SecurityKeyProvider` directly.

### "Permission denied (publickey)" from the server

- **The public key isn't in the server's `authorized_keys`.** Add it:
  ```bash
  PUBKEY=$(cat ~/.ssh/id_nuri_pcsc_sk.pub)
  ssh -i ~/.ssh/EXISTING_WORKING_KEY root@SERVER "echo '$PUBKEY' >> ~/.ssh/authorized_keys"
  ```
- **Stale key on the card.** If you re-enrolled, the old public key in
  `authorized_keys` no longer matches. Remove the old line, add the new
  `~/.ssh/id_nuri_pcsc_sk.pub`.

### Stock macOS `ssh-keygen` says "unknown key type sk-ecdsa-sk"

- **Apple's `/usr/bin/ssh-keygen` is built without FIDO support.** Use
  Homebrew's:
  ```bash
  brew install openssh
  /opt/homebrew/bin/ssh-keygen -t ecdsa-sk ...
  ```
  The installer script detects and uses the Homebrew version if present.

### The card doesn't blink / no tap prompt

- The FIDO2 applet may not be installed. Check:
  ```bash
  npm run card:prf:info
  ```
  If the FIDO2 applet is missing, install it:
  ```bash
  GP_READER_INDEX=2 GP_KEY="your card key" npm run card:install
  ```

---

## What lives where (file reference)

| File | What it is | Secret? |
|---|---|---|
| `scripts/ssh-pcsc-sk-provider.c` | The C provider bridge (source). | No |
| `scripts/ssh-pcsc-sk-helper.py` | Python CTAP2 helper (called by the .so). | No |
| `scripts/install-ssh-card-host.sh` | One-command setup for any machine. | No |
| `dist/nuri-pcsc-sk-provider.so` | Compiled provider bridge (built by the installer). | No |
| `~/.ssh/id_nuri_pcsc_sk` | SSH "private" key file — holds **public key + credential ID only**. | **No** (not the secret) |
| `~/.ssh/id_nuri_pcsc_sk.pub` | SSH public key (goes in `authorized_keys`). | No |
| `~/.ssh/config` | SSH config alias (`SecurityKeyProvider` line points to the `.so`). | No |
| `/tmp/nuri-fido2-real-card-venv/` | Python venv with `fido2` + `pyscard`. | No |
| **The card's secure element** | **The private key.** Generated on-card, never exported. | **YES — and it stays there** |

### Key files are safe to copy

The `~/.ssh/id_nuri_pcsc_sk` file contains:
- The public key (safe to share).
- The credential ID / key handle (a 100-byte reference saying "use credential #X
  on the card" — useless without the physical card).
- The application string (e.g. `ssh:localhost`).

It does **not** contain the private key. Copying it to another machine lets
that machine *ask the card to sign* — but only if the card is physically
present. Without the card, the file is inert.

---

## Proven on a real server

This setup was tested end-to-end on 2026-07-05:

- **Card:** Feitian BioCARD, ATR `3b:81:80:01:80:80` (2025-05-14 OS batch).
- **Reader:** HID Global OMNIKEY 5422 (contact slot).
- **Host:** macOS, Apple clang 17, Homebrew OpenSSH 10.2p1.
- **Server:** `root@89.167.91.99` (Hetzner, Ubuntu 6.8.0-71-generic).
- **Result:** `ssh nuri-wirex` → `OK_FROM_REAL_SERVER`, logged in with the card,
  private key never left the secure element.

Reproduce:
```bash
bash scripts/install-ssh-card-host.sh
ssh nuri-card-host  # tap the card
```