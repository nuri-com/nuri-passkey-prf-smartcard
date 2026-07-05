# Changelog

Running release log. For narrative session notes (Q&A, card states, next steps)
see [`docs/logbook.md`](docs/logbook.md).

## 2026-07-05 (session 2) — ETH signer v1.3: end-to-end ecrecover green

### Fixed
- **ETH applet v1.3: `INS_SIGN` produced wrong signatures (v1.0–v1.2).** The
  signature was a valid ECDSA signature for *some* key Q, but Q ≠ the keygen
  pubkey and Q varied across `sign()` calls (impossible for correct ECDSA where
  Q = d·G must be stable). Root cause: `BigIntegerWrapper.addMod` was not
  aliasing-safe when `result == b` — the prologue `Util.arrayCopy(a, result)`
  clobbered `b` before it was read, so `addMod(z, rd, rd)` computed `2·z`
  instead of `z + rd`. `sign()` and `dbgSignK()` both hit this path
  (`addMod(scratchA, scratchC, scratchC)`), so every signature had wrong `zrd`
  and `s`. Fix: `addMod`/`subMod` now operate index-by-index (read `a[i]` and
  `b[i]` together per byte, write `result[i]` last), so `result` may overlap
  with `a` and/or `b`. `subMod` fixed the same way for robustness (not the
  acute bug, but same latent pattern). Verified end-to-end: `keygen →
  sign(5 hashes) → ecrecover → matches card pubkey` (5/5, v-bit correct,
  low-s enforced). See `docs/gp-macos-troubleshooting.md` "Resolved: INS_SIGN
  produced wrong signatures".

### Diagnosis methodology (documented for future bignum work)
- `dbgKG(k=1)` → exactly G (sanity check on curve parameters).
- `dbgKG(k=random 256-bit)` ×3 → all match host `k·G` (proves the card's
  `generateSecret(k, G)` is correct for production-sized `k`; small `k=2` is
  *not* a valid test — constant-time scalar mult returns a valid but wrong
  point for tiny scalars with 31 leading zero bytes).
- `dbgModInv(a)` ×6, `dbgMulMod(a,b)` ×5 → all match host (isolates the bug
  to the `sign()` composition, not the primitives).
- `dbgSignK(z, k)` (leaks `d`+`k`, debug only) → `r`, `rd`, `kinv` correct;
  `zrd = 2z` instead of `z+rd` → pins the aliasing bug. This INS **must be
  removed before production** (d-leak).

## 2026-07-05 — ETH signer on-card; gp post-mortem; SIGN infinite-loop fix

### Added
- **`card/eth/`** (`NuriEcdsaSigner.java` + Satochip bignum classes) +
  **`dist/nuri-eth-signer.cap`**: secp256k1 ECDSA signer applet for
  Ethereum/EVM — key generated on-card, signs 32-byte hashes, returns
  `r(32)‖s(32)‖v(1)` with EIP-2 low-s. AID `4E55524945544801` ("NURIETH1").
  Spec: `docs/eth-signing-spec.md`; host test: `scripts/card-eth-test.py`.
- **`docs/gp-macos-troubleshooting.md`**: full post-mortem of a lost day —
  "gp can't find the reader" was a broken gp *snapshot* build (jnasmartcardio
  card-present detection); release v26.06.04 worked first try. Plus the macOS
  PC/SC wedge pattern (stalled APDU → system-wide `SCardConnect` hang → re-seat
  the card) and the OMNIKEY 5422 T=0 requirement.

### Fixed
- **ETH applet v1.1: `INS_SIGN` hung the card forever (v1.0).** Three bugs in
  the software `modInverse` (binary extended GCD): guaranteed infinite loop
  (`u` hits 0, `while(isEven(u))` spins on zero; termination waited for `v==0`
  which is unreachable), parity checked on the big-endian MSB instead of the
  LSB, and odd-value halving computed `(x+n) mod n` (a no-op) instead of the
  257-bit integer `(x+n)/2`. New loop terminates on `u==1 || v==1`, halves via
  `add_carry` with the carry re-inserted, reduces the result into `[0,n)`, and
  the iteration cap now throws `6988` instead of never firing. Verified
  off-card against `pow(a,-1,n)` (5000+ cases) before flashing.
- `scripts/card-eth-test.py`: force **T=0** (OMNIKEY 5422 contact slot fails
  T=1 transmits with `0x80100016`).

### Changed
- `~/bin/gp.jar` (dev machine): snapshot `f2af9ef` → **release v26.06.04**
  (backup kept as `gp.jar.f2af9ef.bak`). Rule: only gp release jars.

## 2026-06-30 — Card-as-wallet (browser + reader), FIDO2 user-presence, hardware findings

### Added
- **`web/card-wallet.html`** + server `POST /api/wallet/{address,utxos,spend}`:
  card-does-both wallet — client key = card FIDO2 PRF → `HKDF(app:nuri.com|wallet|v1)`
  → BIP86 `m/86'/0'/0'/0/0`; cosigner = card MuSig2 applet;
  `musig2(client,card)` + `CSV(52500)`. Reader path proven end-to-end on **mainnet**;
  browser path falls back to the reader (this card can't do browser WebAuthn PRF).
- **`web/passkey-wallet.html`** + `POST /api/cosign/passkey-sign`: localhost passkey
  → valid card-cosigned BIP340 signature demo.
- **`patches/0002-advertise-user-presence.patch`** + **`dist/FIDO2-up.cap`**: FIDO2
  applet advertises CTAP2 `up:true` so browsers/macOS accept the card as a passkey
  (the applet already set `UP=1` in every assertion). v1 `dist/FIDO2.cap` preserved.
- **`docs/fido2-user-presence.md`**, **`docs/logbook.md`**, this `CHANGELOG.md`.

### Changed
- `scripts/nuri-card-wallet.mjs`: optional `clientSeedHex` (browser/reader PRF) +
  a key-ownership safety check that refuses to sign a spend unless the passkey/card
  owns the funded address.

### Findings (hardware / platform)
- **secp256k1 / MuSig2 needs card OS `2025-05-14`** (ATR `3b:81:80:01:80:80`). The
  `2023-03-30` OS lacks the EC point-multiply (`ALG_EC_SVDP_DH_PLAIN_XY`) → keygen
  returns `6A81`. Card OS is mask-ROM, not user-updatable. Screen with `gp -i`
  (OS date); confirm with `cosign:real-card:keygen`.
- **macOS Safari does not expose WebAuthn PRF for external security keys** — the
  card enables `hmac-secret` (assertion ED flag true) but Safari returns `prf:null`;
  Chrome can't see a PC/SC contact reader. Browser PRF works only via native-NFC
  app or Windows. `up:true` fix confirmed working on hardware regardless.

## Earlier milestones (from git history)
- `176de67` — card wallet (browser + reader) + FIDO2 user-presence CAP (this session).
- `eba645c` — README rewritten product-first (vision, app/PWA same-wallet story, roadmap).
- `4670451` — Arkade/Lightning: card-backed client identity + tree-round tweak.
- `1012a4c` — full real-card 2-of-2 round proof + headline chart.
- `168a584` — wallet client key derived from card FIDO2 PRF (no host secret).
- `5fa7c95` — Nuri smartcard wallet: stable `musig2(client,card)`+CSV address + real spend.
- Real card co-signed live Signet txs (blocks 308802 / 308804) and a mainnet wallet.
</content>
