# GlobalPlatformPro + macOS + OMNIKEY 5422: post-mortem & field guide

> 2026-07-05. We lost ~a day to "gp can't find the reader" and nearly bricked the
> card with a hand-rolled SCP02 client. None of it was necessary. This is the
> write-up so it never happens again.

## TL;DR — the rules

1. **Only use release builds of gp.** Snapshot/self-built jars can carry broken
   transitive deps (here: jnasmartcardio). Get releases from
   <https://github.com/martinpaljak/GlobalPlatformPro/releases>.
2. **Never hand-roll SCP02 against the ISD.** Every failed EXTERNAL AUTHENTICATE
   (`6982`) increments the card's velocity counter; enough failures **brick the
   Security Domain permanently**. If gp misbehaves, fix gp — don't reimplement it.
3. **On the OMNIKEY 5422 contact slot, force T=0** with this card
   (ATR `3b:81:80:01:80:80`). T=1 transmits fail with `0x80100016`
   (`SCARD_E_NOT_TRANSACTED`).
4. **Never kill a process mid-APDU on macOS.** An interrupted PC/SC transaction
   wedges `SCardConnect` **system-wide** (every tool hangs, even `opensc-tool -l`).
   Recovery: re-seat the card, or `sudo killall usbsmartcardreaderd`.

## The bug we chased (and what it actually was)

**Symptom:** `gp -l` printed *"Specify reader with -r/$GP_READER"* and listed both
OMNIKEY interfaces, but no `-r` value worked — not the index, not the full exact
reader name, not `GP_READER`, not `-X`, not Java 8/17/24. Meanwhile pyscard,
opensc-tool and plain `javax.smartcardio` all reached the card fine.

**Wrong hypotheses we burned time on:** macOS reader-name handling, the "01"
interface suffix, CryptoTokenKit interference, Java versions, and finally "let's
write our own SCP02 client" (which failed EXTERNAL AUTH with `6982` — a wrong
host cryptogram/C-MAC — and risked bricking the ISD, see rule 2).

**Actual root cause:** the gp build in use identified as `GlobalPlatformPro
f2af9ef` — a **snapshot build**, not a release. Its bundled jnasmartcardio layer
has broken reader/card-present detection, so gp filtered out the reader *before*
name matching even ran. That's why no `-r` spelling could ever work: the bug was
inside the jar, not in the invocation. Upstream fixed it on 2026-06-21
(gp commit `1ae44dc` "Update apdu4j to bring in jnasmartcardio fix"), which is
newer than any release at the time of writing.

**Proof it was the build:** the official **v26.06.04 release jar worked on the
first try, with no `-r` flag at all** — auto-selected the reader with the card,
listed the ISD, deleted the old applet, installed the new CAP:

```bash
curl -LO https://github.com/martinpaljak/GlobalPlatformPro/releases/download/v26.06.04/gp.jar
java -jar gp.jar -l                              # just works
java -jar gp.jar --delete 4E55524945544801 --delete 4E555249455448
java -jar gp.jar --install dist/nuri-eth-signer.cap
```

`~/bin/gp.jar` on the dev machine is now v26.06.04; the broken snapshot is kept
as `~/bin/gp.jar.f2af9ef.bak`.

## The macOS PC/SC wedge (separate problem, discovered same day)

While smoke-testing the freshly installed applet we wedged the smart-card stack
twice. Fact pattern:

- `SELECT` + `GET VERSION` over **T=0** work fine (applet answered `9000`,
  version `01 00 01 "ETH1"`).
- The **default (T=1) connection fails** every transmit with `0x80100016`.
- A test run that stalls mid-APDU (or a client killed mid-transaction) leaves
  the slot in a state where **every subsequent `SCardConnect` hangs forever**,
  in every process. `SCardListReaders` still works, which makes it look like a
  tool bug — it isn't. Killing `com.apple.ctkpcscd` does **not** clear it.
- **Recovery: physically re-seat the card** (or `sudo killall
  usbsmartcardreaderd`). The card itself is unharmed — after re-seat, `gp -l`
  and the applet respond normally.

So: "the card crashed" was really *host-side*: a stalled/interrupted APDU +
macOS's non-recovering PC/SC daemon. The card survives every time.

### Resolved: `INS_SIGN` hung the card — an infinite loop in the applet

Stepwise isolation (one INS per run, unbuffered, long timeout, never Ctrl-C
mid-APDU) pinned it down:

| APDU | Result |
|------|--------|
| SELECT, GET VERSION | `9000`, instant |
| KEYGEN (0x03) | `9000` in 0.1 s (native EC keygen) |
| GET_PUBKEY (0x02) | `9000`, instant |
| **SIGN (0x04)** | **card mute forever** → slot wedged |

Root cause — **three bugs in the applet's software `modInverse` (binary
extended GCD), v1.0** (`card/eth/NuriEcdsaSigner.java`):

1. **Guaranteed infinite loop.** The loop terminated on `v == 0`, but `v` can
   never reach 0 (the `v -= u` branch only runs when `u < v`). Instead `u`
   hits 0 when `u == v == 1`, and then `while (isEven(u))` spins forever on
   zero — 0 is even and shifting 0 stays 0. Every single SIGN hung; the
   3000-iteration cap sat on the *outer* loop and never fired.
2. **Parity read from the wrong end.** Buffers are big-endian; `isEven`
   checked byte 0 (the MSB) instead of byte 31 (the LSB).
3. **Halving lost the `+n`.** Odd `x1` must become `(x1 + n) / 2` as a 257-bit
   *integer*; the code did `addMod(x1, n)` first — which is `(x1+n) mod n = x1`,
   a no-op — then halved.

Fix (v1.1): loop terminates on `u == 1 || v == 1` (guaranteed, since
`gcd(a, n) = 1`), result taken from whichever side hit 1, parity read at
byte 31, halving via `add_carry` + shift with the carry re-inserted as the top
bit, final `reduce()` into `[0, n)`, and the iteration cap now *throws `6988`*
instead of being decorative — a card must answer an error, never go mute.
The control flow was verified off-card against `pow(a, -1, n)` for 5000+
random + edge inputs before re-flashing.

**Lessons:** (a) hand-rolled bignum/EC code must be verified off-card *before*
it goes on-card — on-card the only symptom of a logic bug may be "mute card +
wedged macOS PC/SC stack", which looks exactly like a reader/OS problem;
(b) loop caps belong on the innermost loop that can spin, and the escape must
be `ISOException.throwIt`, not a silent exit with a garbage result.

### Resolved: `INS_SIGN` produced wrong signatures (v1.0–v1.2) — aliasing in `addMod`

After the `modInverse` fix (v1.1) and the `negateMod` aliasing fix (v1.2), `sign()`
still returned ECDSA signatures that `ecrecover` could not match to the card's
public key. The card returned a *valid* ECDSA signature for *some* public key Q,
but Q ≠ the keygen pubkey — and Q varied across `sign()` calls with the same key.
That is impossible for correct ECDSA (Q = d·G must be stable), so the bug was in
the `s` computation, not in `k·G` or `d`.

Diagnosis procedure (each step one card session, never Ctrl-C mid-APDU):

| Test | Result |
|------|--------|
| `dbgKG(k=1)` | `04‖Gx‖Gy` exactly G ✅ |
| `dbgKG(k=random 256-bit)` ×3 | all match host `k·G` ✅ |
| `dbgModInv(a)` ×6 (2, 3, …, n-1) | all match `pow(a,-1,n)` ✅ |
| `dbgMulMod(a,b)` ×5 | all match `(a*b)%n` ✅ |
| `dbgSignK(z, k)` (leaks d+k, debug only) | `r`, `rd`, `kinv` correct; `zrd` = `2z` ❌ |

Root cause — **`BigIntegerWrapper.addMod` was not aliasing-safe when
`result == b`** (`card/eth/BigIntegerWrapper.java`):

```java
// OLD — result==b clobbers b before it is read:
Util.arrayCopy(a, a_offset, result, result_offset, size);  // if result==b, b is now a
Biginteger.add_carry(result, result_offset, b, b_offset, size);  // result += b == result += a → 2a
```

`sign()` and `dbgSignK()` both called `addMod(scratchA, scratchC, scratchC)`
(`z + rd`, result into `scratchC` — `result == b`), so every signature computed
`zrd = 2·z` instead of `z + rd`, and `s = k⁻¹·(2z)` instead of `s = k⁻¹·(z+rd)`.
The signature verified against `Q = (2z·k⁻¹)·G`'s implied key, not against `d·G`.

Fix (v1.3): `addMod` and `subMod` now add/subtract index-by-index (read
`a[i]` and `b[i]` together per byte, write `result[i]` last), so `result` may
overlap with `a` and/or `b` safely. Verified end-to-end: `keygen → sign(5 hashes)
→ ecrecover → matches card pubkey` (5/5, v-bit correct, low-s enforced).

**Lesson:** the comment "Can handle aliasing (result can be same as a or b)" on
`addMod`/`subMod` was a *claim*, not a *guarantee* — and it was wrong for
`result == b`. The `Util.arrayCopy(a, result)` prologue broke it. Aliasing
safety in bignum helpers must be *tested*, not asserted: write a host-side
fuzz that calls every helper with `result==a`, `result==b`, `result==a==b`,
and diff against a non-aliased reference. The `dbgSignK` INS that leaks `d`
and `k` was the only way to pin this on-card; for production that INS must be
removed, but while debugging it earned its keep.

### Debug INS 05–08 — small-scalar `dbgKG(k=2)` is not a production test

While diagnosing, `dbgKG(k=2)` returned a valid on-curve point that was *not* `2G`.
That is **not a card bug** — it is an artifact of constant-time scalar
multiplication (`ALG_EC_SVDP_DH_PLAIN_XY`) on tiny scalars: with 31 leading zero
bytes, some implementations produce a valid but wrong point. The production
`sign()` path uses random 256-bit `k` (like the proven MuSig2 `getNonces`), where
`generateSecret(k, G)` is correct (3/3 matches against host `k·G` in testing).

**Do not** use `dbgKG` with small `k` (1, 2, 3, …) as a "does the card work" test.
Use random 256-bit `k`. The only small `k` that is meaningful is `k=1` (must
return exactly `G`), as a sanity check that the curve parameters are right.

## Checklist for "gp can't see my reader/card"

1. `gp --version` — is it a **release** version number (e.g. `26.06.04`)? A git
   hash means snapshot: replace it first, retest.
2. `python3 -c 'from smartcard.System import readers; print(readers())'` — if
   pyscard sees the card and gp doesn't, it's gp's build, not your setup.
3. Reader listing works but connect hangs? → wedged stack, re-seat the card.
4. Transmit fails `0x80100016` on this reader? → force T=0.
5. Still stuck? Check upstream commits *newer than the latest release* — the fix
   may exist but be unreleased (that was exactly our case).
