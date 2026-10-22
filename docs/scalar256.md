# MuSig2 Scalar256 — W16 clean-room arithmetic

```mermaid
flowchart LR
  H[32-byte unsigned input] --> N[Normalize with masked subtraction]
  N --> A[Canonical add or negate]
  N --> M[256-round double-add-select multiply]
  A --> O[Canonical 32-byte output]
  M --> O
  O --> W[Erase private transient scratch]
  O --> P[MuSig2 partial: nonce plus challenge term]
```

## v1.2.0 AID3 release boundary

`00ce5b2` introduced the MIT clean-room fixed-iteration software multiply.
That integration established simulator arithmetic correctness, not hardware
latency: the software loop was not timed on a physical card at that stage.
MIT-compatible RSA square-based acceleration is planned separately; this release
build integration does not itself implement it or qualify its fallback behavior.
No new real-card times are claimed here.

| Identity | Package AID | Applet AID | Acceptance scope |
|---|---|---|---|
| Original | `4E5552494D5547` | `4E5552494D554701` | Historical artifact; not AID3 acceptance |
| AID2 | `4E5552494D554732` | `4E5552494D55473201` | Historical PIN2 cosign receipt; no latency qualification |
| AID3 candidate | `4E5552494D554733` | `4E5552494D55473301` | Reproducible-build integration; hardware unverified |

`scripts/build-musig2-aid3.sh` copies current `card/musig2/*.java`, patches only
its temporary APPLET_AID and normalizes CAP metadata. It leaves tracked Java
sources unchanged. With `JC_KIT`, `ANT_JAVACARD` and `JAVA8_HOME` pointing to the
pinned release toolchain, run:

```sh
scripts/build-musig2-aid3.sh
npm run card:release:verify
```

The default output is `dist/nuri-musig2-v20-keygen-aid3.cap`. The full release
builder includes that artifact in its manifest and the verifier compares its
components and hash. Record the final scalar source, CAP hash and build provenance
together; rebuilding after a scalar change requires updating the distributed CAP
and checksum. A reserved AID and a successful build do not prove acceleration,
PIN behavior, card algorithm availability, side-channel resistance or timeout
suitability. Physical qualification remains a separate, explicitly authorized
spare-card task. No card is accessed by either build command.

The W16/W20 algorithm, line references, hashes and simulator transcripts below
are historical records, not measurements of an AID3 acceleration candidate.

## W20 current boundary (APDU 1.14)

W20 keeps the scalar algorithm and its six official BIP327 fixtures. It adds
`fieldMultiply` and `fieldAdd` modulo secp256k1's field prime for public-point
validation, using the same fixed-width engine with a public modulus selector.
The selector and scratch are reset on exit. Both primes exceed `2^255`, so the
normalization/carry argument applies unchanged. The new simulator oracle checks
164 boundary/random field operand pairs, aliased addition, and scalar modulus
restoration after every pair (`PinHardeningTest.java:132-151`).

`Scalar256.clear()` is now public so the APDU exception boundary can erase it.
The applet's secret products are independently additively blinded and computed
twice; temporary EC keys and all private byte scratch are explicitly erased on
success and exceptions. The W16 remaining-boundaries section below is historical,
not the current implementation. See [MuSig2 PIN and hardening](musig2-pin-and-hardening.md)
for current protocol, measured checks and unverified physical boundaries.

## Scope and provenance

`card/musig2/Scalar256.java` is independently written for the narrow W14 §5.2
call contract: unsigned 256-bit compare/zero, reduce, add, negate and multiply
modulo the secp256k1 group order. The implementer and test author did not open,
copy or transliterate Biginteger.java, BigIntegerWrapper.java,
BigIntegerMod.java, Satochip implementation source or Keycard arithmetic.
The inherited three MuSig2 math files are deleted, not relabelled. Existing
applet protocol/EC/APDU logic was read only to replace the specified calls.
This statement concerns the new scalar file, not an assertion that all other
repository files or historical CAPs are MIT-only.

Independent mathematical references (not implementation sources):

- [BIP327 specification](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki):
  `s_i = (k1 + b*k2) + e*a_i*sk (mod n)`, with the prescribed parity negations.
- [BIP340 specification](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki):
  secp256k1 order, x-only/even-Y convention and Schnorr verification equation.
- [Official BIP327 sign/verify numeric fixtures](https://github.com/bitcoin/bips/blob/master/bip-0327/vectors/sign_verify_vectors.json):
  all six valid cases, including aggregate infinity and variable message length,
  are embedded offline in `test/musig2-jcardsim/Scalar256Test.java:266-333`.
  The test reconstructs coefficients/challenges from those fixtures independently;
  no upstream reference implementation is included. This is scalar-chain coverage,
  not all BIP327 parser/error-vector coverage.

The new file's header records MIT SPDX, the existing root copyright spelling
(`Emin Grande and contributors`), this independent origin and the limitations.
No new dependency is introduced; host tests use the existing pinned jCardSim
3.0.5.11 and its shaded point implementation. External SDK/tool licences remain
unchanged.

## Representation and invariants

- The order is `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
  (`Scalar256.java:28-36`). All scalars are exactly 32-byte big-endian windows.
  Callers must supply non-null arrays with valid, non-negative short offsets and
  at least 32 accessible bytes. The object is non-reentrant.
- Every 256-bit input is below `2*n`, so normalization requires precisely one
  32-byte subtraction and mask selection; equality to `n` becomes zero.
  Each arithmetic input is staged and normalized (`Scalar256.java:68-103,125-128`).
  Host inputs are not rejected merely for being noncanonical.
- Addition computes a 257-bit sum using byte digits and a short carry. For
  canonical operands the sum is below `2*n`. Subtraction is selected if the high
  carry is set or the low sum did not borrow from `n`. This handles wraparound,
  not merely a comparison of the truncated low sum (`Scalar256.java:130-161`).
- Negation computes `n-a` after normalization, masking all bytes to zero when
  `a=0`, so zero never produces the noncanonical representation `n`
  (`Scalar256.java:74-90`). Compare and zero tests scan every byte
  (`Scalar256.java:45-65`).
- Multiplication evaluates the second operand's bits from MSB to LSB. In each
  of exactly 256 rounds: double the accumulator modulo `n`; unconditionally
  compute accumulator plus the first operand; select by the current bit. Each
  round has two canonical additions. No secret-indexed lookup or secret-dependent
  loop/branch is used in the scalar methods (`Scalar256.java:101-123`).
- The private 160-byte transient array contains normalized A/B, accumulator R,
  candidate T and subtraction D (five 32-byte slots). It is allocated only in the
  constructor with `CLEAR_ON_DESELECT`, then explicitly wiped after each successful
  operation (`Scalar256.java:22-42,170-174`). This is not an exceptional-exit
  erasure guarantee for invalid array arguments, nor a claim about JIT/card power
  behavior. Current applet calls supply fixed valid windows.
- Both operands are staged before output is written. Exact or partial output
  overlap with either/both inputs is therefore supported. In particular the third
  signing multiply writes over its second operand, `e*(a_i*sk)`
  (`NuriMuSig2v019.java:449-454`). Input windows themselves can overlap too.
- The existing nonce readiness flags and nonce arrays retain `CLEAR_ON_RESET`;
  the all-zero guard and one-shot finalize behavior are unchanged
  (`NuriMuSig2v019.java:152-160,362-377,473-475`). Native EC point multiplication
  stays on the Java Card key-agreement API; there is no RSA scalar accelerator.

## Verification and reproducible build

Run simulator only:

```sh
npm run card:musig2:test:sim
npm test
```

The scalar suite uses `java.math.BigInteger` only on the host as an independent
oracle. It exercises `0,1,n-1,n,n+1,2^256-1`, every bit position, all boundary
pairs, deterministic random cases including forced noncanonical values, carry
and borrow, exact/partial aliases, nonzero offsets, unchanged guard bytes, scalar
scratch erasure and six official BIP327 valid scalar chains. The APDU suite
verifies partials for canonical/random inputs and all six boundary host inputs
under both parities; retains reset/fresh-nonce/replay tests; and injects each zero
nonce independently while readiness flags remain true to reach the zero guard.

Actual simulator output on this worktree (macOS, Zulu JDK 17):

```text
SCALAR256_OK assertions=15376024 compare=4830 isZero=710 reduce=3479 negate=3721 add=15143 multiply=15411 chains=268 bip327=6 scratchArrays=1 scratchChecks=37756 seed=5343414c41523256
MUSIG2_JCARDSIM_NONCE_LIFETIME_OK
```

Three consecutive complete simulator runs passed after integration. Three
consecutive `npm test` runs each returned **21 tests, 21 pass, 0 fail, 0 skipped**
(Node 22.21.1). The first host run failed because the new worktree had no
`node_modules`; `npm ci --ignore-scripts --no-audit --no-fund` installed the
47 lockfile packages without changing source/lockfiles, then all runs passed.

Six isolated fault-injection copies of the two current MuSig2 sources each
returned exit 1, without mutating the candidate or reading retired source:

| Injected fault | Observed failing assertion |
|---|---|
| Suppress low-sum/equality subtraction | `binary layout=0 shift=0 canonical output` |
| Ignore the 257th-bit carry | `binary layout=6 shift=-31` expected/actual mismatch |
| Invert multiply bit selection | `binary layout=6 shift=-31` expected/actual mismatch |
| Write output before staging multiply operands | `binary layout=6 shift=0` expected/actual mismatch |
| Disable zero-nonce guard only | Both ready-session zero-nonce tests returned `9000`; suite failed |
| Make session flags persistent only | `reset clears both nonce session flags independently` failed |

The last two controls prove that each A1 defense is tested independently rather
than allowing the other guard to mask it. Candidate runs after the fault copies
again passed three times. Full local execution logs are retained in the ignored
`.build/card-v1/w16-evidence/` directory, not represented as shipped artifacts.

Build the two-source CAP with an externally installed Java Card 3.0.4 SDK and
Zulu JDK 8, then normalize its ZIP metadata:

```sh
export JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"
export ANT_OPTS=-Djava.io.tmpdir=${TMPDIR:?select a private temporary directory}
ant -f card/musig2/build.xml -Djckit.path="$JC304_KIT" \
  -Dcap.output="$PWD/.build/card-v1/musig2-raw.cap" build
/opt/homebrew/bin/python3.13 scripts/normalize-cap.py \
  .build/card-v1/musig2-raw.cap dist/nuri-musig2-v20-keygen.cap
shasum -a 256 dist/nuri-musig2-v20-keygen.cap
```

Actual converter/verifier output: conversion completed with **0 errors and
0 warnings**; verification completed with **0 warnings and 0 errors**;
`BUILD SUCCESSFUL`. The pinned ant tool SHA256 was verified as
`def557393fd20dbe478a4581c3273222805b9e494836aa8465dfbe0fb9d64cf2`.
The older ant tool accepts only single-digit package components, so the new CAP
package version is **2.0**, while the APDU version is **1.13** (`010D`), both
separate from the retained compatibility filename (`build.xml:3,9,13` and
`NuriMuSig2v019.java:29-30`). CAP SHA256 is
`0fb0b08bfd728b38c57e137fd54c4a3f5f9bfd80fda1fa1d7acc818e17e1a89a`.
A second independent build plus normalization compared byte-identically using
`cmp`. All eight existing `dist/SHA256SUMS` entries matched their files. CAP
inspection found exactly the applet and Scalar256 class entries; its manifest
reports `Java-Card-Integer-Support-Required: FALSE` and imports only
`A0000000620101` (framework), `A0000000620102` (security), and
`A0000000620001` (language). Source compilation input was exactly two Java files.
The first Linux GitHub CI run independently rebuilt the same MuSig2 hash and
reported `CAP_COMPONENTS_IDENTICAL` for all six CAPs. Its final release gate
failed solely on manifest **row ordering**, not content: the pre-existing
`dist/SHA256SUMS` ordering differed from the builder's order, and the verifier
compares the CAP rows without sorting (`scripts/verify-card-v1-release.sh:22-24`).
The manifest is now ordered exactly as the builder emits; all unrelated hashes
are unchanged. That run's node and virtual-card jobs passed.

## Review and remaining boundaries

Independent source review found no scalar arithmetic blocker. Follow-up findings
outside the narrow arithmetic replacement: `tempPrivKey` retains the last nonce
copy after nonce generation (`NuriMuSig2v019.java:124-125,318-339`); applet byte
cleanup only occurs on successful finalize (`NuriMuSig2v019.java:438-475`). Those
pre-existing key-object/exception-lifecycle boundaries are not solved by erasing
Scalar256's own scratch. Physical exploitability is UNVERIFIED. Do not interpret
this task as a complete applet secret-erasure or side-channel audit.

Hardware latency, reader timeouts, transient memory availability, timing/power
resistance, fault resistance and real reset behavior remain **UNVERIFIED**.
No reader, hardware key, card install or server was touched. The fixed-iteration
software multiply may be slower than hardware RSA; parent must measure on a
supported spare card before any production migration.

## Physical-card acceptance

The old W16 pre-PIN acceptance recipe is withdrawn: it predates the current
1.14 PIN/session-token and attestation contract. Use the
[current MuSig2 spare-card acceptance](musig2-pin-and-hardening.md#exact-parent-spare-card-acceptance-commands--not-executed-here)
and [blank-card personalization](attestation.md#blank-card-personalization).
Do not delete or reinstall an operational wallet or sole SSH-key card.
