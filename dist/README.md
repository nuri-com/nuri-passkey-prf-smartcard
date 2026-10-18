# Card V1 flash artifacts

This directory contains the normalized, reproducible CAP set for Nuri Card V1.
Run `npm run card:release:verify` to rebuild every applet from source, verify the
Java Card converters, compare every internal CAP component with these artifacts,
and check `SHA256SUMS`.

ZIP timestamps and the generated CAP creation-time manifest field are normalized.
This makes the outer CAP hashes deterministic without changing any loadable Java
Card component.

| Artifact | Source | Applet AID | Runtime version | License | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `FIDO2.cap` | `third_party/fido2-applet/` + patch 0001 | `A0000006472F0001` | package 0.4, `up:false` | MIT | `173a6290e7dfb9e55c3c837956345500ca2dcf1b634fabf258e6f51027f7f24d` |
| `FIDO2-up.cap` | same + patches 0001 and 0002 | `A0000006472F0001` | package 0.4, `up:true` | MIT | `ec670c69f0f47c09526c1744d314f899681d7d935806278d2fbfbd2019f699d9` |
| `nuri-musig2-v20-keygen.cap` | `card/musig2/` | `4E5552494D554701` | 1.11 / `KGEN` — no host seed import, one-shot KEYGEN | GPL-2.0-or-later combined work | `a9b2eea825561f31da708836927290fd92b430c5084cdc614020fd5da3648126` |
| `nuri-oath-totp.cap` | `card/totp/` | `4E555249544F5450` | package 1.0 | MIT | `6f33f7c4aedea49238d3ac33867999b787972d8cc0c4f4948ad302c5e9ab1af2` |
| `nuri-eth-signer.cap` | `card/eth/` | `4E55524945544801` | 1.4 / `SIGN` — debug INS removed, one-shot KEYGEN | GPL-2.0-or-later combined work | `0093e7b2b9c15435fd853ac4e6a64180f0779aa5230e56b652b6b8217d1b5217` |
| `nuri-eth2-signer.cap` | `card/eth2/` | `4E5552494554483201` (package `4E55524945544832`) | 2.0 / `ETH2` — native `ALG_ECDSA_SHA_256` + `signPreComputedHash`, no bignum, optional PIN, installs beside v1 | MIT | `f7c122328405d035050c5d3609483b572c4f7ebb03345a4d3e57b54cd268f3c5` |

## Exact build inputs

- FIDO2 Nuri fork base: `4f318197cc08f316ce784a89bdf29dc73cca7fcf`
  (parent: upstream FIDO2Applet v2.0.5 `0194107d9648577379058b59843504924b546514`)
- Java Card SDK checkout: `e2df471e04d86f33de69a947f44766fbef1d9d69`
- FIDO2 converter: Java Card 3.0.5 (`jc305u3_kit`)
- Nuri applet converter: Java Card 3.0.4 (`jc304_kit`)
- Java: Azul Zulu OpenJDK `1.8.0_452`
- Custom-applet build tool: `tools/ant-javacard-proven.jar`, SHA-256
  `def557393fd20dbe478a4581c3273222805b9e494836aa8465dfbe0fb9d64cf2`

The FIDO2 source snapshot is vendored with the packaging exclusions recorded in
`third_party/fido2-applet/UPSTREAM.md`. The Gradle wrapper is not redistributed;
install Gradle 8.2 (supported range: 8.2 through 8.x) separately (`gradle --version`), or set `GRADLE_BIN`
to its absolute executable path. The original wrapper used Gradle 8.2; the build
records the installed version in `BUILD-PROVENANCE.txt`. Reproducibility with a
different Gradle version must be checked, not assumed. The Oracle Java Card SDK
checkout is fetched at its exact public commit and retains its separate licence.
See `../THIRD_PARTY_NOTICES.md` for the source and combined-CAP licence map.

CI installs external Gradle 8.2 and both JDKs. JDK 17 launches Gradle;
`-Dorg.gradle.java.home="$JAVA8_HOME"` runs the CAP build daemon on the pinned
JDK 8 because the upstream Java Card plugin compiles/converts in-process with
Java 1.5 source/target settings. The standalone Ant builds also use JDK 8.
Simulator builds use JDK 17 throughout. Gradle 9 removed `ClosureBackedAction`,
which plugin 1.8.0 requires, and is rejected before downloads or build setup.

On macOS the release builder discovers installed JDK 17 and Zulu JDK 8. To
select explicit installations (also usable on Linux):

```bash
export JAVA17_HOME=/path/to/jdk-17
export JAVA8_HOME=/path/to/zulu-8.0.452
export GRADLE_BIN=/path/to/gradle-8.2/bin/gradle
npm run card:release:verify
```

```mermaid
flowchart LR
  S[Vendored applet source] --> B[External Gradle and Java Card SDK]
  B --> C[Normalized CAP artifacts]
  C --> V[Component and checksum verification]
```

## Which FIDO2 artifact to install

`FIDO2-up.cap` is the Card V1 production candidate. It enables `hmac-secret`
for created credentials and advertises physical card presence as `up:true`.
`FIDO2.cap` is retained only to reproduce the earlier `up:false` card state.

## Build and verify

```bash
npm ci
npm run card:release:verify
```

Successful verification ends with `CARD_V1_RELEASE_VERIFIED`.

## Install all four applets on a blank development card

```bash
CARD_PROVISION_CONFIRM=YES \
GP_READER_INDEX=2 \
GP_KEY="seller-supplied-transport-key" \
scripts/provision-card-v1.sh
```

Never publish the transport key, PIN, credential profile, TOTP secret, or any
card-generated private key. Provisioning a second card creates a new identity;
it does not clone the original card.

See `docs/card-v1-release.md` and `docs/card-v1-acceptance.md` for the complete
rebuild, provisioning, testing, and handoff procedures.
