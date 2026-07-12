# Reproducing the complete Nuri Card V1 repository

This is the clone-to-proof entrypoint for the complete repository. It covers
source inventory, virtual card behavior, Java Card CAP rebuilding, host tools,
and the Expo application while keeping hardware-only claims separate.

## One-command reproduction

Requirements:

- Node.js 20 or newer
- Python 3.10 or newer
- JDK 8 for CAP conversion and JDK 17 for jCardSim/Expo
- Ant, Git, `patch`, `rsync`, and `shasum`
- authenticated read access to `nuri-com/nuri-design-system` for Expo

On systems where both JDKs are not auto-discoverable, provide them explicitly:

```bash
export JAVA8_HOME=/path/to/jdk8
export JAVA17_HOME=/path/to/jdk17
```

`JAVA17_HOME` is used for jCardSim and Android; `JAVA8_HOME` is used only by
the deterministic CAP converter. The one-command runner preserves this split.

```bash
git clone https://github.com/nuri-com/nuri-passkey-prf-smartcard.git
cd nuri-passkey-prf-smartcard
npm run reproduce:v1
```

This performs a clean root install, source-completeness audit, all available
no-card behavioral tests, deterministic rebuild and component verification of
every CAP, then the pinned Expo design-system checkout, clean install, UI guard,
TypeScript check, and Android Metro export.

To include the native arm64 Android build:

```bash
EXPO_NATIVE_ANDROID=YES npm run reproduce:v1
```

An external builder without access to the private Nuri design system can still
reproduce the complete public card/host portion explicitly:

```bash
REPRODUCE_EXPO=NO npm run reproduce:v1
```

This limitation is intentional: private design-system source is not copied into
the public repository without permission. The exact required design-system
commit is pinned and documented.

## Source-to-artifact inventory

| Deliverable | Complete corresponding source | Rebuild/test entrypoint |
| --- | --- | --- |
| FIDO2/PRF CAPs | `third_party/fido2-applet/src/main/` plus both root patches | `npm run fido2:test-prf`, `npm run card:release:verify` |
| MuSig2 CAP | `card/musig2/` | Node method/APDU simulators and `npm run card:release:verify` |
| TOTP CAP | `card/totp/` | TOTP self-check and `npm run card:release:verify` |
| ETH/EVM CAP | `card/eth/` | `npm run card:release:verify`; behavior needs a qualified card |
| Expo NFC app | `mobile/expo-nfc-prf-probe/` | `npm run mobile:verify:v1` |
| Host/card tooling | `src/`, `scripts/`, `web/`, and `bin/` | `npm run test:virtual` |
| PC/SC SSH provider | `scripts/ssh-pcsc-sk-provider.c` and Python helper | documented host build/install script |

`dist/` contains reproducible convenience binaries. It is not a substitute for
source: all Card V1 applet source is present. Generated converter/JCA output is
ignored under `card/**/3.0.4` and is never treated as source.

## Pinned external inputs

Some dependencies cannot or should not be copied into this public repository:

- Oracle Java Card SDK repository at the exact commit recorded in
  `scripts/prepare-card-build-toolchain.sh`
- private Nuri design system at the exact commit recorded in
  `scripts/prepare-expo-v1.sh`
- package artifacts locked by the root and mobile npm lockfiles
- Python card and simulator dependencies pinned by their requirements files
- Gradle distribution protected by `distributionSha256Sum`

The pinned `ant-javacard` JAR has its complete corresponding source under
`third_party/ant-javacard/` at upstream tag `18.05.01`. The Gradle wrapper is a
standard external build bootstrap protected by the official distribution hash;
neither JAR is application or applet source. Origins and licenses are documented
in `tools/README.md` and `THIRD_PARTY_NOTICES.md`.

## Success markers

- `SOURCE_COMPLETENESS_OK`
- `CARD_V1_VIRTUAL_TESTS_OK`
- `CARD_V1_RELEASE_VERIFIED`
- `EXPO_V1_SOURCE_BUNDLE_VERIFIED`
- optionally `EXPO_V1_ANDROID_NATIVE_VERIFIED`
- final `NURI_CARD_V1_FULL_SOURCE_REPRODUCED`

These markers prove source/build/test reproducibility. They do not prove the
physical chip. Blank-card qualification, installation, key generation, NFC,
PC/SC, PIN, and live payments use `docs/card-v1-acceptance.md` and culminate in
`REAL_CARD_V1_ACCEPTANCE_OK`.
