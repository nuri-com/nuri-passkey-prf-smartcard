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
| `nuri-musig2-v20-keygen.cap` | `card/musig2/` | `4E5552494D554701` | 1.10 / `KGEN` | GPL-2.0-or-later portions | `21a729e20feb506bdcaccd36aa0890bc46c359a2db69d241688f0c600ed29a2b` |
| `nuri-oath-totp.cap` | `card/totp/` | `4E555249544F5450` | package 1.0 | MIT | `6f33f7c4aedea49238d3ac33867999b787972d8cc0c4f4948ad302c5e9ab1af2` |
| `nuri-eth-signer.cap` | `card/eth/` | `4E55524945544801` | 1.3 / `SIGN` | GPL-2.0-or-later portions | `a47e4618dc15f7487d17a8527d8203e0dc3322ea43a018c56dc8c3c472f4ba41` |

## Exact build inputs

- FIDO2 Nuri fork base: `4f318197cc08f316ce784a89bdf29dc73cca7fcf`
  (parent: upstream FIDO2Applet v2.0.5 `0194107d9648577379058b59843504924b546514`)
- Java Card SDK checkout: `e2df471e04d86f33de69a947f44766fbef1d9d69`
- FIDO2 converter: Java Card 3.0.5 (`jc305u3_kit`)
- Nuri applet converter: Java Card 3.0.4 (`jc304_kit`)
- Java: Azul Zulu OpenJDK `1.8.0_452`
- Custom-applet build tool: `tools/ant-javacard-proven.jar`, SHA-256
  `def557393fd20dbe478a4581c3273222805b9e494836aa8465dfbe0fb9d64cf2`

The FIDO2 source snapshot and Gradle wrapper are vendored. The Oracle Java Card
SDK checkout is fetched at its exact public commit because its licensing is
separate from this repository. No confidential FEITIAN or IDEX material is used
or distributed.

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
