# Flash Artifacts

## FIDO2.cap

`FIDO2.cap` is a compiled Java Card CAP file built from:

- Source: `https://github.com/BryanJacobs/FIDO2Applet.git`
- Ref: `fb827954cd091a1810163ce51d2f86d42d0b8e20`
- Java Card SDK: `jc305u3_kit`
- Java used for CAP build: JDK 8

Package/app IDs:

- Package AID: `A000000647`
- Applet AID: `A0000006472F0001`

SHA-256:

```text
ac473421bbbe0a2f71d51fab61606634bb50d74db15994cb4122cbbc74bdf149  FIDO2.cap
```

Install on an unlocked Java Card with GlobalPlatformPro:

```bash
GP_READER="your reader name" GP_KEY="404142434445464748494A4B4C4D4E4F" npm run card:install
```

The default `GP_KEY` shown above is the common test/development key, not a production key. Use the key supplied with your card.

This `FIDO2.cap` is the preserved **v1** applet (advertises `up:false`; works
over PC/SC + native NFC, but not browser WebAuthn). Kept unchanged for
reproducibility.

## FIDO2-up.cap (v2 — user-presence update)

Same applet as `FIDO2.cap` plus
[`patches/0002-advertise-user-presence.patch`](../patches/0002-advertise-user-presence.patch):
the CTAP2 getInfo `up` option is advertised as **true**, so Safari/Chrome and
phone-web NFC accept the card as a passkey (the applet already set UP=1 in every
assertion). See [`docs/fido2-user-presence.md`](../docs/fido2-user-presence.md).

```text
SHA-256: 2d80aeeb577b17365d0b58d32a9de879c0217444f89373be84c2bd8b02e750f8  FIDO2-up.cap
```

Install on a card that is OK to wipe (the version to flash going forward):

```bash
CAP=dist/FIDO2-up.cap GP_READER_INDEX=2 npm run card:install
npm run card:prf:info     # expect options.up == true
```

## nuri-musig2-v20-keygen.cap

`nuri-musig2-v20-keygen.cap` is the real-card MuSig2 cosigner applet with
on-card long-term key generation.

- Source workbench: `../nuri-smartcard-musig2/java-applet`
- Base class: `NuriMuSig2v019`
- Applet-reported version: `1.10`
- Applet-reported build tag: `KGEN`
- Java Card SDK: `jc304_kit`
- Java used for CAP build: Zulu JDK 8

Package/app IDs:

- Package AID: `4E5552494D5547`
- Applet AID: `4E5552494D554701`

SHA-256:

```text
21f742c0b1eeef25b03c404a23d0c643e978f5a89af7a6e34f63c39c3589a2de  nuri-musig2-v20-keygen.cap
```

Install on the current developer card:

```bash
npm run card:musig2:install
npm run cosign:real-card
```

The expected real-card proof marker is `REAL_CARD_COSIGN_FLOW_OK` with
`key_origin: on_card_keygen_non_exportable`, `card_partial_verified: true`, and
`final_signature_verified: true`.
