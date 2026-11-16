# Development-card acceptance

```mermaid
flowchart LR
  A[Host checks] --> B[Artifact verification]
  B --> C[Blank-card installation]
  C --> D[Owner initializes intended keys]
  D --> E[Physical transport and signing tests]
```

Qualify one exact card and its reader; simulator success is not hardware success.
Never use a funded card or your only SSH key for installation/reset experiments.

## Host-only checks

```sh
npm ci
npm test
npm run test:virtual
npm run card:release:verify
```

The acceptance wrapper runs Node tests, demos, TOTP self-check and release
verification first. Without `CARD_REAL_TESTS=YES` it prints `HOST_ACCEPTANCE_OK`
and exits. Source: [scripts/accept-card-v1.sh:7–17](../scripts/accept-card-v1.sh#L7-L17).

## Provisioning a blank card

Obtain transport keys from the supplier and securely select the target reader.
Check the [hardware requirements](hardware.md) first.

```sh
CARD_PROVISION_CONFIRM=YES GP_READER="$CARD_READER" GP_KEY="$CARD_TRANSPORT_KEY"   scripts/provision-card-v1.sh
```

For separate transport keys use `GP_KEY_ENC`, `GP_KEY_MAC`, `GP_KEY_DEK`.
The script checks the manifest, refuses known installed AIDs and installs
FIDO2-up, MuSig2, TOTP and ETH v1 (ETH v1 not with `PROVISION_SKIP_ETH1=YES`,
which `scripts/card-setup.sh` always sets). It does **not** install ETH v2 or the
vault, initialize all PINs, personalize attestation or rotate GP keys. It is a demo
installer, not consumer provisioning. For the new stack use
[blank-spare personalization](attestation.md#blank-card-personalization),
[current MuSig2 policy](musig2-pin-and-hardening.md) and
[vault setup](card-vault-applet.md).
Source: [scripts/provision-card-v1.sh:16–23](../scripts/provision-card-v1.sh#L16-L23),
[30–74](../scripts/provision-card-v1.sh#L30-L74).

Key initialization is a separate owner action. Do not blindly run key-generation
commands as diagnostics. Refer to [key handling](real-card-key-handling.md),
[ETH v1](eth-signing-spec.md), [ETH v2](eth-applet-v2.md) and [TOTP](totp-applet.md).
Set the FIDO2 PIN interactively using `npm run card:pin:set`; it does not protect
other applets.

## Owner-operated real-card checks

```sh
CARD_REAL_TESTS=YES scripts/accept-card-v1.sh
```

This branch invokes FIDO2 tests, MuSig2 tests, TOTP status and the ETH test before
printing `REAL_CARD_V1_ACCEPTANCE_OK`.
[scripts/accept-card-v1.sh:19–24](../scripts/accept-card-v1.sh#L19-L24).
It does not establish SSH login, browser interaction, ETH v2 support or Lightning
settlement. TOTP status alone is not an RFC-vector run on the physical card.

Record the source commit, artifact hashes, card/reader identifiers, transport and
complete test output in a sanitized acceptance receipt. Never include PINs,
transport keys, PRF output, private hostnames or personal contact data.
**UNVERIFIED:** fresh launch physical-card acceptance until that receipt exists.
