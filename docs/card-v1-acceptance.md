# Nuri Card V1 provisioning and acceptance

This runbook qualifies one physical blank card. A seller model name or Java
Card version is not acceptance evidence; the exact card must pass every
applicable check.

## 1. Supplier acceptance before purchase

Require written confirmation of:

- unfused/unlocked card with custom CAP load/install/delete rights
- seller-supplied GlobalPlatform transport keys
- Java Card Classic 3.0.5 and GlobalPlatform 2.3
- contact ISO7816 plus ISO14443-A contactless interface
- at least 200K user NVM for the preferred blank-card candidate
- `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`
- custom secp256k1 domain parameters and uncompressed X+Y output

Order samples first. Cards that only advertise generic ECC support are not
accepted for MuSig2/ETH.

## 2. Inspect the untouched sample

```bash
gp -r2 -k "seller-transport-key" --info
gp -r2 -k "seller-transport-key" --list
```

Record supplier, batch, ATR, chip/COS, GP version, protocol, and available
memory without recording the key. Reject a fused card or a card whose transport
keys are unknown.

## 3. Verify release artifacts

```bash
npm ci
npm run card:release:verify
```

Do not flash if any checksum, converter, component, or deterministic-build check
fails.

## 4. Install the four applets

Only run against a blank development card:

```bash
CARD_PROVISION_CONFIRM=YES \
GP_READER_INDEX=2 \
GP_KEY="seller-transport-key" \
scripts/provision-card-v1.sh
```

For separate SCP03 keys, use `GP_KEY_ENC`, `GP_KEY_MAC`, and `GP_KEY_DEK`
instead of `GP_KEY`.

## 5. Initialize card-owned identities

On a new card:

```bash
npm run cosign:real-card:keygen
scripts/run-card-python.sh scripts/card-eth-test.py --regenerate
npm run card:pin:set
```

The new public keys and credential must be registered to the new owner's
account. Never initialize a card using another owner's exported private seed.
Do not send a PIN in the same message or parcel as the card.

TOTP provisioning is optional and service-specific:

```bash
scripts/run-card-python.sh scripts/card-totp.py put "BASE32-SECRET"
```

Treat that command and shell history as secret-bearing operational work.

## 6. Run non-destructive hardware acceptance

After identities exist:

```bash
CARD_REAL_TESTS=YES scripts/accept-card-v1.sh
```

Required markers include:

- `REAL_CARD_WEBAUTHN_PRF_OK`
- `REAL_CARD_COSIGN_FLOW_OK`
- `REAL_CARD_TOTP_SELECT_OK`
- `REAL_CARD_ETH_SIGN_FLOW_OK`
- `REAL_CARD_V1_ACCEPTANCE_OK`

The ETH acceptance test uses the existing key by default. `--regenerate` is
explicitly destructive and must not be used on an enrolled owner card.

## 7. Expo/phone acceptance

On a physical NFC Android device:

1. Enter PIN and read the profile.
2. Confirm Lightning address, balance, wallet address, card status, and card
   reference.
3. Leave the card removed and verify incoming-payment polling remains visible.
4. Present the card only when claim approval/signing is requested.
5. Complete a terminal payment through both MuSig2 rounds, Ark broadcast,
   server completion, Boltz funded status, and merchant settlement.
6. Verify success and error exits return to a usable screen.

Local app verification:

```bash
cd mobile/expo-nfc-prf-probe
npm ci
npm run check:design-system
npm run typecheck
```

The native acceptance test requires the documented live endpoint environment
and an enrolled credential profile. Those are deployment/card state, not source
artifacts, and must never be committed.

## 8. Handoff

Before shipping:

- rotate the card-manager keys from seller defaults and vault them
- confirm the owner's recovery policy authorizes a second independent card
- record only public card identifiers and the release/tag/checksum set
- do not ship transport keys, PIN, TOTP secret, or credential profile with the card
- keep a second separately initialized recovery card; do not clone private keys
