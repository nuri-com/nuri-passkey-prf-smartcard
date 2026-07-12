# FIDO2 PRF Baseline

## Viable Source

The viable source is the Bryan Jacobs FIDO2Applet lineage. It already implements CTAP2.1, Java Card builds, jCardSim support, and CTAP2 `hmac-secret`.

Card V1 vendors the exact clean Nuri-fork base at commit
`4f318197cc08f316ce784a89bdf29dc73cca7fcf` under
`third_party/fido2-applet/`. Its parent is upstream FIDO2Applet v2.0.5 commit
`0194107d9648577379058b59843504924b546514`. The Nuri PRF and user-presence
changes remain separate under `patches/`.

## Why Not A CTAP `prf` Extension

WebAuthn `prf` is a browser/client extension. The authenticator-side primitive is CTAP2 `hmac-secret`.

For a browser PRF flow:

1. The RP asks WebAuthn for `extensions.prf`.
2. The browser hashes PRF inputs as specified by WebAuthn.
3. The browser talks to the authenticator with CTAP2 `hmac-secret`.
4. The browser maps the returned hmac-secret output back into `clientExtensionResults.prf`.

So the applet should pass `hmac-secret` tests and should not add a separate GetInfo `"prf"` string unless a specific client requires it.

## Local Simulator Workflow

Prepare the isolated patched build tree:

```bash
scripts/prepare-fido2-baseline.sh
```

Run PRF primitive tests:

```bash
scripts/run-fido2-prf-sim-tests.sh
```

The test script:

- uses Java 17 when available,
- creates a temporary Python venv,
- installs the vendored baseline's `requirements.txt`,
- builds `jar` and `testJar`,
- runs `python_tests.ctap.test_hmac_secret.HMACSecretTestCase`,
- runs this repo's `test/fido2_prf_e2e.py` browser-PRF mapping test.

## Card Requirements

The target card must support the primitives needed by FIDO2Applet:

- Java Card Classic 3.0.4-ish or a vendor profile with equivalent algorithms.
- P-256 key generation and ECDSA SHA-256.
- ECDH plain output plus SHA-256.
- AES-256 CBC no padding.
- SHA-256 and secure random.
- enough transient RAM and persistent storage for resident credentials.

Good first targets are NXP JCOP3/JCOP4 cards such as J3H145 or J3R180-class cards. See `docs/hardware-manufacturer-spec.md` for the manufacturer checklist.

## Browser Caveat

A PC/SC smartcard reader is not automatically a browser WebAuthn roaming authenticator on every OS/browser. Desktop Chrome/Firefox commonly expect CTAP HID for roaming keys. For browser E2E we need one of:

- a real NFC path accepted by the browser/OS,
- a USB HID bridge to PC/SC,
- a platform/browser combination that can speak to the card as a FIDO authenticator.
