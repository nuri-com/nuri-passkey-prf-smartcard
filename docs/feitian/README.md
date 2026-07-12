# Feitian Source Documents

This folder contains local Feitian BioCARD source material used during the
2026-06-13/2026-06-14 qualification work:

- `Datasheet FT_JCOS BioCard E076.pdf`
- `Manual FP Card 076.pdf`
- `Manual FT-JCOS BioCARD V1.2EN (2209).pdf`
- `Datasheet FTSleeve.pdf`
- `Gmail - Re_ Inquiry - Fingerprint Card.pdf`

The relevant public handoff summary is in the top-level `README.md`. Do not use
the raw PDFs/email export alone as product proof. The tested card state in this
repo is:

```text
FIDO2 auth + WebAuthn PRF / CTAP2 hmac-secret: real card working
MuSig2 Taproot partial signing: simulator/APDU contract working, not installed
  on the real card yet
Feitian fingerprint API from our own applet: not implemented, SDK/NDA needed
```

The Feitian vendor-preloaded FIDO2 applet on the tested sample rejected fresh
credential creation over PC/SC with `CTAP 0x27 OPERATION_DENIED`. The working
real-card state was reached by installing the local `dist/FIDO2.cap` applet and
creating the standard FIDO2 instance `A0000006472F0001`.

## Confidential NDA SDK workflow

The Feitian BioCARD SDK supplied under NDA must never be committed, attached to
a GitHub issue/release, copied into CI, or printed into test logs. Keep the
unmodified SDK and all confidential vendor examples in this ignored local path:

```text
vendor/feitian-nda-sdk/
```

If confidential supporting documents must be kept near the existing Feitian
notes, use the separately ignored path:

```text
docs/feitian/nda/
```

Prepare a local checkout without copying any SDK files into tracked source:

```bash
mkdir -p vendor/feitian-nda-sdk
export FEITIAN_NDA_SDK_DIR="$PWD/vendor/feitian-nda-sdk"
git check-ignore -v "$FEITIAN_NDA_SDK_DIR"
npm run source:audit
```

Future integration code must consume the SDK through `FEITIAN_NDA_SDK_DIR`.
Only code that the NDA permits us to publish may live outside the ignored
directory. Do not reproduce proprietary headers, sample code, API documents,
keys, binaries, filenames, or vendor excerpts in public source, commits, test
fixtures, logs, issues, or release artifacts. Before publishing any adapter,
review the NDA and keep the public interface limited to independently authored
code.

The repository source audit fails if either reserved NDA path is ever tracked.
Local SDK tests must remain opt-in and must not run in public GitHub Actions.
