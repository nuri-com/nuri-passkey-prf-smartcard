#!/usr/bin/env python3
"""Package the Chrome prototype with manifest.json at the selected folder root."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = (
    "manifest.json", "background.js", "content.js", "inpage.js", "popup.html",
    "popup.js", "approve.html", "approve.js", "ui.css", "icon16.png", "icon32.png", "icon128.png", "test-dapp.html",
    "lib/hashing.js", "lib/bitcoin.js", "third_party/ethers.umd.min.js", "third_party/ethers.LICENSE.md",
)


def package(output):
    output = Path(output).expanduser().resolve()
    archive = output.with_suffix(".zip")
    # Never replace an existing unpacked installation or overwrite user files.
    if output.exists() or archive.exists():
        raise ValueError(f"Output already exists: {output} or {archive}")
    for name in RUNTIME:
        if not (ROOT / "extension" / name).is_file():
            raise ValueError(f"Missing extension input: {name}")
    revision = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    output.mkdir(parents=True)
    for name in RUNTIME:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "extension" / name, target)
    for name in ("LICENSE", "host/install-macos.sh", "host/nuri_card_host.py",
                 "host/webauthn_bridge.py", "host/bitcoin_commands.py",
                 "scripts/nuri_pcsc.py", "scripts/nuri_attest.py", "scripts/nuri_musig2_card.py",
                 "scripts/card-cosign-tweaked.py", "scripts/real-card-arkade-signer-proof.py",
                 "scripts/card-arkade-claim-signer.py", "scripts/card-prf-backup.py",
                 "scripts/musig2-card-status.py", "scripts/ext-card-wallet.mjs",
                 "scripts/lib/card-arkade-identity.mjs"):
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    (output / "Install Host.command").write_text(
        '#!/bin/bash\nset -euo pipefail\ncd "$(dirname "$0")"\n'
        'exec bash host/install-macos.sh --python "${PYTHON_BIN:-/opt/homebrew/bin/python3.13}" "$@"\n'
    )
    (output / "Install Host.command").chmod(0o755)
    (output / "START HERE.txt").write_text(
        "NURI CARD — CHROME PROTOTYPE 0.3.0\n"
        f"Source revision: {revision}\n"
        "Repository: https://github.com/nuri-com/nuri-passkey-prf-smartcard\n\n"
        "1. Chrome: chrome://extensions → Developer mode → Load unpacked.\n"
        "2. Select THIS Nuri Card folder. manifest.json is directly inside it.\n"
        "3. Pin Nuri Card using Chrome's Extensions menu.\n"
        "4. The local native host must also be installed. Existing installations remain unchanged.\n"
        "   macOS: double-click Install Host.command (requires Homebrew Python 3.13).\n"
        "   This installs Python dependencies and the host; it never provisions or resets a card.\n"
        "   Legacy ETH1 demo cards require an explicit terminal install with --eth1-demo.\n"
        "5. Bitcoin needs Node + host env NURI_ARKADE_SIGNER_URL, NURI_CARD_RECEIVE_PROFILE\n"
        "   and NURI_CARD_RECEIVE_PROFILE_PATH (see docs/chrome-extension.md).\n"
        "6. Serve this folder: python3 -m http.server 8787 --bind 127.0.0.1\n"
        "   Open http://127.0.0.1:8787/test-dapp.html → Connect → approve → Sign message → approve.\n"
        "   Expected result: matches. Signing a message does not transfer money.\n\n"
        "TEST SCOPE: browser automation uses the explicitly labelled software simulator.\n"
        "It is not real-card, ETH2 PIN, reader, recovery, broadcast or public-release qualification.\n"
        "See browser-evidence.json when supplied with the tested download.\n"
    )
    hashes = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "BUILD.json").write_text(json.dumps({"extension_version": "0.3.0", "source_revision": revision,
        "built_by": "Hermes Agent", "files_sha256": hashes}, indent=2) + "\n")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(output.rglob("*")):
            if p.is_file():
                z.write(p, str(p.relative_to(output.parent)))
    print(json.dumps({"folder": str(output), "zip": str(archive), "revision": revision}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="New folder to create; manifest.json goes directly inside")
    args = parser.parse_args()
    try:
        package(args.output)
    except ValueError as error:
        parser.exit(2, f"{error}\n")
