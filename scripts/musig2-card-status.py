#!/usr/bin/env python3
"""Read-only status of the NuriMuSig2 applet on the physically inserted card.

Prints one JSON object. No signing, no keygen, no PIN setup and no state change:
only GET_VERSION, PIN_STATUS (1.14+) and GET_PUBKEY.

GET_PUBKEY on a PIN-required applet can answer 6982; the shared driver then reads
the PIN from NURI_CARD_PIN (or a terminal prompt) and retries the same read. The
PIN is never echoed.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nuri_musig2_card as musig2  # noqa: E402


def main() -> int:
    card = musig2.MuSig2Card()
    try:
        card.connect()
        pub = card.pubkey()
        if len(pub) != 33 or pub[0] not in (2, 3):
            raise RuntimeError("card returned an invalid compressed MuSig2 public key")
        info = card.version_info()
        print(json.dumps({
            "status": "NURI_MUSIG2_CARD_STATUS_OK",
            "reader": card.reader,
            "version": info["version"],
            "build": info["build"],
            "capabilities": info["capabilities"],
            "pin_required": info["pin_required"],
            "pin_set": info["pin_set"],
            "pin_tries_left": info["pin_tries"],
            "card_pk33": pub.hex(),
        }))
        return 0
    finally:
        card.close()


if __name__ == "__main__":
    sys.exit(main())
