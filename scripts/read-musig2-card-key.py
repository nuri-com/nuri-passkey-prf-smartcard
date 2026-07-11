#!/usr/bin/env python3
"""Read the public MuSig2 identity from the physically inserted Nuri card."""

import importlib.util
import json
from pathlib import Path


CORE_PATH = Path(__file__).with_name("card-cosign-tweaked.py")
CORE_SPEC = importlib.util.spec_from_file_location("card_cosign_tweaked", CORE_PATH)
core = importlib.util.module_from_spec(CORE_SPEC)
CORE_SPEC.loader.exec_module(core)


def main():
    card = core.Card()
    card.connect()
    try:
        public_key = card.pubkey()
        if len(public_key) != 33 or public_key[0] not in (2, 3):
            raise RuntimeError("card returned an invalid compressed MuSig2 public key")
        print(json.dumps({
            "status": "NURI_MUSIG2_CARD_KEY_OK",
            "reader": card.reader,
            "card_version": card.version(),
            "card_pk33": public_key.hex(),
        }))
    finally:
        card.close()


if __name__ == "__main__":
    main()
