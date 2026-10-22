#!/usr/bin/env python3
"""REAL_CARD_COSIGN_PYTHON stand-in for Node server tests: runs the given card
script unchanged, but against test/musig2_fake_card.py instead of PC/SC.

Env: FAKE_MUSIG2_VERSION (e.g. 1.14 or 1.13), FAKE_MUSIG2_PIN (card's set PIN),
FAKE_MUSIG2_ARGV_LOG (append argv + whether NURI_CARD_PIN arrived via env).
"""
import json
import os
import runpy
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import musig2_fake_card  # noqa: E402

major, minor = (int(x) for x in os.environ.get("FAKE_MUSIG2_VERSION", "1.14").split("."))
musig2_fake_card.install(version=(major, minor), pin=os.environ.get("FAKE_MUSIG2_PIN") or None)

log = os.environ.get("FAKE_MUSIG2_ARGV_LOG")
if log:
    with open(log, "a") as fh:
        fh.write(json.dumps({"argv": sys.argv[1:], "pin_env_present": "NURI_CARD_PIN" in os.environ}) + "\n")

script = sys.argv[1]
sys.argv = sys.argv[1:]
runpy.run_path(script, run_name="__main__")
