#!/usr/bin/env python3
"""Read-only inventory of every PC/SC reader and the card in it.

  python3 scripts/card-readers.py            # human readable table
  python3 scripts/card-readers.py --json     # one JSON object per reader

Only SELECT by AID and GET DATA (CPLC, FIDO2 authenticatorGetInfo) are sent.
No PIN is tried, nothing is written, no key is created.

Why this exists: a Mac with two readers (OMNIKEY contact + contactless, a
CASTLES EZCCID, ...) lists several PC/SC names and GlobalPlatform asks for a
reader number. This prints what is where so you can pick once, then use
  export NURI_READER="HID Global OMNIKEY 5422 Smartcard Reader"
for every card script. scripts/card-setup.sh auto-selects when exactly one
reader holds a usable card.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nuri_pcsc  # noqa: E402

APPLETS = (
    ("FIDO2", "A0000006472F0001"),
    ("MuSig2", "4E5552494D554701"),
    ("MuSig2-UV", "4E5552494D55473501"),
    ("ETH1", "A00000000101"),
    ("ETH2", "4E5552494554483201"),
    ("ETH2-UV", "4E5552494554483301"),
    ("Vault", "4E555249564C5401"),
    ("TOTP", "4E555249544F5450"),
    ("Satochip", "5361746F4368697001"),
)
# CPLC serial lives at offset 9..13 of the 42 CPLC bytes (NXP/Infineon layout).
GET_CPLC = bytes.fromhex("80CA9F7F00")
CHIPS = (("4790", "NXP JCOP"), ("4090", "Infineon"))
# Javelin-OS ATR seen on the IDEX TrustedBio card (no CPLC via the GP ISD).
JAVELIN_ATR = "3B9F96C0F031FE45754A6176656C696E2D4F5320312E30AB"
GET_INFO = bytes.fromhex("800100000104")
# A contactless reader may report a pseudo ATR and refuse every APDU. Known
# case on macOS 15: CASTLES EZCCID reports 3B119580 and fails all transmits.
PSEUDO_ATRS = {"3B119580"}


def scan_reader(reader) -> dict:
    name = str(reader)
    out = {"reader": name, "card": False, "atr": None, "serial": None,
           "chip": None, "applets": [], "error": None, "note": None}
    try:
        conn = reader.createConnection()
        nuri_pcsc.connect_ladder(conn, lambda c: True)
    except Exception as error:  # NoCardException and transport errors
        out["error"] = type(error).__name__
        return out
    try:
        atr = bytes(conn.getATR() or b"").hex().upper()
        out.update(card=True, atr=atr)
        if atr == JAVELIN_ATR:
            out["chip"] = "IDEX TrustedBio (Javelin-OS)"
        data, sw = b"", 0
        try:
            data, sw = nuri_pcsc.transmit_raw(conn, GET_CPLC)
        except Exception as error:
            out["error"] = type(error).__name__
        if sw == 0x9000 and len(data) >= 42:
            cplc = bytes(data)[-42:]
            out["serial"] = cplc[9:13].hex().upper()
            fab = cplc[0:2].hex().upper()
            out["chip"] = next((label for prefix, label in CHIPS if fab == prefix), fab)
        for label, aid in APPLETS:
            try:
                _, sw = nuri_pcsc.transmit_raw(conn, nuri_pcsc.select_apdu(aid))
            except Exception as error:
                out["error"] = type(error).__name__
                break
            if sw == 0x9000:
                out["applets"].append(label)
        if out["atr"] in PSEUDO_ATRS and not out["applets"]:
            out["note"] = ("pseudo ATR, no APDU answered: on macOS this reader "
                           "cannot talk to the card. Use the OMNIKEY contact slot.")
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    readers = list(nuri_pcsc._list_readers())
    if not readers:
        print("No PC/SC reader found. Plug the reader in and wait 2 seconds.")
        return 1
    rows = [scan_reader(r) for r in readers]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for row in rows:
        print(f"{row['reader']}")
        if not row["card"]:
            hint = " (contactless slot: lay the card flat on it)" if "01" in row["reader"] or "EZCCID" in row["reader"] else ""
            print(f"  no card{hint}")
            continue
        print(f"  ATR    {row['atr']}")
        print(f"  card   {row['chip'] or 'unknown'}" + (f"  serial {row['serial']}" if row["serial"] else ""))
        print(f"  Nuri   {', '.join(row['applets']) if row['applets'] else 'no known applet (blank or other card)'}")
        if row["note"]:
            print(f"  note   {row['note']}")
    usable = [r for r in rows if r["card"] and r["applets"]]
    if len(usable) == 1:
        print(f"\nOne usable card. To pin every script to it:\n  export NURI_READER=\"{usable[0]['reader']}\"")
    return 0


if __name__ == "__main__":
    sys.exit(main())
