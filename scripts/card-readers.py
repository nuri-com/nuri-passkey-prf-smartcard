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
    ("ETH1", "4E55524945544801"),
    ("ETH2", "4E5552494554483201"),
    ("ETH2-UV", "4E5552494554483301"),
    ("Vault", "4E555249564C5401"),
    ("TOTP", "4E555249544F5450"),
    ("NURI-SC", "4E55524953433031"),
    ("PIV", "A000000308000010000100"),
    ("IBA", "A00000090501000101"),
    ("Feitian-FP", "46505356434170706C6574"),
    ("NuriAuth", "4E5552494155544801"),
    ("NuriAuth-Test", "4E5552494155544802"),
    ("Satochip", "5361746F4368697001"),
)
# GlobalPlatform CPLC ICSerialNumber lives at bytes 12..16 of the 42-byte CPLC payload.
GET_CPLC = bytes.fromhex("80CA9F7F00")
CHIPS = (("4790", "NXP JCOP"), ("4090", "Infineon"))
# Javelin-OS ATR seen on the IDEX TrustedBio card.
JAVELIN_ATR = "3B9F96C0F031FE45754A6176656C696E2D4F5320312E30AB"
PSEUDO_ATRS = {"3B119580"}


def scan_reader(reader) -> dict:
    name = str(reader)
    out = {"reader": name, "card": False, "atr": None, "serial": None,
           "chip": None, "protocol": None, "applets": [], "error": None, "note": None}

    def _probe(c) -> bool:
        # Verify an actual APDU roundtrip so readers like ACS ACR39U on macOS
        # (where default T=1 fails transmit) automatically step down to T=0.
        nuri_pcsc.transmit_raw(c, GET_CPLC)
        return True

    conn = None
    try:
        conn = reader.createConnection()
        out["protocol"] = nuri_pcsc.connect_ladder(conn, _probe)
    except nuri_pcsc.CardError as error:
        if error.code == "NO_CARD":
            out["error"] = error.code
            return out
        # A card is physically present (e.g. CASTLES EZCCID with pseudo-ATR 3B119580)
        # even though every protocol failed APDU transmission.
        try:
            conn.connect()
            out["atr"] = bytes(conn.getATR() or b"").hex().upper()
            out["card"] = bool(out["atr"])
        except Exception:
            pass
        out["error"] = error.code
        if out["atr"] in PSEUDO_ATRS:
            out["note"] = ("pseudo ATR, no APDU answered: on macOS this reader "
                           "cannot talk to the card. Use OMNIKEY or T=0 reader.")
        return out
    except Exception as error:
        out["error"] = type(error).__name__
        return out

    try:
        atr = bytes(conn.getATR() or b"").hex().upper()
        out.update(card=True, atr=atr)
        is_javelin = atr == JAVELIN_ATR
        if is_javelin:
            out["chip"] = "IDEX TrustedBio (Javelin-OS)"
        data, sw = b"", 0
        try:
            data, sw = nuri_pcsc.transmit_raw(conn, GET_CPLC)
        except Exception as error:
            out["error"] = type(error).__name__
        if sw == 0x9000 and len(data) >= 42:
            cplc = bytes(data)[-42:]
            out["serial"] = cplc[12:16].hex().upper()
            fab = cplc[0:2].hex().upper()
            if not is_javelin:
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
