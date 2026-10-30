#!/usr/bin/env python3
"""Read-only card identity and applet presence for scripts/card-setup.sh.

Two subcommands, both without any write APDU:

  info    read the CPLC (fabricator, OS, serial) and the ATR from the card
  verify  SELECT every expected applet AID and report the status word

Every call goes through scripts/nuri_pcsc.py, so cheap T=0-only readers work
and the protocol ladder is shared with the other card scripts.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import nuri_pcsc  # noqa: E402
from card_lock import CPLC_FIELDS  # noqa: E402

ISD_AID = "A000000003000000"
GET_CPLC = bytes.fromhex("80CA9F7F00")
EXPECTED_AIDS = (
    "A0000006472F0001",  # FIDO2
    "4E5552494D554701",  # MuSig2 AID1
    "4E555249544F5450",  # TOTP
    "4E55524945544801",  # ETH1
    "4E5552494554483201",  # ETH2
    "4E5552494D55473201",  # MuSig2 AID2
    "4E5552494D55473301",  # MuSig2 AID3
    "4E555249564C5401",  # vault
)
FABRICATORS = {"4790": "NXP", "4090": "Infineon"}
CPLC_SIZE = sum(size for _, size in CPLC_FIELDS)


def read_info(reader: str) -> dict[str, str]:
    with nuri_pcsc.open_applet(ISD_AID, reader) as applet:
        atr = applet.atr()
        data, sw = applet.transmit(GET_CPLC)
    if sw != 0x9000:
        raise SystemExit(f"ERROR: CPLC read returned {sw:04X}")
    if len(data) != CPLC_SIZE:
        raise SystemExit(f"ERROR: CPLC is {len(data)} bytes, expected {CPLC_SIZE}")
    values, offset = {}, 0
    for field, size in CPLC_FIELDS:
        values[field] = data[offset:offset + size].hex().upper()
        offset += size
    ascii_atr = "".join(chr(byte) if 32 <= byte < 127 else "" for byte in atr)
    chip = FABRICATORS.get(values["ICFabricator"], "unknown")
    if "JCOPv241" in ascii_atr:
        chip += " JCOP 2.4.1"
    return {
        "SERIAL": values["ICSerialNumber"],
        "CPLC": "".join(values[field] for field, _ in CPLC_FIELDS),
        "ATR": atr.hex().upper(),
        "FABRICATOR": values["ICFabricator"],
        "CHIP": chip,
        "OS_DATE": values["OperatingSystemReleaseDate"],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("info", "verify"))
    parser.add_argument("--reader", required=True)
    parser.add_argument("--aids", default=",".join(EXPECTED_AIDS),
                        help="comma separated AIDs for verify")
    args = parser.parse_args(argv)

    try:
        if args.command == "info":
            for key, value in read_info(args.reader).items():
                print(f"{key}={value}")
            return 0
        missing = 0
        for aid in [a.strip().upper() for a in args.aids.split(",") if a.strip()]:
            if not re.fullmatch(r"[0-9A-F]{10,32}", aid):
                print(f"BAD_AID {aid}")
                missing += 1
                continue
            try:
                applet = nuri_pcsc.open_applet(aid, args.reader)
            except nuri_pcsc.CardError as error:
                print(f"SELECT_FAILED {aid} {error.code}")
                missing += 1
                continue
            data, sw = applet.transmit(nuri_pcsc.select_apdu(aid))
            applet.close()
            if sw != 0x9000 and (sw >> 8) != 0x61:
                print(f"SELECT_FAILED {aid} {sw:04X}")
                missing += 1
                continue
            print(f"SELECT_OK {aid} {sw:04X}")
        return 1 if missing else 0
    except nuri_pcsc.CardError as error:
        print(f"ERROR: {error.code} {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
