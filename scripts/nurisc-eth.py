#!/usr/bin/env python3
"""NuriSC ETH2: hidden one-time import, public-key read and hash signing."""
import argparse, getpass, json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from nuri_pcsc import open_applet
AID = "4E55524945544802"

def main():
    p = argparse.ArgumentParser(prog="nurisc-eth")
    p.add_argument("command", choices=["import", "pubkey", "sign"])
    p.add_argument("digest", nargs="?", help="32-byte hex digest for sign")
    a = p.parse_args()
    with open_applet(AID) as card:
        if a.command == "import":
            # One-time host-side input; never print, log, or save this value.
            secret = getpass.getpass("ETH private key (hidden input): ").strip()
            raw = bytes.fromhex(secret.removeprefix("0x"))
            secret = ""
            if len(raw) != 32:
                raise SystemExit("Expected exactly 32 bytes")
            data, sw = card.transmit(bytes([0,5,0,0,32]) + raw)
            raw = b""
        elif a.command == "pubkey":
            data, sw = card.transmit(bytes.fromhex("0002000000"))
        else:
            if not a.digest:
                p.error("sign requires a digest")
            raw = bytes.fromhex(a.digest.removeprefix("0x"))
            if len(raw) != 32:
                p.error("digest must be 32 bytes")
            data, sw = card.transmit(bytes([0,4,0,0,32]) + raw)
        print(json.dumps({"sw": f"{sw:04X}", "data": data.hex()}))
        if sw != 0x9000:
            raise SystemExit(1)

if __name__ == "__main__":
    main()
