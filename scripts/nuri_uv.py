#!/usr/bin/env python3
"""Configure NuriUV on-card PIN/fingerprint policy (vendor-neutral APDUs)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nuri_pcsc  # noqa: E402

UV_AID = "4E5552494155544801"
CLIENT_AID = "4E5552494155544802"
POLICIES = {"pin": 0, "or": 1, "and": 2}


def emit(**fields) -> None:
    print(json.dumps(fields, separators=(",", ":")), flush=True)


def command(applet, ins: int, p1: int = 0, data: bytes = b"", le: int = 0) -> tuple[bytes, int]:
    # Feitian T=0 requires Case 4 APDUs (explicit Le) even for empty responses.
    apdu = bytes([0, ins, p1, 0, len(data)]) + data + bytes([le])
    return applet.transmit(apdu)


def require_ok(data: bytes, sw: int) -> bytes:
    if sw != 0x9000:
        raise RuntimeError(f"NuriUV returned SW={sw:04X} data={data.hex().upper()}")
    return data


def check_client(applet) -> tuple[bytes, int]:
    require_ok(*applet.transmit(nuri_pcsc.select_apdu(CLIENT_AID)))
    return applet.transmit(bytes.fromhex("0001000002"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", required=True)
    parser.add_argument("--initial-policy", choices=tuple(POLICIES), default="pin")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--client-check", action="store_true")
    action.add_argument("--set-pin-stdin", action="store_true")
    action.add_argument("--verify-pin-stdin", action="store_true")
    action.add_argument("--pin-check-stdin", action="store_true")
    action.add_argument("--and-check-stdin", action="store_true")
    action.add_argument("--finger-check", action="store_true")
    action.add_argument("--finger", action="store_true")
    action.add_argument("--policy", choices=tuple(POLICIES))
    action.add_argument("--logout", action="store_true")
    args = parser.parse_args()

    applet = None
    try:
        if args.client_check:
            applet = nuri_pcsc.open_applet(CLIENT_AID, reader=args.reader)
            data, sw = applet.transmit(bytes.fromhex("0001000002"))
            emit(ok=sw == 0x9000, authorized=sw == 0x9000, sw=f"{sw:04X}", data=data.hex().upper())
            return 0 if sw == 0x9000 else 1

        applet = nuri_pcsc.open_applet(UV_AID, reader=args.reader)
        if args.pin_check_stdin or args.and_check_stdin or args.finger_check:
            if not args.finger_check:
                pin = sys.stdin.read().splitlines()[0].encode("ascii")
                require_ok(*command(applet, 0x20, data=pin))
            if not args.pin_check_stdin:
                emit(ok=True, event="waiting", instruction="Touch an authorized finger now")
                require_ok(*command(applet, 0x2A))
            data, sw = check_client(applet)
            emit(ok=sw == 0x9000, authorized=sw == 0x9000, sw=f"{sw:04X}", data=data.hex().upper())
            return 0 if sw == 0x9000 else 1
        if args.set_pin_stdin or args.verify_pin_stdin:
            pin = sys.stdin.read().splitlines()[0].encode("ascii")
            ins = 0x31 if args.set_pin_stdin else 0x20
            p1 = POLICIES[args.initial_policy] if args.set_pin_stdin else 0
            require_ok(*command(applet, ins, p1, pin))
            emit(ok=True, pin_set=True)
        elif args.finger:
            emit(ok=True, event="waiting", instruction="Touch an authorized finger now")
            require_ok(*command(applet, 0x2A))
            emit(ok=True, event="matched")
        elif args.policy:
            require_ok(*command(applet, 0x38, POLICIES[args.policy]))
            emit(ok=True, policy=args.policy)
        else:
            require_ok(*command(applet, 0x35))
            emit(ok=True, logged_out=True)
        return 0
    except Exception as error:
        emit(ok=False, error=str(error))
        return 1
    finally:
        if applet is not None:
            applet.close()


if __name__ == "__main__":
    raise SystemExit(main())
