#!/usr/bin/env python3
"""Manage Feitian BioCARD fingerprints without exposing biometric data.

The preinstalled FPSVCApplet performs enrollment and matching on the card. This
host tool only exchanges status bytes; it never receives an image or template.
No delete operation is provided. Existing applets and templates are preserved.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nuri_pcsc  # noqa: E402

FEITIAN_AID = "46505356434170706C6574"  # ASCII "FPSVCApplet"
DEFAULT_TOUCHES = 12


def emit(**fields) -> None:
    print(json.dumps(fields, separators=(",", ":")), flush=True)


def response_error(operation: str, data: bytes, sw: int) -> RuntimeError:
    code = data[0] if data else 0
    messages = {
        0xE0: "Fingerprint did not match",
        0xE9: "Fingerprint sensor timed out; try again",
        0xEA: "No free fingerprint template slot",
        0xE1: "Fingerprint sensor operation failed",
    }
    detail = messages.get(code, f"Unexpected response data={data.hex().upper()} SW={sw:04X}")
    return RuntimeError(f"{operation}: {detail}")


class FeitianFingerprint:
    def __init__(self, reader: str):
        self.card = nuri_pcsc.open_applet(FEITIAN_AID, reader=reader)

    def close(self) -> None:
        self.card.close()

    def _command(self, ins: int, p1: int = 0) -> bytes:
        data, sw = self.card.transmit(bytes([0x00, 0xF1, ins, p1, 0x00]))
        if sw != 0x9000:
            raise response_error("APDU", data, sw)
        return data

    def list(self) -> int:
        data = self._command(0x51)
        if len(data) < 4 or data[1] != 0x51 or data[3] != 0x90:
            raise response_error("LIST", data, 0x9000)
        return data[0]

    def match(self) -> None:
        data = self._command(0x53)
        if len(data) < 4 or data[:4] != bytes.fromhex("00530090"):
            raise response_error("MATCH", data, 0x9000)

    def enroll(self) -> int:
        touch = 1
        while True:
            data = self._command(0x50, touch)
            if len(data) < 4 or data[1] != 0x50 or data[3] != 0x90:
                raise response_error("ENROLL", data, 0x9000)
            current, maximum = data[0], data[2]
            if current == 0 or maximum == 0 or current > maximum:
                raise response_error("ENROLL", data, 0x9000)
            emit(ok=True, event="touch", current=current, maximum=maximum)
            if current == maximum:
                return current
            touch = current + 1


def status(reader: str) -> dict:
    """Read-only scanner metadata; unsupported cards are not an error."""
    try:
        card = FeitianFingerprint(reader)
    except nuri_pcsc.CardError as error:
        if error.code == "NO_APPLET":
            return {"fingerprint_supported": False, "fingerprint_count": 0, "fingerprint_backend": ""}
        raise
    try:
        return {
            "fingerprint_supported": True,
            "fingerprint_count": card.list(),
            "fingerprint_backend": "feitian",
        }
    finally:
        card.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", required=True, help="Exact PC/SC reader name")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--list", action="store_true", help="Count enrolled templates (default)")
    action.add_argument("--match", action="store_true", help="Touch the sensor to match one enrolled finger")
    action.add_argument("--enroll", action="store_true", help="Enroll a new finger using 12 touches")
    args = parser.parse_args()

    card = None
    try:
        card = FeitianFingerprint(args.reader)
        common = {"reader": card.card.reader_name, "protocol": card.card.protocol, "backend": "feitian"}
        if args.match:
            emit(ok=True, event="waiting", instruction="Touch an enrolled finger on the card sensor", **common)
            card.match()
            emit(ok=True, event="matched", **common)
        elif args.enroll:
            count = card.list()
            emit(ok=True, event="waiting", instruction="Touch and lift the same finger 12 times", template_count=count, **common)
            touches = card.enroll()
            emit(ok=True, event="enrolled", touches=touches, template_count=card.list(), **common)
        else:
            emit(ok=True, event="listed", template_count=card.list(), **common)
        return 0
    except Exception as error:
        emit(ok=False, error=str(error))
        return 1
    finally:
        if card is not None:
            card.close()


if __name__ == "__main__":
    raise SystemExit(main())
