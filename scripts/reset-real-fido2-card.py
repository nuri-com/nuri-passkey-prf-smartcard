#!/usr/bin/env python3
import os
import sys

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.pcsc import CtapPcscDevice

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nuri_pcsc  # noqa: E402

# T=0-only readers (Realtek 0bda:0165): make CtapPcscDevice.list_devices() find the card.
nuri_pcsc.patch_fido2()


def main():
    devices = list(CtapPcscDevice.list_devices())
    if not devices:
        print("No PC/SC FIDO2 smartcard device found.")
        return 2

    index_raw = os.environ.get("FIDO2_PCSC_INDEX")
    if len(devices) > 1 and index_raw is None:
        print("Multiple PC/SC FIDO2 smartcard devices found; set FIDO2_PCSC_INDEX.", file=sys.stderr)
        for i, device in enumerate(devices):
            print(f"[{i}] {device}", file=sys.stderr)
        return 4

    index = int(index_raw or "0")
    if index < 0 or index >= len(devices):
        print(f"FIDO2_PCSC_INDEX={index} is out of range for {len(devices)} device(s).", file=sys.stderr)
        return 5

    dev = devices[index]
    print(f"Using PC/SC device: {dev}")
    ctap = Ctap2(dev)
    info = ctap.info
    print(f"Before reset versions={info.versions}")
    print(f"Before reset extensions={info.extensions}")
    print(f"Before reset options={info.options}")

    try:
        ctap.reset()
    except CtapError as exc:
        print(f"Reset failed: {exc}")
        return 3

    info = Ctap2(dev).info
    print(f"After reset versions={info.versions}")
    print(f"After reset extensions={info.extensions}")
    print(f"After reset options={info.options}")
    print("REAL_CARD_FIDO2_RESET_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
