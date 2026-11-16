#!/usr/bin/env python3
import argparse
import getpass
import os
import sys
import time

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.pcsc import CtapPcscDevice

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nuri_pcsc  # noqa: E402

# T=0-only readers (Realtek 0bda:0165): make CtapPcscDevice.list_devices() find the card.
nuri_pcsc.patch_fido2()


def describe_ctap_error(error: CtapError) -> str:
    code = getattr(error, "code", None)
    if hasattr(code, "name"):
        return f"{code.name}: {error}"
    return str(error)


def select_device():
    last_error = None
    for attempt in range(1, 6):
        try:
            devices = list(CtapPcscDevice.list_devices())
            break
        except Exception as error:
            last_error = error
            if attempt >= 5:
                raise
            time.sleep(0.35 * attempt)
    if not devices:
        print("No PC/SC FIDO2 smartcard device found.", file=sys.stderr)
        if last_error:
            print(f"Last reader error: {last_error}", file=sys.stderr)
        print("Check reader/card insertion and make sure the FIDO2 applet is installed.", file=sys.stderr)
        return None

    index_raw = os.environ.get("FIDO2_PCSC_INDEX")
    if index_raw is None and len(devices) > 1:
        print("Multiple PC/SC FIDO2 devices are visible:", file=sys.stderr)
        for index, device in enumerate(devices):
            print(f"  {index}: {device}", file=sys.stderr)
        print("Set FIDO2_PCSC_INDEX to choose one.", file=sys.stderr)
        return None

    index = int(index_raw or "0")
    if index < 0 or index >= len(devices):
        print(f"FIDO2_PCSC_INDEX={index} is out of range for {len(devices)} device(s).", file=sys.stderr)
        return None

    return devices[index]


def get_info(device):
    ctap = Ctap2(device)
    return ctap, ctap.info


def print_status(device) -> int:
    ctap, info = get_info(device)
    print(f"Using PC/SC device: {device}")
    print(f"versions: {info.versions}")
    print(f"extensions: {info.extensions}")
    print(f"options: {info.options}")
    print(f"clientPin: {info.options.get('clientPin')}")
    print(f"pin_uv_protocols: {info.pin_uv_protocols}")
    print(f"min_pin_length: {info.min_pin_length}")
    print(f"max_pin_length: {info.max_pin_length}")
    print(f"uv_modality: {info.uv_modality}")

    if ClientPin.is_supported(info):
        client_pin = ClientPin(ctap)
        try:
            retries, power_cycle_state = client_pin.get_pin_retries()
            print(f"pin_retries: {retries}")
            print(f"pin_power_cycle_state: {power_cycle_state}")
        except CtapError as error:
            print(f"pin_retries_error: {describe_ctap_error(error)}")

    print("FIDO2_PIN_STATUS_OK")
    return 0


def prompt_new_pin(info):
    min_len = info.min_pin_length or 4
    max_len = info.max_pin_length or 63
    pin = getpass.getpass(f"New FIDO2 PIN ({min_len}-{max_len} chars): ")
    confirm = getpass.getpass("Repeat new FIDO2 PIN: ")

    if pin != confirm:
        raise ValueError("PIN entries did not match.")
    if len(pin) < min_len:
        raise ValueError(f"PIN is too short; minimum is {min_len} characters.")
    if len(pin.encode("utf-8")) > max_len:
        raise ValueError(f"PIN is too long; maximum is {max_len} UTF-8 bytes.")
    return pin


def set_pin(device) -> int:
    ctap, info = get_info(device)
    if not ClientPin.is_supported(info):
        print("This authenticator does not advertise CTAP clientPin support.", file=sys.stderr)
        return 3
    if info.options.get("clientPin") is True:
        print("A FIDO2 PIN is already set. Use `npm run card:pin:change` to change it.", file=sys.stderr)
        return 4

    pin = prompt_new_pin(info)
    ClientPin(ctap).set_pin(pin)
    print("FIDO2_PIN_SET_OK")
    return print_status(device)


def change_pin(device) -> int:
    ctap, info = get_info(device)
    if not ClientPin.is_supported(info):
        print("This authenticator does not advertise CTAP clientPin support.", file=sys.stderr)
        return 3
    if info.options.get("clientPin") is not True:
        print("No FIDO2 PIN is set yet. Use `npm run card:pin:set` first.", file=sys.stderr)
        return 4

    old_pin = getpass.getpass("Current FIDO2 PIN: ")
    new_pin = prompt_new_pin(info)
    ClientPin(ctap).change_pin(old_pin, new_pin)
    print("FIDO2_PIN_CHANGE_OK")
    return print_status(device)


def verify_pin(device) -> int:
    ctap, info = get_info(device)
    if not ClientPin.is_supported(info):
        print("This authenticator does not advertise CTAP clientPin support.", file=sys.stderr)
        return 3
    if info.options.get("clientPin") is not True:
        print("No FIDO2 PIN is set yet. Use `npm run card:pin:set` first.", file=sys.stderr)
        return 4

    pin = getpass.getpass("FIDO2 PIN to verify: ")
    token = ClientPin(ctap).get_pin_token(pin)
    if not token:
        print("Authenticator returned an empty PIN token.", file=sys.stderr)
        return 5
    print("FIDO2_PIN_VERIFY_OK")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Manage the FIDO2 CTAP client PIN on a PC/SC smartcard.")
    parser.add_argument("command", choices=["status", "set", "change", "verify"])
    args = parser.parse_args()

    device = select_device()
    if device is None:
        return 2

    try:
        if args.command == "status":
            return print_status(device)
        if args.command == "set":
            return set_pin(device)
        if args.command == "change":
            return change_pin(device)
        if args.command == "verify":
            return verify_pin(device)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 6
    except CtapError as error:
        print(f"CTAP error: {describe_ctap_error(error)}", file=sys.stderr)
        return 7

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
