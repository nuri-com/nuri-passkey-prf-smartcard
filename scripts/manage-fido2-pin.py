#!/usr/bin/env python3
import argparse
import getpass
import json
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


def select_device(reader_filter: str | None = None, quiet: bool = False):
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
    if reader_filter:
        needle = reader_filter.lower()
        devices = [d for d in devices if needle in str(d).lower()]
    if not devices:
        if not quiet:
            print("No PC/SC FIDO2 smartcard device found.", file=sys.stderr)
            if last_error:
                print(f"Last reader error: {last_error}", file=sys.stderr)
            print("Check reader/card insertion and make sure the FIDO2 applet is installed.", file=sys.stderr)
        return None

    index_raw = os.environ.get("FIDO2_PCSC_INDEX")
    if index_raw is None and len(devices) > 1 and not reader_filter:
        if not quiet:
            print("Multiple PC/SC FIDO2 devices are visible:", file=sys.stderr)
            for index, device in enumerate(devices):
                print(f"  {index}: {device}", file=sys.stderr)
            print("Set FIDO2_PCSC_INDEX to choose one.", file=sys.stderr)
        return None

    index = int(index_raw or "0")
    if index < 0 or index >= len(devices):
        if not quiet:
            print(f"FIDO2_PCSC_INDEX={index} is out of range for {len(devices)} device(s).", file=sys.stderr)
        return None

    return devices[index]


def get_info(device):
    ctap = Ctap2(device)
    return ctap, ctap.info


def get_retries(ctap, info) -> tuple[int | None, bool | None]:
    if not ClientPin.is_supported(info):
        return None, None
    try:
        retries, pcs = ClientPin(ctap).get_pin_retries()
        return int(retries), bool(pcs)
    except CtapError:
        return None, None


def print_status(device, json_mode: bool = False) -> int:
    ctap, info = get_info(device)
    retries, power_cycle_state = get_retries(ctap, info)
    if json_mode:
        print(json.dumps({
            "ok": True,
            "device": str(device),
            "client_pin": bool(info.options.get("clientPin")),
            "pin_retries": retries,
            "pin_power_cycle_state": power_cycle_state,
            "min_pin_length": info.min_pin_length or 4,
            "max_pin_length": info.max_pin_length or 63,
        }))
        return 0

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
        if retries is not None:
            print(f"pin_retries: {retries}")
            print(f"pin_power_cycle_state: {power_cycle_state}")
        else:
            print("pin_retries_error: unavailable")

    print("FIDO2_PIN_STATUS_OK")
    return 0


def validate_new_pin(info, pin: str, confirm: str | None = None) -> str:
    min_len = info.min_pin_length or 4
    max_len = info.max_pin_length or 63
    if confirm is not None and pin != confirm:
        raise ValueError("PIN entries did not match.")
    if len(pin) < min_len:
        raise ValueError(f"PIN is too short; minimum is {min_len} characters.")
    if len(pin.encode("utf-8")) > max_len:
        raise ValueError(f"PIN is too long; maximum is {max_len} UTF-8 bytes.")
    return pin


def prompt_new_pin(info):
    min_len = info.min_pin_length or 4
    max_len = info.max_pin_length or 63
    pin = getpass.getpass(f"New FIDO2 PIN ({min_len}-{max_len} chars): ")
    confirm = getpass.getpass("Repeat new FIDO2 PIN: ")
    return validate_new_pin(info, pin, confirm)


def set_pin(device, stdin_lines: list[str] | None = None, json_mode: bool = False) -> int:
    ctap, info = get_info(device)
    if not ClientPin.is_supported(info):
        msg = "This authenticator does not advertise CTAP clientPin support."
        if json_mode:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 3
    if info.options.get("clientPin") is True:
        msg = "A FIDO2 PIN is already set. Use `npm run card:pin:change` to change it."
        if json_mode:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 4

    if stdin_lines is not None:
        if not stdin_lines:
            raise ValueError("Expected new FIDO2 PIN on stdin.")
        pin = validate_new_pin(info, stdin_lines[0])
    else:
        pin = prompt_new_pin(info)
    ClientPin(ctap).set_pin(pin)
    if not json_mode:
        print("FIDO2_PIN_SET_OK")
    return print_status(device, json_mode=json_mode)


def change_pin(device, stdin_lines: list[str] | None = None, json_mode: bool = False) -> int:
    ctap, info = get_info(device)
    if not ClientPin.is_supported(info):
        msg = "This authenticator does not advertise CTAP clientPin support."
        if json_mode:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 3
    if info.options.get("clientPin") is not True:
        msg = "No FIDO2 PIN is set yet. Use `npm run card:pin:set` first."
        if json_mode:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 4

    if stdin_lines is not None:
        if len(stdin_lines) < 2:
            raise ValueError("Expected current and new FIDO2 PIN on stdin.")
        old_pin = stdin_lines[0]
        new_pin = validate_new_pin(info, stdin_lines[1])
    else:
        old_pin = getpass.getpass("Current FIDO2 PIN: ")
        new_pin = prompt_new_pin(info)
    ClientPin(ctap).change_pin(old_pin, new_pin)
    if not json_mode:
        print("FIDO2_PIN_CHANGE_OK")
    return print_status(device, json_mode=json_mode)


def verify_pin(device, stdin_lines: list[str] | None = None, json_mode: bool = False) -> int:
    ctap, info = get_info(device)
    if not ClientPin.is_supported(info):
        msg = "This authenticator does not advertise CTAP clientPin support."
        if json_mode:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 3
    if info.options.get("clientPin") is not True:
        msg = "No FIDO2 PIN is set yet. Use `npm run card:pin:set` first."
        if json_mode:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 4

    if stdin_lines is not None:
        if not stdin_lines:
            raise ValueError("Expected FIDO2 PIN on stdin.")
        pin = stdin_lines[0]
    else:
        pin = getpass.getpass("FIDO2 PIN to verify: ")
    token = ClientPin(ctap).get_pin_token(pin)
    if not token:
        msg = "Authenticator returned an empty PIN token."
        if json_mode:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(msg, file=sys.stderr)
        return 5
    if json_mode:
        retries, pcs = get_retries(ctap, info)
        print(json.dumps({"ok": True, "pin_retries": retries, "pin_power_cycle_state": pcs}))
    else:
        print("FIDO2_PIN_VERIFY_OK")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Manage the FIDO2 CTAP client PIN on a PC/SC smartcard.")
    parser.add_argument("command", choices=["status", "set", "change", "verify"])
    parser.add_argument("--reader", help="Reader name substring to select")
    parser.add_argument("--stdin", action="store_true", help="Read PIN(s) line-by-line from stdin")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON on stdout")
    args = parser.parse_args()

    device = select_device(args.reader, quiet=args.json)
    if device is None:
        if args.json:
            print(json.dumps({"ok": False, "error": "No matching PC/SC FIDO2 smartcard device found."}))
        return 2

    stdin_lines = sys.stdin.read().splitlines() if args.stdin else None

    try:
        if args.command == "status":
            return print_status(device, json_mode=args.json)
        if args.command == "set":
            return set_pin(device, stdin_lines=stdin_lines, json_mode=args.json)
        if args.command == "change":
            return change_pin(device, stdin_lines=stdin_lines, json_mode=args.json)
        if args.command == "verify":
            return verify_pin(device, stdin_lines=stdin_lines, json_mode=args.json)
    except ValueError as error:
        if args.json:
            print(json.dumps({"ok": False, "error": str(error)}))
        else:
            print(str(error), file=sys.stderr)
        return 6
    except CtapError as error:
        if args.json:
            retries, pcs = None, None
            try:
                ctap, info = get_info(device)
                retries, pcs = get_retries(ctap, info)
            except Exception:
                pass
            print(json.dumps({
                "ok": False,
                "error": describe_ctap_error(error),
                "pin_retries": retries,
                "pin_power_cycle_state": pcs,
            }))
        else:
            print(f"CTAP error: {describe_ctap_error(error)}", file=sys.stderr)
        return 7

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
