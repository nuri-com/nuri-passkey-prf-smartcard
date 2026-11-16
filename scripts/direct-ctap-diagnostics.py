#!/usr/bin/env python3
import argparse
import getpass
import json
import os
import sys
import time

from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.pcsc import CtapPcscDevice

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nuri_pcsc  # noqa: E402

# T=0-only readers (Realtek 0bda:0165): make CtapPcscDevice.list_devices() find the card.
nuri_pcsc.patch_fido2()


def select_device():
    last_error = None
    for attempt in range(1, 13):
        try:
            devices = list(CtapPcscDevice.list_devices())
            break
        except Exception as error:
            last_error = error
            if attempt >= 12:
                raise
            time.sleep(0.35 * attempt)
    if not devices:
        detail = f" Last reader error: {last_error}" if last_error else ""
        raise RuntimeError(f"No PC/SC FIDO2 smartcard device found.{detail}")
    index = int(os.environ.get("FIDO2_PCSC_INDEX", "0"))
    return devices[index]


def makecred_matrix():
    device = select_device()
    ctap = Ctap2(device)
    variants = [
        None,
        {"rk": False},
        {"rk": False, "uv": False},
        {"rk": True},
        {"rk": True, "uv": False},
        {"uv": False},
        {"uv": True},
        {"rk": True, "uv": True},
    ]

    result = {
        "device": repr(device),
        "info_options": ctap.info.options,
        "results": [],
    }
    for options in variants:
        try:
            response = ctap.make_credential(
                os.urandom(32),
                {"id": "nuri.local", "name": "Nuri Direct CTAP"},
                {
                    "id": os.urandom(32),
                    "name": "diag",
                    "displayName": "diag",
                },
                [{"type": "public-key", "alg": -7}],
                options=options,
            )
            auth_data = response.auth_data
            result["results"].append(
                {
                    "ok": True,
                    "options": options,
                    "credential_id_hex": auth_data.credential_data.credential_id.hex(),
                    "flags": auth_data.flags,
                }
            )
        except Exception as error:
            result["results"].append(
                {
                    "ok": False,
                    "options": options,
                    "error_type": type(error).__name__,
                    "error": str(error),
                }
            )

    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0 if any(item["ok"] for item in result["results"]) else 9


def makecred_pin():
    device = select_device()
    ctap = Ctap2(device)
    client_pin = ClientPin(ctap)
    pin = getpass.getpass("FIDO2 PIN: ")
    rp_id = "nuri.local"
    pin_token = client_pin.get_pin_token(
        pin,
        ClientPin.PERMISSION.MAKE_CREDENTIAL,
        rp_id,
    )
    variants = [
        None,
        {"rk": False},
        {"rk": True},
        {"rk": False, "uv": False},
    ]

    result = {
        "device": repr(device),
        "info_options": ctap.info.options,
        "pin_protocol": client_pin.protocol.VERSION,
        "results": [],
    }
    for options in variants:
        client_data_hash = os.urandom(32)
        pin_uv_param = client_pin.protocol.authenticate(pin_token, client_data_hash)
        try:
            response = ctap.make_credential(
                client_data_hash,
                {"id": rp_id, "name": "Nuri Direct CTAP"},
                {
                    "id": os.urandom(32),
                    "name": "diag",
                    "displayName": "diag",
                },
                [{"type": "public-key", "alg": -7}],
                options=options,
                pin_uv_param=pin_uv_param,
                pin_uv_protocol=client_pin.protocol.VERSION,
            )
            auth_data = response.auth_data
            result["results"].append(
                {
                    "ok": True,
                    "options": options,
                    "credential_id_hex": auth_data.credential_data.credential_id.hex(),
                    "flags": auth_data.flags,
                }
            )
        except Exception as error:
            result["results"].append(
                {
                    "ok": False,
                    "options": options,
                    "error_type": type(error).__name__,
                    "error": str(error),
                }
            )

    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0 if any(item["ok"] for item in result["results"]) else 9


def run_makecred_with_token(command_name, device, ctap, pin_token, pin_protocol):
    variants = [
        None,
        {"rk": False},
        {"rk": True},
        {"rk": False, "uv": False},
    ]
    result = {
        "device": repr(device),
        "info_options": ctap.info.options,
        "pin_protocol": pin_protocol.VERSION,
        "token_source": command_name,
        "results": [],
    }
    for options in variants:
        client_data_hash = os.urandom(32)
        pin_uv_param = pin_protocol.authenticate(pin_token, client_data_hash)
        try:
            response = ctap.make_credential(
                client_data_hash,
                {"id": "nuri.local", "name": "Nuri Direct CTAP"},
                {
                    "id": os.urandom(32),
                    "name": "diag",
                    "displayName": "diag",
                },
                [{"type": "public-key", "alg": -7}],
                options=options,
                pin_uv_param=pin_uv_param,
                pin_uv_protocol=pin_protocol.VERSION,
            )
            auth_data = response.auth_data
            result["results"].append(
                {
                    "ok": True,
                    "options": options,
                    "credential_id_hex": auth_data.credential_data.credential_id.hex(),
                    "flags": auth_data.flags,
                }
            )
        except Exception as error:
            result["results"].append(
                {
                    "ok": False,
                    "options": options,
                    "error_type": type(error).__name__,
                    "error": str(error),
                }
            )
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0 if any(item["ok"] for item in result["results"]) else 9


def makecred_uv():
    device = select_device()
    ctap = Ctap2(device)
    client_pin = ClientPin(ctap)
    pin_token = client_pin.get_uv_token(
        ClientPin.PERMISSION.MAKE_CREDENTIAL,
        "nuri.local",
    )
    return run_makecred_with_token("uv", device, ctap, pin_token, client_pin.protocol)


def main():
    parser = argparse.ArgumentParser(description="Direct CTAP2 PC/SC diagnostics.")
    parser.add_argument("command", choices=["makecred-matrix", "makecred-pin", "makecred-uv"])
    args = parser.parse_args()
    if args.command == "makecred-matrix":
        return makecred_matrix()
    if args.command == "makecred-pin":
        return makecred_pin()
    if args.command == "makecred-uv":
        return makecred_uv()
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(2)
