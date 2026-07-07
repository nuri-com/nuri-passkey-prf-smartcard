#!/usr/bin/env python3
import argparse
import base64
import getpass
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.hid import CtapHidDevice
from fido2.pcsc import CtapPcscDevice
from fido2.webauthn import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

try:
    from smartcard.Exceptions import CardConnectionException
    from smartcard.pcsc.PCSCExceptions import EstablishContextException
except Exception:  # pragma: no cover - only absent when fido2[pcsc] is unavailable
    CardConnectionException = ()
    EstablishContextException = ()


PROFILE_SCHEMA = "nuri-card-prf-profile-v1"
DEFAULT_PROFILE_DIR = Path(".nuri-card-prf")
DEFAULT_SALT = "nuri-offline-backup-v1"
P256_SPKI_PREFIX = bytes.fromhex(
    "3059301306072A8648CE3D020106082A8648CE3D030107034200"
)


class CliUserInteraction(UserInteraction):
    def __init__(self, pin=None, pin_prompt=False):
        self.pin = pin or os.environ.get("FIDO2_BACKUP_PIN") or os.environ.get("FIDO2_TEST_PIN")
        self.prompt_pin = pin_prompt or os.environ.get("FIDO2_BACKUP_PIN_PROMPT") == "YES"

    def prompt_up(self) -> None:
        print("User presence requested by authenticator.")

    def request_pin(self, permissions, rp_id):
        if self.pin is None and self.prompt_pin:
            self.pin = getpass.getpass("FIDO2 PIN: ")
        return self.pin

    def request_uv(self, permissions, rp_id) -> bool:
        return True


def b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    return base64.urlsafe_b64decode(padded)


def output_bytes(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return b64u_decode(value)
    return bytes(value)


def ext_value(results, key):
    if hasattr(results, "get"):
        return results.get(key)
    return getattr(results, key, None)


def extension_results(value):
    return getattr(value, "client_extension_results", getattr(value, "extension_results", {}))


def credential_response(value):
    return getattr(value, "response", value)


def credential_id(value):
    response = credential_response(value)
    if hasattr(response, "attestation_object"):
        return response.attestation_object.auth_data.credential_data.credential_id
    return response.auth_data.credential_data.credential_id


def credential_public_key(value):
    response = credential_response(value)
    if hasattr(response, "attestation_object"):
        return response.attestation_object.auth_data.credential_data.public_key
    return response.auth_data.credential_data.public_key


def p256_uncompressed_public_key(cose_key) -> bytes:
    try:
        x = output_bytes(cose_key[-2])
        y = output_bytes(cose_key[-3])
    except Exception as error:
        raise ValueError(f"unsupported credential public key format: {error}") from error
    if len(x) != 32 or len(y) != 32:
        raise ValueError("P-256 credential public key coordinates must be 32 bytes")
    return b"\x04" + x + y


def p256_spki_public_key(cose_key) -> bytes:
    return P256_SPKI_PREFIX + p256_uncompressed_public_key(cose_key)


def prf_enabled(value):
    prf = ext_value(extension_results(value), "prf")
    return ext_value(prf, "enabled") if prf else None


def hmac_create_secret_enabled(value):
    return ext_value(extension_results(value), "hmacCreateSecret")


def registration_extensions(mode):
    if mode == "disabled":
        return None
    if mode == "prf":
        return {"prf": {}}
    if mode == "hmacCreateSecret":
        return {"hmacCreateSecret": True}
    raise ValueError("registration PRF mode must be prf, hmacCreateSecret, or disabled")


def prf_outputs(assertion):
    results = getattr(assertion, "client_extension_results", {})
    prf = ext_value(results, "prf")
    if not prf:
        return None, None
    prf_results = ext_value(prf, "results")
    if not prf_results:
        return None, None
    return output_bytes(ext_value(prf_results, "first")), output_bytes(
        ext_value(prf_results, "second")
    )


def describe_ctap_error(error: CtapError) -> str:
    code = getattr(error, "code", None)
    if hasattr(code, "name"):
        return f"{code.name}: {error}"
    return str(error)


def select_device(args):
    transport = args.transport.strip().lower()
    last_error = None
    for attempt in range(1, 13):
        try:
            if transport == "hid":
                devices = list(CtapHidDevice.list_devices())
            elif transport == "pcsc":
                devices = list(CtapPcscDevice.list_devices())
            else:
                raise ValueError("transport must be pcsc or hid")
            break
        except Exception as error:
            last_error = error
            if attempt >= 12:
                raise
            time.sleep(0.35 * attempt)

    if not devices:
        detail = f" Last reader error: {last_error}" if last_error else ""
        raise RuntimeError(f"No {transport.upper()} FIDO2 device found.{detail}")

    if args.device_index is None and len(devices) > 1:
        print(f"Multiple {transport.upper()} FIDO2 devices are visible:", file=sys.stderr)
        for index, device in enumerate(devices):
            print(f"  {index}: {device}", file=sys.stderr)
        raise RuntimeError("Use --device-index to choose one.")

    index = args.device_index if args.device_index is not None else 0
    if index < 0 or index >= len(devices):
        raise RuntimeError(f"--device-index={index} is out of range for {len(devices)} device(s).")
    return devices[index]


def client_for(args, device, origin):
    collector = DefaultClientDataCollector(origin=origin)
    return Fido2Client(
        device,
        collector,
        extensions=[HmacSecretExtension(True)],
        user_interaction=CliUserInteraction(pin=args.pin, pin_prompt=args.pin_prompt),
    )


def resident_key(raw):
    raw = raw.strip().lower()
    if raw == "required":
        return ResidentKeyRequirement.REQUIRED
    if raw == "preferred":
        return ResidentKeyRequirement.PREFERRED
    if raw == "discouraged":
        return ResidentKeyRequirement.DISCOURAGED
    raise ValueError("resident key must be required, preferred, or discouraged")


def user_verification(raw):
    raw = raw.strip().lower()
    if raw == "required":
        return UserVerificationRequirement.REQUIRED
    if raw == "preferred":
        return UserVerificationRequirement.PREFERRED
    if raw == "discouraged":
        return UserVerificationRequirement.DISCOURAGED
    raise ValueError("user verification must be required, preferred, or discouraged")


def profile_path(args) -> Path:
    if args.profile_path:
        return Path(args.profile_path)
    name = args.profile.replace("/", "_").replace("\\", "_")
    return DEFAULT_PROFILE_DIR / f"{name}.json"


def write_profile(path: Path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(encoded)


def read_profile(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        profile = json.load(handle)
    if profile.get("schema") != PROFILE_SCHEMA:
        raise ValueError(f"{path} is not a {PROFILE_SCHEMA} profile.")
    return profile


def salt_bytes(args, attr, hex_attr):
    hex_value = getattr(args, hex_attr)
    text_value = getattr(args, attr)
    if hex_value:
        return bytes.fromhex(hex_value)
    return text_value.encode("utf-8")


def print_json(data):
    print(json.dumps(data, indent=2, sort_keys=True))


def command_info(args):
    device = select_device(args)
    info = Ctap2(device).info
    data = {
        "device": repr(device),
        "versions": info.versions,
        "extensions": info.extensions,
        "options": info.options,
        "pin_uv_protocols": info.pin_uv_protocols,
        "min_pin_length": info.min_pin_length,
        "max_pin_length": info.max_pin_length,
        "uv_modality": info.uv_modality,
    }
    print_json(data)
    return 0


def command_enroll(args):
    path = profile_path(args)
    if path.exists() and not args.force:
        print(f"Profile already exists: {path}", file=sys.stderr)
        print("Use --force to overwrite it, or choose --profile/--profile-path.", file=sys.stderr)
        return 4

    device = select_device(args)
    info = Ctap2(device).info
    if args.registration_prf != "disabled" and "hmac-secret" not in info.extensions:
        print("Authenticator does not advertise hmac-secret.", file=sys.stderr)
        return 3

    uv = user_verification(args.user_verification)
    rk = resident_key(args.resident_key)
    extensions = registration_extensions(args.registration_prf)
    client = client_for(args, device, args.origin)
    credential = client.make_credential(
        PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(id=args.rp_id, name=args.rp_name),
            user=PublicKeyCredentialUserEntity(
                id=os.urandom(32),
                name=args.user_name,
                display_name=args.user_name,
            ),
            challenge=os.urandom(32),
            pub_key_cred_params=[
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY,
                    alg=ES256.ALGORITHM,
                )
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=rk,
                user_verification=uv,
            ),
            extensions=extensions,
        )
    )

    if args.registration_prf == "prf" and prf_enabled(credential) is not True:
        print("Credential did not report WebAuthn PRF enabled.", file=sys.stderr)
        return 5
    if (
        args.registration_prf == "hmacCreateSecret"
        and hmac_create_secret_enabled(credential) is not True
    ):
        print("Credential did not report hmacCreateSecret enabled.", file=sys.stderr)
        return 5

    cred_id = credential_id(credential)
    public_key = credential_public_key(credential)
    public_key_uncompressed = p256_uncompressed_public_key(public_key)
    public_key_spki = p256_spki_public_key(public_key)
    profile = {
        "schema": PROFILE_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "transport": args.transport,
        "rp_id": args.rp_id,
        "rp_name": args.rp_name,
        "origin": args.origin,
        "user_name": args.user_name,
        "resident_key": args.resident_key,
        "user_verification": args.user_verification,
        "registration_prf": args.registration_prf,
        "credential_id": b64u_encode(cred_id),
        "credential_id_hex": cred_id.hex(),
        "credential_public_key_uncompressed_hex": public_key_uncompressed.hex(),
        "credential_public_key_spki_b64u": b64u_encode(public_key_spki),
        "credential_public_key_spki_hex": public_key_spki.hex(),
        "note": "Not secret, but required to derive the same PRF unless the credential is discoverable and recovered separately.",
    }
    write_profile(path, profile)
    print_json(
        {
            "profile": str(path),
            "credential_id": profile["credential_id"],
            "credential_id_hex": profile["credential_id_hex"],
            "credential_public_key_spki_b64u": profile["credential_public_key_spki_b64u"],
            "credential_public_key_uncompressed_hex": profile["credential_public_key_uncompressed_hex"],
            "prf_enabled": prf_enabled(credential),
            "hmac_create_secret_enabled": hmac_create_secret_enabled(credential),
            "registration_prf": args.registration_prf,
            "status": "CARD_FIDO2_PROFILE_ENROLLED_NO_PRF"
            if args.registration_prf == "disabled"
            else "CARD_PRF_PROFILE_ENROLLED",
        }
    )
    return 0


def derive_once(args, profile, first_salt: bytes, second_salt: bytes | None):
    device = select_device(args)
    client = client_for(args, device, profile["origin"])
    prf_eval = {"first": first_salt}
    if second_salt is not None:
        prf_eval["second"] = second_salt
    request_options = PublicKeyCredentialRequestOptions(
        challenge=os.urandom(32),
        rp_id=profile["rp_id"],
        allow_credentials=[
            {
                "type": PublicKeyCredentialType.PUBLIC_KEY,
                "id": b64u_decode(profile["credential_id"]),
            }
        ],
        user_verification=user_verification(
            getattr(args, "user_verification", None) or profile.get("user_verification", "discouraged")
        ),
        extensions={"prf": {"eval": prf_eval}},
    )
    assertions = client.get_assertion(request_options)
    assertion = assertions.get_response(0)
    first, second = prf_outputs(assertion)
    if first is None or len(first) != 32:
        raise RuntimeError("Authenticator did not return a 32-byte PRF first output.")
    if second_salt is not None and (second is None or len(second) != 32):
        raise RuntimeError("Authenticator did not return a 32-byte PRF second output.")
    return first, second


def command_derive(args):
    profile = read_profile(profile_path(args))
    first_salt = salt_bytes(args, "salt", "salt_hex")
    second_salt = None
    if args.second_salt or args.second_salt_hex:
        second_salt = salt_bytes(args, "second_salt", "second_salt_hex")

    first, second = derive_once(args, profile, first_salt, second_salt)
    result = {
        "profile": str(profile_path(args)),
        "rp_id": profile["rp_id"],
        "credential_id": profile["credential_id"],
        "salt_utf8": args.salt if not args.salt_hex else None,
        "salt_hex": args.salt_hex or first_salt.hex(),
        "prf_first_hex": first.hex(),
        "prf_first_b64url": b64u_encode(first),
        "status": "CARD_PRF_DERIVE_OK",
    }
    if second is not None:
        result["prf_second_hex"] = second.hex()
        result["prf_second_b64url"] = b64u_encode(second)

    if args.raw:
        print(first.hex())
    else:
        print_json(result)
    return 0


def command_selftest(args):
    path = profile_path(args)
    if args.force or not path.exists():
        if args.force and path.exists():
            print(f"Re-enrolling profile {path} because --force was set.")
        else:
            print(f"Profile {path} does not exist; enrolling it first.")
        enroll_args = argparse.Namespace(**vars(args))
        enroll_args.force = True
        enroll_args.rp_id = args.rp_id
        enroll_args.rp_name = args.rp_name
        enroll_args.origin = args.origin
        enroll_args.user_name = args.user_name
        enroll_args.resident_key = args.resident_key
        enroll_args.user_verification = args.user_verification
        enroll_args.registration_prf = args.registration_prf
        status = command_enroll(enroll_args)
        if status != 0:
            return status

    profile = read_profile(path)
    if profile.get("registration_prf") == "disabled":
        print_json(
            {
                "profile": str(path),
                "rp_id": profile["rp_id"],
                "credential_id": profile["credential_id"],
                "registration_prf": "disabled",
                "status": "CARD_FIDO2_CREATE_NO_PRF_OK",
                "next_step": "Repeat with --registration-prf prf. If that fails, credential creation works but hmac-secret/PRF creation is blocked.",
            }
        )
        return 0

    first_salt = args.salt.encode("utf-8")
    first_a, _ = derive_once(args, profile, first_salt, None)
    first_b, _ = derive_once(args, profile, first_salt, None)
    other, _ = derive_once(args, profile, (args.salt + ":different").encode("utf-8"), None)

    stable = first_a == first_b
    separated = first_a != other
    print_json(
        {
            "profile": str(path),
            "salt": args.salt,
            "first_run_hex": first_a.hex(),
            "second_run_hex": first_b.hex(),
            "different_salt_hex": other.hex(),
            "same_salt_stable": stable,
            "different_salt_changed": separated,
            "status": "CARD_PRF_STABLE_OK" if stable and separated else "CARD_PRF_STABLE_FAILED",
        }
    )
    return 0 if stable and separated else 6


def command_webauthn_assert(args):
    """Produce a WebAuthn assertion over a server-supplied challenge.

    Used for the Arkade receive-claim approval, which requires a real UV
    assertion from the card's registered credential (not a software passkey)."""
    profile = None
    try:
        profile = read_profile(profile_path(args))
    except (FileNotFoundError, ValueError):
        profile = None
    rp_id = args.rp_id or (profile and profile.get("rp_id"))
    origin = args.origin or (profile and profile.get("origin"))
    cred_b64u = args.credential_id or (profile and profile.get("credential_id"))
    if not (rp_id and origin and cred_b64u):
        raise ValueError("need --rp-id, --origin and --credential-id (or a saved --profile)")

    challenge = b64u_decode(args.challenge_b64u)
    device = select_device(args)
    client = client_for(args, device, origin)
    request_options = PublicKeyCredentialRequestOptions(
        challenge=challenge,
        rp_id=rp_id,
        allow_credentials=[
            {"type": PublicKeyCredentialType.PUBLIC_KEY, "id": b64u_decode(cred_b64u)}
        ],
        user_verification=user_verification(args.user_verification or "required"),
    )
    assertion = client.get_assertion(request_options).get_response(0)
    resp = getattr(assertion, "response", assertion)
    client_data = bytes(getattr(resp, "client_data", None) or getattr(resp, "client_data_json"))
    auth_data = bytes(getattr(resp, "authenticator_data", None) or getattr(resp, "auth_data"))
    signature = bytes(resp.signature)
    raw_id = getattr(assertion, "raw_id", None) or getattr(assertion, "credential_id", None)
    if raw_id is None and getattr(assertion, "id", None):
        raw_id = b64u_decode(assertion.id)
    credential_id = bytes(raw_id) if raw_id else b64u_decode(cred_b64u)

    print_json(
        {
            "status": "CARD_WEBAUTHN_ASSERT_OK",
            "rp_id": rp_id,
            "origin": origin,
            "user_verification": args.user_verification or "required",
            "credential_id_b64u": b64u_encode(credential_id),
            "client_data_b64u": b64u_encode(client_data),
            "auth_data_b64u": b64u_encode(auth_data),
            "sig_b64u": b64u_encode(signature),
        }
    )
    return 0


def command_webauthn_probe(args):
    """Fast, single-shot card + PIN check for the terminal. No retry loop.
    Prints {"present": bool, "pin_ok": bool} so the UI can keep scanning until a
    card with the right PIN appears. Never raises — all outcomes are JSON."""
    profile = None
    try:
        profile = read_profile(profile_path(args))
    except (FileNotFoundError, ValueError):
        profile = None
    rp_id = args.rp_id or (profile and profile.get("rp_id"))
    origin = args.origin or (profile and profile.get("origin"))
    cred_b64u = args.credential_id or (profile and profile.get("credential_id"))
    if not (rp_id and origin and cred_b64u):
        print_json({"present": False, "error": "profile incomplete"})
        return 0

    # Single-shot device enumeration — no waiting/retry (the browser polls us).
    try:
        devices = list(CtapPcscDevice.list_devices())
    except Exception as error:  # reader/PCSC hiccup counts as "no card yet"
        print_json({"present": False, "error": str(error)})
        return 0
    if not devices:
        print_json({"present": False})
        return 0
    index = args.device_index if args.device_index is not None else 0
    if index < 0 or index >= len(devices):
        print_json({"present": False})
        return 0

    def pin_related(err) -> bool:
        text = f"{getattr(err, 'code', '')} {err}".upper()
        return any(k in text for k in ("PIN", "0X31", "UNAUTH", "UV_", "0X36", "0X37"))

    try:
        client = client_for(args, devices[index], origin)
        request_options = PublicKeyCredentialRequestOptions(
            challenge=b64u_decode(args.challenge_b64u),
            rp_id=rp_id,
            allow_credentials=[
                {"type": PublicKeyCredentialType.PUBLIC_KEY, "id": b64u_decode(cred_b64u)}
            ],
            user_verification=user_verification("required"),
        )
        client.get_assertion(request_options).get_response(0)
        print_json({"present": True, "pin_ok": True})
    except CtapError as error:
        print_json({"present": True, "pin_ok": not pin_related(error), "reason": str(error)})
    except ClientError as error:
        ctap = next((item for item in error.args if isinstance(item, CtapError)), None)
        if ctap is not None:
            print_json({"present": True, "pin_ok": not pin_related(ctap), "reason": str(ctap)})
        else:
            print_json({"present": True, "pin_ok": False, "reason": str(error)})
    except CardConnectionException as error:
        print_json({"present": False, "error": str(error)})
    except Exception as error:
        print_json({"present": False, "error": str(error)})
    return 0


def add_device_args(parser):
    parser.add_argument("--transport", choices=["pcsc", "hid"], default=os.environ.get("FIDO2_BACKUP_TRANSPORT", "pcsc"))
    parser.add_argument("--device-index", type=int, default=None)
    parser.add_argument("--pin", default=None, help="Development only. Prefer --pin-prompt or FIDO2_BACKUP_PIN_PROMPT=YES.")
    parser.add_argument("--pin-prompt", action="store_true", help="Prompt for a FIDO2 PIN if the authenticator asks for one.")


def add_profile_args(parser):
    parser.add_argument("--profile", default="default")
    parser.add_argument("--profile-path", default=None)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Enroll and derive stable WebAuthn PRF outputs from a real FIDO2 card."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    info = subparsers.add_parser("info", help="Show CTAP getInfo for the selected device.")
    add_device_args(info)
    info.set_defaults(func=command_info)

    enroll = subparsers.add_parser("enroll", help="Create one PRF-enabled credential and save its profile.")
    add_device_args(enroll)
    add_profile_args(enroll)
    enroll.add_argument("--rp-id", default="nuri.local")
    enroll.add_argument("--origin", default="https://nuri.local")
    enroll.add_argument("--rp-name", default="Nuri Offline Backup")
    enroll.add_argument("--user-name", default="nuri-offline-backup")
    enroll.add_argument("--resident-key", choices=["required", "preferred", "discouraged"], default="required")
    enroll.add_argument("--user-verification", choices=["required", "preferred", "discouraged"], default="discouraged")
    enroll.add_argument("--registration-prf", choices=["prf", "hmacCreateSecret", "disabled"], default="prf")
    enroll.add_argument("--force", action="store_true")
    enroll.set_defaults(func=command_enroll)

    derive = subparsers.add_parser("derive", help="Derive a stable 32-byte PRF output from a saved profile.")
    add_device_args(derive)
    add_profile_args(derive)
    derive.add_argument("--salt", default=DEFAULT_SALT)
    derive.add_argument("--salt-hex", default=None)
    derive.add_argument("--second-salt", default=None)
    derive.add_argument("--second-salt-hex", default=None)
    derive.add_argument("--user-verification", choices=["required", "preferred", "discouraged"], default=None)
    derive.add_argument("--raw", action="store_true", help="Print only prf_first_hex.")
    derive.set_defaults(func=command_derive)

    selftest = subparsers.add_parser("selftest", help="Enroll if needed, then prove same salt -> same PRF.")
    add_device_args(selftest)
    add_profile_args(selftest)
    selftest.add_argument("--salt", default=DEFAULT_SALT)
    selftest.add_argument("--rp-id", default="nuri.local")
    selftest.add_argument("--origin", default="https://nuri.local")
    selftest.add_argument("--rp-name", default="Nuri Offline Backup")
    selftest.add_argument("--user-name", default="nuri-offline-backup")
    selftest.add_argument("--resident-key", choices=["required", "preferred", "discouraged"], default="required")
    selftest.add_argument("--user-verification", choices=["required", "preferred", "discouraged"], default="discouraged")
    selftest.add_argument("--registration-prf", choices=["prf", "hmacCreateSecret", "disabled"], default="prf")
    selftest.add_argument("--force", action="store_true")
    selftest.set_defaults(func=command_selftest)

    wassert = subparsers.add_parser(
        "webauthn-assert",
        help="Produce a WebAuthn assertion over a server challenge (Arkade receive-claim approval).",
    )
    add_device_args(wassert)
    add_profile_args(wassert)
    wassert.add_argument("--challenge-b64u", required=True)
    wassert.add_argument("--rp-id", default=None)
    wassert.add_argument("--origin", default=None)
    wassert.add_argument("--credential-id", default=None)
    wassert.add_argument(
        "--user-verification", choices=["required", "preferred", "discouraged"], default="required"
    )
    wassert.set_defaults(func=command_webauthn_assert)

    wprobe = subparsers.add_parser(
        "webauthn-probe",
        help="Fast single-shot card+PIN presence check for the terminal (JSON, never raises).",
    )
    add_device_args(wprobe)
    add_profile_args(wprobe)
    wprobe.add_argument("--challenge-b64u", default="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    wprobe.add_argument("--rp-id", default=None)
    wprobe.add_argument("--origin", default=None)
    wprobe.add_argument("--credential-id", default=None)
    wprobe.set_defaults(func=command_webauthn_probe)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except CtapError as error:
        print(f"CTAP error: {describe_ctap_error(error)}", file=sys.stderr)
        return 7
    except ClientError as error:
        ctap_error = next((item for item in error.args if isinstance(item, CtapError)), None)
        if ctap_error:
            print(f"FIDO2 client error from authenticator: {describe_ctap_error(ctap_error)}", file=sys.stderr)
            if "OPERATION_DENIED" in describe_ctap_error(ctap_error):
                print(
                    "The authenticator refused makeCredential. Test --registration-prf disabled to separate base credential creation from PRF/hmac-secret creation.",
                    file=sys.stderr,
                )
        else:
            print(f"FIDO2 client error: {error}", file=sys.stderr)
        return 9
    except CardConnectionException as error:
        print(f"PC/SC card connection error: {error}", file=sys.stderr)
        print("If another command was using the same reader, wait a second and retry.", file=sys.stderr)
        return 8
    except EstablishContextException as error:
        print(f"PC/SC service error: {error}", file=sys.stderr)
        print("macOS PC/SC service is not accepting a context. Unplug/replug the reader or wait a few seconds and retry.", file=sys.stderr)
        return 8
    except (RuntimeError, ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
