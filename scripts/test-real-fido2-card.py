#!/usr/bin/env python3
import base64
import getpass
import hashlib
import os
import sys

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.cose import ES256
from fido2.ctap2 import Ctap2
from fido2.ctap2.extensions import HmacSecretExtension
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


class CliUserInteraction(UserInteraction):
    def __init__(self):
        self.pin = os.environ.get("FIDO2_TEST_PIN")
        self.prompt_pin = os.environ.get("FIDO2_TEST_PIN_PROMPT") == "YES"

    def prompt_up(self) -> None:
        print("User presence requested by authenticator.")

    def request_pin(self, permissions, rp_id):
        if self.pin is None and self.prompt_pin:
            self.pin = getpass.getpass("FIDO2 PIN for real-card PRF test: ")
        return self.pin

    def request_uv(self, permissions, rp_id) -> bool:
        return True


def output_bytes(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        padded = value + ("=" * ((4 - len(value) % 4) % 4))
        return base64.urlsafe_b64decode(padded)
    return bytes(value)


def ext_value(results, key):
    if hasattr(results, "get"):
        return results.get(key)
    return getattr(results, key, None)


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


def extension_results(value):
    return getattr(value, "client_extension_results", getattr(value, "extension_results", {}))


def credential_response(value):
    return getattr(value, "response", value)


def credential_id(value):
    response = credential_response(value)
    if hasattr(response, "attestation_object"):
        return response.attestation_object.auth_data.credential_data.credential_id
    return response.auth_data.credential_data.credential_id


def prf_enabled(value):
    prf = ext_value(extension_results(value), "prf")
    return ext_value(prf, "enabled") if prf else None


def user_verification_requirement():
    raw = os.environ.get("FIDO2_TEST_UV", "discouraged").strip().lower()
    if raw == "required":
        return UserVerificationRequirement.REQUIRED
    if raw == "preferred":
        return UserVerificationRequirement.PREFERRED
    if raw == "discouraged":
        return UserVerificationRequirement.DISCOURAGED
    raise ValueError("FIDO2_TEST_UV must be discouraged, preferred, or required")


def main():
    devices = list(CtapPcscDevice.list_devices())
    if not devices:
        print("No PC/SC FIDO2 smartcard device found.", file=sys.stderr)
        print("Check reader/card insertion and make sure the FIDO2 applet is installed.", file=sys.stderr)
        return 2

    index = int(os.environ.get("FIDO2_PCSC_INDEX", "0"))
    device = devices[index]
    print(f"Using PC/SC device: {device}")

    info = Ctap2(device).info
    print(f"versions: {info.versions}")
    print(f"extensions: {info.extensions}")
    print(f"options: {info.options}")
    if "hmac-secret" not in info.extensions:
        print("Card does not advertise hmac-secret.", file=sys.stderr)
        return 3

    rp_id = os.environ.get("FIDO2_RP_ID", "example.com")
    origin = os.environ.get("FIDO2_ORIGIN", f"https://{rp_id}")
    collector = DefaultClientDataCollector(origin=origin)
    user_verification = user_verification_requirement()
    print(f"user_verification={user_verification.value}")
    client = Fido2Client(
        device,
        collector,
        extensions=[HmacSecretExtension(True)],
        user_interaction=CliUserInteraction(),
    )

    challenge = os.urandom(32)
    user_id = os.urandom(32)
    create_options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(id=rp_id, name="Nuri Real Card Test"),
        user=PublicKeyCredentialUserEntity(id=user_id, name="nuri-real-card"),
        challenge=challenge,
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                alg=ES256.ALGORITHM,
            )
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=user_verification,
        ),
        extensions={"prf": {}},
    )
    credential = client.make_credential(create_options)
    if prf_enabled(credential) is not True:
        print("Credential did not report PRF enabled.", file=sys.stderr)
        return 4

    request_options = PublicKeyCredentialRequestOptions(
        challenge=os.urandom(32),
        rp_id=rp_id,
        allow_credentials=[
            {
                "type": PublicKeyCredentialType.PUBLIC_KEY,
                "id": credential_id(credential),
            }
        ],
        user_verification=user_verification,
        extensions={
            "prf": {
                "eval": {
                    "first": b"nuri browser prf first input",
                    "second": b"nuri browser prf second input",
                }
            }
        },
    )
    assertions = client.get_assertion(request_options)
    assertion = assertions.get_response(0)
    output1, output2 = prf_outputs(assertion)

    if output1 is None or output2 is None or len(output1) != 32 or len(output2) != 32:
        print("Unexpected PRF output length.", file=sys.stderr)
        return 5

    print(f"credential_id={credential_id(credential).hex()}")
    print(f"prf_first={output1.hex()}")
    print(f"prf_second={output2.hex()}")
    print("REAL_CARD_WEBAUTHN_PRF_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
