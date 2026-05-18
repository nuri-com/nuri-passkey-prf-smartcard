#!/usr/bin/env python3
import base64
import hashlib
import os
import sys
import unittest


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIDO2_BASELINE = os.environ.get(
    "FIDO2_BASELINE",
    os.path.join(ROOT, "vendor", "FIDO2Applet-clean"),
)
if FIDO2_BASELINE not in sys.path:
    sys.path.insert(0, FIDO2_BASELINE)

from fido2.ctap2.extensions import HmacSecretExtension
from fido2.webauthn import ResidentKeyRequirement

from python_tests.ctap.ctap_test import CTAPTestCase


def webauthn_prf_salt(value: bytes) -> bytes:
    return hashlib.sha256(b"WebAuthn PRF\x00" + value).digest()


def client_extensions(value):
    return getattr(value, "client_extension_results", getattr(value, "extension_results", {}))


def extension_value(extensions, key):
    if hasattr(extensions, "get"):
        return extensions.get(key)
    return getattr(extensions, key, None)


def hmac_outputs(assertion):
    hmac = extension_value(client_extensions(assertion), "hmacGetSecret")
    if isinstance(hmac, dict):
        return output_bytes(hmac["output1"]), output_bytes(hmac.get("output2"))
    return output_bytes(hmac.output1), output_bytes(getattr(hmac, "output2", None))


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


def credential_public_key(credential):
    response = getattr(credential, "response", credential)
    attestation_object = getattr(response, "attestation_object", None)
    if attestation_object is not None:
        return attestation_object.auth_data.credential_data.public_key
    return response.auth_data.credential_data.public_key


def assertion_fields(assertion):
    response = getattr(assertion, "response", assertion)
    return (
        getattr(response, "authenticator_data"),
        getattr(response, "signature"),
        getattr(response, "client_data"),
    )


class BrowserPrfMappingE2ETest(CTAPTestCase):
    def _assertion_prf(self, client, cred, first: bytes, second: bytes | None = None):
        hmac_get_secret = {"salt1": webauthn_prf_salt(first)}
        if second is not None:
            hmac_get_secret["salt2"] = webauthn_prf_salt(second)

        opts = self.get_high_level_assertion_opts_from_cred(
            None,
            rp_id=self.rp_id,
            client_data=self.get_random_client_data(),
            extensions={"hmacGetSecret": hmac_get_secret},
        )
        assertions = client.get_assertion(options=opts)
        self.assertEqual(1, len(assertions.get_assertions()))
        response = assertions.get_response(0)

        auth_data, signature, client_data = assertion_fields(response)
        pubkey = credential_public_key(cred)
        pubkey.verify(auth_data + client_data.hash, signature)

        output1, output2 = hmac_outputs(response)
        out = {"first": output1}
        if second is not None:
            out["second"] = output2
        return out

    def test_discoverable_passkey_auth_and_browser_prf_mapping(self):
        client = self.get_high_level_client(extensions=[HmacSecretExtension(True)])

        cred = client.make_credential(
            options=self.get_high_level_make_cred_options(
                resident_key=ResidentKeyRequirement.REQUIRED,
                extensions={"hmacCreateSecret": True},
            )
        )
        self.assertTrue(extension_value(client_extensions(cred), "hmacCreateSecret"))

        first = b"nuri browser prf first input"
        second = b"nuri browser prf second input"
        changed = b"nuri browser prf changed input"

        prf_a = self._assertion_prf(client, cred, first, second)
        prf_b = self._assertion_prf(client, cred, first, second)
        prf_c = self._assertion_prf(client, cred, changed, second)

        self.assertEqual(32, len(prf_a["first"]))
        self.assertEqual(32, len(prf_a["second"]))
        self.assertEqual(prf_a, prf_b)
        self.assertNotEqual(prf_a["first"], prf_c["first"])
        self.assertEqual(prf_a["second"], prf_c["second"])


if __name__ == "__main__":
    unittest.main()
