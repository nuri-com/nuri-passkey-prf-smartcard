#!/usr/bin/env python3
"""Tests for host/webauthn_bridge.py with a real python-fido2 client over a
software CTAP2 authenticator. No reader, card or network.

Run: <venv with fido2>=2.2>/bin/python host/test_webauthn_bridge.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import webauthn_bridge as wb  # noqa: E402
import nuri_card_host as host  # noqa: E402

from fido2.utils import websafe_decode, websafe_encode  # noqa: E402

ORIGIN = "https://connect.nuri.com"
CHALLENGE = websafe_encode(b"c" * 32)


def create_options(**patch):
    o = {
        "rp": {"id": "nuri.com", "name": "Nuri Wallet"},
        "user": {"id": websafe_encode(b"u" * 16), "name": "emin", "displayName": "emin"},
        "challenge": CHALLENGE,
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"},
        "attestation": "none",
        "extensions": {"prf": {}},
    }
    o.update(patch)
    return o


def get_options(cred_id=None, salt=b"nuri-prf-salt-v1", **patch):
    o = {"challenge": CHALLENGE, "rpId": "nuri.com", "userVerification": "required"}
    if cred_id:
        o["allowCredentials"] = [{"type": "public-key", "id": cred_id}]
    if salt is not None:
        o["extensions"] = {"prf": {"eval": {"first": websafe_encode(salt)}}}
    o.update(patch)
    return o


class GateTests(unittest.TestCase):
    def test_rejects_foreign_origin_before_touching_card(self):
        for origin in ("https://app.nuri.com", "https://evil.test", None, "https://connect.nuri.com.evil.test"):
            with self.assertRaises(wb.BridgeError) as cm:
                wb.webauthn_get({"origin": origin, "publicKey": get_options()}, None,
                                open_device=lambda: self.fail("card opened"))
            self.assertEqual(cm.exception.code, "ORIGIN_NOT_ALLOWED")

    def test_rejects_other_rp(self):
        with self.assertRaises(wb.BridgeError) as cm:
            wb.webauthn_create({"origin": ORIGIN, "publicKey": create_options(rp={"id": "evil.test", "name": "x"})}, None,
                               open_device=lambda: self.fail("card opened"))
        self.assertEqual(cm.exception.code, "RP_NOT_ALLOWED")
        with self.assertRaises(wb.BridgeError) as cm:
            wb.webauthn_get({"origin": ORIGIN, "publicKey": get_options(rpId="evil.test")}, None,
                            open_device=lambda: self.fail("card opened"))
        self.assertEqual(cm.exception.code, "RP_NOT_ALLOWED")

    def test_bad_shapes(self):
        for params in (None, [], {"origin": ORIGIN}, {"origin": ORIGIN, "publicKey": "x"}):
            with self.assertRaises(wb.BridgeError) as cm:
                wb.webauthn_get(params, None, open_device=lambda: self.fail("card opened"))
            self.assertIn(cm.exception.code, ("BAD_REQUEST", "ORIGIN_NOT_ALLOWED"))


class SoftAuthenticatorTests(unittest.TestCase):
    """End to end through the real Fido2Client against an in-memory CTAP2 card."""

    def setUp(self):
        from soft_ctap2 import SoftCtap2Device
        self.dev = SoftCtap2Device(pin="2468")

    def call(self, kind, options, pin: str | None = "2468"):
        return (wb.webauthn_create if kind == "create" else wb.webauthn_get)(
            {"origin": ORIGIN, "publicKey": options},
            bytearray(pin.encode()) if pin else None,
            open_device=lambda: self.dev,
        )

    def test_create_then_prf_get_matches_chrome_prf_salt(self):
        reg = self.call("create", create_options())
        self.assertEqual(reg["type"], "public-key")
        self.assertEqual(reg["authenticatorAttachment"], "cross-platform")
        self.assertEqual(reg["clientExtensionResults"]["prf"]["enabled"], True)
        cd = json.loads(websafe_decode(reg["response"]["clientDataJSON"]))
        self.assertEqual((cd["type"], cd["origin"], cd["challenge"]), ("webauthn.create", ORIGIN, CHALLENGE))
        cred_id = reg["id"]

        auth = self.call("get", get_options(cred_id))
        self.assertEqual(auth["id"], cred_id)
        cd = json.loads(websafe_decode(auth["response"]["clientDataJSON"]))
        self.assertEqual((cd["type"], cd["origin"]), ("webauthn.get", ORIGIN))
        prf = websafe_decode(auth["clientExtensionResults"]["prf"]["results"]["first"])
        # WebAuthn PRF: salt = SHA-256("WebAuthn PRF" || 0x00 || input); output = HMAC(credRandom, salt)
        salt = hashlib.sha256(b"WebAuthn PRF\x00" + b"nuri-prf-salt-v1").digest()
        self.assertEqual(prf, self.dev.expected_hmac(websafe_decode(cred_id), salt))
        again = self.call("get", get_options(cred_id))
        self.assertEqual(again["clientExtensionResults"], auth["clientExtensionResults"])
        auth_data = websafe_decode(auth["response"]["authenticatorData"])
        self.assertEqual(auth_data[:32], hashlib.sha256(b"nuri.com").digest())
        self.assertTrue(auth_data[32] & 0x04, "UV flag")

    def test_wrong_pin_reports_tries(self):
        reg = self.call("create", create_options())
        with self.assertRaises(wb.BridgeError) as cm:
            self.call("get", get_options(reg["id"]), pin="0000")
        self.assertEqual(cm.exception.code, "PIN_WRONG")
        self.assertEqual(cm.exception.extra["tries_left"], 7)

    def test_missing_pin(self):
        with self.assertRaises(wb.BridgeError) as cm:
            self.call("create", create_options(), pin=None)
        self.assertEqual(cm.exception.code, "PIN_REQUIRED")

    def test_unknown_credential(self):
        with self.assertRaises(wb.BridgeError) as cm:
            self.call("get", get_options(websafe_encode(b"x" * 32)))
        self.assertEqual(cm.exception.code, "NO_CREDENTIAL")


class HostDispatchTests(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.pop("NURI_CARD_SIM", None)

    def tearDown(self):
        if self._env is not None:
            os.environ["NURI_CARD_SIM"] = self._env

    def test_sim_mode_refused(self):
        os.environ["NURI_CARD_SIM"] = "1"
        resp = host.handle({"id": 1, "method": "webauthn_get", "params": {"origin": ORIGIN, "publicKey": get_options()}})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "CONFIG_ERROR")

    def test_origin_gate_through_host_and_pin_never_echoed(self):
        req = {"id": 2, "method": "webauthn_get", "params": {"origin": "https://app.nuri.com", "publicKey": get_options(), "pin": "2468"}}
        resp = host.handle(req)
        self.assertEqual(resp["error"]["code"], "ORIGIN_NOT_ALLOWED")
        self.assertNotIn("2468", json.dumps(resp))
        self.assertNotIn("pin", req["params"])

    def test_bad_pin_shape(self):
        resp = host.handle({"id": 3, "method": "webauthn_create", "params": {"origin": ORIGIN, "publicKey": create_options(), "pin": "12"}})
        self.assertEqual(resp["error"]["code"], "BAD_REQUEST")


if __name__ == "__main__":
    unittest.main(verbosity=2)
