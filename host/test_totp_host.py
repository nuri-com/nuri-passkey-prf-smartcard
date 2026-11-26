#!/usr/bin/env python3
"""Tests for host/totp_commands.py and host/nuri_card_host.py TOTP methods.

Covers Base32 / otpauth URI parsing, RFC 6238 sim vectors, v1.0 & v1.1 card APDUs,
PIN error mapping, and error-path redaction. Never touches a physical reader.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nuri_card_host as host  # noqa: E402
import totp_commands as tc  # noqa: E402


class FakeApplet:
    def __init__(self, version: str = "1.1", pin: bytes = b"1234", secret: bytes | None = None):
        self.version = version
        self.pin = pin
        self.secret = secret
        self.tries = 5
        self.closed = False
        self.apdus: list[bytes] = []

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        raw = bytes(apdu)
        self.apdus.append(raw)
        ins = raw[1]
        if ins == tc.INS_STATUS:
            if self.version == "1.0":
                return b"", 0x6D00
            return bytes([1 if self.secret is not None else 0, 0, self.tries]), 0x9000
        if ins == tc.INS_PUT:
            lc = raw[4]
            data = raw[5:5 + lc]
            if self.version == "1.0":
                self.secret = data
                return b"", 0x9000
            if self.tries == 0:
                return b"", 0x6983
            plen = data[0]
            pin = data[1:1 + plen]
            secret = data[1 + plen:]
            if self.pin and pin != self.pin:
                self.tries -= 1
                return b"", 0x6983 if self.tries == 0 else (0x63C0 | self.tries)
            self.tries = 5
            self.pin = pin
            self.secret = secret
            return b"", 0x9000
        if ins == tc.INS_CALC:
            if self.secret is None:
                return b"", 0x6985
            ctr = raw[5:13]
            return hmac.new(self.secret, ctr, hashlib.sha1).digest(), 0x9000
        return b"", 0x6D00

    def close(self) -> None:
        self.closed = True


class TotpCommandsTests(unittest.TestCase):
    def setUp(self):
        self._old_sim = os.environ.get("NURI_CARD_SIM")
        tc._SIM_SECRET = None

    def tearDown(self):
        tc._SIM_SECRET = None
        if self._old_sim is None:
            os.environ.pop("NURI_CARD_SIM", None)
        else:
            os.environ["NURI_CARD_SIM"] = self._old_sim

    def test_parse_secret_base32_and_otpauth(self):
        self.assertEqual(tc.parse_secret("JBSW Y3DP EHPK 3PXP"), b"Hello!\xde\xad\xbe\xef")
        uri = "otpauth://totp/Hetzner:user@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Hetzner"
        self.assertEqual(tc.parse_secret(uri), b"12345678901234567890")
        with self.assertRaises(host.HostError):
            tc.parse_secret("not*base32")
        with self.assertRaises(host.HostError):
            tc.parse_secret("otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP")

    def test_sim_mode_put_and_rfc6238_vector(self):
        os.environ["NURI_CARD_SIM"] = "1"
        r1 = host.handle({"id": 1, "method": "totp_status"})
        self.assertTrue(r1["ok"])
        self.assertFalse(r1["result"]["provisioned"])
        # RFC 6238 secret "12345678901234567890" -> Base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        r2 = host.handle({"id": 2, "method": "totp_put", "params": {"secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}})
        self.assertTrue(r2["ok"])
        self.assertEqual(r2["result"]["version"], "sim")
        with patch.object(tc.time, "time", return_value=59.0):
            res = tc.handle_code({"digits": 8})
            self.assertEqual(res["code"], "94287082")
            self.assertEqual(res["remaining"], 1)

    def test_card_v10_raw_put_and_calc(self):
        os.environ.pop("NURI_CARD_SIM", None)
        fake = FakeApplet(version="1.0")
        with patch.object(tc, "_open_applet", return_value=fake):
            st = host.handle({"id": 1, "method": "totp_status"})
            self.assertEqual(st["result"]["version"], "1.0")
            self.assertFalse(st["result"]["pin_required"])

            missing = host.handle({"id": 2, "method": "totp_code"})
            self.assertFalse(missing["ok"])
            self.assertEqual(missing["error"]["code"], "NOT_PROVISIONED")

            saved = host.handle({"id": 3, "method": "totp_put", "params": {"secret": "JBSWY3DPEHPK3PXP"}})
            self.assertTrue(saved["ok"])
            self.assertEqual(fake.secret, b"Hello!\xde\xad\xbe\xef")

            code = host.handle({"id": 4, "method": "totp_code"})
            self.assertTrue(code["ok"])
            self.assertRegex(code["result"]["code"], r"^\d{6}$")
        self.assertTrue(fake.closed)

    def test_card_v11_pin_gates_and_redacts_errors(self):
        os.environ.pop("NURI_CARD_SIM", None)
        fake = FakeApplet(version="1.1", pin=b"2468")
        with patch.object(tc, "_open_applet", return_value=fake):
            no_pin = host.handle({"id": 1, "method": "totp_put", "params": {"secret": "JBSWY3DPEHPK3PXP"}})
            self.assertEqual(no_pin["error"]["code"], "PIN_REQUIRED")

            wrong = host.handle({"id": 2, "method": "totp_put", "params": {"secret": "JBSWY3DPEHPK3PXP", "pin": "0000"}})
            self.assertEqual(wrong["error"]["code"], "WRONG_PIN")
            self.assertEqual(wrong["error"]["tries_left"], 4)

            ok = host.handle({"id": 3, "method": "totp_put", "params": {"secret": "JBSWY3DPEHPK3PXP", "pin": "2468"}})
            self.assertTrue(ok["ok"])

        class LeakyError(RuntimeError):
            pass

        with patch.object(tc, "handle_put", side_effect=LeakyError("SECRET_LEAK_XYZ PIN_9999")):
            redacted = host.handle({"id": 4, "method": "totp_put", "params": {"secret": "JBSWY3DPEHPK3PXP", "pin": "2468"}})
            self.assertFalse(redacted["ok"])
            self.assertNotIn("SECRET_LEAK_XYZ", redacted["error"]["message"])
            self.assertNotIn("PIN_9999", redacted["error"]["message"])


if __name__ == "__main__":
    unittest.main()
