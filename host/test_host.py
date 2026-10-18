#!/usr/bin/env python3
"""Tests for host/nuri_card_host.py: framing + sim signing round-trip.

Run:  NURI_CARD_SIM=1 <venv>/bin/python host/test_host.py
Sim only. Never touches a reader or a card.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["NURI_CARD_SIM"] = "1"

import nuri_card_host as host  # noqa: E402

SIM_PUBKEY = "0x03bcd83232b6276e8856605cfd877f7795536a5099555684422fe82f2b6adb95e2"
CARD_PUBKEY = "031f0f76cf2da4d2c679130f1accfb1e3b149c20ea15291a49b643e350cc63c4b1"
CARD_ADDRESS = "0x77bab29aa61949f03f233118ebc0a263f61cc385"


def frame(obj) -> bytes:
    body = json.dumps(obj).encode()
    return struct.pack("<I", len(body)) + body


def unframe_all(data: bytes) -> list:
    out = []
    pos = 0
    while pos + 4 <= len(data):
        (n,) = struct.unpack("<I", data[pos:pos + 4])
        out.append(json.loads(data[pos + 4:pos + 4 + n]))
        pos += 4 + n
    return out


def recover_address(digest: bytes, r: int, s: int, y_parity: int) -> str:
    """Independent ecrecover (not via the host's recovery helper)."""
    from ecdsa import SECP256k1, VerifyingKey
    from ecdsa.ellipticcurve import PointJacobi
    from ecdsa.numbertheory import square_root_mod_prime, inverse_mod
    curve = SECP256k1.curve
    G = SECP256k1.generator
    n = SECP256k1.order
    p = curve.p()
    alpha = (pow(r, 3, p) + curve.a() * r + curve.b()) % p
    beta = square_root_mod_prime(alpha, p)
    y = beta if (beta % 2) == y_parity else p - beta
    R = PointJacobi(curve, r, y, 1, n)
    e = int.from_bytes(digest, "big")
    rinv = inverse_mod(r, n)
    Q = (R * s + G * (-e % n)) * rinv
    vk = VerifyingKey.from_public_point(Q, curve=SECP256k1)
    return host.pubkey_to_address(vk.to_string("compressed"))


class AddressTests(unittest.TestCase):
    def test_card_pubkey_to_address_matches_known_card(self):
        addr = host.pubkey_to_address(bytes.fromhex(CARD_PUBKEY))
        self.assertEqual(addr.lower(), CARD_ADDRESS)
        self.assertNotEqual(addr, CARD_ADDRESS, "expected EIP-55 mixed case")

    def test_keccak_known_vector(self):
        self.assertEqual(host.keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")


class SimSignTests(unittest.TestCase):
    def setUp(self):
        host._SIGNER = None

    def test_info(self):
        resp = host.handle({"id": 1, "method": "info"})
        self.assertTrue(resp["ok"], resp)
        res = resp["result"]
        self.assertEqual(res["mode"], "sim")
        self.assertEqual(res["applet"], "eth1")
        self.assertEqual(res["pubkey"], SIM_PUBKEY)
        self.assertTrue(res["address"].startswith("0x") and len(res["address"]) == 42)
        self.assertEqual(res["address"], host.pubkey_to_address(bytes.fromhex(SIM_PUBKEY[2:])))

    def test_sign_hash_round_trip_recovers_sim_address(self):
        info = host.handle({"id": 1, "method": "info"})["result"]
        for i in range(8):
            digest = hashlib.sha256(f"nuri test vector {i}".encode()).digest()
            resp = host.handle({"id": 2 + i, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})
            self.assertTrue(resp["ok"], resp)
            res = resp["result"]
            r = int(res["r"], 16)
            s = int(res["s"], 16)
            self.assertLessEqual(s, host.curve_order() // 2, "s must be low-s")
            self.assertIn(res["yParity"], (0, 1))
            self.assertEqual(len(res["signature"]), 2 + 130)
            self.assertEqual(res["signature"][-2:], "1b" if res["yParity"] == 0 else "1c")
            self.assertEqual(res["signature"][2:66], res["r"][2:])
            self.assertEqual(res["signature"][66:130], res["s"][2:])
            self.assertEqual(recover_address(digest, r, s, res["yParity"]), info["address"])
            # the other parity must NOT recover the sim address
            self.assertNotEqual(recover_address(digest, r, s, 1 - res["yParity"]), info["address"])

    def test_bad_requests(self):
        self.assertEqual(host.handle({"id": 1, "method": "nope"})["error"]["code"], "BAD_REQUEST")
        self.assertEqual(host.handle({"id": 1, "method": "sign_hash", "params": {"hash": "0x1234"}})["error"]["code"], "BAD_REQUEST")
        self.assertEqual(host.handle({"id": 1, "method": "sign_hash", "params": {"hash": "zz" * 32}})["error"]["code"], "BAD_REQUEST")
        self.assertEqual(host.handle({"id": 1, "method": "sign_hash"})["error"]["code"], "BAD_REQUEST")
        self.assertEqual(host.handle([1, 2])["error"]["code"], "BAD_REQUEST")

    def test_verify_failed_on_tampered_signer(self):
        class Bad(host.SimSigner):
            def sign_digest(self, digest):
                r, s = super().sign_digest(digest)
                return r, (s + 1) % host.curve_order()
        host._SIGNER = Bad()
        resp = host.handle({"id": 9, "method": "sign_hash", "params": {"hash": "0x" + "11" * 32}})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "VERIFY_FAILED")

    def test_high_s_from_signer_is_normalized(self):
        class HighS(host.SimSigner):
            def sign_digest(self, digest):
                r, s = super().sign_digest(digest)
                return r, host.curve_order() - s  # same signature, high-s form
        host._SIGNER = HighS()
        digest = b"\x42" * 32
        resp = host.handle({"id": 9, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})
        self.assertTrue(resp["ok"], resp)
        self.assertLessEqual(int(resp["result"]["s"], 16), host.curve_order() // 2)
        self.assertEqual(recover_address(digest, int(resp["result"]["r"], 16), int(resp["result"]["s"], 16),
                                         resp["result"]["yParity"]),
                         host.handle({"id": 1, "method": "info"})["result"]["address"])


class FakePcscCardTests(unittest.TestCase):
    """Card mode against a fake nuri_pcsc module (C1 shape). No reader, no card."""

    def _install_fake(self, applets: set, sim_key):
        import types
        from ecdsa.util import sigencode_string, sigencode_der
        calls = []

        class CardError(Exception):
            def __init__(self, code, msg=""):
                super().__init__(msg or code)
                self.code = code

        class Applet:
            def __init__(self, aid):
                self.aid = aid
                self.reader_name = "Fake Reader 00 00"
                self.protocol = "T0"
                self.closed = False

            def transmit(self, apdu):
                calls.append(bytes(apdu).hex())
                ins = apdu[1]
                if ins == 0x01:
                    return (b"\x01\x03\x01ETH1" if self.aid == host.AID_ETH_V1 else b"\x02\x00\x00ETH2"), 0x9000
                if ins == 0x02:
                    vk = sim_key.get_verifying_key()
                    return (vk.to_string("compressed") if self.aid == host.AID_ETH_V1 else vk.to_string("uncompressed")), 0x9000
                if ins == 0x04:
                    digest = bytes(apdu[5:37])
                    if self.aid == host.AID_ETH_V1:
                        sig = sim_key.sign_digest_deterministic(digest, sigencode=sigencode_string)
                        return sig + b"\x00", 0x9000  # v byte is deliberately wrong; host must recover it
                    return sim_key.sign_digest_deterministic(digest, sigencode=sigencode_der), 0x9000
                return b"", 0x6D00

            def close(self):
                self.closed = True

        def open_applet(aid_hex, reader=None):
            if aid_hex not in applets:
                raise CardError("NO_APPLET", f"SELECT {aid_hex} failed")
            return Applet(aid_hex)

        mod = types.ModuleType("nuri_pcsc")
        mod.CardError = CardError
        mod.Applet = Applet
        mod.open_applet = open_applet
        sys.modules["nuri_pcsc"] = mod
        return calls

    def setUp(self):
        from ecdsa import SigningKey, SECP256k1
        self.key = SigningKey.from_secret_exponent(0x1234567, curve=SECP256k1)
        self.saved_env = os.environ.pop("NURI_CARD_SIM", None)
        host._SIGNER = None

    def tearDown(self):
        sys.modules.pop("nuri_pcsc", None)
        host._SIGNER = None
        if self.saved_env is not None:
            os.environ["NURI_CARD_SIM"] = self.saved_env

    def test_eth1_fallback_signs_and_recovers(self):
        calls = self._install_fake({host.AID_ETH_V1}, self.key)
        info = host.handle({"id": 1, "method": "info"})
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["result"]["applet"], "eth1")
        self.assertEqual(info["result"]["applet_version"], "1.3.1")
        self.assertEqual(info["result"]["mode"], "card")
        self.assertEqual(info["result"]["reader"], "Fake Reader 00 00")
        self.assertEqual(info["result"]["pubkey"], "0x" + self.key.get_verifying_key().to_string("compressed").hex())
        digest = b"\x77" * 32
        resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})
        self.assertTrue(resp["ok"], resp)
        res = resp["result"]
        self.assertEqual(recover_address(digest, int(res["r"], 16), int(res["s"], 16), res["yParity"]), info["result"]["address"])
        self.assertIn("8004000020" + digest.hex(), calls)
        self.assertIn("8001000000", calls)
        self.assertIn("8002000000", calls)

    def test_eth2_preferred_der_signature(self):
        self._install_fake({host.AID_ETH_V1, host.AID_ETH_V2}, self.key)
        info = host.handle({"id": 1, "method": "info"})
        self.assertEqual(info["result"]["applet"], "eth2")
        self.assertEqual(info["result"]["applet_version"], "2.0.0")
        digest = hashlib.sha256(b"eth2").digest()
        res = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})["result"]
        self.assertEqual(recover_address(digest, int(res["r"], 16), int(res["s"], 16), res["yParity"]), info["result"]["address"])

    def test_no_applet_error_code(self):
        self._install_fake(set(), self.key)
        resp = host.handle({"id": 1, "method": "info"})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "NO_APPLET")

    def test_missing_nuri_pcsc_is_card_error(self):
        sys.modules.pop("nuri_pcsc", None)
        if os.path.exists(os.path.join(os.path.dirname(HERE), "scripts", "nuri_pcsc.py")):
            self.skipTest("nuri_pcsc.py present on this branch")
        resp = host.handle({"id": 1, "method": "info"})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "CARD_ERROR")
        self.assertIn("nuri_pcsc", resp["error"]["message"])


class FramingTests(unittest.TestCase):
    def test_serve_in_process(self):
        host._SIGNER = None
        stdin = io.BytesIO(frame({"id": 1, "method": "info"}) + frame({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "00" * 32}}) + frame({"id": 3, "method": "x"}))
        stdout = io.BytesIO()
        host.serve(stdin, stdout)
        msgs = unframe_all(stdout.getvalue())
        self.assertEqual([m["id"] for m in msgs], [1, 2, 3])
        self.assertTrue(msgs[0]["ok"] and msgs[1]["ok"] and not msgs[2]["ok"])

    def test_invalid_json_frame_is_reported_not_fatal(self):
        bad = b"{not json"
        stdin = io.BytesIO(struct.pack("<I", len(bad)) + bad + frame({"id": 7, "method": "info"}))
        stdout = io.BytesIO()
        host.serve(stdin, stdout)
        msgs = unframe_all(stdout.getvalue())
        self.assertEqual(msgs[0]["error"]["code"], "BAD_REQUEST")
        self.assertEqual(msgs[1]["id"], 7)

    def test_subprocess_round_trip(self):
        env = dict(os.environ, NURI_CARD_SIM="1")
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "nuri_card_host.py"), "chrome-extension://test/"],
            input=frame({"id": 1, "method": "info"}) + frame({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "ab" * 32}}),
            capture_output=True, env=env, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        msgs = unframe_all(proc.stdout)
        self.assertEqual(len(msgs), 2)
        self.assertEqual(msgs[0]["result"]["pubkey"], SIM_PUBKEY)
        self.assertTrue(msgs[1]["ok"], msgs[1])
        res = msgs[1]["result"]
        self.assertEqual(recover_address(bytes.fromhex("ab" * 32), int(res["r"], 16), int(res["s"], 16), res["yParity"]),
                         msgs[0]["result"]["address"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
