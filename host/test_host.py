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
import tempfile
import time
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

    def test_parse_hash_is_strict_full_match_32_bytes(self):
        ok = ["0x" + "ab" * 32, "0X" + "AB" * 32, "cd" * 32]
        for v in ok:
            self.assertEqual(len(host.parse_hash(v)), 32, v)
        bad = [
            "00 " * 21 + " ",            # 64 chars, bytes.fromhex -> 21 bytes (W13 R11)
            "0x" + "00 " * 21 + " ",
            "0x" + "00" * 31 + " 0",     # embedded whitespace
            "0x" + "00" * 32 + "\n",     # trailing newline
            " 0x" + "00" * 32,
            "0x" + "00" * 31,            # 31 bytes
            "0x" + "00" * 33,            # 33 bytes
            "0x" + "0" * 63,             # odd length
            "0x" + "\uff10" * 64,        # non-ASCII digits
            "0x0x" + "00" * 31,
            "", "0x", None, 123, ["00" * 32], b"\x00" * 32,
        ]
        for v in bad:
            with self.assertRaises(host.HostError, msg=repr(v)) as ctx:
                host.parse_hash(v)
            self.assertEqual(ctx.exception.code, "BAD_REQUEST")
        resp = host.handle({"id": 3, "method": "sign_hash", "params": {"hash": "00 " * 21 + " "}})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "BAD_REQUEST")

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

    def _install_fake(self, applets: set, sim_key, eth2_format="der", eth2_echo_key=None):
        """eth2_format: "der" (legacy fake) or "rspub" (real applet: r||s||pub65, 129 B)."""
        import types
        from ecdsa.util import sigencode_string, sigencode_der
        calls = []
        echo_vk = (eth2_echo_key or sim_key).get_verifying_key()

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
                    return (b"\x01\x03\x01ETH1" if self.aid == host.AID_ETH_V1 else b"\x02\x00\x00ETH2\x01\x05"), 0x9000
                if ins == 0x02:
                    vk = sim_key.get_verifying_key()
                    return (vk.to_string("compressed") if self.aid == host.AID_ETH_V1 else vk.to_string("uncompressed")), 0x9000
                if ins == 0x04:
                    digest = bytes(apdu[5:37])
                    if self.aid == host.AID_ETH_V1:
                        sig = sim_key.sign_digest_deterministic(digest, sigencode=sigencode_string)
                        return sig + b"\x00", 0x9000  # v byte is deliberately wrong; host must recover it
                    if eth2_format == "der":
                        return sim_key.sign_digest_deterministic(digest, sigencode=sigencode_der), 0x9000
                    sig = sim_key.sign_digest_deterministic(digest, sigencode=sigencode_string)
                    return sig + echo_vk.to_string("uncompressed"), 0x9000
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

    def test_eth2_native_rs_pub_signature(self):
        """Real ETH2 output: r(32)||s(32)||pub(65). Host must parse, verify and recover v."""
        calls = self._install_fake({host.AID_ETH_V2}, self.key, eth2_format="rspub")
        info = host.handle({"id": 1, "method": "info"})
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["result"]["applet"], "eth2")
        digest = hashlib.sha256(b"eth2-rspub").digest()
        resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})
        self.assertTrue(resp["ok"], resp)
        res = resp["result"]
        self.assertLessEqual(int(res["s"], 16), host.curve_order() // 2)
        self.assertEqual(recover_address(digest, int(res["r"], 16), int(res["s"], 16), res["yParity"]), info["result"]["address"])
        self.assertIn("8004000020" + digest.hex(), calls)

    def test_eth2_echoed_pubkey_mismatch_is_verify_failed(self):
        from ecdsa import SigningKey, SECP256k1
        other = SigningKey.from_secret_exponent(0x7654321, curve=SECP256k1)
        self._install_fake({host.AID_ETH_V2}, self.key, eth2_format="rspub", eth2_echo_key=other)
        host.handle({"id": 1, "method": "info"})
        resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "11" * 32}})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "VERIFY_FAILED")

    def test_eth2_parse_rejects_garbage(self):
        with self.assertRaises(host.HostError) as ctx:
            host.parse_eth2_signature(b"\x00" * 40)
        self.assertEqual(ctx.exception.code, "CARD_ERROR")

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
    def test_timeout_configuration_cannot_disable_the_read_deadline(self):
        from unittest.mock import patch
        for value in ("inf", "nan", "0", "-1", "999999", "invalid"):
            with self.subTest(value=value), patch.dict(os.environ, {"NURI_CARD_HOST_FRAME_TIMEOUT": value}):
                self.assertEqual(host.frame_timeout_from_env(), host.DEFAULT_FRAME_TIMEOUT)
        with patch.dict(os.environ, {"NURI_CARD_HOST_FRAME_TIMEOUT": "0.1"}):
            self.assertEqual(host.frame_timeout_from_env(), 0.1)

    def test_serve_in_process(self):
        host._SIGNER = None
        stdin = io.BytesIO(frame({"id": 1, "method": "info"}) + frame({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "00" * 32}}) + frame({"id": 3, "method": "x"}))
        stdout = io.BytesIO()
        host.serve(stdin, stdout)
        msgs = unframe_all(stdout.getvalue())
        self.assertEqual([m["id"] for m in msgs], [1, 2, 3])
        self.assertTrue(msgs[0]["ok"] and msgs[1]["ok"] and not msgs[2]["ok"])

    # -- framing hardening (W13 R11) -------------------------------------- #

    def _serve_bytes(self, data: bytes, **kw):
        host._SIGNER = None
        stdout = io.BytesIO()
        rc = host.serve(io.BytesIO(data), stdout, **kw)
        return rc, unframe_all(stdout.getvalue())

    TRAILER = frame({"id": 99, "method": "info"})  # must never be answered after a framing error

    def _assert_closed(self, data: bytes, needle: str):
        rc, msgs = self._serve_bytes(data + self.TRAILER)
        self.assertEqual(rc, 1, msgs)
        self.assertEqual(len(msgs), 1, msgs)
        self.assertFalse(msgs[0]["ok"])
        self.assertIsNone(msgs[0]["id"])
        self.assertEqual(msgs[0]["error"]["code"], "BAD_REQUEST")
        self.assertIn(needle, msgs[0]["error"]["message"])
        self.assertNotIn(99, [m["id"] for m in msgs])

    def test_oversized_length_closes_without_reading_trailer(self):
        self._assert_closed(struct.pack("<I", host.MAX_MESSAGE_BYTES + 1), "too large")
        self._assert_closed(struct.pack("<I", 0xFFFFFFFF), "too large")

    def test_oversized_with_embedded_frame_in_body_is_not_parsed(self):
        # The old host kept framing at offset 4, i.e. inside the rejected body.
        smuggled = frame({"id": 42, "method": "sign_hash", "params": {"hash": "0x" + "00" * 32}})
        rc, msgs = self._serve_bytes(struct.pack("<I", host.MAX_MESSAGE_BYTES + 1) + smuggled)
        self.assertEqual(rc, 1)
        self.assertEqual([m["id"] for m in msgs], [None])

    def test_exactly_max_size_is_accepted(self):
        head = b'{"id":5,"method":"info","pad":"'
        tail = b'"}'
        body = head + b"x" * (host.MAX_MESSAGE_BYTES - len(head) - len(tail)) + tail
        self.assertEqual(len(body), host.MAX_MESSAGE_BYTES)
        rc, msgs = self._serve_bytes(struct.pack("<I", len(body)) + body + self.TRAILER)
        self.assertEqual(rc, 0)
        self.assertEqual([m["id"] for m in msgs], [5, 99])
        self.assertTrue(msgs[0]["ok"], msgs[0])

    def test_zero_length_closes(self):
        self._assert_closed(struct.pack("<I", 0), "length 0")

    def test_invalid_json_closes(self):
        bad = b"{not json"
        self._assert_closed(struct.pack("<I", len(bad)) + bad, "invalid JSON")

    def test_invalid_utf8_closes(self):
        bad = b'{"id":1,"method":"\xff\xfe"}'
        self._assert_closed(struct.pack("<I", len(bad)) + bad, "UTF-8")

    def test_deeply_nested_json_recursion_closes(self):
        bad = b"[" * 200000 + b"]" * 200000
        self.assertLess(len(bad), host.MAX_MESSAGE_BYTES)
        self._assert_closed(struct.pack("<I", len(bad)) + bad, "nested too deeply")
        bad_obj = b'{"a":' * 150000 + b"1" + b"}" * 150000
        self._assert_closed(struct.pack("<I", len(bad_obj)) + bad_obj, "nested too deeply")

    def test_huge_integer_literal_closes(self):
        bad = b'{"id":' + b"9" * 50000 + b',"method":"info"}'
        self._assert_closed(struct.pack("<I", len(bad)) + bad, "invalid JSON")

    def test_truncated_header_after_valid_frame(self):
        rc, msgs = self._serve_bytes(frame({"id": 1, "method": "info"}) + b"\x05\x00")
        self.assertEqual(rc, 1)
        self.assertEqual([m["id"] for m in msgs], [1, None])
        self.assertTrue(msgs[0]["ok"])
        self.assertIn("truncated header", msgs[1]["error"]["message"])

    def test_truncated_body_closes(self):
        body = json.dumps({"id": 1, "method": "info"}).encode()
        rc, msgs = self._serve_bytes(struct.pack("<I", len(body) + 10) + body)
        self.assertEqual(rc, 1)
        self.assertEqual(len(msgs), 1)
        self.assertIn("truncated body", msgs[0]["error"]["message"])

    def test_clean_eof_and_empty_stream(self):
        self.assertEqual(self._serve_bytes(b""), (0, []))
        rc, msgs = self._serve_bytes(frame({"id": 1, "method": "info"}))
        self.assertEqual((rc, [m["id"] for m in msgs]), (0, [1]))

    def test_non_object_json_is_request_error_and_session_continues_with_logging(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = os.path.join(d, "host.log")
            old = os.environ.get("NURI_CARD_HOST_LOG")
            os.environ["NURI_CARD_HOST_LOG"] = log_path
            try:
                rc, msgs = self._serve_bytes(
                    frame([1, 2]) + frame("str") + frame(None) + frame(7)
                    + frame({"id": {"x": 1}, "method": ["m"], "params": {"hash": "0x" + "ab" * 32}})
                    + frame({"id": 8, "method": "sign_hash", "params": {"hash": "0x" + "ab" * 32}})
                )
            finally:
                if old is None:
                    os.environ.pop("NURI_CARD_HOST_LOG", None)
                else:
                    os.environ["NURI_CARD_HOST_LOG"] = old
            with open(log_path) as fh:
                lines = [json.loads(line) for line in fh]
        self.assertEqual(rc, 0)
        self.assertEqual(len(msgs), 6)
        for m in msgs[:5]:
            self.assertEqual(m["error"]["code"], "BAD_REQUEST", m)
        self.assertTrue(msgs[5]["ok"], msgs[5])
        self.assertEqual(len(lines), 6)
        self.assertEqual(lines[0]["invalid"], "list")
        self.assertEqual(lines[4]["request"], {"id": None, "method": None})
        self.assertEqual(lines[5]["request"], {"id": 8, "method": "sign_hash"})
        self.assertNotIn("ab" * 32, json.dumps(lines))  # params never logged

    def _spawn(self, timeout="0.5"):
        env = dict(os.environ, NURI_CARD_SIM="1", NURI_CARD_HOST_FRAME_TIMEOUT=timeout)
        env.pop("NURI_CARD_HOST_LOG", None)
        return subprocess.Popen(
            [sys.executable, os.path.join(HERE, "nuri_card_host.py"), "chrome-extension://test/"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )

    def test_subprocess_oversized_then_valid_exits_1_without_answering(self):
        proc = self._spawn()
        out, err = proc.communicate(struct.pack("<I", host.MAX_MESSAGE_BYTES + 1) + self.TRAILER, timeout=30)
        self.assertEqual(proc.returncode, 1, err.decode())
        msgs = unframe_all(out)
        self.assertEqual(len(msgs), 1)
        self.assertIn("too large", msgs[0]["error"]["message"])
        self.assertEqual(err, b"")  # no traceback

    def test_subprocess_deep_nesting_exits_1_no_traceback(self):
        bad = b"[" * 300000 + b"]" * 300000
        proc = self._spawn()
        out, err = proc.communicate(struct.pack("<I", len(bad)) + bad + self.TRAILER, timeout=30)
        self.assertEqual(proc.returncode, 1, err.decode())
        self.assertEqual(len(unframe_all(out)), 1)
        self.assertEqual(err, b"")

    def test_subprocess_stalled_frame_hits_deadline(self):
        for partial in (b"\x10", frame({"id": 1, "method": "info"})[:-3]):
            proc = self._spawn("0.5")
            proc.stdin.write(partial)
            proc.stdin.flush()  # pipe stays open: a stalled sender, not EOF
            t0 = time.monotonic()
            try:
                rc = proc.wait(timeout=10)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
            elapsed = time.monotonic() - t0
            out = proc.stdout.read()
            proc.stdin.close(); proc.stdout.close(); proc.stderr.close()
            self.assertEqual(rc, 1)
            self.assertLess(elapsed, 5)
            msgs = unframe_all(out)
            self.assertEqual(len(msgs), 1)
            self.assertIn("stalled", msgs[0]["error"]["message"])

    def test_subprocess_idle_host_is_not_timed_out(self):
        proc = self._spawn("0.3")
        try:
            time.sleep(1.2)  # idle 4x the frame deadline before the first byte
            self.assertIsNone(proc.poll(), "idle host must keep waiting for a request")
            body = frame({"id": 1, "method": "info"})
            proc.stdin.write(body[:2]); proc.stdin.flush()
            time.sleep(0.05)  # split frame, completed well within the deadline
            proc.stdin.write(body[2:] + frame({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "cd" * 32}}))
            proc.stdin.flush()
            time.sleep(1.0)  # idle again between frames
            self.assertIsNone(proc.poll())
            out, err = proc.communicate(frame({"id": 3, "method": "info"}), timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.assertEqual(proc.returncode, 0, err.decode())
        msgs = unframe_all(out)
        self.assertEqual([m["id"] for m in msgs], [1, 2, 3])
        self.assertTrue(all(m["ok"] for m in msgs), msgs)

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
