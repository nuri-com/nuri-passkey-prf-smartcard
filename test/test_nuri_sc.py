#!/usr/bin/env python3
"""Unit + jCardSim cross-language tests for NURI-SC v1 (`scripts/nuri_sc.py` + `card/sc/`)."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cryptography.hazmat.primitives.asymmetric import ec

import nuri_sc as sc

AID = sc.DEFAULT_AID


class TestSecureChannelHostAndOracle(unittest.TestCase):
    def setUp(self):
        self.ident = ec.generate_private_key(ec.SECP256R1())
        self.card = sc.SimCard(AID, self.ident)
        self.host = sc.HostChannel(AID)

    def handshake(self):
        host_eph = self.host.start()
        resp = self.card.open(host_eph)
        return self.host.finish(resp, self.ident.public_key())

    def roundtrip(self, inner_cmd: bytes, rsp_data: bytes = b"", rsp_sw: int = 0x9000) -> tuple[bytes, int]:
        body = self.host.wrap(inner_cmd)
        got = self.card.unwrap(body)
        self.assertEqual(got, inner_cmd)
        rsp = self.card.wrap(rsp_data, rsp_sw)
        return self.host.unwrap(rsp)

    def test_handshake_and_roundtrip(self):
        res = self.handshake()
        self.assertTrue(self.host.is_open)
        self.assertEqual(len(res.session_id), 8)
        data, sw = self.roundtrip(sc.inner_apdu(0x80, sc.INS_SET_PIN, data=b"123456"), b"", 0x9000)
        self.assertEqual((data, sw), (b"", 0x9000))

    def test_reopen_while_open_refused_on_host(self):
        self.handshake()
        with self.assertRaises(sc.ScError) as ctx:
            self.host.start()
        self.assertEqual(ctx.exception.code, sc.SW_ALREADY_OPEN)

    def test_wrap_before_open_refused(self):
        with self.assertRaises(sc.ScError) as ctx:
            self.host.wrap(b"\x80\x50\x00\x00")
        self.assertEqual(ctx.exception.code, sc.SW_CONDITIONS_NOT_SATISFIED)

    def test_tampered_ciphertext_and_tag_fail_and_wipe(self):
        self.handshake()
        body = bytearray(self.host.wrap(sc.inner_apdu(0x80, sc.INS_VERIFY_PIN, data=b"123456")))
        body[-1] ^= 0x01
        with self.assertRaises(sc.ScError) as ctx:
            self.card.unwrap(bytes(body))
        self.assertEqual(ctx.exception.code, sc.SW_SC_ERROR)
        self.assertIsNone(self.card._k_c2d)

    def test_replayed_command_fails(self):
        self.handshake()
        first = self.host.wrap(sc.inner_apdu(0x80, sc.INS_PING, data=b"abc"))
        self.card.unwrap(first)
        with self.assertRaises(sc.ScError):
            self.card.unwrap(first)

    def test_counter_gap_fails(self):
        self.handshake()
        _a = self.host.wrap(sc.inner_apdu(0x80, sc.INS_PING))
        b = self.host.wrap(sc.inner_apdu(0x80, sc.INS_PING))
        with self.assertRaises(sc.ScError):
            self.card.unwrap(b)

    def test_response_replay_fails(self):
        self.handshake()
        self.roundtrip(sc.inner_apdu(0x80, sc.INS_PING))
        _ = self.host.wrap(sc.inner_apdu(0x80, sc.INS_PING))
        rsp = self.card.wrap(b"ok", 0x9000)
        self.assertEqual(self.host.unwrap(rsp), (b"ok", 0x9000))
        with self.assertRaises(sc.ScError):
            self.host.unwrap(rsp)

    def test_wrong_identity_key_fails_handshake(self):
        host_eph = self.host.start()
        resp = self.card.open(host_eph)
        impostor = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaises(sc.ScError) as ctx:
            self.host.finish(resp, impostor)
        self.assertEqual(ctx.exception.code, sc.SW_SC_ERROR)
        self.assertFalse(self.host.is_open)

    def test_session_open_requires_pinned_pubkey_unless_tofu(self):
        sess = sc.ScCardSession(lambda _cmd: (b"", 0x9000), AID)
        with self.assertRaises(ValueError):
            sess.open()

    def test_iso9797_padding_boundaries(self):
        for n in (1, 15, 16, 17, 31, 32, 64, 200):
            msg = bytes((i & 0xFF) for i in range(n))
            padded = sc.iso9797_m2_pad(msg)
            self.assertEqual(len(padded) % 16, 0)
            self.assertEqual(sc.iso9797_m2_unpad(padded), msg)

    def test_keys_differ_per_handshake(self):
        r1 = self.handshake()
        k1 = self.host._k_c2d
        self.host.close()
        r2 = self.handshake()
        self.assertNotEqual(k1, self.host._k_c2d)
        self.assertNotEqual(r1.session_id, r2.session_id)


class TestSecureChannelJCardSimBridge(unittest.TestCase):
    """Cross-language E2E against the compiled Java Card applet in jCardSim."""

    def setUp(self):
        cp = os.environ.get("SC_BRIDGE_CP")
        if not cp:
            build = Path(os.environ.get("SC_SIM_BUILD", ROOT / ".build/sc-sim"))
            jar = build / "jcardsim-3.0.5.11.jar"
            classes = build / "classes"
            if not jar.exists() or not classes.exists():
                self.skipTest("SC_BRIDGE_CP not set and .build/sc-sim not built yet")
            cp = f"{classes}{os.pathsep}{jar}"
        java_bin = "java"
        j17 = Path("/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home/bin/java")
        if j17.exists():
            java_bin = str(j17)
        self.proc = subprocess.Popen(
            [java_bin, "-cp", cp, "test.sc.ScApduBridge"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self._cleanup_proc)
        self.wire_apdus: list[bytes] = []

    def _cleanup_proc(self):
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=10)
        err = self.proc.stderr.read() if self.proc.stderr else ""
        if self.proc.stdout:
            self.proc.stdout.close()
        if self.proc.stderr:
            self.proc.stderr.close()
        self.assertEqual(self.proc.returncode, 0, err)

    def tx(self, apdu: bytes) -> tuple[bytes, int]:
        self.wire_apdus.append(bytes(apdu))
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(bytes(apdu).hex() + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline().strip()
        raw = bytes.fromhex(line)
        self.assertGreaterEqual(len(raw), 2)
        return raw[:-2], (raw[-2] << 8) | raw[-1]

    def test_end_to_end_java_applet_tunnel_and_attacks(self):
        sess = sc.ScCardSession(self.tx, AID)
        sess.select()

        st = sess.status()
        self.assertEqual(st[0], 1)
        self.assertEqual(st[2], 0)
        self.assertEqual(st[3], 0)
        self.assertEqual(st[4], 5)

        pub = sess.get_pubkey()
        self.assertEqual(len(pub), 65)
        self.assertEqual(pub[0], 0x04)

        for ins in (sc.INS_SET_PIN, sc.INS_VERIFY_PIN, sc.INS_PUT_SECRET, sc.INS_HMAC, sc.INS_PING):
            _, sw = self.tx(sc.outer_apdu(0x80, ins, 0, 0, b"123456"))
            self.assertEqual(sw, 0x6985)

        opened = sess.open(pub)
        self.assertEqual(len(opened.session_id), 8)
        self.assertEqual(sess.status()[2], 1)

        for n in (0, 1, 13, 14, 15, 16, 32, 127, 180):
            payload = bytes(((i * 7 + 3) & 0xFF) for i in range(n))
            echo, sw = sess.transceive(0x80, sc.INS_PING, data=payload)
            self.assertEqual(sw, 0x9000)
            self.assertEqual(echo, payload)

        pin_secret = b"948271"
        before_idx = len(self.wire_apdus)
        _, sw = sess.transceive(0x80, sc.INS_SET_PIN, data=pin_secret)
        self.assertEqual(sw, 0x9000)
        for raw in self.wire_apdus[before_idx:]:
            self.assertNotIn(pin_secret, raw)

        _, inner_sw = sess.transceive(0x80, sc.INS_VERIFY_PIN, data=b"000000")
        self.assertEqual(inner_sw, 0x63C4)

        _, inner_sw = sess.transceive(0x80, sc.INS_VERIFY_PIN, data=pin_secret)
        self.assertEqual(inner_sw, 0x9000)
        self.assertEqual(sess.status()[4], 5)

        key = b"Jefe"
        msg = b"what do ya want for nothing?"
        _, sw = sess.transceive(0x80, sc.INS_PUT_SECRET, data=key)
        self.assertEqual(sw, 0x9000)
        mac_out, sw = sess.transceive(0x80, sc.INS_HMAC, data=msg)
        self.assertEqual(sw, 0x9000)
        self.assertEqual(mac_out.hex(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        self.assertEqual(mac_out, hmac.new(key, msg, hashlib.sha256).digest())

        valid_frame = sess.channel.wrap(sc.inner_apdu(0x80, sc.INS_PING, data=b"replay"))
        rsp1, sw1 = self.tx(sc.wrap_apdu(valid_frame))
        self.assertEqual(sw1, 0x9000)
        self.assertEqual(sess.channel.unwrap(rsp1), (b"replay", 0x9000))

        _, sw_replay = self.tx(sc.wrap_apdu(valid_frame))
        self.assertEqual(sw_replay, 0x6988)
        sess.channel.close()
        self.assertEqual(sess.status()[2], 0)

        sess.open(pub)
        _, sw_unauth = sess.transceive(0x80, sc.INS_HMAC, data=msg)
        self.assertEqual(sw_unauth, 0x6982)

        self.assertEqual(sess.transceive(0x80, sc.INS_VERIFY_PIN, data=pin_secret)[1], 0x9000)
        tampered = bytearray(sess.channel.wrap(sc.inner_apdu(0x80, sc.INS_HMAC, data=msg)))
        tampered[20] ^= 0x80
        _, sw_tamper = self.tx(sc.wrap_apdu(bytes(tampered)))
        self.assertEqual(sw_tamper, 0x6988)
        sess.channel.close()
        self.assertEqual(sess.status()[2], 0)

        sess.open(pub)
        self.assertEqual(sess.status()[2], 1)
        sess.close()
        self.assertEqual(sess.status()[2], 0)


if __name__ == "__main__":
    unittest.main()
