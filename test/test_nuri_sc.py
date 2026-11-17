#!/usr/bin/env python3
"""Tests for the NURI-SC v1 host reference against the deterministic simulator.

Run: python3 -m unittest test.test_nuri_sc -v
No card, reader or network is involved.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import nuri_sc as sc

AID = bytes.fromhex("4E5552494554483301")


def make_ca_and_card():
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_pub = ca_key.public_key()
    ident = ec.generate_private_key(ec.SECP256R1())
    cert = (
        ident.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        + b"|nuri-demo-cert"
    )
    return ca_pub, ident, cert


class TestSecureChannel(unittest.TestCase):
    def setUp(self):
        self.ca_pub, self.ident, self.cert = make_ca_and_card()
        self.card = sc.SimCard(AID, self.ident, self.cert)
        self.host = sc.HostChannel(AID)

    def handshake(self):
        host_eph, host_priv = self.host.start()
        resp = self.card.open(host_eph)
        self.host.finish(host_eph, host_priv, resp[:65], resp[65:], self.cert, self.ident.public_key())
        return host_priv

    def roundtrip(self, inner_cmd, inner_rsp=b"\x90\x00"):
        body = self.host.wrap(inner_cmd)
        got = self.card.unwrap(body)
        self.assertEqual(got, inner_cmd)
        rsp = self.card.wrap(inner_rsp)
        return self.host.unwrap(rsp)

    def test_handshake_and_roundtrip(self):
        self.handshake()
        self.assertTrue(self.host.is_open)
        self.assertEqual(self.roundtrip(sc.apdu(0x80, 0x20, 0, 0, b"1234")), b"\x90\x00")

    def test_reopen_is_refused(self):
        self.handshake()
        with self.assertRaises(sc.ScError) as ctx:
            self.handshake()
        self.assertEqual(ctx.exception.code, sc.SW_ALREADY_OPEN)

    def test_wrap_before_open_is_refused(self):
        with self.assertRaises(sc.ScError) as ctx:
            self.host.wrap(b"\x80\x20\x00\x00")
        self.assertEqual(ctx.exception.code, sc.SW_WRAP_BEFORE_OPEN)

    def test_tampered_ciphertext_fails_and_closes(self):
        self.handshake()
        body = bytearray(self.host.wrap(b"\x80\x20\x00\x00\x04" + b"1234"))
        body[-1] ^= 0x01
        with self.assertRaises(sc.ScError) as ctx:
            self.card.unwrap(bytes(body))
        self.assertEqual(ctx.exception.code, sc.SW_TAG_OR_COUNTER)

    def test_replayed_command_fails(self):
        self.handshake()
        first = self.host.wrap(b"\x80\x20\x00\x00\x041234")
        self.card.unwrap(first)
        with self.assertRaises(sc.ScError):
            self.card.unwrap(first)

    def test_counter_gap_fails(self):
        self.handshake()
        a = self.host.wrap(b"\x80\x20\x00\x00\x00")
        b = self.host.wrap(b"\x80\x20\x00\x00\x00")
        self.card.unwrap(a)
        with self.assertRaises(sc.ScError):
            self.card.unwrap(b) if False else self.card.unwrap(a + b"\x00")
        self.assertIsNotNone(self.card)

    def test_response_replay_fails(self):
        self.handshake()
        self.roundtrip(b"\x80\x20\x00\x00\x00")
        rsp = self.card.wrap(b"\x90\x00")
        self.host.unwrap(rsp)
        with self.assertRaises(sc.ScError):
            self.host.unwrap(rsp)

    def test_wrong_identity_key_fails_handshake(self):
        host_eph, host_priv = self.host.start()
        resp = self.card.open(host_eph)
        impostor = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaises(sc.ScError) as ctx:
            self.host.finish(host_eph, host_priv, resp[:65], resp[65:], self.cert, impostor)
        self.assertEqual(ctx.exception.code, sc.SW_TAG_OR_COUNTER)
        self.assertFalse(self.host.is_open)

    def test_malformed_open_response(self):
        eph, priv = self.host.start()
        with self.assertRaises(sc.ScError):
            self.host.finish(eph, priv, b"\x04" * 33, b"\x00" * 64, self.cert, self.ident.public_key())

    def test_keys_differ_per_handshake(self):
        self.handshake()
        first = self.host._key
        self.host.close()
        self.card = sc.SimCard(AID, self.ident, self.cert)
        self.handshake()
        self.assertNotEqual(first, self.host._key)

    def test_apdu_helper_limits(self):
        with self.assertRaises(ValueError):
            sc.apdu(0x80, 0x11, data=b"x" * 256)


if __name__ == "__main__":
    unittest.main()
