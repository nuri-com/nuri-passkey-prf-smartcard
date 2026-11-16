#!/usr/bin/env python3
"""Host-caller tests for the MuSig2 1.14 PIN protocol (fake card, no hardware).

Run: python3 -m unittest discover -s test -p test_musig2_host_pin.py -v
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "test"))

import musig2_fake_card  # noqa: E402
import nuri_musig2_card as host  # noqa: E402
import nuri_pcsc  # noqa: E402

PIN = "482915"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


proof = load("real_card_cosign_proof", "real-card-cosign-proof.py")
tweaked = load("card_cosign_tweaked", "card-cosign-tweaked.py")
arkade = load("real_card_arkade_signer_proof", "real-card-arkade-signer-proof.py")

P = proof.P


def proof_args(**kw):
    base = dict(message="pin test", msg32="", use_existing_card_key=True, client_secret_hex="",
                include_demo_client_secret=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


def tweaked_args(**kw):
    base = dict(message="pin test tweaked", msg32="", client_secret_hex="", script_root="",
                include_demo_client_secret=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


def ins_seq(card):
    return [[apdu[1] for apdu in s.log] for s in card.sessions]


class Base(unittest.TestCase):
    def setUp(self):
        self._open = nuri_pcsc.open_applet
        self._env = os.environ.pop(host.PIN_ENV, None)
        host._pin_cache.clear()
        self._tty = host._tty
        host._tty = lambda: False  # tests are never a trusted terminal

    def tearDown(self):
        nuri_pcsc.open_applet = self._open
        host._tty = self._tty
        host._pin_cache.clear()
        os.environ.pop(host.PIN_ENV, None)
        if self._env is not None:
            os.environ[host.PIN_ENV] = self._env


class LegacyTests(Base):
    def test_legacy_113_plain_cosign_no_pin_97_byte_finalize(self):
        card = musig2_fake_card.install(version=(1, 13))
        result = proof.run(proof_args())
        self.assertEqual(result["status"], "REAL_CARD_COSIGN_FLOW_OK")
        self.assertEqual(result["card_protocol"], "legacy-pre-1.14")
        self.assertFalse(result["card_pin_verified"])
        self.assertNotIn(0x20, sum(ins_seq(card), []))
        self.assertNotIn(0x22, sum(ins_seq(card), []))
        self.assertEqual([len(p) for p in card.finalize_payloads], [97])

    def test_legacy_113_tweaked_and_arkade_core_callers(self):
        card = musig2_fake_card.install(version=(1, 13))
        self.assertEqual(tweaked.run(tweaked_args())["status"], "REAL_CARD_TWEAKED_COSIGN_OK")
        ark = arkade.run(types.SimpleNamespace(
            msg32="", message="ark", case="all", script_root32="11" * 32,
            asp_secret_hex="", include_demo_asp_secret=False))
        self.assertEqual(ark["status"], "REAL_CARD_ARKADE_CLIENT_SIGNER_PROOF_OK")
        self.assertTrue(all(len(p) == 97 for p in card.finalize_payloads))


class Pin114Tests(Base):
    def test_transport_exception_cannot_echo_pin_and_drops_validation(self):
        card = musig2_fake_card.install(version=(1, 14), pin=PIN)
        c = host.MuSig2Card().connect()
        session = card.sessions[-1]
        def broken(apdu):
            raise RuntimeError("provider echoed PIN " + PIN + " " + bytes(apdu).hex())
        session.transmit = broken
        c.pin_verified = True
        c._token = b"test"
        with self.assertRaises(host.PinError) as ctx:
            c.verify_pin(PIN.encode())
        self.assertNotIn(PIN, str(ctx.exception))
        self.assertNotIn(PIN.encode().hex(), str(ctx.exception))
        self.assertFalse(c.pin_verified)
        self.assertIsNone(c._token)
        c.close()

    def test_keygen_already_set_error_reverifies_before_nonce(self):
        card = musig2_fake_card.install(version=(1, 14), pin=PIN)
        os.environ[host.PIN_ENV] = PIN
        c = host.MuSig2Card().connect()
        with self.assertRaisesRegex(RuntimeError, "6989"):
            c.keygen()
        self.assertFalse(c.pin_verified)
        c.nonces()
        self.assertEqual(ins_seq(card)[0].count(0x20), 2)
        c.close()

    def test_arkade_114_plain_and_tweaked_pass_actual_points(self):
        card = musig2_fake_card.install(version=(1, 14), pin=PIN)
        os.environ[host.PIN_ENV] = PIN
        result = arkade.run(types.SimpleNamespace(
            msg32="", message="ark pin", case="all", script_root32="11" * 32,
            asp_secret_hex="", include_demo_asp_secret=False))
        self.assertEqual(result["status"], "REAL_CARD_ARKADE_CLIENT_SIGNER_PROOF_OK")
        self.assertTrue(card.finalize_payloads)
        self.assertTrue(all(len(p) == 231 for p in card.finalize_payloads))

    def test_plain_cosign_verifies_pin_and_sends_actual_ragg_pagg(self):
        card = musig2_fake_card.install(version=(1, 14), pin=PIN)
        os.environ[host.PIN_ENV] = PIN
        result = proof.run(proof_args())
        self.assertEqual(result["status"], "REAL_CARD_COSIGN_FLOW_OK")
        self.assertEqual(result["card_protocol"], "pin-1.14")
        self.assertTrue(result["card_pin_verified"])
        self.assertNotIn(host.PIN_ENV, os.environ, "PIN env must be consumed, not inherited by children")
        (seq,) = ins_seq(card)
        self.assertLess(seq.index(0x20), seq.index(0x40))
        self.assertEqual(seq.count(0x20), 1)
        (payload,) = card.finalize_payloads
        self.assertEqual(len(payload), 231)
        parity, ragg, pagg = payload[64], payload[101:166], payload[166:231]
        sig = bytes.fromhex(result["final_signature64"])
        self.assertEqual(ragg[1:33], sig[:32], "Ragg x == signature R x")
        self.assertEqual(ragg[64] & 1, parity, "parity byte == y parity of actual Ragg")
        self.assertEqual(result["parity"], parity)
        self.assertEqual(pagg[1:33].hex(), result["aggregate_xonly32"])
        self.assertEqual(pagg[64] & 1, 0)
        self.assertEqual(payload[97:101], card.issued_tokens[-1], "token echoed from GET_NONCES")

    def test_tweaked_cosign_sends_tweaked_output_key_as_pagg(self):
        card = musig2_fake_card.install(version=(1, 14), pin=PIN)
        os.environ[host.PIN_ENV] = PIN
        result = tweaked.run(tweaked_args())
        self.assertEqual(result["status"], "REAL_CARD_TWEAKED_COSIGN_OK")
        (payload,) = card.finalize_payloads
        self.assertEqual(len(payload), 231)
        self.assertEqual(payload[167:199].hex(), result["tweaked_output_xonly32"])
        self.assertEqual(payload[102:134], bytes.fromhex(result["final_signature64"])[:32])

    def test_every_selection_verifies_again(self):
        card = musig2_fake_card.install(version=(1, 14), pin=PIN)
        os.environ[host.PIN_ENV] = PIN
        for _ in range(2):
            self.assertEqual(tweaked.run(tweaked_args())["status"], "REAL_CARD_TWEAKED_COSIGN_OK")
        self.assertEqual(len(card.sessions), 2)
        for seq in ins_seq(card):
            self.assertEqual(seq.count(0x20), 1)
            self.assertLess(seq.index(0x20), seq.index(0x40))
        c = host.MuSig2Card()
        c.connect()
        c.close()
        c.connect()
        self.assertFalse(c.pin_verified, "reconnect must drop the old validation")
        c.nonces()
        self.assertTrue(c.pin_verified)
        c.close()

    def test_required_pin_unset_fails_closed_before_nonces(self):
        card = musig2_fake_card.install(version=(1, 14), pin=None)
        os.environ[host.PIN_ENV] = PIN
        with self.assertRaises(host.PinError) as ctx:
            tweaked.run(tweaked_args())
        self.assertIn("none is set", str(ctx.exception))
        self.assertNotIn(0x40, sum(ins_seq(card), []))
        self.assertEqual(card.finalize_payloads, [])

    def test_pin_set_but_not_provided_fails_closed(self):
        card = musig2_fake_card.install(version=(1, 14), pin=PIN)
        with self.assertRaises(host.PinError) as ctx:
            proof.run(proof_args())
        self.assertIn("NURI_CARD_PIN", str(ctx.exception))
        self.assertNotIn(0x40, sum(ins_seq(card), []))

    def test_wrong_pin_never_echoed_and_counts_down(self):
        card = musig2_fake_card.install(version=(1, 14), pin=PIN)
        wrong = "135790"
        os.environ[host.PIN_ENV] = wrong
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(host.PinError) as ctx:
                tweaked.run(tweaked_args())
        text = str(ctx.exception) + repr(ctx.exception) + out.getvalue() + err.getvalue()
        self.assertNotIn(wrong, text)
        self.assertNotIn(wrong.encode().hex(), text.lower())
        self.assertIn("63C4", text)
        self.assertEqual(card.tries, 4)

    def test_malformed_pin_rejected_before_any_verify_apdu(self):
        card = musig2_fake_card.install(version=(1, 14), pin=PIN)
        for bad in ("123", "1234567890123", "12a456", "１２３４"):
            host._pin_cache.clear()
            os.environ[host.PIN_ENV] = bad
            with self.assertRaises(host.PinError) as ctx:
                proof.run(proof_args())
            self.assertNotIn(bad, str(ctx.exception))
        self.assertNotIn(0x20, sum(ins_seq(card), []))
        self.assertEqual(card.tries, 5)

    def test_caller_without_ragg_pagg_fails_closed_on_114(self):
        musig2_fake_card.install(version=(1, 14), pin=PIN)
        os.environ[host.PIN_ENV] = PIN
        c = host.MuSig2Card()
        c.connect()
        c.nonces()
        with self.assertRaises(RuntimeError) as ctx:
            c.finalize(b"\x01" * 32, b"\x02" * 32, 0, b"\x03" * 32)
        self.assertIn("aggregate R", str(ctx.exception))
        c.close()

    def test_114_short_nonce_response_is_not_downgraded(self):
        card = musig2_fake_card.install(version=(1, 14), pin=PIN)
        os.environ[host.PIN_ENV] = PIN
        c = host.MuSig2Card()
        c.connect()
        session = card.sessions[-1]
        real = session.transmit
        session.transmit = lambda apdu: (lambda r: (r[0][:66], r[1]) if apdu[1] == 0x40 else r)(real(apdu))
        with self.assertRaises(RuntimeError) as ctx:
            c.nonces()
        self.assertIn("needs 70", str(ctx.exception))
        c.close()

    def test_parity_mismatch_and_bad_points_rejected_host_side(self):
        musig2_fake_card.install(version=(1, 14), pin=PIN)
        os.environ[host.PIN_ENV] = PIN
        c = host.MuSig2Card()
        c.connect()
        c.nonces()
        g = (proof.GX, proof.GY)
        with self.assertRaises(ValueError):
            c.finalize(b"\x01" * 32, b"\x02" * 32, 1, b"\x03" * 32, r_agg=g, p_agg=g)  # G has even y
        with self.assertRaises(ValueError):
            host.uncompressed((1, 1))
        c.close()

    def test_set_pin_cli_path_once(self):
        card = musig2_fake_card.install(version=(1, 14), pin=None)
        c = host.MuSig2Card()
        c.connect()
        self.assertEqual(c.pin_status, {"required": True, "set": False, "tries": 5})
        c.set_pin(host.validate_pin(PIN))
        self.assertTrue(c.pin_status["set"])
        with self.assertRaises(host.PinError):
            c.set_pin(host.validate_pin("999999"))
        c.close()
        self.assertEqual(card.pin, PIN.encode())


if __name__ == "__main__":
    unittest.main()
