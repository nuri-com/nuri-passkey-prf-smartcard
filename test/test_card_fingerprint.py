#!/usr/bin/env python3
"""Feitian fingerprint host protocol tests; no reader or biometric data."""
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import card_fingerprint as fp  # noqa: E402


class FakeCard:
    reader_name = "fake"
    protocol = "T0"

    def __init__(self, responses):
        self.responses = iter(responses)
        self.commands = []
        self.closed = False

    def transmit(self, apdu):
        self.commands.append(apdu)
        return next(self.responses)

    def close(self):
        self.closed = True


class FeitianFingerprintTests(unittest.TestCase):
    def card(self, responses):
        fake = FakeCard(responses)
        with mock.patch.object(fp.nuri_pcsc, "open_applet", return_value=fake):
            return fp.FeitianFingerprint("fake"), fake

    def test_list_preserves_templates(self):
        card, fake = self.card([(bytes.fromhex("0351009000"), 0x9000)])
        self.assertEqual(card.list(), 3)
        self.assertEqual(fake.commands, [bytes.fromhex("00F1510000")])

    def test_match_success(self):
        card, _ = self.card([(bytes.fromhex("0053009000"), 0x9000)])
        card.match()

    def test_match_rejects_wrong_finger(self):
        card, _ = self.card([(bytes.fromhex("E000000000"), 0x9000)])
        with self.assertRaisesRegex(RuntimeError, "did not match"):
            card.match()

    def test_enroll_requests_every_touch(self):
        responses = [(bytes([n, 0x50, 12, 0x90, 0]), 0x9000) for n in range(1, 13)]
        card, fake = self.card(responses)
        with mock.patch.object(fp, "emit"):
            self.assertEqual(card.enroll(), 12)
        self.assertEqual([cmd[3] for cmd in fake.commands], list(range(1, 13)))

    def test_enroll_timeout_does_not_retry_automatically(self):
        card, fake = self.card([(bytes.fromhex("E9500C0000"), 0x9000)])
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            card.enroll()
        self.assertEqual(len(fake.commands), 1)

    def test_malformed_success_is_rejected(self):
        card, _ = self.card([(bytes.fromhex("0053009000"), 0x9000)])
        with mock.patch.object(card, "_command", return_value=b"\x00"):
            with self.assertRaisesRegex(RuntimeError, "Unexpected response"):
                card.match()


if __name__ == "__main__":
    unittest.main()
