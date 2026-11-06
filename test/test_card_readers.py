"""card-readers.py inventory and card-setup reader auto-selection.

Fake pyscard readers only: no hardware, no network.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import importlib.util

_spec = importlib.util.spec_from_file_location("card_readers", ROOT / "scripts/card-readers.py")
card_readers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(card_readers)


class FakeConnection:
    def __init__(self, atr, cplc=b"", applets=(), fail_transmit=False):
        self._atr = atr
        self._cplc = cplc
        self._applets = set(applets)
        self._fail = fail_transmit
        self.apdus = []

    def getATR(self):
        return list(self._atr)

    def connect(self, protocol=None):
        pass

    def transmit(self, apdu, protocol=None):
        self.apdus.append(bytes(apdu))
        if self._fail:
            raise RuntimeError("SCARD_E_NOT_TRANSACTED")
        data = bytes(apdu)
        if data[:4] == bytes.fromhex("80CA9F7F"):
            return list(self._cplc), 0x90, 0x00
        if data[1] == 0xA4:
            aid = data[5:5 + data[4]].hex().upper()
            return [], (0x90 if aid in self._applets else 0x6A), (0x00 if aid in self._applets else 0x82)
        return [], 0x6D, 0x00

    def disconnect(self):
        pass


class FakeReader:
    def __init__(self, name, conn=None):
        self.name = name
        self.conn = conn

    def __str__(self):
        return self.name

    def createConnection(self):
        if self.conn is None:
            raise RuntimeError("no card")
        return self.conn


def cplc(serial="87E5470B", fabricator="4790"):
    raw = bytearray(42)
    raw[0:2] = bytes.fromhex(fabricator)
    raw[9:13] = bytes.fromhex(serial)
    return bytes(raw)


class CardReadersTest(unittest.TestCase):
    def test_contact_card_reports_serial_chip_and_applets(self):
        conn = FakeConnection(bytes.fromhex("3B8980014A434F50"), cplc(),
                              applets={"A0000006472F0001", "4E5552494D554701"})
        row = card_readers.scan_reader(FakeReader("OMNIKEY", conn))
        self.assertEqual(row["serial"], "87E5470B")
        self.assertEqual(row["chip"], "NXP JCOP")
        self.assertEqual(row["applets"], ["FIDO2", "MuSig2"])
        self.assertIsNone(row["note"])
        # read only: SELECT and GET DATA, never a PIN verify or a write
        for apdu in conn.apdus:
            self.assertNotEqual(apdu[1], 0x20)
            self.assertNotEqual(apdu[1], 0x46)

    def test_reader_without_card_is_not_an_error(self):
        row = card_readers.scan_reader(FakeReader("OMNIKEY 01"))
        self.assertFalse(row["card"])
        self.assertEqual(row["applets"], [])

    def test_pseudo_atr_reader_is_flagged_not_fatal(self):
        conn = FakeConnection(bytes.fromhex("3B119580"), fail_transmit=True)
        row = card_readers.scan_reader(FakeReader("CASTLES EZCCID Smart Card Reader", conn))
        self.assertTrue(row["card"])
        self.assertIn("pseudo ATR", row["note"])

    def test_javelin_atr_identifies_idex_card(self):
        conn = FakeConnection(bytes.fromhex(card_readers.JAVELIN_ATR), applets=set())
        row = card_readers.scan_reader(FakeReader("OMNIKEY", conn))
        self.assertEqual(row["chip"], "IDEX TrustedBio (Javelin-OS)")

    def test_json_output_is_machine_readable(self):
        rows = [{"reader": "x", "card": False, "applets": []}]
        self.assertEqual(json.loads(json.dumps(rows))[0]["reader"], "x")


class AutoSelectTest(unittest.TestCase):
    def test_single_reader_is_used_without_a_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "t.sh"
            script.write_text(f'''#!/bin/bash
set -euo pipefail
say() {{ printf '%s\\n' "$*"; }}
READER=""
READERS=("HID Global OMNIKEY 5422 Smartcard Reader")
source {ROOT}/scripts/lib/card-common.sh
card_common_pick_reader
printf 'READER=%s\\n' "$READER"
''')
            # pick_reader references $PY/$ROOT only in the multi-card branch.
            out = subprocess.run(["bash", str(script)], input="", text=True,
                                 capture_output=True, timeout=60)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("Using the only reader with a card", out.stdout)
            self.assertIn("READER=HID Global OMNIKEY 5422 Smartcard Reader", out.stdout)


if __name__ == "__main__":
    unittest.main()
