"""Minimal fake pyscard for scripts/card-setup-card.py. No hardware.

State file (FAKE_CARD_STATE, the same JSON the gp fake uses): aids, serial,
atr. A SELECT answers 9000 for an installed AID and 6A82 otherwise; the CPLC
APDU (80 CA 9F 7F 00) answers a 42-byte CPLC with the state serial inside.
"""
import json
import os
from pathlib import Path


def _state():
    return json.loads(Path(os.environ["FAKE_CARD_STATE"]).read_text())


def _cplc(state):
    cplc = bytearray()
    cplc += bytes.fromhex(state.get("fabricator", "4790"))
    cplc += bytes.fromhex("D3214700000000000000")  # ICType, OS id, OS date, OS level, fab date
    cplc += bytes.fromhex(state.get("serial", "12345678"))
    cplc += bytes(42 - len(cplc))
    return cplc


class NoCardException(Exception):
    pass


class CardConnectionException(Exception):
    pass


class CardConnection:
    T0_protocol = 0x00000001
    T1_protocol = 0x00000002

    def __init__(self, reader):
        self.reader = reader
        self.connected = False

    def connect(self, protocol=None):
        self.connected = True

    def disconnect(self):
        self.connected = False

    def getATR(self):
        return list(bytes.fromhex(_state().get("atr", "3BF81300008131FE454A434F5076323431B7")))

    def transmit(self, apdu):
        state = _state()
        apdu = list(apdu)
        if apdu[:2] == [0x00, 0xA4]:
            length = apdu[4]
            aid = bytes(apdu[5:5 + length]).hex().upper()
            if aid == "A000000003000000" or aid in state.get("aids", []):
                return list(b""), 0x90, 0x00
            return list(b""), 0x6A, 0x82
        if apdu == [0x80, 0xCA, 0x9F, 0x7F, 0x00]:
            return list(_cplc(state)), 0x90, 0x00
        return list(b""), 0x6D, 0x00


class _Reader:
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

    def createConnection(self):
        return CardConnection(self.name)


def readers():
    return [_Reader(name) for name in _state().get("card_readers", ["Fake reader"])]
