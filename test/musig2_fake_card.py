#!/usr/bin/env python3
"""Software stand-in for the NuriMuSig2 applet APDU surface (no hardware).

Models applet 1.13 (legacy: 66-byte nonces, 97-byte FINALIZE, no PIN) and the
agreed 1.14 protocol (VERIFY/SET_PIN/PIN_STATUS, 70-byte nonces with a 4-byte
token, 231-byte FINALIZE with Ragg65/Pagg65 point validation, 6982 without a
verified PIN). Written from the protocol text only, not from applet source.
The secret key is a fixed test scalar; nothing here is secret.

    install(version=(1, 14), pin="123456")   # patches nuri_pcsc.open_applet
"""
from __future__ import annotations

import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import nuri_pcsc  # noqa: E402

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
AID = "4E5552494D554701"


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def _mul(k, pt):
    r = None
    k %= N
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def _comp(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def _on_curve_65(raw):
    if len(raw) != 65 or raw[0] != 4:
        return False
    x, y = int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")
    return x < P and y < P and (y * y - x * x * x - 7) % P == 0


class FakeMuSig2Card:
    """Persistent card state (key, PIN, tries) shared across sessions."""

    def __init__(self, version=(1, 14), pin=None, pin_required=True, sk=None):
        self.version = version
        self.pin = pin.encode() if pin else None
        self.pin_required = pin_required and version >= (1, 14)
        self.tries = 5
        sk = sk or int.from_bytes(hashlib.sha256(b"nuri fake musig2 card").digest(), "big") % N
        pt = _mul(sk, G)
        if pt[1] & 1:
            sk = N - sk
            pt = _mul(sk, G)
        self.sk = sk
        self.pk33 = _comp(pt)
        self.key_generated = True
        self.counter = 0
        self.sessions = []
        self.finalize_payloads = []
        self.issued_tokens = []

    @property
    def pin_protocol(self):
        return self.version >= (1, 14)

    def open(self):
        session = FakeSession(self)
        self.sessions.append(session)
        return session


class FakeSession:
    """One SELECT: PIN validation and nonces are transient (die with the session)."""

    def __init__(self, card):
        self.card = card
        self.validated = False
        self.k = None
        self.token = None
        self.log = []
        self.reader_name = "Fake NuriMuSig2 reader"
        self.protocol = "default"
        self.conn = self
        self.closed = False

    def close(self):
        self.closed = True
        self.k = None
        self.validated = False

    def transmit(self, apdu: bytes):
        apdu = bytes(apdu)
        self.log.append(apdu)
        c = self.card
        cla, ins = apdu[0], apdu[1]
        data = apdu[5:5 + apdu[4]] if len(apdu) > 5 else b""
        if cla != 0:
            return b"", 0x6E00
        if ins == 0x01:
            caps = 0x03
            if c.pin_protocol:
                caps |= (0x04 if c.pin_required else 0) | (0x08 if c.pin else 0)
            return bytes([c.version[0], c.version[1], caps]) + b"KGEN", 0x9000
        if ins == 0x03:
            return c.pk33, 0x9000
        if c.pin_protocol and ins == 0x22:
            return bytes([int(c.pin_required), int(c.pin is not None), c.tries]), 0x9000
        if c.pin_protocol and ins == 0x21:
            if c.pin is not None:
                return b"", 0x6985
            if not (4 <= len(data) <= 12 and data.isdigit()):
                return b"", 0x6A80
            c.pin = bytes(data)
            return b"", 0x9000
        if c.pin_protocol and ins == 0x20:
            if c.pin is None:
                return b"", 0x6985
            if c.tries == 0:
                return b"", 0x6983
            if bytes(data) != c.pin:
                c.tries -= 1
                return b"", 0x63C0 | c.tries
            c.tries = 5
            self.validated = True
            return b"", 0x9000
        gated = c.pin_protocol and (c.pin is not None or c.pin_required)
        if ins in (0x04, 0x40, 0x41) and gated and not self.validated:
            return b"", 0x6982
        if ins == 0x04:
            return b"", 0x6989
        if ins == 0x40:
            k1 = int.from_bytes(os.urandom(32), "big") % N or 1
            k2 = int.from_bytes(os.urandom(32), "big") % N or 1
            self.k = (k1, k2)
            out = _comp(_mul(k1, G)) + _comp(_mul(k2, G))
            if c.pin_protocol:
                c.counter += 1
                self.token = (c.counter & 0xFFFF).to_bytes(2, "big") + os.urandom(2)
                c.issued_tokens.append(self.token)
                out += self.token
            return out, 0x9000
        if ins == 0x41:
            want = 231 if c.pin_protocol else 97
            if len(data) != want:
                return b"", 0x6700
            if self.k is None:
                return b"", 0x6984
            a, b, parity, e = data[:32], data[32:64], data[64], data[65:97]
            if c.pin_protocol:
                token, r65, p65 = data[97:101], data[101:166], data[166:231]
                if token != self.token:
                    return b"", 0x6984
                if not (_on_curve_65(r65) and _on_curve_65(p65)) or (r65[64] & 1) != parity:
                    return b"", 0x6A80
            c.finalize_payloads.append(bytes(data))
            k1, k2 = self.k
            self.k, self.token = None, None
            kk = (k1 + int.from_bytes(b, "big") * k2) % N
            if parity == 1:
                kk = (-kk) % N
            s = (kk + int.from_bytes(e, "big") * int.from_bytes(a, "big") % N * c.sk) % N
            return s.to_bytes(32, "big"), 0x9000
        return b"", 0x6D00


def install(**kwargs) -> FakeMuSig2Card:
    """Patch nuri_pcsc.open_applet so every caller talks to one fake card."""
    card = FakeMuSig2Card(**kwargs)

    def open_applet(aid_hex, reader=None):
        if aid_hex.upper() != AID:
            raise nuri_pcsc.CardError("NO_APPLET", aid_hex)
        return card.open()

    nuri_pcsc.open_applet = open_applet
    return card
