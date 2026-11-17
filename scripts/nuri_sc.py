#!/usr/bin/env python3
"""NURI-SC v1 host reference implementation.

Design: docs/secure-channel.md. Nothing here is implemented on a card yet, so this
module is the host half plus a deterministic simulator half used by the tests.

Primitives: P-256 ECDH (cryptography), HKDF-SHA256, AES-128-CCM with a 16-byte tag.
The card is expected to use the same layout with native Java Card primitives.

This file is a reference and a test oracle, not a shipping transport. Do not wire it
into a signing path while `docs/secure-channel.md` says "not implemented".
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature, InvalidTag

PROTOCOL = b"NURI-SC-V1"
K_ENC_INFO = b"nuri-sc-v1/enc"
K_MAC_INFO = b"nuri-sc-v1/mac"
TAG_LEN = 16
KEY_LEN = 16

CLA_OPEN, INS_OPEN = 0x80, 0x10
CLA_WRAP, INS_WRAP = 0x80, 0x11
CLA_CLOSE, INS_CLOSE = 0x80, 0x12
DIR_CMD, DIR_RSP = 0x00, 0x01

SW_TAG_OR_COUNTER = 0x6988
SW_WRAP_BEFORE_OPEN = 0x6985
SW_ALREADY_OPEN = 0x6A81


class ScError(Exception):
    """Any channel failure. The host must close the channel and re-OPEN."""

    def __init__(self, code: int, why: str):
        super().__init__(f"{code:04X} {why}")
        self.code = code


def _p256_public_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def _p256_from_bytes(raw: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def transcript(aid: bytes, host_eph: bytes, card_eph: bytes) -> bytes:
    return hashlib.sha256(PROTOCOL + aid + host_eph + card_eph).digest()


def derive(shared: bytes, cert_der: bytes) -> bytes:
    """PRK then one Expand call for the encryption key."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=hashlib.sha256(cert_der).digest(),
        info=K_ENC_INFO,
    ).derive(shared)


def _nonce(direction: int, counter: int, salt8: bytes) -> bytes:
    return bytes([direction]) + struct.pack(">I", counter) + salt8


def _aad(direction: int, counter: int) -> bytes:
    # Both sides know these bytes before decryption; the inner APDU header does
    # not, because CCM needs the AAD up front.
    return PROTOCOL + bytes([direction]) + struct.pack(">I", counter)


@dataclass
class OpenResult:
    card_eph: bytes
    signature: bytes
    cert_der: bytes


class HostChannel:
    """Host side. `open()` performs the handshake; `wrap`/`unwrap` move one APDU."""

    def __init__(self, aid: bytes):
        self.aid = aid
        self._key: bytes | None = None
        self._salt8 = b""
        self._tx = 0
        self._rx = 0
        self._pending: ec.EllipticCurvePrivateKey | None = None

    @property
    def is_open(self) -> bool:
        return self._key is not None

    def start(self) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
        """Generate the host ephemeral key. Send `open_apdu(host_eph)` and keep the key."""
        if self.is_open:
            raise ScError(SW_ALREADY_OPEN, "channel already open")
        if self._pending is not None:
            raise ScError(SW_ALREADY_OPEN, "handshake already started")
        priv = ec.generate_private_key(ec.SECP256R1())
        self._pending = priv
        return _p256_public_bytes(priv.public_key()), priv

    def finish(
        self,
        host_eph: bytes,
        host_private: ec.EllipticCurvePrivateKey,
        card_eph: bytes,
        signature: bytes,
        cert_der: bytes,
        identity_public: ec.EllipticCurvePublicKey,
    ) -> OpenResult:
        """Verify the card's transcript signature, then derive the tunnel keys."""
        if self.is_open or self._pending is None:
            raise ScError(SW_ALREADY_OPEN, "no handshake in progress")
        if len(card_eph) != 65 or len(signature) != 64:
            self._pending = None
            raise ScError(SW_TAG_OR_COUNTER, "malformed OPEN response")
        t = transcript(self.aid, host_eph, card_eph)
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
        try:
            identity_public.verify(encode_dss_signature(r, s), t, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            self._pending = None
            raise ScError(SW_TAG_OR_COUNTER, "bad handshake signature") from exc
        z1 = host_private.exchange(ec.ECDH(), _p256_from_bytes(card_eph))
        z2 = host_private.exchange(ec.ECDH(), identity_public)
        self._key = derive(z1 + z2, cert_der)
        self._salt8 = t[-8:]
        self._tx = self._rx = 0
        self._pending = None
        return OpenResult(card_eph=card_eph, signature=signature, cert_der=cert_der)

    def wrap(self, apdu: bytes) -> bytes:
        """Return the body of a WRAP command: counter32 || ciphertext || tag."""
        if not self.is_open:
            raise ScError(SW_WRAP_BEFORE_OPEN, "wrap before OPEN")
        if len(apdu) > 255 + 5:
            raise ValueError("inner APDU over the short-APDU limit")
        self._tx += 1
        body = AESCCM(self._key, tag_length=TAG_LEN).encrypt(
            _nonce(DIR_CMD, self._tx, self._salt8),
            apdu,
            _aad(DIR_CMD, self._tx),
        )
        return struct.pack(">I", self._tx) + body

    def unwrap(self, body: bytes) -> bytes:
        if not self.is_open:
            raise ScError(SW_WRAP_BEFORE_OPEN, "unwrap before OPEN")
        if len(body) < 4 + TAG_LEN:
            raise ScError(SW_TAG_OR_COUNTER, "short frame")
        if len(body) > 4 + 255 + TAG_LEN:
            raise ScError(SW_TAG_OR_COUNTER, "frame over 255 bytes: short APDU only")
        counter = struct.unpack(">I", body[:4])[0]
        if counter != self._rx + 1:
            self.close()
            raise ScError(SW_TAG_OR_COUNTER, f"counter {counter} != {self._rx + 1}")
        try:
            inner = AESCCM(self._key, tag_length=TAG_LEN).decrypt(
                _nonce(DIR_RSP, counter, self._salt8),
                body[4:],
                _aad(DIR_RSP, counter),
            )
        except InvalidTag as exc:
            self.close()
            raise ScError(SW_TAG_OR_COUNTER, "bad tag") from exc
        self._rx = counter
        return inner

    def close(self) -> None:
        self._key = None
        self._pending = None
        self._salt8 = b""
        self._tx = self._rx = 0


class SimCard:
    """Deterministic card half: same algorithm, independent code path."""

    def __init__(self, aid: bytes, identity_private: ec.EllipticCurvePrivateKey, cert_der: bytes):
        self.aid = aid
        self.identity = identity_private
        self.cert_der = cert_der
        self._key: bytes | None = None
        self._salt8 = b""
        self._rx = 0
        self._tx = 0

    def open(self, host_eph: bytes) -> bytes:
        eph = ec.generate_private_key(ec.SECP256R1())
        card_eph = _p256_public_bytes(eph.public_key())
        t = transcript(self.aid, host_eph, card_eph)
        sig = self.identity.sign(t, ec.ECDSA(hashes.SHA256()))
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        r, s = decode_dss_signature(sig)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        z1 = eph.exchange(ec.ECDH(), _p256_from_bytes(host_eph))
        z2 = self.identity.exchange(ec.ECDH(), _p256_from_bytes(host_eph))
        self._key = derive(z1 + z2, self.cert_der)
        self._salt8 = t[-8:]
        self._rx = self._tx = 0
        return card_eph + raw

    def unwrap(self, body: bytes) -> bytes:
        if self._key is None:
            raise ScError(SW_WRAP_BEFORE_OPEN, "unwrap before OPEN")
        counter = struct.unpack(">I", body[:4])[0]
        if counter != self._rx + 1:
            raise ScError(SW_TAG_OR_COUNTER, "counter")
        try:
            inner = AESCCM(self._key, tag_length=TAG_LEN).decrypt(
                _nonce(DIR_CMD, counter, self._salt8),
                body[4:],
                _aad(DIR_CMD, counter),
            )
        except InvalidTag as exc:
            raise ScError(SW_TAG_OR_COUNTER, "bad tag") from exc
        self._rx = counter
        return inner

    def wrap(self, rsp: bytes) -> bytes:
        if self._key is None:
            raise ScError(SW_WRAP_BEFORE_OPEN, "wrap before OPEN")
        self._tx += 1
        body = AESCCM(self._key, tag_length=TAG_LEN).encrypt(
            _nonce(DIR_RSP, self._tx, self._salt8), rsp, _aad(DIR_RSP, self._tx)
        )
        return struct.pack(">I", self._tx) + body


def apdu(cla: int, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"", le: int | None = None) -> bytes:
    if le is None:
        return bytes([cla, ins, p1, p2, len(data)]) + data
    if len(data) > 255:
        raise ValueError("short APDU only")
    return bytes([cla, ins, p1, p2, len(data)]) + data + bytes([le])


def open_apdu(host_eph: bytes) -> bytes:
    return apdu(CLA_OPEN, INS_OPEN, 0x01, 0x00, host_eph)


def wrap_apdu(direction: int, body: bytes) -> bytes:
    return apdu(CLA_WRAP, INS_WRAP, direction, 0x00, body)


def close_apdu() -> bytes:
    return apdu(CLA_CLOSE, INS_CLOSE, 0x00, 0x00)
