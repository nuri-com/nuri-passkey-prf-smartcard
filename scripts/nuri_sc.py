#!/usr/bin/env python3
"""NURI-SC v1 host implementation and PC/SC / jCardSim client.

Matches `card/sc/NuriSecureChannel.java` byte-for-byte on Java Card 3.0.4 Classic:
- Handshake (`INS_OPEN = 0x10`):
    host sends 65-byte uncompressed P-256 ephemeral key.
    card generates fresh P-256 ephemeral key, computes
      z_ee = ECDH(card_eph_priv, host_eph)
      z_se = ECDH(identity_priv, host_eph)
    signs raw transcript:
      T = "NURI-SC-V1" || len(AID) || AID || host_eph(65) || card_eph(65)
    with ECDSA-SHA256 (ASN.1 DER), and derives directional keys via RFC 5869
    HKDF-SHA256(salt = SHA256(T), ikm = z_ee || z_se, info = "nuri-sc-v1/keys", L = 104):
      k_c2d(16) || k_d2c(16) || m_c2d(32) || m_d2c(32) || session_id(8)
    Response: card_eph(65) || session_id(8) || sig_len(1) || sig_der(sig_len).
- Transport (`INS_WRAP = 0x11`):
    Encrypt-then-MAC using AES-128-CBC with ISO/IEC 9797-1 Method 2 padding
    (`0x80 0x00...`) and truncated RFC 2104 HMAC-SHA256-128 over:
      "NURI-SC-V1" || dir(1) || session_id(8) || counter32_be(4) || iv16(16) || ct.
    C2D inner payload: canonical short APDU (`CLA INS P1 P2` or `CLA INS P1 P2 Lc Data`).
    D2C inner payload: `resp_data || sw1 || sw2`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL = b"NURI-SC-V1"
HKDF_INFO = b"nuri-sc-v1/keys"
DEFAULT_AID = bytes.fromhex("4E55524953433031")

CLA_SC = 0x80
INS_STATUS = 0x01
INS_GET_PUBKEY = 0x02
INS_OPEN = 0x10
INS_WRAP = 0x11
INS_CLOSE = 0x12

INS_SET_PIN = 0x20
INS_VERIFY_PIN = 0x21
INS_PUT_SECRET = 0x30
INS_HMAC = 0x40
INS_PING = 0x50

DIR_C2D = 0x01
DIR_D2C = 0x02

TAG_LEN = 16
IV_LEN = 16

SW_OK = 0x9000
SW_SC_ERROR = 0x6988
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_ALREADY_OPEN = 0x6A81


class ScError(Exception):
    """Any outer secure-channel failure. Session state is wiped on error."""

    def __init__(self, code: int, why: str):
        super().__init__(f"{code:04X} {why}")
        self.code = code


def p256_public_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def p256_from_bytes(raw: bytes) -> ec.EllipticCurvePublicKey:
    if len(raw) != 65 or raw[0] != 0x04:
        raise ScError(SW_SC_ERROR, "invalid uncompressed P-256 point")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def transcript(aid: bytes, host_eph: bytes, card_eph: bytes) -> bytes:
    if not (1 <= len(aid) <= 16):
        raise ValueError("AID must be 1..16 bytes")
    return PROTOCOL + bytes([len(aid)]) + aid + host_eph + card_eph


def derive_keys(z_ee: bytes, z_se: bytes, raw_transcript: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=104,
        salt=hashlib.sha256(raw_transcript).digest(),
        info=HKDF_INFO,
    ).derive(z_ee + z_se)
    return okm[0:16], okm[16:32], okm[32:64], okm[64:96], okm[96:104]


def iso9797_m2_pad(data: bytes) -> bytes:
    rem = (16 - ((len(data) + 1) % 16)) % 16
    return data + b"\x80" + (b"\x00" * rem)


def iso9797_m2_unpad(padded: bytes) -> bytes:
    if not padded or len(padded) % 16 != 0:
        raise ScError(SW_SC_ERROR, "invalid padded block length")
    idx = len(padded) - 1
    while idx >= 0 and padded[idx] == 0x00:
        idx -= 1
    if idx < 0 or padded[idx] != 0x80:
        raise ScError(SW_SC_ERROR, "bad ISO9797-M2 padding")
    return padded[:idx]


def mac_tag(mac_key: bytes, direction: int, session_id: bytes, counter: int, iv_and_ct: bytes) -> bytes:
    header = PROTOCOL + bytes([direction]) + session_id + struct.pack(">I", counter)
    return hmac.new(mac_key, header + iv_and_ct, hashlib.sha256).digest()[:TAG_LEN]


def _aes_cbc_encrypt(key: bytes, iv: bytes, padded: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(ct) + dec.finalize()


@dataclass
class OpenResult:
    card_eph: bytes
    session_id: bytes
    signature_der: bytes


class HostChannel:
    """Host side of NURI-SC v1."""

    def __init__(self, aid: bytes = DEFAULT_AID):
        self.aid = aid
        self._k_c2d: bytes | None = None
        self._k_d2c: bytes | None = None
        self._m_c2d: bytes = b""
        self._m_d2c: bytes = b""
        self._session_id: bytes = b""
        self._tx = 0
        self._rx = 0
        self._pending: tuple[bytes, ec.EllipticCurvePrivateKey] | None = None

    @property
    def is_open(self) -> bool:
        return self._k_c2d is not None

    @property
    def session_id(self) -> bytes:
        return self._session_id

    def start(self) -> bytes:
        if self.is_open or self._pending is not None:
            raise ScError(SW_ALREADY_OPEN, "channel or handshake already active")
        priv = ec.generate_private_key(ec.SECP256R1())
        host_eph = p256_public_bytes(priv.public_key())
        self._pending = (host_eph, priv)
        return host_eph

    def finish(self, open_response: bytes, identity_public: ec.EllipticCurvePublicKey) -> OpenResult:
        if self.is_open or self._pending is None:
            raise ScError(SW_ALREADY_OPEN, "no handshake in progress")
        host_eph, host_priv = self._pending
        self._pending = None
        if len(open_response) < 74 + 8:
            raise ScError(SW_SC_ERROR, "short OPEN response")
        card_eph = open_response[:65]
        sid_wire = open_response[65:73]
        sig_len = open_response[73]
        sig_der = open_response[74:]
        if len(sig_der) != sig_len:
            raise ScError(SW_SC_ERROR, "malformed OPEN signature length")
        card_pub = p256_from_bytes(card_eph)
        t = transcript(self.aid, host_eph, card_eph)
        try:
            identity_public.verify(sig_der, t, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise ScError(SW_SC_ERROR, "bad handshake signature") from exc

        z_ee = host_priv.exchange(ec.ECDH(), card_pub)
        z_se = host_priv.exchange(ec.ECDH(), identity_public)
        k_c2d, k_d2c, m_c2d, m_d2c, sid = derive_keys(z_ee, z_se, t)
        if not hmac.compare_digest(sid, sid_wire):
            raise ScError(SW_SC_ERROR, "session_id mismatch")

        self._k_c2d = k_c2d
        self._k_d2c = k_d2c
        self._m_c2d = m_c2d
        self._m_d2c = m_d2c
        self._session_id = sid
        self._tx = 0
        self._rx = 0
        return OpenResult(card_eph=card_eph, session_id=sid, signature_der=sig_der)

    def wrap(self, inner_apdu: bytes, iv: bytes | None = None) -> bytes:
        if not self.is_open or self._k_c2d is None:
            raise ScError(SW_CONDITIONS_NOT_SATISFIED, "wrap before OPEN")
        if len(inner_apdu) < 4 or len(inner_apdu) > 207:
            raise ValueError("inner APDU must be 4..207 bytes")
        if self._tx >= 0xFFFFFFFF:
            self.close()
            raise ScError(SW_SC_ERROR, "TX counter exhausted")
        self._tx += 1
        iv16 = os.urandom(IV_LEN) if iv is None else iv
        if len(iv16) != IV_LEN:
            raise ValueError("IV must be 16 bytes")
        ct = _aes_cbc_encrypt(self._k_c2d, iv16, iso9797_m2_pad(inner_apdu))
        iv_ct = iv16 + ct
        tag = mac_tag(self._m_c2d, DIR_C2D, self._session_id, self._tx, iv_ct)
        return iv_ct + tag

    def unwrap(self, body: bytes) -> tuple[bytes, int]:
        if not self.is_open or self._k_d2c is None:
            raise ScError(SW_CONDITIONS_NOT_SATISFIED, "unwrap before OPEN")
        ct_len = len(body) - (IV_LEN + TAG_LEN)
        if len(body) < 48 or ct_len % 16 != 0:
            self.close()
            raise ScError(SW_SC_ERROR, "malformed wrapped response length")
        if self._rx >= 0xFFFFFFFF:
            self.close()
            raise ScError(SW_SC_ERROR, "RX counter exhausted")
        next_rx = self._rx + 1
        iv_ct = body[:-TAG_LEN]
        got_tag = body[-TAG_LEN:]
        exp_tag = mac_tag(self._m_d2c, DIR_D2C, self._session_id, next_rx, iv_ct)
        if not hmac.compare_digest(got_tag, exp_tag):
            self.close()
            raise ScError(SW_SC_ERROR, "bad response MAC tag")
        try:
            plain = iso9797_m2_unpad(_aes_cbc_decrypt(self._k_d2c, body[:IV_LEN], body[IV_LEN:-TAG_LEN]))
        except ScError:
            self.close()
            raise
        if len(plain) < 2:
            self.close()
            raise ScError(SW_SC_ERROR, "inner response missing status word")
        self._rx = next_rx
        sw = (plain[-2] << 8) | plain[-1]
        return plain[:-2], sw

    def close(self) -> None:
        self._k_c2d = None
        self._k_d2c = None
        self._m_c2d = b""
        self._m_d2c = b""
        self._session_id = b""
        self._pending = None
        self._tx = 0
        self._rx = 0


class SimCard:
    """Pure-Python oracle matching NuriSecureChannel.java for fast unit tests."""

    def __init__(self, aid: bytes, identity_private: ec.EllipticCurvePrivateKey):
        self.aid = aid
        self.identity = identity_private
        self._k_c2d: bytes | None = None
        self._k_d2c: bytes | None = None
        self._m_c2d = b""
        self._m_d2c = b""
        self._session_id = b""
        self._rx = 0
        self._tx = 0

    def reset(self) -> None:
        self._k_c2d = None
        self._k_d2c = None
        self._m_c2d = b""
        self._m_d2c = b""
        self._session_id = b""
        self._rx = 0
        self._tx = 0

    def open(self, host_eph: bytes) -> bytes:
        self.reset()
        host_pub = p256_from_bytes(host_eph)
        eph = ec.generate_private_key(ec.SECP256R1())
        card_eph = p256_public_bytes(eph.public_key())
        t = transcript(self.aid, host_eph, card_eph)
        sig_der = self.identity.sign(t, ec.ECDSA(hashes.SHA256()))
        z_ee = eph.exchange(ec.ECDH(), host_pub)
        z_se = self.identity.exchange(ec.ECDH(), host_pub)
        self._k_c2d, self._k_d2c, self._m_c2d, self._m_d2c, self._session_id = derive_keys(z_ee, z_se, t)
        return card_eph + self._session_id + bytes([len(sig_der)]) + sig_der

    def unwrap(self, body: bytes) -> bytes:
        if self._k_c2d is None:
            raise ScError(SW_CONDITIONS_NOT_SATISFIED, "unwrap before OPEN")
        ct_len = len(body) - 32
        if len(body) < 48 or ct_len % 16 != 0:
            self.reset()
            raise ScError(SW_SC_ERROR, "bad frame length")
        self._rx += 1
        exp = mac_tag(self._m_c2d, DIR_C2D, self._session_id, self._rx, body[:-16])
        if not hmac.compare_digest(exp, body[-16:]):
            self.reset()
            raise ScError(SW_SC_ERROR, "bad tag")
        try:
            plain = iso9797_m2_unpad(_aes_cbc_decrypt(self._k_c2d, body[:16], body[16:-16]))
        except ScError:
            self.reset()
            raise
        if len(plain) < 4:
            self.reset()
            raise ScError(SW_SC_ERROR, "short inner APDU")
        return plain

    def wrap(self, data: bytes, sw: int = SW_OK) -> bytes:
        if self._k_d2c is None:
            raise ScError(SW_CONDITIONS_NOT_SATISFIED, "wrap before OPEN")
        self._tx += 1
        iv16 = os.urandom(16)
        ct = _aes_cbc_encrypt(self._k_d2c, iv16, iso9797_m2_pad(data + struct.pack(">H", sw)))
        iv_ct = iv16 + ct
        return iv_ct + mac_tag(self._m_d2c, DIR_D2C, self._session_id, self._tx, iv_ct)


def inner_apdu(cla: int, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"") -> bytes:
    if not data:
        return bytes([cla, ins, p1, p2])
    if len(data) > 202:
        raise ValueError("inner APDU payload exceeds limit")
    return bytes([cla, ins, p1, p2, len(data)]) + data


def outer_apdu(cla: int, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"", le: int | None = None) -> bytes:
    if not data:
        return bytes([cla, ins, p1, p2]) if le is None else bytes([cla, ins, p1, p2, le & 0xFF])
    if len(data) > 255:
        raise ValueError("short APDU only")
    out = bytes([cla, ins, p1, p2, len(data)]) + data
    return out if le is None else out + bytes([le & 0xFF])


def select_apdu(aid: bytes = DEFAULT_AID) -> bytes:
    return outer_apdu(0x00, 0xA4, 0x04, 0x00, aid, 0x00)


def open_apdu(host_eph: bytes) -> bytes:
    return outer_apdu(CLA_SC, INS_OPEN, 0x01, 0x00, host_eph, 0x00)


def wrap_apdu(body: bytes) -> bytes:
    return outer_apdu(CLA_SC, INS_WRAP, DIR_C2D, 0x00, body, 0x00)


def close_apdu() -> bytes:
    return outer_apdu(CLA_SC, INS_CLOSE, 0x00, 0x00)


TransmitFn = Callable[[bytes], tuple[bytes, int]]


class ScCardSession:
    """High-level transport wrapper over any APDU `transmit(cmd_bytes) -> (data, sw)` callable."""

    def __init__(self, transmit: TransmitFn, aid: bytes = DEFAULT_AID):
        self._tx_fn = transmit
        self.aid = aid
        self.channel = HostChannel(aid)
        self.identity_pub_bytes: bytes = b""

    def select(self) -> None:
        _, sw = self._tx_fn(select_apdu(self.aid))
        if sw != SW_OK:
            raise ScError(sw, "SELECT failed")
        self.channel.close()

    def status(self) -> bytes:
        data, sw = self._tx_fn(outer_apdu(CLA_SC, INS_STATUS, 0, 0, b"", 0x00))
        if sw != SW_OK or len(data) != 5:
            raise ScError(sw, "STATUS failed")
        return data

    def get_pubkey(self) -> bytes:
        data, sw = self._tx_fn(outer_apdu(CLA_SC, INS_GET_PUBKEY, 0, 0, b"", 0x00))
        if sw != SW_OK or len(data) != 65:
            raise ScError(sw, "GET_PUBKEY failed")
        self.identity_pub_bytes = data
        return data

    def open(self, pinned_pubkey: bytes | None = None, *, allow_tofu: bool = False) -> OpenResult:
        """Open NURI-SC v1 session.

        Pass a CA-verified or operator-pinned 65-byte uncompressed P-256 identity
        public key via `pinned_pubkey`. Unauthenticated `INS_GET_PUBKEY` discovery
        is refused unless `allow_tofu=True` is explicitly passed.
        """
        if pinned_pubkey is not None:
            pub_bytes = pinned_pubkey
        elif allow_tofu:
            pub_bytes = self.identity_pub_bytes or self.get_pubkey()
        else:
            raise ValueError(
                "pinned_pubkey is required to prevent MITM key substitution "
                "(pass allow_tofu=True only for physically trusted pairing)"
            )
        host_eph = self.channel.start()
        rsp, sw = self._tx_fn(open_apdu(host_eph))
        if sw != SW_OK:
            self.channel.close()
            raise ScError(sw, "OPEN failed")
        return self.channel.finish(rsp, p256_from_bytes(pub_bytes))

    def transceive(self, cla: int, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"") -> tuple[bytes, int]:
        frame = self.channel.wrap(inner_apdu(cla, ins, p1, p2, data))
        rsp, outer_sw = self._tx_fn(wrap_apdu(frame))
        if outer_sw != SW_OK:
            self.channel.close()
            raise ScError(outer_sw, "outer WRAP failed")
        return self.channel.unwrap(rsp)

    def close(self) -> None:
        try:
            _, sw = self._tx_fn(close_apdu())
            if sw != SW_OK:
                raise ScError(sw, "CLOSE failed")
        finally:
            self.channel.close()
