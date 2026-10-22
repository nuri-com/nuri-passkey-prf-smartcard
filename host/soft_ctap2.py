"""Test-only software CTAP2.1 authenticator (PIN protocol v1, ES256, hmac-secret).

Speaks the CTAPHID.CBOR call interface python-fido2 expects from a device, so the
real Fido2Client runs unmodified against it. Never installed; never a wallet.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fido2 import cbor
from fido2.ctap import CtapDevice, CtapError
from fido2.hid import CAPABILITY, CTAPHID

AAGUID = bytes.fromhex("6e75726973696d000000000000000000")
ERR = CtapError.ERR


def _aes(key, data, enc):
    c = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
    op = c.encryptor() if enc else c.decryptor()
    return op.update(data) + op.finalize()


def _hm16(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()[:16]


def _cose(pub):
    n = pub.public_numbers()
    return {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}


class SoftCtap2Device(CtapDevice):
    def __init__(self, pin: str):
        self._pin_hash = hashlib.sha256(pin.encode()).digest()[:16]
        self.retries = 8
        self._ka = ec.generate_private_key(ec.SECP256R1())
        self._token = os.urandom(32)
        self.creds: dict[bytes, dict] = {}
        self.counter = 0

    @property
    def capabilities(self):
        return CAPABILITY.CBOR

    @classmethod
    def list_devices(cls):
        return iter(())

    def expected_hmac(self, cred_id: bytes, salt: bytes) -> bytes:
        return hmac.new(self.creds[cred_id]["cred_random"], salt, hashlib.sha256).digest()

    # -- transport ---------------------------------------------------------
    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        if cmd != CTAPHID.CBOR:
            raise CtapError(ERR.INVALID_COMMAND)
        op, args = data[0], (cbor.decode(data[1:]) if len(data) > 1 else {})
        try:
            out = {0x04: self._info, 0x06: self._client_pin, 0x01: self._make, 0x02: self._get}[op](args)
        except CtapError as e:
            return struct.pack(">B", e.code)
        except KeyError:
            return struct.pack(">B", ERR.INVALID_COMMAND)
        return b"\x00" + (cbor.encode(out) if out else b"")

    # -- commands ----------------------------------------------------------
    def _info(self, _):
        return {1: ["FIDO_2_0", "FIDO_2_1"], 2: ["hmac-secret"], 3: AAGUID,
                4: {"rk": True, "up": True, "clientPin": True, "pinUvAuthToken": True},
                5: 1200, 6: [1]}

    def _shared(self, peer):
        x, y = int.from_bytes(peer[-2], "big"), int.from_bytes(peer[-3], "big")
        pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        return hashlib.sha256(self._ka.exchange(ec.ECDH(), pk)).digest()

    def _client_pin(self, a):
        sub = a[2]
        if sub == 1:
            return {3: self.retries}
        if sub == 2:
            return {1: _cose(self._ka.public_key())}
        if sub in (5, 9):
            if self.retries == 0:
                raise CtapError(ERR.PIN_BLOCKED)
            ss = self._shared(a[3])
            if not hmac.compare_digest(_aes(ss, a[6], False), self._pin_hash):
                self.retries -= 1
                self._ka = ec.generate_private_key(ec.SECP256R1())
                raise CtapError(ERR.PIN_BLOCKED if self.retries == 0 else ERR.PIN_INVALID)
            self.retries = 8
            self._token = os.urandom(32)
            return {2: _aes(ss, self._token, True)}
        raise CtapError(ERR.INVALID_SUBCOMMAND)

    def _check_uv(self, cdh, auth):
        if auth is None:
            raise CtapError(ERR.PUAT_REQUIRED)
        if not hmac.compare_digest(_hm16(self._token, cdh), auth):
            raise CtapError(ERR.PIN_AUTH_INVALID)

    def _auth_data(self, rp_id, flags, attested=b"", ext=None):
        self.counter += 1
        return (hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
                + attested + (cbor.encode(ext) if ext else b""))

    def _make(self, a):
        cdh, rp, user = a[1], a[2], a[3]
        if not any(p.get("alg") == -7 for p in a[4]):
            raise CtapError(ERR.UNSUPPORTED_ALGORITHM)
        self._check_uv(cdh, a.get(8))
        key = ec.generate_private_key(ec.SECP256R1())
        cred_id = os.urandom(32)
        self.creds[cred_id] = {"rp": rp["id"], "user": user, "key": key, "cred_random": os.urandom(32)}
        ext = {"hmac-secret": True} if (a.get(6) or {}).get("hmac-secret") else None
        attested = AAGUID + struct.pack(">H", len(cred_id)) + cred_id + cbor.encode(_cose(key.public_key()))
        flags = 0x01 | 0x04 | 0x40 | (0x80 if ext else 0)
        return {1: "none", 2: self._auth_data(rp["id"], flags, attested, ext), 3: {}}

    def _get(self, a):
        rp_id, cdh = a[1], a[2]
        opts = a.get(5) or {}
        up = opts.get("up", True)
        allow = [c["id"] for c in a.get(3) or []]
        found = [cid for cid, c in self.creds.items() if c["rp"] == rp_id and (not allow or cid in allow)]
        if not found:
            raise CtapError(ERR.NO_CREDENTIALS)
        uv = a.get(6) is not None
        if uv:
            self._check_uv(cdh, a[6])
        cid = found[0]
        cred = self.creds[cid]
        ext = None
        hs = (a.get(4) or {}).get("hmac-secret")
        if hs and up:
            ss = self._shared(hs[1])
            if not hmac.compare_digest(_hm16(ss, hs[2]), hs[3]):
                raise CtapError(ERR.EXTENSION_FIRST)
            salts = _aes(ss, hs[2], False)
            out = b"".join(hmac.new(cred["cred_random"], salts[i:i + 32], hashlib.sha256).digest()
                           for i in range(0, len(salts), 32))
            ext = {"hmac-secret": _aes(ss, out, True)}
        flags = (0x01 if up else 0) | (0x04 if uv else 0) | (0x80 if ext else 0)
        auth_data = self._auth_data(rp_id, flags, ext=ext)
        sig = cred["key"].sign(auth_data + cdh, ec.ECDSA(hashes.SHA256()))
        resp = {1: {"type": "public-key", "id": cid}, 2: auth_data, 3: sig, 4: {"id": cred["user"]["id"]}}
        if not allow:
            resp[5] = len(found)
        return resp
