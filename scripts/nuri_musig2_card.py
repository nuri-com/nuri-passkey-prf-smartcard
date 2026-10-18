#!/usr/bin/env python3
"""Host side of the NuriMuSig2 applet APDU protocol (legacy <1.14 and PIN-gated 1.14+).

One place for every caller (real-card-cosign-proof.py, card-cosign-tweaked.py and
the scripts that import card-cosign-tweaked.py as `core`).

Protocol (CLA 00):
  01 GET_VERSION  -> maj min caps build4 (7 bytes). caps bit0 sign, bit1 keygen,
                     bit2 PIN required, bit3 PIN set (bits 2/3 only from 1.14).
  03 GET_PUBKEY   -> pk33
  04 KEYGEN       -> pk33 (one-shot, 6989 when a key exists)
  20 VERIFY       data = PIN ASCII, 4..12 decimal digits            (1.14+)
  21 SET_PIN      data = PIN ASCII, once, only while no PIN is set  (1.14+)
  22 PIN_STATUS   -> required set tries                             (1.14+)
  40 GET_NONCES   legacy: K1(33)||K2(33) = 66 bytes
                  1.14+:  K1(33)||K2(33)||token(4) = 70 bytes
  41 FINALIZE     legacy: a32||b32||parity1||e32 = 97 bytes
                  1.14+:  a32||b32||parity1||e32||token4||Ragg65||Pagg65 = 231 bytes
                  (Ragg / Pagg uncompressed 04||x||y; the card validates the
                  points natively, the host stays responsible for a/b/e).

PIN handling: only from env NURI_CARD_PIN, or a getpass prompt when stdin and
stderr are a terminal. Never from argv, never printed, never put into an
exception message, never echoed as APDU bytes. The env var is popped after it is
read so it does not leak into anything this process might spawn.

Legacy (<1.14) applets keep working without PIN for the public demo card; the
branch is explicit (`protocol` == "legacy-pre-1.14") and a 1.14+ card is never
downgraded: wrong nonce length, missing Ragg/Pagg or a required-but-unset PIN
fail closed.
"""
from __future__ import annotations

import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nuri_pcsc  # noqa: E402  shared PC/SC: reader + protocol ladder, 61XX/6CXX

APPLET_AID = bytes.fromhex("4E5552494D554701")
PIN_PROTOCOL_VERSION = (1, 14)
PIN_ENV = "NURI_CARD_PIN"
NEW_PIN_ENV = "NURI_CARD_NEW_PIN"

INS_GET_VERSION = 0x01
INS_GET_PUBKEY = 0x03
INS_KEYGEN = 0x04
INS_VERIFY = 0x20
INS_SET_PIN = 0x21
INS_PIN_STATUS = 0x22
INS_GET_NONCES = 0x40
INS_FINALIZE = 0x41

CAP_SIGN = 0x01
CAP_KEYGEN = 0x02
CAP_PIN_REQUIRED = 0x04
CAP_PIN_SET = 0x08

LEGACY_NONCES_LEN = 66
PIN_NONCES_LEN = 70
TOKEN_LEN = 4
LEGACY_FINALIZE_LEN = 97
PIN_FINALIZE_LEN = 231

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


class PinError(RuntimeError):
    """PIN missing, malformed, wrong or blocked. Message never contains the PIN."""


def validate_pin(pin: str) -> bytes:
    if not isinstance(pin, str) or not (4 <= len(pin) <= 12) or not pin.isascii() or not pin.isdigit():
        raise PinError("card PIN must be 4..12 ASCII decimal digits")
    return pin.encode("ascii")


def _tty() -> bool:
    try:
        return sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


_pin_cache: dict = {}


def read_pin(env_name: str = PIN_ENV, prompt: str = "Nuri card PIN: ") -> bytes:
    """PIN from env or a trusted-terminal getpass prompt. Never argv.

    The env var is popped on first read (kept only in this process's memory) so
    nothing this process spawns inherits it; later card sessions in the same
    process reuse the cached value instead of prompting again."""
    if env_name in _pin_cache:
        return _pin_cache[env_name]
    pin = os.environ.pop(env_name, None)
    if pin is None and _tty():
        pin = getpass.getpass(prompt)
    if not pin:
        raise PinError(f"card PIN required: set {env_name} or run from a terminal to be prompted")
    _pin_cache[env_name] = validate_pin(pin)
    return _pin_cache[env_name]


def uncompressed(point) -> bytes:
    """(x, y) affine secp256k1 point -> 04||x32||y32 (65 bytes)."""
    if point is None:
        raise ValueError("point at infinity has no SEC1 encoding")
    x, y = point
    if not (0 <= x < _P and 0 <= y < _P) or (y * y - x * x * x - 7) % _P:
        raise ValueError("not a secp256k1 point")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _sw_text(sw: int) -> str:
    if sw == 0x6982:
        return "security status not satisfied (PIN required: unset or not verified)"
    if sw == 0x6983:
        return "PIN blocked"
    if (sw & 0xFFF0) == 0x63C0:
        return f"wrong PIN, {sw & 0x0F} tries left"
    if sw == 0x6985:
        return "conditions not satisfied"
    return ""


class MuSig2Card:
    """Connected NuriMuSig2 applet. connect() selects and reads version (and on
    1.14+ PIN_STATUS). VERIFY happens once per card session, before the first
    KEYGEN / GET_NONCES / FINALIZE (and before GET_PUBKEY if the card answers
    6982), so a public-key read does not need the PIN unless the applet says so."""

    def __init__(self, applet=None, pin_reader=None):
        self.applet = applet
        self.conn = None
        self.reader = None
        self._pin_reader = pin_reader
        self._token = None
        self.version_tuple = None
        self.capabilities = 0
        self.build = ""
        self.pin_status = None
        self.pin_verified = False

    # -- transport -------------------------------------------------------
    def connect(self, verify_pin: bool = False):
        if self.applet is None:
            try:
                self.applet = nuri_pcsc.open_applet(APPLET_AID.hex())
            except nuri_pcsc.CardError as error:
                raise RuntimeError(f"No NuriMuSig2 card found ({error})") from error
        self.conn = self.applet.conn
        self.reader = f"{self.applet.reader_name} [{self.applet.protocol}]"
        # Fresh selection = fresh applet session: PIN validation and nonce token
        # do not carry over, so VERIFY again before GET_NONCES / FINALIZE.
        self.pin_verified = False
        self.pin_status = None
        self._token = None
        self._read_version()
        if self.pin_protocol:
            self._read_pin_status()
            if verify_pin:
                self.ensure_pin(strict=False)
        return self

    def close(self):
        self._token = None
        self.pin_verified = False
        if self.applet is not None:
            try:
                self.applet.close()
            except Exception:
                pass
            self.applet = None  # a later connect() re-selects (new session, new VERIFY)

    disconnect = close

    def _tx(self, apdu) -> bytes:
        resp, sw = self.applet.transmit(bytes(apdu))
        if sw != 0x9000:
            # Applet 1.14 burns both validation and nonce state on every error.
            self.pin_verified = False
            self._token = None
            hint = _sw_text(sw)
            # INS byte only: never echo the APDU (VERIFY/SET_PIN carry the PIN).
            raise RuntimeError(f"APDU INS={apdu[1]:02X} failed: SW={sw:04X}" + (f" ({hint})" if hint else ""))
        return bytes(resp)

    # -- version / PIN ---------------------------------------------------
    def _read_version(self):
        r = self._tx([0x00, INS_GET_VERSION, 0x00, 0x00, 0x00])
        if len(r) < 3:
            raise RuntimeError(f"unexpected version response length: {len(r)}")
        self.version_tuple = (r[0], r[1])
        self.capabilities = r[2]
        self.build = r[3:7].decode("ascii", errors="ignore")

    @property
    def pin_protocol(self) -> bool:
        return self.version_tuple is not None and self.version_tuple >= PIN_PROTOCOL_VERSION

    @property
    def protocol(self) -> str:
        return "pin-1.14" if self.pin_protocol else "legacy-pre-1.14"

    def _ver(self) -> str:
        return f"{self.version_tuple[0]}.{self.version_tuple[1]}" if self.version_tuple else "?"

    def version(self) -> str:
        return self._ver()

    def version_info(self) -> dict:
        return {
            "version": self._ver(),
            "build": self.build,
            "capabilities": self.capabilities,
            "protocol": self.protocol,
            "pin_required": self.pin_protocol and bool(self.capabilities & CAP_PIN_REQUIRED),
            "pin_set": self.pin_protocol and bool(self.capabilities & CAP_PIN_SET),
            "pin_tries": self.pin_status["tries"] if self.pin_status else None,
            "pin_verified": self.pin_verified,
        }

    def _read_pin_status(self) -> dict:
        r = self._tx([0x00, INS_PIN_STATUS, 0x00, 0x00, 0x00])
        if len(r) < 3:
            raise RuntimeError(f"unexpected PIN_STATUS length: {len(r)}")
        self.pin_status = {"required": bool(r[0]), "set": bool(r[1]), "tries": r[2]}
        return self.pin_status

    def ensure_pin(self, strict: bool = True):
        """1.14+: VERIFY if a PIN is set. strict: also fail closed (before the
        card would answer 6982) when a PIN is required but not set yet."""
        if not self.pin_protocol or self.pin_verified:
            return
        status = self.pin_status or self._read_pin_status()
        required = status["required"] or bool(self.capabilities & CAP_PIN_REQUIRED)
        pin_set = status["set"] or bool(self.capabilities & CAP_PIN_SET)
        if pin_set:
            if status["tries"] == 0:
                raise PinError("card PIN is blocked (0 tries left)")
            self.verify_pin((self._pin_reader or read_pin)())
        elif required and strict:
            raise PinError(
                "card requires a PIN but none is set (applet would answer 6982); "
                "set it once with: scripts/run-card-python.sh scripts/nuri_musig2_card.py set-pin"
            )

    def verify_pin(self, pin: bytes):
        if not self.pin_protocol:
            raise RuntimeError("VERIFY needs applet >= 1.14")
        try:
            self._tx(bytes([0x00, INS_VERIFY, 0x00, 0x00, len(pin)]) + pin)
        except RuntimeError as error:
            raise PinError(str(error)) from None
        self.pin_verified = True

    def set_pin(self, pin: bytes):
        if not self.pin_protocol:
            raise RuntimeError("SET_PIN needs applet >= 1.14")
        try:
            self._tx(bytes([0x00, INS_SET_PIN, 0x00, 0x00, len(pin)]) + pin)
        except RuntimeError as error:
            raise PinError(str(error)) from None
        self._read_pin_status()

    # -- MuSig2 ----------------------------------------------------------
    def pubkey(self) -> bytes:
        try:
            return self._tx([0x00, INS_GET_PUBKEY, 0x00, 0x00, 0x00])
        except RuntimeError as error:
            if not (self.pin_protocol and not self.pin_verified and "SW=6982" in str(error)):
                raise
        self.ensure_pin(strict=False)
        return self._tx([0x00, INS_GET_PUBKEY, 0x00, 0x00, 0x00])

    def keygen(self) -> bytes:
        # Not strict: whether KEYGEN may precede SET_PIN is the applet's call.
        self.ensure_pin(strict=False)
        r = self._tx([0x00, INS_KEYGEN, 0x00, 0x00, 0x00])
        if len(r) != 33:
            raise RuntimeError(f"unexpected keygen pubkey length: {len(r)}")
        return r

    def nonces(self):
        """-> (K1 33, K2 33). On 1.14+ the session token is kept for FINALIZE."""
        self.ensure_pin()
        r = self._tx([0x00, INS_GET_NONCES, 0x00, 0x00, 0x00])
        want = PIN_NONCES_LEN if self.pin_protocol else LEGACY_NONCES_LEN
        if len(r) != want:
            raise RuntimeError(f"unexpected nonce response length: {len(r)} (applet {self._ver()} needs {want})")
        self._token = r[66:70] if self.pin_protocol else None
        return r[:33], r[33:66]

    def finalize(self, a: bytes, b: bytes, parity: int, e: bytes, r_agg=None, p_agg=None) -> bytes:
        """Card partial. r_agg / p_agg: actual aggregate nonce R (before parity
        negation) and aggregate signing pubkey, as (x, y) or 65-byte SEC1.
        Mandatory on 1.14+, ignored on legacy applets."""
        if len(a) != 32 or len(b) != 32 or len(e) != 32 or parity not in (0, 1):
            raise ValueError("finalize needs a32, b32, parity 0/1, e32")
        payload = a + b + bytes([parity]) + e
        if self.pin_protocol:
            if r_agg is None or p_agg is None:
                raise RuntimeError(
                    f"applet {self._ver()} FINALIZE needs aggregate R and aggregate pubkey; "
                    "this caller does not pass them"
                )
            if self._token is None:
                raise RuntimeError("FINALIZE without a GET_NONCES session token")
            self.ensure_pin()
            r65 = r_agg if isinstance(r_agg, (bytes, bytearray)) else uncompressed(r_agg)
            p65 = p_agg if isinstance(p_agg, (bytes, bytearray)) else uncompressed(p_agg)
            if len(r65) != 65 or r65[0] != 4 or len(p65) != 65 or p65[0] != 4:
                raise ValueError("Ragg/Pagg must be 65-byte uncompressed points")
            if (r65[64] & 1) != parity:
                raise ValueError("parity byte does not match the y parity of Ragg")
            payload += self._token + bytes(r65) + bytes(p65)
            if len(payload) != PIN_FINALIZE_LEN:
                raise AssertionError(len(payload))
        elif len(payload) != LEGACY_FINALIZE_LEN:
            raise AssertionError(len(payload))
        self._token = None  # one FINALIZE per nonce session, success or not
        r = self._tx(bytes([0x00, INS_FINALIZE, 0x00, 0x00, len(payload)]) + payload + b"\x20")
        if len(r) != 32:
            raise RuntimeError(f"unexpected partial length: {len(r)}")
        return r


def _cli(argv) -> int:
    """pin-status | set-pin. set-pin reads NURI_CARD_NEW_PIN or prompts twice."""
    import json

    cmd = argv[0] if argv else "pin-status"
    card = MuSig2Card()
    card.connect(verify_pin=False)
    try:
        if cmd == "pin-status":
            print(json.dumps({"status": "NURI_MUSIG2_PIN_STATUS", "reader": card.reader, **card.version_info()}))
            return 0
        if cmd == "set-pin":
            pin = os.environ.pop(NEW_PIN_ENV, None)
            if pin is None:
                if not _tty():
                    raise PinError(f"set {NEW_PIN_ENV} or run from a terminal")
                pin = getpass.getpass("New Nuri card PIN: ")
                if getpass.getpass("Repeat PIN: ") != pin:
                    raise PinError("PINs do not match")
            card.set_pin(validate_pin(pin))
            print(json.dumps({"status": "NURI_MUSIG2_PIN_SET", **card.version_info()}))
            return 0
        print("usage: nuri_musig2_card.py pin-status|set-pin", file=sys.stderr)
        return 2
    finally:
        card.close()


if __name__ == "__main__":
    try:
        sys.exit(_cli(sys.argv[1:]))
    except (PinError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
