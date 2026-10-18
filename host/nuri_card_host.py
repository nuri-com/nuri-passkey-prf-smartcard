#!/usr/bin/env python3
"""Chrome native messaging host `com.nuri.card` (contract C2).

Framing: 4-byte little-endian length + UTF-8 JSON, one request -> one response,
looped until stdin closes (works for both sendNativeMessage and connectNative).

Methods (issue info first on the same connection; signing refuses otherwise)
  {"id": n, "method": "info"}
      -> {applet, applet_version, pubkey, address, reader, mode, pin_set, pin_tries_left}
  {"id": n, "method": "sign_hash", "params": {"hash": "0x<64 hex>"}}
      no-PIN path (ETH1 / ETH2 without PIN); PIN-protected ETH2 -> PIN_REQUIRED
  {"id": n, "method": "verify_pin",
   "params": {"pin": "<4..16 bytes>", "hash": "0x<64 hex>", "address": "<EIP-55 from info>"}}
      VERIFY_PIN + SIGN on one ETH2 session, closed on every exit. PIN never
      stored, cached, logged or echoed. Errors PIN_WRONG (error.tries_left),
      PIN_BLOCKED, PIN_NOT_SET, ADDRESS_MISMATCH.
Every sign re-opens the card and re-reads VERSION + PUBKEY; a different
applet/key than the last info -> CARD_CHANGED (info required again).

The host only ever signs 32-byte hashes (keccak/RLP/EIP-712 hashing is the
extension's job). Every signature is verified against the card pubkey, low-s
normalized (EIP-2) and gets its yParity by public-key recovery before it is
returned; an unverifiable signature is reported as VERIFY_FAILED.

Modes
  card (default): lazily imports scripts/nuri_pcsc.py (contract C1) and talks
       to the ETH applet. Prefers ETH v2 (AID 4E5552494554483201, C4), falls
       back to ETH v1 (AID 4E55524945544801, C3).
  sim: only when env NURI_CARD_SIM is exactly "1" -> PUBLIC software key
       d = int(sha256(b"nuri-card-sim-v1")) mod n. Signing additionally needs a
       successful info(mode=sim) in this process. --sim alone authorizes nothing;
       any other NURI_CARD_SIM value is CONFIG_ERROR (no fallback either way).

Dependencies: python-ecdsa (verify / recovery), pycryptodome (keccak256 for the
EIP-55 address; same choice as scripts/card-dashboard-server.py), pyscard only
in card mode via nuri_pcsc.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import sys
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")

AID_ETH_V1 = "4E55524945544801"
AID_ETH_V2 = os.environ.get("NURI_ETH2_AID", "4E5552494554483201")  # _launch/CONTRACTS.md C4

SIM_SEED = b"nuri-card-sim-v1"

APDU_VERSION = bytes.fromhex("8001000000")
APDU_PUBKEY = bytes.fromhex("8002000000")
APDU_SIGN_HDR = bytes.fromhex("8004000020")


class HostError(Exception):
    def __init__(self, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.code = code
        self.message = message
        self.extra = extra


# --------------------------------------------------------------------------- #
# secp256k1 helpers (python-ecdsa)                                            #
# --------------------------------------------------------------------------- #

def _curve():
    from ecdsa import SECP256k1
    return SECP256k1


def curve_order() -> int:
    return _curve().order


def keccak256(data: bytes) -> bytes:
    from Crypto.Hash import keccak
    return keccak.new(digest_bits=256).update(data).digest()


def pubkey_to_address(pubkey: bytes) -> str:
    """EIP-55 checksummed address from a compressed (33) or uncompressed (65) pubkey."""
    from ecdsa import VerifyingKey
    vk = VerifyingKey.from_string(pubkey, curve=_curve())
    raw = vk.to_string("uncompressed")[1:]
    addr = keccak256(raw)[-20:].hex()
    digest = keccak256(addr.encode("ascii")).hex()
    out = []
    for i, ch in enumerate(addr):
        if ch in "0123456789":
            out.append(ch)
        else:
            out.append(ch.upper() if int(digest[i], 16) >= 8 else ch)
    return "0x" + "".join(out)


def compress_pubkey(pubkey: bytes) -> bytes:
    from ecdsa import VerifyingKey
    return VerifyingKey.from_string(pubkey, curve=_curve()).to_string("compressed")


def normalize_low_s(r: int, s: int) -> tuple[int, int]:
    n = curve_order()
    if s > n // 2:
        s = n - s
    return r, s


def verify_and_recover(pubkey: bytes, digest: bytes, r: int, s: int) -> dict[str, Any]:
    """Verify (r,s) over digest against pubkey; low-s normalize; find yParity by recovery.

    Raises HostError("VERIFY_FAILED") if the signature does not verify or no
    recovery candidate matches the card pubkey.
    """
    from ecdsa import VerifyingKey, BadSignatureError
    from ecdsa.util import sigdecode_string

    n = curve_order()
    if not (1 <= r < n and 1 <= s < n):
        raise HostError("VERIFY_FAILED", "r or s out of range")
    r, s = normalize_low_s(r, s)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    vk = VerifyingKey.from_string(pubkey, curve=_curve())
    try:
        vk.verify_digest(sig, digest, sigdecode=sigdecode_string)
    except BadSignatureError as exc:
        raise HostError("VERIFY_FAILED", f"signature does not verify against card pubkey: {exc}")

    expected = vk.to_string("compressed")
    try:
        candidates = VerifyingKey.from_public_key_recovery_with_digest(
            sig, digest, _curve(), sigdecode=sigdecode_string
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise HostError("VERIFY_FAILED", f"recovery failed: {exc}")
    # python-ecdsa returns the candidates in recovery-id order (even y first).
    y_parity = None
    for idx, cand in enumerate(candidates):
        if cand.to_string("compressed") == expected:
            y_parity = idx
            break
    if y_parity is None:
        raise HostError("VERIFY_FAILED", "no recovery candidate matches card pubkey")
    v = 27 + y_parity
    return {
        "r": "0x" + r.to_bytes(32, "big").hex(),
        "s": "0x" + s.to_bytes(32, "big").hex(),
        "yParity": y_parity,
        "signature": "0x" + sig.hex() + bytes([v]).hex(),
    }


def parse_der_signature(der: bytes) -> tuple[int, int]:
    from ecdsa.util import sigdecode_der
    return sigdecode_der(der, curve_order())


def parse_eth2_signature(resp: bytes, expected_pubkey: bytes | None = None) -> tuple[int, int]:
    """Parse an ETH v2 SIGN response (card/eth2/NuriEthSignerV2.java).

    Native format: r(32) || s(32, low-S) || pubkey(65, uncompressed) = 129 bytes.
    The echoed pubkey must match the card identity when one is given (a
    mismatch means we are talking to a different key than `info` reported).
    A DER SEQUENCE is accepted too so a card OS that skips the on-card
    r||s||pub packing still works; the caller verifies either way.
    """
    if len(resp) == 129 and resp[64] == 0x04:
        if expected_pubkey is not None and compress_pubkey(resp[64:]) != compress_pubkey(expected_pubkey):
            raise HostError("VERIFY_FAILED", "ETH2 SIGN echoed a pubkey that differs from the card identity")
        return int.from_bytes(resp[:32], "big"), int.from_bytes(resp[32:64], "big")
    if resp[:1] == b"\x30":
        try:
            return parse_der_signature(resp)
        except Exception as exc:
            raise HostError("CARD_ERROR", f"ETH2 DER signature unparsable: {resp.hex()} ({exc})")
    raise HostError("CARD_ERROR", f"ETH2 signature must be r||s||pub65 (129 B) or DER, got {len(resp)} B: {resp.hex()}")


# --------------------------------------------------------------------------- #
# Signers                                                                     #
# --------------------------------------------------------------------------- #

class SimSigner:
    """Public, deterministic software key. NEVER a wallet: anyone can derive d."""

    mode = "sim"
    applet = "eth1"
    applet_version = "sim"
    reader = "simulator"
    pin_set = False
    pin_tries_left = None

    def __init__(self) -> None:
        from ecdsa import SigningKey
        n = curve_order()
        d = int.from_bytes(hashlib.sha256(SIM_SEED).digest(), "big") % n
        self._sk = SigningKey.from_secret_exponent(d, curve=_curve())
        self.pubkey = self._sk.get_verifying_key().to_string("compressed")

    def sign_digest(self, digest: bytes, expected: dict | None = None) -> tuple[int, int]:
        from ecdsa.util import sigencode_string
        sig = self._sk.sign_digest_deterministic(digest, sigencode=sigencode_string)
        return int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")

    def verify_pin_and_sign(self, pin: bytearray, digest: bytes, expected: dict) -> tuple[int, int]:
        raise HostError("PIN_NOT_SET", "simulator has no PIN; use sign_hash")

    def close(self) -> None:
        pass


def _wipe(buf: Any) -> None:
    """Zero a mutable buffer in place (best effort; immutable str/bytes copies cannot be wiped)."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


_PCSC_CODES = ("NO_READER", "NO_CARD", "NO_APPLET")


def _check_sw(sw: int, what: str) -> None:
    """Map a status word to a C2 error code. Messages never contain APDU data."""
    if sw == 0x9000:
        return
    if sw == 0x6982:
        raise HostError("PIN_REQUIRED", f"{what}: applet requires PIN verification (SW 6982)")
    if sw == 0x6983:
        raise HostError("PIN_BLOCKED", f"{what}: PIN blocked (SW 6983)", tries_left=0)
    if (sw & 0xFFF0) == 0x63C0:
        left = sw & 0x0F
        if left == 0:
            raise HostError("PIN_BLOCKED", f"{what}: PIN blocked (SW {sw:04X})", tries_left=0)
        raise HostError("PIN_WRONG", f"{what}: wrong PIN, {left} tries left (SW {sw:04X})", tries_left=left)
    if sw == 0x6985 and what == "VERIFY PIN":
        raise HostError("PIN_NOT_SET", f"{what}: applet has no PIN configured (SW 6985)")
    raise HostError("CARD_ERROR", f"{what}: SW {sw:04X}")


class CardSigner:
    """Talks to the ETH applet through scripts/nuri_pcsc.py (contract C1).

    Every operation opens a fresh applet session and closes it on every exit.
    Signing re-reads VERSION + PUBKEY in the signing session and refuses
    (CARD_CHANGED) unless applet and pubkey equal the identity `info` returned.
    """

    mode = "card"

    def __init__(self, reader: str | None = None) -> None:
        if SCRIPTS_DIR not in sys.path:
            sys.path.insert(0, SCRIPTS_DIR)
        try:
            import nuri_pcsc  # noqa: F401  (W1 deliverable; present after merge)
        except ImportError as exc:
            raise HostError(
                "CARD_ERROR",
                f"scripts/nuri_pcsc.py not importable ({exc}); card mode needs the W1 branch merged.",
            )
        self._pcsc = nuri_pcsc
        self._reader_hint = reader or os.environ.get("NURI_READER") or None
        self.applet = "eth1"
        self.applet_version = "?"
        self.reader = ""
        self.pin_set = False
        self.pin_tries_left = None
        self._applet = None
        self.pubkey = b""
        self._open()
        try:
            self._load_identity()
        finally:
            self.close()

    # -- transport ---------------------------------------------------------
    def _open(self) -> None:
        CardError = self._pcsc.CardError

        def code_of(exc) -> str:
            code = getattr(exc, "code", "")
            return code if code in _PCSC_CODES else "CARD_ERROR"

        try:
            self._applet = self._pcsc.open_applet(AID_ETH_V2, reader=self._reader_hint)
            self.applet = "eth2"
        except CardError as exc:
            if getattr(exc, "code", "") != "NO_APPLET":
                raise HostError(code_of(exc), str(exc))
            try:
                self._applet = self._pcsc.open_applet(AID_ETH_V1, reader=self._reader_hint)
                self.applet = "eth1"
            except CardError as exc2:
                raise HostError(code_of(exc2), str(exc2))
        self.reader = getattr(self._applet, "reader_name", "")

    def _tx(self, apdu: Any, what: str) -> bytes:
        data, sw = self._applet.transmit(apdu)
        _check_sw(sw, what)
        return bytes(data)

    def close(self) -> None:
        if self._applet is not None:
            try:
                self._applet.close()
            except Exception:
                pass
            self._applet = None

    # -- identity ------------------------------------------------------------
    def _load_identity(self) -> None:
        self.pin_set = False
        self.pin_tries_left = None
        ver = self._tx(APDU_VERSION, "GET VERSION")
        if len(ver) >= 3:
            self.applet_version = f"{ver[0]}.{ver[1]}.{ver[2]}"
        if self.applet == "eth2":
            if len(ver) < 9:
                raise HostError("CARD_ERROR", f"ETH2 VERSION must be 9 bytes, got {len(ver)}")
            # 02 00 00 'ETH2' state(b0 keyed, b1 pinSet) pinTriesLeft (card/eth2/NuriEthSignerV2.java:227-236)
            self.pin_set = bool(ver[7] & 0x02)
            self.pin_tries_left = ver[8] if self.pin_set else None
            if not (ver[7] & 0x01):
                raise HostError("CARD_ERROR", "ETH2 applet has no key yet (KEYGEN not run)")
        pub = self._tx(APDU_PUBKEY, "GET PUBKEY")
        if self.applet == "eth2":
            if len(pub) != 65 or pub[0] != 0x04:
                raise HostError("CARD_ERROR", f"ETH2 pubkey malformed: {pub.hex()}")
            self.pubkey = compress_pubkey(pub)
        else:
            if len(pub) != 33 or pub[0] not in (0x02, 0x03):
                raise HostError("CARD_ERROR", f"ETH1 pubkey malformed: {pub.hex()}")
            self.pubkey = pub

    def _check_identity(self, expected: dict) -> None:
        if self.applet != expected["applet"] or self.pubkey != expected["pubkey"]:
            raise HostError("CARD_CHANGED", "card identity differs from the last info; call info again")

    def _sign_in_session(self, digest: bytes) -> tuple[int, int]:
        apdu = bytearray(5 + len(digest))
        apdu[0:5] = APDU_SIGN_HDR
        apdu[5:] = digest
        try:
            resp = self._tx(apdu, "SIGN")
        finally:
            _wipe(apdu)
        if self.applet == "eth2":
            return parse_eth2_signature(resp, self.pubkey)
        if len(resp) != 65:
            raise HostError("CARD_ERROR", f"ETH1 signature must be 65 bytes, got {len(resp)}: {resp.hex()}")
        # Card-reported v (resp[64]) is ignored on purpose: yParity is recomputed by recovery.
        return int.from_bytes(resp[:32], "big"), int.from_bytes(resp[32:64], "big")

    # -- signing -------------------------------------------------------------
    def sign_digest(self, digest: bytes, expected: dict) -> tuple[int, int]:
        """No-PIN path: ETH1, or ETH2 without a PIN. PIN-protected ETH2 -> PIN_REQUIRED."""
        self._open()
        try:
            self._load_identity()
            self._check_identity(expected)
            if self.applet == "eth2" and self.pin_set:
                raise HostError("PIN_REQUIRED", "ETH2 PIN is set; use verify_pin", tries_left=self.pin_tries_left)
            return self._sign_in_session(digest)
        finally:
            self.close()

    def verify_pin_and_sign(self, pin: bytearray, digest: bytes, expected: dict) -> tuple[int, int]:
        """VERIFY_PIN then SIGN on the SAME open ETH2 session; closed on every exit.

        Validation is session-scoped on the card (deselect resets it,
        card/eth2/NuriEthSignerV2.java:188-191), so closing ends it.
        """
        self._open()
        apdu = None
        try:
            self._load_identity()
            self._check_identity(expected)
            if self.applet != "eth2" or not self.pin_set:
                raise HostError("PIN_NOT_SET", "applet has no PIN configured; use sign_hash")
            apdu = bytearray(5 + len(pin))  # filled in place: no unwiped temporaries
            apdu[0:5] = b"\x80\x20\x00\x00" + bytes([len(pin)])
            apdu[5:] = pin
            try:
                self._tx(apdu, "VERIFY PIN")
            finally:
                _wipe(apdu)
            return self._sign_in_session(digest)
        finally:
            _wipe(apdu)
            self.close()


# Process-local session state. Nothing here is a secret; the PIN is never stored.
_SIGNER = None
_INFO: dict | None = None      # identity returned by the last successful info
_SIM_ACK = False               # set only after info returned ok with mode == "sim"
_SIM_FLAG = False              # --sim was passed on argv (a declaration, not authorization)


def resolve_mode() -> str:
    """card unless NURI_CARD_SIM is exactly "1". Unknown values fail closed (no sim, no card)."""
    raw = os.environ.get("NURI_CARD_SIM")
    if raw == "1":
        return "sim"
    if _SIM_FLAG:
        raise HostError("CONFIG_ERROR", "--sim requires NURI_CARD_SIM=1 exactly in the environment")
    if raw in (None, "", "0"):
        return "card"
    raise HostError("CONFIG_ERROR", "NURI_CARD_SIM must be unset, 0 or exactly 1")


def get_signer():
    """Signer for `info`: sim is reused, card identity is re-read on every info."""
    global _SIGNER
    mode = resolve_mode()
    if mode == "sim":
        if not isinstance(_SIGNER, SimSigner):
            _SIGNER = SimSigner()
    else:
        _SIGNER = CardSigner()
    return _SIGNER


def _signing_signer():
    """Signer for sign_hash / verify_pin: only the one `info` just reported."""
    mode = resolve_mode()
    if _INFO is None or _INFO["mode"] != mode or _SIGNER is None or _SIGNER.mode != mode:
        raise HostError("INFO_REQUIRED", "call info on this connection before signing")
    if mode == "sim":
        if not _SIM_ACK or os.environ.get("NURI_CARD_SIM") != "1":
            raise HostError("SIM_NOT_AUTHORIZED", "simulator signing needs NURI_CARD_SIM=1 and a prior sim info")
    return _SIGNER


def _reset_session() -> None:
    global _INFO, _SIM_ACK
    _INFO = None
    _SIM_ACK = False


# --------------------------------------------------------------------------- #
# Request handling                                                            #
# --------------------------------------------------------------------------- #

_STRICT_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
_STRICT_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")


def parse_hash(value: Any) -> bytes:
    if not isinstance(value, str):
        raise HostError("BAD_REQUEST", "params.hash must be a 0x-prefixed hex string")
    h = value[2:] if value.lower().startswith("0x") else value
    if len(h) != 64:
        raise HostError("BAD_REQUEST", "params.hash must be exactly 32 bytes (64 hex chars)")
    try:
        return bytes.fromhex(h)
    except ValueError:
        raise HostError("BAD_REQUEST", "params.hash is not valid hex")


def parse_hash_strict(value: Any) -> bytes:
    if not isinstance(value, str) or not _STRICT_HASH.fullmatch(value):
        raise HostError("BAD_REQUEST", "params.hash must be 0x + exactly 64 hex chars")
    return bytes.fromhex(value[2:])


def parse_address(value: Any) -> str:
    if not isinstance(value, str) or not _STRICT_ADDR.fullmatch(value):
        raise HostError("BAD_REQUEST", "params.address must be 0x + 40 hex chars")
    lower = value.lower()
    if value != _checksum(lower[2:]):
        raise HostError("BAD_REQUEST", "params.address must be EIP-55 checksummed")
    return value


def _checksum(addr_hex_lower: str) -> str:
    digest = keccak256(addr_hex_lower.encode("ascii")).hex()
    return "0x" + "".join(
        ch.upper() if ch not in "0123456789" and int(digest[i], 16) >= 8 else ch
        for i, ch in enumerate(addr_hex_lower)
    )


def _pin_buffer(pin: Any) -> bytearray:
    if not isinstance(pin, str):
        raise HostError("BAD_REQUEST", "params.pin must be a string")
    buf = bytearray(pin.encode("utf-8"))
    if not 4 <= len(buf) <= 16:
        _wipe(buf)
        raise HostError("BAD_REQUEST", "params.pin must be 4..16 bytes")
    return buf


def _do_info(req_id: Any) -> dict[str, Any]:
    global _INFO, _SIM_ACK
    _reset_session()
    signer = get_signer()
    if signer.mode not in ("card", "sim"):
        raise HostError("CONFIG_ERROR", "unknown signer mode")
    address = pubkey_to_address(signer.pubkey)
    _INFO = {"mode": signer.mode, "applet": signer.applet, "pubkey": signer.pubkey, "address": address}
    _SIM_ACK = signer.mode == "sim"
    return ok_response(req_id, {
        "applet": signer.applet,
        "applet_version": signer.applet_version,
        "pubkey": "0x" + signer.pubkey.hex(),
        "address": address,
        "reader": signer.reader,
        "mode": signer.mode,
        "pin_set": bool(signer.pin_set),
        "pin_tries_left": signer.pin_tries_left,
    })


def handle(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        return error_response(None, "BAD_REQUEST", "request must be a JSON object")
    req_id = request.get("id")
    method = request.get("method")
    params = request.get("params")
    # Pop the PIN before anything else can fail, log or echo the request.
    pin = params.pop("pin", None) if isinstance(params, dict) else None
    request.pop("pin", None)
    pin_buf = None
    try:
        if method == "info":
            return _do_info(req_id)
        if method == "sign_hash":
            params = params or {}
            if not isinstance(params, dict):
                raise HostError("BAD_REQUEST", "params must be an object")
            digest = parse_hash(params.get("hash"))
            signer = _signing_signer()
            r, s = signer.sign_digest(digest, _INFO)
            return ok_response(req_id, verify_and_recover(signer.pubkey, digest, r, s))
        if method == "verify_pin":
            if not isinstance(params, dict):
                raise HostError("BAD_REQUEST", "params must be an object")
            pin_buf = _pin_buffer(pin)
            pin = None
            digest = parse_hash_strict(params.get("hash"))
            address = parse_address(params.get("address"))
            signer = _signing_signer()
            if address != _INFO["address"]:
                raise HostError("ADDRESS_MISMATCH", "params.address is not the address info reported")
            r, s = signer.verify_pin_and_sign(pin_buf, digest, _INFO)
            return ok_response(req_id, verify_and_recover(signer.pubkey, digest, r, s))
        raise HostError("BAD_REQUEST", f"unknown method {method!r}")
    except HostError as exc:
        if exc.code == "CARD_CHANGED":
            _reset_session()
        return error_response(req_id, exc.code, exc.message, exc.extra)
    except Exception as exc:  # never leak a traceback as a crash; report it
        if method == "verify_pin":
            # The exception text may embed APDU bytes (the PIN): never echo it.
            return error_response(req_id, "CARD_ERROR", f"internal error during verify_pin ({type(exc).__name__})")
        return error_response(req_id, "CARD_ERROR", f"{type(exc).__name__}: {exc}")
    finally:
        _wipe(pin_buf)
        pin = None
        if isinstance(params, dict):
            params.pop("pin", None)


def ok_response(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"id": req_id, "ok": True, "result": result}


def error_response(req_id: Any, code: str, message: str, extra: dict | None = None) -> dict[str, Any]:
    err = {"code": code, "message": message}
    if extra:
        err.update(extra)
    return {"id": req_id, "ok": False, "error": err}


# --------------------------------------------------------------------------- #
# Framing                                                                     #
# --------------------------------------------------------------------------- #

def read_message(stream) -> Any | None:
    raw_len = stream.read(4)
    if not raw_len or len(raw_len) < 4:
        return None
    (length,) = struct.unpack("<I", raw_len)
    if length > 1024 * 1024:
        raise HostError("BAD_REQUEST", f"message too large: {length} bytes")
    body = stream.read(length)
    if len(body) < length:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        # No exception text: it may quote bytes of the frame (which may hold a PIN).
        raise HostError("BAD_REQUEST", "invalid JSON frame")


def write_message(stream, obj: Any) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack("<I", len(body)) + body)
    stream.flush()


def serve(stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    log_path = os.environ.get("NURI_CARD_HOST_LOG")
    log = open(log_path, "a") if log_path else None
    while True:
        try:
            request = read_message(stdin)
        except HostError as exc:
            write_message(stdout, error_response(None, exc.code, exc.message))
            continue
        if request is None:
            break
        req_id = request.get("id") if isinstance(request, dict) else None
        method = request.get("method") if isinstance(request, dict) else None
        response = handle(request)
        request = None
        if log:
            # Only id, method and error code: never params, never error messages.
            log.write(json.dumps({"id": req_id if isinstance(req_id, (int, str)) else None,
                                  "method": method if isinstance(method, str) else None,
                                  "ok": response.get("ok"),
                                  "error_code": (response.get("error") or {}).get("code")}) + "\n")
            log.flush()
        write_message(stdout, response)
    return 0


def main(argv: list[str]) -> int:
    global _SIM_FLAG
    # --sim only declares intent; it never authorizes sim. Without NURI_CARD_SIM=1
    # every request fails CONFIG_ERROR (no silent card or sim fallback).
    _SIM_FLAG = "--sim" in argv
    # Chrome passes the extension origin (chrome-extension://<id>/) as argv[1]; nothing to do with it.
    return serve()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
