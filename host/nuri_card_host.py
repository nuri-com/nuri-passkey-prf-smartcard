#!/usr/bin/env python3
"""Chrome native messaging host `com.nuri.card` (contract C2).

Framing: 4-byte little-endian length + UTF-8 JSON, one request -> one response,
looped until stdin closes (works for both sendNativeMessage and connectNative).

Methods
  {"id": n, "method": "info"}
  {"id": n, "method": "sign_hash", "params": {"hash": "0x<64 hex>"}}

The host only ever signs 32-byte hashes (keccak/RLP/EIP-712 hashing is the
extension's job). Every signature is verified against the card pubkey, low-s
normalized (EIP-2) and gets its yParity by public-key recovery before it is
returned; an unverifiable signature is reported as VERIFY_FAILED.

Modes
  card (default): lazily imports scripts/nuri_pcsc.py (contract C1) and talks
       to the ETH applet. Prefers ETH v2 (AID 4E5552494554483201, C4), falls
       back to ETH v1 (AID 4E55524945544801, C3).
  sim: env NURI_CARD_SIM=1 or --sim -> software key
       d = int(sha256(b"nuri-card-sim-v1")) mod n. Tests use sim only.

Dependencies: python-ecdsa (verify / recovery), pycryptodome (keccak256 for the
EIP-55 address; same choice as scripts/card-dashboard-server.py), pyscard only
in card mode via nuri_pcsc.
"""

from __future__ import annotations

import hashlib
import json
import os
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
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


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


# --------------------------------------------------------------------------- #
# Signers                                                                     #
# --------------------------------------------------------------------------- #

class SimSigner:
    mode = "sim"
    applet = "eth1"
    applet_version = "sim"
    reader = "simulator"

    def __init__(self) -> None:
        from ecdsa import SigningKey
        n = curve_order()
        d = int.from_bytes(hashlib.sha256(SIM_SEED).digest(), "big") % n
        self._sk = SigningKey.from_secret_exponent(d, curve=_curve())
        self.pubkey = self._sk.get_verifying_key().to_string("compressed")

    def sign_digest(self, digest: bytes) -> tuple[int, int]:
        from ecdsa.util import sigencode_string
        sig = self._sk.sign_digest_deterministic(digest, sigencode=sigencode_string)
        return int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")

    def close(self) -> None:
        pass


class CardSigner:
    """Talks to the ETH applet through scripts/nuri_pcsc.py (contract C1)."""

    mode = "card"

    def __init__(self, reader: str | None = None) -> None:
        if SCRIPTS_DIR not in sys.path:
            sys.path.insert(0, SCRIPTS_DIR)
        try:
            import nuri_pcsc  # noqa: F401  (W1 deliverable; present after merge)
        except ImportError as exc:
            raise HostError(
                "CARD_ERROR",
                f"scripts/nuri_pcsc.py not importable ({exc}); card mode needs the W1 branch merged. "
                "Use NURI_CARD_SIM=1 for the software simulator.",
            )
        self._pcsc = nuri_pcsc
        self._reader_hint = reader or os.environ.get("NURI_READER") or None
        self.applet = "eth1"
        self.applet_version = "?"
        self.reader = ""
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
        try:
            self._applet = self._pcsc.open_applet(AID_ETH_V2, reader=self._reader_hint)
            self.applet = "eth2"
        except CardError as exc:
            if getattr(exc, "code", "") != "NO_APPLET":
                raise HostError(getattr(exc, "code", "CARD_ERROR"), str(exc))
            try:
                self._applet = self._pcsc.open_applet(AID_ETH_V1, reader=self._reader_hint)
                self.applet = "eth1"
            except CardError as exc2:
                raise HostError(getattr(exc2, "code", "CARD_ERROR"), str(exc2))
        self.reader = getattr(self._applet, "reader_name", "")

    def _tx(self, apdu: bytes, what: str) -> bytes:
        data, sw = self._applet.transmit(apdu)
        if sw == 0x6982:
            raise HostError("PIN_REQUIRED", f"{what}: applet requires PIN verification (SW 6982)")
        if sw != 0x9000:
            raise HostError("CARD_ERROR", f"{what}: SW {sw:04X}")
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
        ver = self._tx(APDU_VERSION, "GET VERSION")
        if len(ver) >= 3:
            self.applet_version = f"{ver[0]}.{ver[1]}.{ver[2]}"
        pub = self._tx(APDU_PUBKEY, "GET PUBKEY")
        if self.applet == "eth2":
            if len(pub) != 65 or pub[0] != 0x04:
                raise HostError("CARD_ERROR", f"ETH2 pubkey malformed: {pub.hex()}")
            self.pubkey = compress_pubkey(pub)
        else:
            if len(pub) != 33 or pub[0] not in (0x02, 0x03):
                raise HostError("CARD_ERROR", f"ETH1 pubkey malformed: {pub.hex()}")
            self.pubkey = pub

    # -- signing -------------------------------------------------------------
    def sign_digest(self, digest: bytes) -> tuple[int, int]:
        self._open()
        try:
            resp = self._tx(APDU_SIGN_HDR + digest, "SIGN")
        finally:
            self.close()
        if self.applet == "eth2":
            try:
                return parse_der_signature(resp)
            except Exception as exc:
                raise HostError("CARD_ERROR", f"ETH2 DER signature unparsable: {resp.hex()} ({exc})")
        if len(resp) != 65:
            raise HostError("CARD_ERROR", f"ETH1 signature must be 65 bytes, got {len(resp)}: {resp.hex()}")
        # Card-reported v (resp[64]) is ignored on purpose: yParity is recomputed by recovery.
        return int.from_bytes(resp[:32], "big"), int.from_bytes(resp[32:64], "big")


_SIGNER = None


def get_signer():
    global _SIGNER
    if _SIGNER is None:
        if os.environ.get("NURI_CARD_SIM") == "1":
            _SIGNER = SimSigner()
        else:
            _SIGNER = CardSigner()
    return _SIGNER


# --------------------------------------------------------------------------- #
# Request handling                                                            #
# --------------------------------------------------------------------------- #

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


def handle(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        return error_response(None, "BAD_REQUEST", "request must be a JSON object")
    req_id = request.get("id")
    method = request.get("method")
    try:
        if method == "info":
            signer = get_signer()
            return ok_response(req_id, {
                "applet": signer.applet,
                "applet_version": signer.applet_version,
                "pubkey": "0x" + signer.pubkey.hex(),
                "address": pubkey_to_address(signer.pubkey),
                "reader": signer.reader,
                "mode": signer.mode,
            })
        if method == "sign_hash":
            params = request.get("params") or {}
            if not isinstance(params, dict):
                raise HostError("BAD_REQUEST", "params must be an object")
            digest = parse_hash(params.get("hash"))
            signer = get_signer()
            r, s = signer.sign_digest(digest)
            return ok_response(req_id, verify_and_recover(signer.pubkey, digest, r, s))
        raise HostError("BAD_REQUEST", f"unknown method {method!r}")
    except HostError as exc:
        return error_response(req_id, exc.code, exc.message)
    except Exception as exc:  # never leak a traceback as a crash; report it
        return error_response(req_id, "CARD_ERROR", f"{type(exc).__name__}: {exc}")


def ok_response(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"id": req_id, "ok": True, "result": result}


def error_response(req_id: Any, code: str, message: str) -> dict[str, Any]:
    return {"id": req_id, "ok": False, "error": {"code": code, "message": message}}


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
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HostError("BAD_REQUEST", f"invalid JSON: {exc}")


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
        response = handle(request)
        if log:
            log.write(json.dumps({"request": {k: v for k, v in request.items() if k != "params"},
                                  "response_ok": response.get("ok")}) + "\n")
            log.flush()
        write_message(stdout, response)
    return 0


def main(argv: list[str]) -> int:
    if "--sim" in argv:
        os.environ["NURI_CARD_SIM"] = "1"
    # Chrome passes the extension origin (chrome-extension://<id>/) as argv[1]; nothing to do with it.
    return serve()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
