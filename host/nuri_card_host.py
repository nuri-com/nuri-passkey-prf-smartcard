#!/usr/bin/env python3
"""Chrome native messaging host `com.nuri.card` (contract C2).

Framing: 4-byte little-endian length + UTF-8 JSON, one request -> one response,
looped until stdin closes (works for both sendNativeMessage and connectNative).
A malformed frame (partial header/body, length 0 or > 1 MiB, bad UTF-8/JSON,
too-deep nesting, or a frame not completed within NURI_CARD_HOST_FRAME_TIMEOUT
seconds of its first byte, default 5) gets one error reply and ends the
session with exit code 1; nothing after it is parsed.

Methods (issue info first on the same connection; signing refuses otherwise)
  {"id": n, "method": "info"}
      -> {applet, applet_version, pubkey, address, reader, mode, pin_set, pin_tries_left,
          attestation: {verified, reason}}
      Authenticity is false/unverified without NURI_CARD_CA_PUBKEY (a PEM/hex
      P256 CA public-key file). Only fresh, key/AID-bound evidence can be true.
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
       to the ETH applet. Prefers ETH v2 (AID 4E5552494554483201, C4). W28: the
       legacy PIN-less ETH v1 (AID 4E55524945544801, C3) is used ONLY when env
       NURI_ALLOW_ETH1_DEMO is exactly "1" (else ETH1_DEMO_DISABLED) AND every
       reader positively answers SELECT ETH2 with 6A82 (else DOWNGRADE_REFUSED:
       nuri_pcsc's NO_APPLET also covers SELECT transport faults). Transport and
       PIN failures on ETH2 never downgrade. ETH1 use warns on stderr and in info.
  sim: only when env NURI_CARD_SIM is exactly "1" -> PUBLIC software key
       d = int(sha256(b"nuri-card-sim-v1")) mod n. Signing additionally needs a
       successful info(mode=sim) in this process. --sim alone authorizes nothing;
       any other NURI_CARD_SIM value is CONFIG_ERROR (no fallback either way).
  Every response (ok and error, including framing errors) carries a top-level
  "mode": "card" | "sim" | "invalid" (NURI_CARD_SIM/--sim misconfigured).
  Startup prints a stderr warning in sim mode and when the ETH1 demo is enabled.

Dependencies: python-ecdsa (verify / recovery), pycryptodome (keccak256 for the
EIP-55 address; same choice as scripts/card-dashboard-server.py), pyscard only
in card mode via nuri_pcsc.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import select
import struct
import sys
import time
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")

AID_ETH_V1 = "4E55524945544801"
AID_ETH_V2 = os.environ.get("NURI_ETH2_AID", "4E5552494554483201")  # _launch/CONTRACTS.md C4

SIM_SEED = b"nuri-card-sim-v1"

ETH1_DEMO_ENV = "NURI_ALLOW_ETH1_DEMO"
SW_FILE_NOT_FOUND = 0x6A82
ETH1_WARNING = ("WARNING: ETH1 DEMO (NURI_ALLOW_ETH1_DEMO=1): the legacy ETH1 applet has NO PIN; "
                "any local process can sign with it. Demo only, never fund its address.")
SIM_WARNING = ("WARNING: SIM MODE (NURI_CARD_SIM=1): signing with a PUBLIC software key "
               "(sha256(b'nuri-card-sim-v1')); anyone can derive it. Never fund its address.")


def eth1_demo_allowed() -> bool:
    return os.environ.get(ETH1_DEMO_ENV) == "1"


def _warn(text: str) -> None:
    """stderr only: stdout carries native-messaging frames."""
    try:
        print(text, file=sys.stderr, flush=True)
    except Exception:
        pass

APDU_VERSION = bytes.fromhex("8001000000")
APDU_PUBKEY = bytes.fromhex("8002000000")
APDU_SIGN_HDR = bytes.fromhex("8004000020")


class HostError(Exception):
    def __init__(self, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.code = code
        self.message = message
        self.extra = extra


class FramingError(HostError):
    """The byte stream can no longer be trusted; serve() must stop reading."""

    def __init__(self, message: str):
        super().__init__("BAD_REQUEST", message)


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
        self.attestation = {"verified": False, "reason": "unverified"}
        self._open()
        try:
            self._load_identity()
            self._load_attestation()
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
                raise HostError(code_of(exc), str(exc))  # no reader/card/transport: never downgrade
            if not eth1_demo_allowed():
                raise HostError("ETH1_DEMO_DISABLED",
                                "PIN-gated ETH2 applet not found; the legacy ETH1 applet has no PIN and needs "
                                f"{ETH1_DEMO_ENV}=1 exactly (demo only)")
            self._confirm_eth2_absent()
            try:
                self._applet = self._pcsc.open_applet(AID_ETH_V1, reader=self._reader_hint)
                self.applet = "eth1"
            except CardError as exc2:
                raise HostError(code_of(exc2), str(exc2))
            _warn_eth1_once()
        self.reader = getattr(self._applet, "reader_name", "")

    def _confirm_eth2_absent(self) -> None:
        """Re-probe every candidate reader; only SW 6A82 on all of them allows ETH1.

        nuri_pcsc.open_applet reports NO_APPLET both for 6A82 and for a SELECT whose
        transmit raised, so its NO_APPLET alone is never trusted for a downgrade.
        Same pattern as scripts/pkcs11-helper.py require_eth2_absent (inline: the
        installed host is a fixed file snapshot).
        """
        pcsc = self._pcsc
        try:
            candidates = pcsc._select_readers(pcsc._list_readers(), self._reader_hint)
            select = pcsc.select_apdu(AID_ETH_V2)
        except Exception as exc:
            raise HostError("DOWNGRADE_REFUSED", f"cannot confirm ETH2 absence ({type(exc).__name__}); refusing ETH1")
        if not candidates:
            raise HostError("DOWNGRADE_REFUSED", "cannot confirm ETH2 absence: no reader; refusing ETH1")
        faults = []
        for rdr in candidates:
            conn = rdr.createConnection()
            absent = False

            def probe(raw):
                nonlocal absent
                try:
                    _, sw = pcsc.transmit_raw(raw, select)
                except Exception:
                    faults.append("ETH2 SELECT transport failure")
                    raise
                if sw == SW_FILE_NOT_FOUND:
                    absent = True
                    return True  # absence positively known; stop the protocol ladder
                faults.append(f"ETH2 absence not confirmed (SW {sw:04X})")
                return False

            try:
                pcsc.connect_ladder(conn, probe)
            except Exception:
                faults.append("ETH2 reader/protocol failure")
            finally:
                pcsc._disconnect(conn)
            if not absent:
                faults.append("ETH2 absence not confirmed for reader")
        if faults:
            raise HostError("DOWNGRADE_REFUSED", "refusing ETH1 downgrade: " + "; ".join(faults))

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

    def _load_attestation(self) -> None:
        """Read-only, fresh evidence on the SAME selection as VERSION/PUBKEY.

        A missing CA pin, legacy applet, failed transport or invalid evidence
        never prevents info/signing; none of those paths can assert authenticity.
        The CA setting is a local PEM/hex public-key FILE, never response data.
        """
        ca_path = os.environ.get("NURI_CARD_CA_PUBKEY")
        if not ca_path:
            return
        if self.applet != "eth2":
            self.attestation = {"verified": False, "reason": "unsupported"}
            return
        try:
            import nuri_attest

            expected_aid = bytes.fromhex(AID_ETH_V2)
            if expected_aid != nuri_attest.ETH2_AID:
                self.attestation = {"verified": False, "reason": "unsupported"}
                return
            with open(ca_path, "rb") as stream:
                ca_pubkey = stream.read(16385)
            if len(ca_pubkey) > 16384:
                raise ValueError("CA public key file too large")
            verifier = nuri_attest.ChallengeVerifier()
            challenge = verifier.issue()
            try:
                response = nuri_attest.read_attestation(self._applet, 0x80, challenge)
            except nuri_attest.AttestationCommandError as error:
                if error.sw in (0x6D00, 0x6E00):
                    self.attestation = {"verified": False, "reason": "unsupported"}
                    return
                raise
            verifier.verify(response, ca_pubkey, challenge, expected_aid, self.pubkey)
            self.attestation = {"verified": True, "reason": "verified"}
        except Exception:
            # Do not echo arbitrary transport/file/verification exception text.
            self.attestation = {"verified": False, "reason": "verification_failed"}

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


_ETH1_WARNED = False


def _warn_eth1_once() -> None:
    global _ETH1_WARNED
    if not _ETH1_WARNED:
        _ETH1_WARNED = True
        _warn(ETH1_WARNING)


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

_HASH_RE = re.compile(r"(?:0[xX])?[0-9a-fA-F]{64}")


def parse_hash(value: Any) -> bytes:
    """Strict: optional 0x prefix + exactly 64 ASCII hex digits -> exactly 32 bytes.

    bytes.fromhex alone skips whitespace, so a 64-char string such as
    "00 " * 21 + " " would decode to 21 bytes (W13 R11). fullmatch rejects it.
    """
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise HostError("BAD_REQUEST", "params.hash must be 0x + exactly 64 hex chars (32 bytes)")
    digest = bytes.fromhex(value[2:] if value[:2] in ("0x", "0X") else value)
    if len(digest) != 32:  # unreachable given the regex; kept as a hard invariant
        raise HostError("BAD_REQUEST", "params.hash must decode to exactly 32 bytes")
    return digest


_STRICT_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
_STRICT_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")


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
    extra = {"warning": ETH1_WARNING} if signer.mode == "card" and signer.applet == "eth1" else {}
    return ok_response(req_id, {**extra,
        "applet": signer.applet,
        "applet_version": signer.applet_version,
        "pubkey": "0x" + signer.pubkey.hex(),
        "address": address,
        "reader": signer.reader,
        "mode": signer.mode,
        "pin_set": bool(signer.pin_set),
        "pin_tries_left": signer.pin_tries_left,
        "attestation": dict(getattr(signer, "attestation", {"verified": False, "reason": "unverified"})),
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
            digest = parse_hash_strict(params.get("hash"))
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


def response_mode() -> str:
    """Mode label carried on EVERY response: card | sim | invalid (misconfigured sim env/flag)."""
    try:
        return resolve_mode()
    except HostError:
        return "invalid"


def ok_response(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"id": req_id, "ok": True, "mode": response_mode(), "result": result}


def error_response(req_id: Any, code: str, message: str, extra: dict | None = None) -> dict[str, Any]:
    err = {"code": code, "message": message}
    if extra:
        err.update(extra)
    return {"id": req_id, "ok": False, "mode": response_mode(), "error": err}


def startup_warnings() -> list[str]:
    """Warnings printed on stderr at startup (sim key, ETH1 demo, misconfiguration)."""
    out = []
    mode = response_mode()
    if mode == "sim":
        out.append(SIM_WARNING)
    elif mode == "invalid":
        out.append("WARNING: NURI_CARD_SIM/--sim misconfigured (need NURI_CARD_SIM=1 exactly for sim, or unset/0 "
                   "without --sim for card); every request fails CONFIG_ERROR")
    if eth1_demo_allowed():
        out.append(ETH1_WARNING + " (enabled only if the card has no ETH2 applet)")
    return out


# --------------------------------------------------------------------------- #
# Framing                                                                     #
# --------------------------------------------------------------------------- #

MAX_MESSAGE_BYTES = 1024 * 1024  # Chrome caps host-bound messages at 4 GiB; we accept 1 MiB.
DEFAULT_FRAME_TIMEOUT = 5.0  # seconds from a frame's first byte to its last


def frame_timeout_from_env() -> float:
    try:
        value = float(os.environ.get("NURI_CARD_HOST_FRAME_TIMEOUT", DEFAULT_FRAME_TIMEOUT))
    except ValueError:
        return DEFAULT_FRAME_TIMEOUT
    return value if 0 < value <= DEFAULT_FRAME_TIMEOUT else DEFAULT_FRAME_TIMEOUT


def _stream_fd(stream) -> int | None:
    """Real fd for pipes/files (deadline-capable), None for in-memory streams."""
    if os.name == "nt":  # select() does not work on Windows pipes; no deadline there
        return None
    try:
        return stream.fileno()
    except (AttributeError, OSError, ValueError):
        return None


def _read_exact(stream, fd: int | None, n: int, deadline: float | None) -> bytes:
    """Read exactly n bytes, or fewer only at EOF. Raises FramingError past the deadline.

    With a real fd we bypass Python's buffer (os.read) so select() sees all
    pending data; the caller never mixes buffered reads on the same stream.
    """
    buf = bytearray()
    while len(buf) < n:
        if fd is not None:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FramingError(f"frame stalled: {len(buf)}/{n} bytes before deadline")
                ready, _, _ = select.select([fd], [], [], remaining)
                if not ready:
                    raise FramingError(f"frame stalled: {len(buf)}/{n} bytes before deadline")
            chunk = os.read(fd, n - len(buf))
        else:
            chunk = stream.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


EOF = object()  # distinct from a JSON `null` body, which is a (bad) request, not end of stream


MAX_INT_DIGITS = 4300  # CPython 3.11+ int_max_str_digits default; enforced here for 3.9/3.10 too


def _bounded_int(text: str) -> int:
    # JSON ints longer than this are a CPU DoS on old Pythons; ValueError -> FramingError below.
    if len(text.lstrip("-")) > MAX_INT_DIGITS:
        raise ValueError("integer literal too long")
    return int(text)


def read_message(stream, frame_timeout: float | None = None) -> Any:
    """Return the decoded JSON value, or EOF on clean end of stream between frames.

    Any malformed frame raises FramingError: the caller must stop, because
    after a bad length or a partial frame the next byte is not a frame start.
    The deadline starts at the first header byte, so an idle host waiting
    for the next request is never timed out.
    """
    fd = _stream_fd(stream)
    first = _read_exact(stream, fd, 1, None)
    if not first:
        return EOF
    deadline = time.monotonic() + frame_timeout if (frame_timeout and fd is not None) else None
    rest = _read_exact(stream, fd, 3, deadline)
    if len(rest) < 3:
        raise FramingError(f"truncated header: {1 + len(rest)}/4 bytes")
    (length,) = struct.unpack("<I", first + rest)
    if length == 0:
        raise FramingError("empty message (length 0)")
    if length > MAX_MESSAGE_BYTES:
        raise FramingError(f"message too large: {length} bytes (max {MAX_MESSAGE_BYTES})")
    body = _read_exact(stream, fd, length, deadline)
    if len(body) < length:
        raise FramingError(f"truncated body: {len(body)}/{length} bytes")
    try:
        return json.loads(body.decode("utf-8"), parse_int=_bounded_int)
    except UnicodeDecodeError:
        raise FramingError("message is not valid UTF-8") from None
    except RecursionError:
        raise FramingError("JSON nested too deeply") from None
    except ValueError:  # JSONDecodeError, int-digit limit
        # No exception text: it may quote bytes of the frame (which may hold a PIN).
        raise FramingError("invalid JSON frame") from None


def write_message(stream, obj: Any) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    stream.write(struct.pack("<I", len(body)) + body)
    stream.flush()


def _log_entry(request: Any, response: dict[str, Any]) -> dict[str, Any]:
    """Only typed, bounded fields reach the log; never params or arbitrary keys."""
    if not isinstance(request, dict):
        return {"request": None, "invalid": type(request).__name__, "response_ok": response.get("ok")}
    req_id = request.get("id")
    method = request.get("method")
    return {
        "request": {
            "id": req_id if isinstance(req_id, (int, str)) and not isinstance(req_id, bool) and len(str(req_id)) <= 64 else None,
            "method": method if isinstance(method, str) and len(method) <= 64 else None,
        },
        "response_ok": response.get("ok"),
    }


def serve(stdin=None, stdout=None, frame_timeout: float | None = None) -> int:
    """Request loop. Returns 0 on clean EOF, 1 after a framing error (session closed)."""
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    if frame_timeout is None:
        frame_timeout = frame_timeout_from_env()
    log_path = os.environ.get("NURI_CARD_HOST_LOG")
    log = open(log_path, "a") if log_path else None
    try:
        while True:
            try:
                request = read_message(stdin, frame_timeout)
            except FramingError as exc:
                if log:
                    log.write(json.dumps({"framing_error": exc.message}) + "\n")
                    log.flush()
                write_message(stdout, error_response(None, exc.code, exc.message))
                return 1  # never parse bytes after a broken frame
            if request is EOF:
                return 0
            response = handle(request)
            entry = _log_entry(request, response) if log else None
            request = None  # drop the only reference to params (may hold a PIN)
            if log:
                log.write(json.dumps(entry) + "\n")
                log.flush()
            write_message(stdout, response)
    finally:
        if log:
            log.close()


def main(argv: list[str]) -> int:
    global _SIM_FLAG
    # --sim only declares intent; it never authorizes sim. Without NURI_CARD_SIM=1
    # every request fails CONFIG_ERROR (no silent card or sim fallback).
    _SIM_FLAG = "--sim" in argv
    for text in startup_warnings():
        _warn(text)
    # Chrome passes the extension origin (chrome-extension://<id>/) as argv[1]; nothing to do with it.
    return serve()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
