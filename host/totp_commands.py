"""On-card OATH-TOTP commands for the Chrome native messaging host.

Supports both the v1.0 applet (no STATUS, unauthenticated PUT) and v1.1+
(STATUS + PIN-authenticated PUT, 5 tries). Secrets stay on the card once saved
and are never logged, persisted on disk, or echoed back on errors.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import sys
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

AID = "4E555249544F5450"  # "NURITOTP"
INS_PUT = 0x01
INS_CALC = 0x02
INS_STATUS = 0x03
PIN_MIN, PIN_MAX = 4, 16

_SIM_SECRET: bytes | None = None


def parse_secret(raw_input: Any) -> bytes:
    """Decode a Base32 string or otpauth://totp/... URI into 1..64 secret bytes."""
    import nuri_card_host as host

    if not isinstance(raw_input, str) or not raw_input.strip():
        raise host.HostError("BAD_REQUEST", "secret must be a non-empty Base32 string or otpauth:// URI")
    text = raw_input.strip()
    if text.lower().startswith("otpauth://"):
        parsed = urlparse(text)
        if parsed.netloc.lower() != "totp":
            raise host.HostError("BAD_REQUEST", "only otpauth://totp/ URIs are supported")
        vals = parse_qs(parsed.query).get("secret")
        if not vals or not vals[0].strip():
            raise host.HostError("BAD_REQUEST", "otpauth:// URI is missing a secret parameter")
        text = vals[0].strip()
    cleaned = text.replace(" ", "").replace("-", "").upper()
    if not cleaned:
        raise host.HostError("BAD_REQUEST", "TOTP secret cannot be empty")
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        secret = base64.b32decode(padded, casefold=True)
    except Exception:
        raise host.HostError("BAD_REQUEST", "TOTP secret is not valid Base32") from None
    if not 1 <= len(secret) <= 64:
        raise host.HostError("BAD_REQUEST", f"TOTP secret must be 1..64 bytes (got {len(secret)})")
    return secret


def truncate(digest: bytes, digits: int = 6) -> str:
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % (10 ** digits):0{digits}d}"


def counter_bytes(step: int = 30, now: float | None = None) -> tuple[bytes, int]:
    t = time.time() if now is None else float(now)
    sec = int(t)
    ctr = struct.pack(">Q", sec // step)
    remaining = step - (sec % step)
    return ctr, remaining


def _validate_calc_params(params: Any) -> tuple[int, int]:
    import nuri_card_host as host

    if params is None:
        return 30, 6
    if not isinstance(params, dict):
        raise host.HostError("BAD_REQUEST", "params must be an object")
    step = params.get("step", 30)
    digits = params.get("digits", 6)
    if isinstance(step, bool) or not isinstance(step, int) or not 10 <= step <= 300:
        raise host.HostError("BAD_REQUEST", "step must be an integer between 10 and 300")
    if isinstance(digits, bool) or not isinstance(digits, int) or not 6 <= digits <= 8:
        raise host.HostError("BAD_REQUEST", "digits must be 6, 7, or 8")
    return step, digits


def _open_applet():
    import nuri_card_host as host

    if host.SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, host.SCRIPTS_DIR)
    try:
        import nuri_pcsc
    except ImportError as exc:
        raise host.HostError("CARD_ERROR", f"scripts/nuri_pcsc.py not importable ({exc})")
    reader_hint = os.environ.get("NURI_READER") or None
    try:
        return nuri_pcsc.open_applet(AID, reader=reader_hint)
    except nuri_pcsc.CardError as exc:
        code = exc.code if exc.code in ("NO_READER", "NO_CARD", "NO_APPLET") else "CARD_ERROR"
        raise host.HostError(code, str(exc))


def _probe_status(applet) -> dict[str, Any]:
    import nuri_card_host as host

    data, sw = applet.transmit(bytes([0x00, INS_STATUS, 0x00, 0x00, 0x00]))
    if sw == 0x9000 and len(data) == 3:
        return {
            "version": "1.1",
            "provisioned": bool(data[0]),
            "engine": "native" if data[1] == 0 else "software",
            "pin_tries_left": int(data[2]),
            "pin_required": True,
        }
    if sw == 0x6D00:
        return {
            "version": "1.0",
            "provisioned": None,
            "engine": "v1.0",
            "pin_tries_left": None,
            "pin_required": False,
        }
    raise host.HostError("CARD_ERROR", f"TOTP STATUS failed: SW {sw:04X}")


def handle_status(params: Any = None) -> dict[str, Any]:
    import nuri_card_host as host

    if host.resolve_mode() == "sim":
        return {
            "version": "sim",
            "provisioned": _SIM_SECRET is not None,
            "engine": "sim",
            "pin_tries_left": None,
            "pin_required": False,
        }
    applet = _open_applet()
    try:
        return _probe_status(applet)
    finally:
        applet.close()


def handle_code(params: Any = None, *, now: float | None = None) -> dict[str, Any]:
    import nuri_card_host as host

    step, digits = _validate_calc_params(params)
    ctr, remaining = counter_bytes(step, now)
    if host.resolve_mode() == "sim":
        if _SIM_SECRET is None:
            raise host.HostError("NOT_PROVISIONED", "No TOTP secret stored yet")
        digest = hmac.new(_SIM_SECRET, ctr, hashlib.sha1).digest()
        return {"code": truncate(digest, digits), "remaining": remaining, "step": step, "digits": digits}

    applet = _open_applet()
    try:
        data, sw = applet.transmit(bytes([0x00, INS_CALC, 0x00, 0x00, len(ctr)]) + ctr + b"\x00")
        if sw == 0x6985:
            raise host.HostError("NOT_PROVISIONED", "No TOTP secret stored on card yet")
        if sw != 0x9000 or len(data) != 20:
            raise host.HostError("CARD_ERROR", f"TOTP CALC failed: SW {sw:04X}")
        return {"code": truncate(bytes(data), digits), "remaining": remaining, "step": step, "digits": digits}
    finally:
        applet.close()


def handle_put(params: dict[str, Any], pin_buf: bytearray | None) -> dict[str, Any]:
    global _SIM_SECRET
    import nuri_card_host as host

    secret_buf = bytearray(parse_secret(params.get("secret")))
    body = None
    try:
        if host.resolve_mode() == "sim":
            _SIM_SECRET = bytes(secret_buf)
            return {"provisioned": True, "version": "sim"}

        applet = _open_applet()
        try:
            status = _probe_status(applet)
            if status["version"] == "1.1":
                if pin_buf is None or not PIN_MIN <= len(pin_buf) <= PIN_MAX:
                    raise host.HostError("PIN_REQUIRED", f"TOTP admin PIN ({PIN_MIN}-{PIN_MAX} chars) required")
                body = bytearray([len(pin_buf)]) + pin_buf + secret_buf
                _, sw = applet.transmit(bytes([0x00, INS_PUT, 0x00, 0x00, len(body)]) + bytes(body))
                if (sw & 0xFFF0) == 0x63C0:
                    left = sw & 0x0F
                    raise host.HostError("WRONG_PIN", f"Wrong TOTP PIN ({left} tries left)", tries_left=left)
                if sw == 0x6983:
                    raise host.HostError("PIN_BLOCKED", "TOTP PIN blocked; reinstall applet to reprovision", tries_left=0)
            else:
                _, sw = applet.transmit(bytes([0x00, INS_PUT, 0x00, 0x00, len(secret_buf)]) + bytes(secret_buf))
            if sw != 0x9000:
                raise host.HostError("CARD_ERROR", f"TOTP PUT failed: SW {sw:04X}")
            return {"provisioned": True, "version": status["version"]}
        finally:
            applet.close()
    finally:
        host._wipe(secret_buf)
        host._wipe(body)
