#!/usr/bin/env python3
"""Direct CLI PC/SC WebAuthn (FIDO2 + PRF) runner for Nuri Connect.

Reuses host/webauthn_bridge.py directly over PC/SC (OMNIKEY / NFC reader) —
no browser or Chrome extension needed.

Reads a JSON request from stdin:
  {
    "kind": "get" | "create",
    "params": { "origin": "https://connect.nuri.com", "publicKey": { ... } },
    "include_cred_pubkey": true
  }

PIN acquisition (never via argv, never logged):
  1. File descriptor in $NURI_CARD_PIN_FD (if set)
  2. $NURI_CARD_PIN environment variable (if set)
  3. Interactive masked prompt on /dev/tty (only when card reports clientPin=True)

Writes JSON result to stdout:
  { "ok": true, "response": <WebAuthnJSON>, "credential_pubkey_b64u": "..." | null }
  or
  { "ok": false, "code": "...", "error": "...", "extra": { ... } }
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "host"))
sys.path.insert(0, str(ROOT / "scripts"))

import webauthn_bridge as wb  # noqa: E402


def _zeroize(buf: bytearray | None) -> None:
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0


def _read_pin_from_env_or_tty() -> bytearray | None:
    fd_env = os.environ.get("NURI_CARD_PIN_FD", "").strip()
    if fd_env:
        fd = int(fd_env)
        with os.fdopen(fd, "rb", closefd=True) as fh:
            raw = fh.read().strip(b"\r\n")
        return bytearray(raw) if raw else None

    pin_env = os.environ.get("NURI_CARD_PIN")
    if pin_env is not None and pin_env != "":
        return bytearray(pin_env.encode("utf-8"))

    # Check whether the card actually requires a client PIN before prompting.
    dev = wb._open_device()
    try:
        from fido2.ctap2 import Ctap2
        info = Ctap2(dev).get_info()
        needs_pin = bool((info.options or {}).get("clientPin")) and not bool((info.options or {}).get("uv"))
        retries = wb._pin_retries(Ctap2(dev)) if needs_pin else None
    finally:
        try:
            dev.close()
        except Exception:
            pass

    if not needs_pin:
        return None

    hint = f" ({retries} retries left)" if retries is not None else ""
    try:
        pin = getpass.getpass(f"Nuri Card FIDO2 PIN{hint}: ")
    except EOFError:
        raise wb.BridgeError(
            "PIN_REQUIRED",
            "Card requires a FIDO2 PIN and no TTY is attached. Run interactively or pass NURI_CARD_PIN_FD.",
            retries=retries,
        )
    if not pin:
        raise wb.BridgeError("PIN_REQUIRED", "Empty PIN aborted", retries=retries)
    return bytearray(pin.encode("utf-8"))


def _lookup_credential_spki_b64u(rp_id: str, cred_id_b64u: str, pin_buf: bytearray | None) -> str | None:
    """Best-effort CTAP2 CredentialManagement lookup for ES256 DER SPKI pubkey."""
    if not pin_buf:
        return None
    dev = wb._open_device()
    try:
        from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
        from fido2.utils import websafe_decode
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        ctap2 = Ctap2(dev)
        info = ctap2.get_info()
        if not (info.options or {}).get("credMgmt"):
            return None
        client_pin = ClientPin(ctap2)
        token = client_pin.get_pin_token(
            pin_buf.decode("utf-8"),
            permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT,
        )
        cm = CredentialManagement(ctap2, client_pin.protocol, token)
        target_id = websafe_decode(cred_id_b64u)
        rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        for cred in cm.enumerate_creds(rp_hash):
            cid = (cred.get(CredentialManagement.RESULT.CREDENTIAL_ID) or {}).get("id")
            if cid != target_id:
                continue
            key = cred.get(CredentialManagement.RESULT.PUBLIC_KEY) or {}
            if key.get(3) == -7 and key.get(-1) == 1:
                spki = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(key[-2], "big"),
                    int.from_bytes(key[-3], "big"),
                    ec.SECP256R1(),
                ).public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                return wb._b64u(spki)
        return None
    except Exception:
        return None
    finally:
        try:
            dev.close()
        except Exception:
            pass


def main() -> int:
    raw = sys.stdin.read().strip()
    if not raw:
        print(json.dumps({"ok": False, "code": "BAD_REQUEST", "error": "empty stdin JSON"}))
        return 1
    req = json.loads(raw)
    kind = req.get("kind", "get")
    params = req.get("params")
    include_cred_pubkey = bool(req.get("include_cred_pubkey", True))

    pin_buf: bytearray | None = None
    try:
        pin_buf = _read_pin_from_env_or_tty()
        if kind == "create":
            response = wb.webauthn_create(params, pin_buf)
            cred_pk = (response.get("response") or {}).get("publicKey")
        elif kind == "get":
            response = wb.webauthn_get(params, pin_buf)
            cred_pk = None
            if include_cred_pubkey and response.get("id"):
                rp_id = ((params or {}).get("publicKey") or {}).get("rpId") or wb.RP_ID
                cred_pk = _lookup_credential_spki_b64u(rp_id, response["id"], pin_buf)
        else:
            raise wb.BridgeError("BAD_REQUEST", f"unsupported kind: {kind!r}")

        print(json.dumps({
            "ok": True,
            "response": response,
            "credential_pubkey_b64u": cred_pk,
        }))
        return 0
    except wb.BridgeError as exc:
        print(json.dumps({
            "ok": False,
            "code": exc.code,
            "error": exc.message,
            "extra": wb.jsonify(exc.extra) if exc.extra else {},
        }))
        return 2
    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "code": "CARD_ERROR",
            "error": f"{type(exc).__name__}: {exc}",
            "extra": {},
        }))
        return 1
    finally:
        _zeroize(pin_buf)


if __name__ == "__main__":
    raise SystemExit(main())
