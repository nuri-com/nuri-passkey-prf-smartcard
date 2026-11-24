#!/usr/bin/env python3
"""Direct CLI PC/SC + USB-HID WebAuthn (FIDO2 + PRF) runner for Nuri Connect.

Reuses host/webauthn_bridge.py directly over PC/SC (OMNIKEY / NFC reader) or
USB-HID FIDO2 security keys — zero browser or Chrome extension needed.

Modes:
  --probe  Read-only hardware detection (never asks for PIN or burns retries).
           Prints {"ok": true, "available": true|false, "transport": ..., ...}.
  stdin    JSON request:
           {
             "kind": "get" | "create",
             "params": { "origin": "https://connect.nuri.com", "publicKey": { ... } },
             "summary": "Authorize Nuri Agent Wallet (slot #0) ...",
             "include_cred_pubkey": true
           }

PIN acquisition (never via argv, never logged, zeroized in finally):
  1. File descriptor in $NURI_CARD_PIN_FD (if set)
  2. $NURI_CARD_PIN environment variable (if set)
  3. Interactive masked prompt on /dev/tty (when a TTY is attached)
  4. Native OS hidden-input PIN dialog (macOS osascript) when invoked non-interactively
     (e.g. by an AI coding agent) — PIN goes directly from OS UI into memory, never to the LLM.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import subprocess
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


def _open_any_device():
    """Open a PC/SC Nuri Smartcard first, falling back to a USB-HID FIDO2 security key."""
    pcsc_err = None
    try:
        return wb._open_device(), "pcsc"
    except Exception as exc:
        pcsc_err = exc

    try:
        from fido2.hid import CtapHidDevice
        hids = list(CtapHidDevice.list_devices())
        if hids:
            return hids[0], "hid"
    except Exception:
        pass

    if isinstance(pcsc_err, wb.BridgeError):
        raise pcsc_err
    raise wb.BridgeError(
        "NO_CARD",
        f"No PC/SC smartcard or USB-HID FIDO2 security key detected ({pcsc_err or 'none'})",
    )


def _probe_device() -> dict:
    try:
        dev, transport = _open_any_device()
    except wb.BridgeError as exc:
        return {"ok": True, "available": False, "code": exc.code, "reason": exc.message}
    try:
        from fido2.ctap2 import Ctap2
        ctap2 = Ctap2(dev)
        info = ctap2.get_info()
        opts = dict(info.options or {})
        exts = list(info.extensions or [])
        return {
            "ok": True,
            "available": True,
            "transport": transport,
            "device": str(dev),
            "versions": list(info.versions or []),
            "hmac_secret": "hmac-secret" in exts,
            "client_pin": bool(opts.get("clientPin")),
            "uv": bool(opts.get("uv")),
            "cred_mgmt": bool(opts.get("credMgmt")),
            "pin_retries": wb._pin_retries(ctap2) if opts.get("clientPin") else None,
        }
    except Exception as exc:
        return {"ok": True, "available": False, "code": "CARD_ERROR", "reason": f"{type(exc).__name__}: {exc}"}
    finally:
        try:
            dev.close()
        except Exception:
            pass


def _has_tty() -> bool:
    try:
        with open("/dev/tty", "rb"):
            return True
    except OSError:
        return False


def _macos_pin_dialog(summary: str, retries: int | None) -> bytearray:
    hint = f" ({retries} retries left)" if retries is not None else ""
    body_lines = []
    if summary:
        body_lines.append(summary)
        body_lines.append("")
    body_lines.append(f"Enter your Nuri Card FIDO2 PIN{hint}:")
    prompt = "\n".join(body_lines)
    script = (
        "on run argv\n"
        "  activate\n"
        "  set msg to item 1 of argv\n"
        "  set res to display dialog msg with title \"Nuri Smartcard Approval\" "
        "default answer \"\" with hidden answer buttons {\"Cancel\", \"Approve\"} default button \"Approve\"\n"
        "  return text returned of res\n"
        "end run\n"
    )
    proc = subprocess.run(
        ["osascript", "-e", script, "--", prompt],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise wb.BridgeError("USER_CANCELLED", "Smartcard PIN entry cancelled", retries=retries)
    pin = proc.stdout.rstrip("\r\n")
    if not pin:
        raise wb.BridgeError("PIN_REQUIRED", "Empty PIN aborted", retries=retries)
    return bytearray(pin.encode("utf-8"))


def _macos_choose_credential(credentials: list[dict]) -> str:
    labels = []
    id_by_label = {}
    for idx, c in enumerate(credentials, start=1):
        name = c.get("name") or c.get("displayName") or "(unnamed)"
        cid = c.get("id", "")
        label = f"{idx}. {name} ({cid[:12]}...)"
        labels.append(label)
        id_by_label[label] = cid
    script = (
        "on run argv\n"
        "  activate\n"
        "  set chosen to choose from list argv with title \"Nuri Smartcard\" "
        "with prompt \"Choose which Nuri credential on the card to use:\"\n"
        "  if chosen is false then error number -128\n"
        "  return item 1 of chosen\n"
        "end run\n"
    )
    proc = subprocess.run(
        ["osascript", "-e", script, "--", *labels],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise wb.BridgeError("USER_CANCELLED", "Credential selection cancelled")
    chosen = proc.stdout.rstrip("\r\n")
    cid = id_by_label.get(chosen)
    if not cid:
        raise wb.BridgeError("AMBIGUOUS_CREDENTIAL", "No credential chosen", credentials=credentials)
    return cid


def _read_pin(summary: str, interactive_tty: bool = False) -> tuple[bytearray | None, str]:
    """Return (pin_buf, transport)."""
    fd_env = os.environ.get("NURI_CARD_PIN_FD", "").strip()
    if fd_env:
        fd = int(fd_env)
        with os.fdopen(fd, "rb", closefd=True) as fh:
            raw = fh.read().strip(b"\r\n")
        return (bytearray(raw) if raw else None), "fd"

    pin_env = os.environ.get("NURI_CARD_PIN")
    if pin_env is not None and pin_env != "":
        return bytearray(pin_env.encode("utf-8")), "env"

    dev, transport = _open_any_device()
    try:
        from fido2.ctap2 import Ctap2
        ctap2 = Ctap2(dev)
        info = ctap2.get_info()
        opts = info.options or {}
        needs_pin = bool(opts.get("clientPin")) and not bool(opts.get("uv"))
        retries = wb._pin_retries(ctap2) if needs_pin else None
    finally:
        try:
            dev.close()
        except Exception:
            pass

    if not needs_pin:
        return None, transport

    if interactive_tty and _has_tty():
        hint = f" ({retries} retries left)" if retries is not None else ""
        try:
            pin = getpass.getpass(f"Nuri Card FIDO2 PIN{hint}: ")
        except EOFError:
            pin = ""
        if not pin:
            raise wb.BridgeError("PIN_REQUIRED", "Empty PIN aborted", retries=retries)
        return bytearray(pin.encode("utf-8")), transport

    if sys.platform == "darwin" and os.environ.get("NURI_CARD_NO_GUI", "") != "1":
        return _macos_pin_dialog(summary, retries), transport

    raise wb.BridgeError(
        "PIN_REQUIRED",
        "Card requires a FIDO2 PIN and no TTY/GUI is attached. Run interactively or pass NURI_CARD_PIN_FD.",
        retries=retries,
    )


def _lookup_credential_spki_b64u(rp_id: str, cred_id_b64u: str, pin_buf: bytearray | None) -> str | None:
    """Best-effort CTAP2 CredentialManagement lookup for ES256 DER SPKI pubkey."""
    if not pin_buf:
        return None
    try:
        dev, _ = _open_any_device()
    except Exception:
        return None
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
    if "--probe" in sys.argv[1:]:
        print(json.dumps(_probe_device()))
        return 0

    raw = sys.stdin.read().strip()
    if not raw:
        print(json.dumps({"ok": False, "code": "BAD_REQUEST", "error": "empty stdin JSON"}))
        return 1
    req = json.loads(raw)
    kind = req.get("kind", "get")
    params = req.get("params")
    summary = str(req.get("summary") or "").strip()
    interactive_tty = bool(req.get("interactive_tty", False))
    include_cred_pubkey = bool(req.get("include_cred_pubkey", True))

    def _open_only():
        dev, _ = _open_any_device()
        return dev

    pin_buf: bytearray | None = None
    try:
        pin_buf, transport = _read_pin(summary, interactive_tty=interactive_tty)
        if kind == "create":
            response = wb.webauthn_create(params, pin_buf, open_device=_open_only)
            cred_pk = (response.get("response") or {}).get("publicKey")
        elif kind == "get":
            try:
                response = wb.webauthn_get(params, pin_buf, open_device=_open_only)
            except wb.BridgeError as exc:
                if (
                    exc.code == "AMBIGUOUS_CREDENTIAL"
                    and exc.extra.get("credentials")
                    and sys.platform == "darwin"
                    and not interactive_tty
                    and os.environ.get("NURI_CARD_NO_GUI", "") != "1"
                ):
                    chosen_id = _macos_choose_credential(exc.extra["credentials"])
                    retry_params = json.loads(json.dumps(params))
                    retry_params["publicKey"]["allowCredentials"] = [
                        {"type": "public-key", "id": chosen_id}
                    ]
                    response = wb.webauthn_get(retry_params, pin_buf, open_device=_open_only)
                else:
                    raise
            cred_pk = None
            if include_cred_pubkey and response.get("id"):
                rp_id = ((params or {}).get("publicKey") or {}).get("rpId") or wb.RP_ID
                cred_pk = _lookup_credential_spki_b64u(rp_id, response["id"], pin_buf)
        else:
            raise wb.BridgeError("BAD_REQUEST", f"unsupported kind: {kind!r}")

        print(json.dumps({
            "ok": True,
            "transport": transport,
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
