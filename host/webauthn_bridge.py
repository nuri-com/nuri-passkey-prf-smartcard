"""Card-backed WebAuthn (FIDO2 + PRF) for Nuri Connect over PC/SC.

Host methods (dispatched from nuri_card_host.handle):
  webauthn_create {origin, publicKey: <PublicKeyCredentialCreationOptionsJSON>} + pin
  webauthn_get    {origin, publicKey: <PublicKeyCredentialRequestOptionsJSON>}  + pin
Results are the WebAuthn JSON forms (RegistrationResponseJSON /
AuthenticationResponseJSON, base64url), including clientExtensionResults.prf.

The origin comes from the extension (Chrome's sender URL, never the page) and
must be in ALLOWED_ORIGINS; rp.id must be RP_ID. PRF uses python-fido2's
hmac-secret mapping, i.e. salt = SHA-256("WebAuthn PRF" || 0x00 || input),
the same as Chrome's navigator.credentials PRF. The PIN is used for one
ClientPIN token and never stored, logged or echoed.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from typing import Any, Callable

ALLOWED_ORIGINS = ("https://connect.nuri.com",)
RP_ID = "nuri.com"


class BridgeError(Exception):
    def __init__(self, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.code = code
        self.message = message
        self.extra = extra


def _b64u(data: bytes) -> str:
    from fido2.utils import websafe_encode
    return websafe_encode(data)


def jsonify(value: Any) -> Any:
    """Recursively turn fido2 objects into plain JSON (bytes -> base64url)."""
    if isinstance(value, (bytes, bytearray)):
        return _b64u(bytes(value))
    if isinstance(value, Mapping):
        return {str(k): jsonify(value[k]) for k in value}
    if isinstance(value, (list, tuple)):
        return [jsonify(v) for v in value]
    if hasattr(value, "value") and type(value).__module__.startswith("fido2"):  # enums
        return value.value
    return value


def _check_request(params: Any, kind: str) -> tuple[str, dict]:
    if not isinstance(params, dict):
        raise BridgeError("BAD_REQUEST", "params must be an object")
    origin = params.get("origin")
    if origin not in ALLOWED_ORIGINS:
        raise BridgeError("ORIGIN_NOT_ALLOWED", f"origin {origin!r} may not use the card authenticator")
    options = params.get("publicKey")
    if not isinstance(options, dict):
        raise BridgeError("BAD_REQUEST", "params.publicKey must be an object")
    rp_id = (options.get("rp") or {}).get("id") if kind == "create" else options.get("rpId")
    if rp_id != RP_ID:
        raise BridgeError("RP_NOT_ALLOWED", f"rp id {rp_id!r} is not {RP_ID!r}")
    return origin, options


def _open_device():
    scripts = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    try:
        import nuri_pcsc
        from fido2.pcsc import CtapPcscDevice
    except ImportError as exc:
        raise BridgeError("CONFIG_ERROR", f"fido2/pyscard not installed in the host venv ({exc})")
    nuri_pcsc.patch_fido2()  # T=0-only readers
    try:
        devices = list(CtapPcscDevice.list_devices())
    except Exception as exc:
        raise BridgeError("NO_READER", f"PC/SC unavailable ({type(exc).__name__})")
    if not devices:
        raise BridgeError("NO_CARD", "no FIDO2 card on any reader")
    for extra in devices[1:]:
        extra.close()
    return devices[0]


def _pin_retries(ctap2) -> int | None:
    try:
        from fido2.ctap2 import ClientPin
        return ClientPin(ctap2).get_pin_retries()[0]
    except Exception:
        return None


def _map_error(exc: Exception, device) -> BridgeError:
    from fido2.client import ClientError, PinRequiredError
    from fido2.ctap import CtapError

    if isinstance(exc, PinRequiredError):
        return BridgeError("PIN_REQUIRED", "card PIN required")
    cause = exc.cause if isinstance(exc, ClientError) else exc
    if isinstance(cause, CtapError):
        if cause.code == CtapError.ERR.PIN_INVALID:
            tries = None
            try:
                from fido2.ctap2 import Ctap2
                tries = _pin_retries(Ctap2(device))
            except Exception:
                pass
            return BridgeError("PIN_WRONG", "wrong card PIN", tries_left=tries)
        if cause.code in (CtapError.ERR.PIN_BLOCKED, CtapError.ERR.PIN_AUTH_BLOCKED):
            return BridgeError("PIN_BLOCKED", "card PIN blocked", tries_left=0)
        if cause.code == CtapError.ERR.PIN_NOT_SET:
            return BridgeError("PIN_NOT_SET", "card has no FIDO2 PIN")
    if isinstance(exc, ClientError):
        if exc.code == ClientError.ERR.DEVICE_INELIGIBLE:
            return BridgeError("NO_CREDENTIAL", "this card holds no matching credential")
        if exc.code == ClientError.ERR.TIMEOUT:
            return BridgeError("TIMEOUT", "card timed out")
        return BridgeError("CARD_ERROR", f"FIDO2 client error {exc.code.name}")
    if isinstance(exc, ValueError):  # bad options from from_dict / salt lengths
        return BridgeError("BAD_REQUEST", f"invalid WebAuthn options ({exc})")
    return BridgeError("CARD_ERROR", f"internal error ({type(exc).__name__})")


def _client(device, origin: str, pin_buf: bytearray | None):
    from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
    from fido2.ctap2.extensions import HmacSecretExtension

    class _Pin(UserInteraction):
        def request_pin(self, permissions, rp_id):
            return pin_buf.decode("utf-8") if pin_buf else None

        def request_uv(self, permissions, rp_id):
            return False  # contactless card: PIN only, never internal UV prompts

    return Fido2Client(
        device,
        DefaultClientDataCollector(origin=origin),
        user_interaction=_Pin(),
        extensions=[HmacSecretExtension(allow_hmac_secret=False)],  # PRF only
    )


def _run(params: Any, pin_buf: bytearray | None, kind: str,
         open_device: Callable = _open_device, client_factory: Callable = _client) -> dict:
    origin, raw = _check_request(params, kind)
    from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions
    try:
        options = (PublicKeyCredentialCreationOptions if kind == "create" else PublicKeyCredentialRequestOptions).from_dict(raw)
    except Exception as exc:
        raise BridgeError("BAD_REQUEST", f"invalid WebAuthn options ({type(exc).__name__}: {exc})")
    device = open_device()
    try:
        client = client_factory(device, origin, pin_buf)
        try:
            if kind == "create":
                response = client.make_credential(options)
            else:
                selection = client.get_assertion(options)
                if len(selection.get_assertions()) != 1:
                    raise BridgeError("AMBIGUOUS_CREDENTIAL", "card holds several credentials; pass allowCredentials")
                response = selection.get_response(0)
        except BridgeError:
            raise
        except Exception as exc:
            raise _map_error(exc, device)
        out = jsonify(dict(response))
        if kind == "create":
            # Mirror AuthenticatorAttestationResponse.getPublicKey(): DER SPKI (ES256 only).
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            key = response.response.attestation_object.auth_data.credential_data.public_key
            if key.get(3) != -7 or key.get(-1) != 1:
                raise BridgeError("CARD_ERROR", "card did not return an ES256 P-256 key")
            spki = ec.EllipticCurvePublicNumbers(
                int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"), ec.SECP256R1()
            ).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            out["response"]["publicKey"] = _b64u(spki)
            out["response"]["publicKeyAlgorithm"] = -7
        return out
    finally:
        try:
            device.close()
        except Exception:
            pass


def webauthn_create(params: Any, pin_buf: bytearray | None, **kw: Any) -> dict:
    return _run(params, pin_buf, "create", **kw)


def webauthn_get(params: Any, pin_buf: bytearray | None, **kw: Any) -> dict:
    return _run(params, pin_buf, "get", **kw)
