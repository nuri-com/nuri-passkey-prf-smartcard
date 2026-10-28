#!/usr/bin/env python3
"""Execute-only JSON-lines bridge; importing this module never opens a reader.

Operations: assert, pubkey, nonces, finalize, prf-proof. The latter accepts
payload={"credential": <existing credential ID, unpadded base64url>} (optional
rp_id/origin must match the constants below). It evaluates the fixed Nuri wallet
salt in TWO assertions, then returns ONLY client_pk33, prf_commitment_sha256 and
deterministic. No enrollment, reset, provisioning, key import/export or retries.

PRF material and the derived software key necessarily exist in host memory;
Python cannot guarantee zeroization. This is NOT the MuSig2 applet's public key
and is not a remotely verifiable attestation of a PRF result.

API checked against python-fido2 tag 2.2.1: ctap2/extensions.py
HmacSecretExtension.get_assertion -> AuthenticationExtensionProcessor's
prepare_inputs(selected, pin_token) / prepare_outputs(response, pin_token).
That upstream processor uses ClientPin._get_shared_secret() for hmac-secret's
ECDH encryption/authentication, separately from the assertion's PIN token.
Derivation port: ../card-arkade-key.mjs (HKDF-SHA256 -> BIP32 -> BIP86 internal
compressed public key, m/86'/0'/0'/0/0; no Taproot output-key tweak).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import re
import stat
import sys

RP_ID = "nuri.com"
ORIGIN = "https://arkade.nuri.com"
PRF_SALT = b"nuri-prf-salt-v1"
MUSIG2_AID = "4E5552494D55473301"
SCRIPTS = Path(__file__).resolve().parents[1]
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ERROR = {"error": "card operation failed; no retry; session closed"}
OPS = frozenset(("assert", "prf-proof", "pubkey", "nonces", "finalize"))


def b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_b64(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("expected unpadded base64url")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if not raw or b64(raw) != value:
        raise ValueError("noncanonical base64url")
    return raw


def read_pin():
    pin = os.environ.pop("NURI_FIDO_PIN", None)
    if pin is None:
        path = Path.home() / ".hermes/cache/scratch/.card_pin"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid()):
                raise RuntimeError("PIN file must be an owned regular file with mode 600")
            if info.st_size > 128:
                raise RuntimeError("PIN unavailable or malformed")
            pin = os.read(fd, 129).decode("ascii").strip()
        finally:
            os.close(fd)
    if not isinstance(pin, str) or not re.fullmatch(r"[0-9]{4,12}", pin):
        raise RuntimeError("PIN unavailable or malformed")
    return pin


def local_pcsc():
    # Repository-relative imports, never a developer's external worktree path.
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    import nuri_pcsc
    return nuri_pcsc


def select_reader(all_readers, wanted):
    if not isinstance(wanted, str) or not wanted.strip():
        raise RuntimeError("reader selector required")
    candidates = list(all_readers)
    matches = [r for r in candidates if str(r) == wanted]
    if not matches:
        matches = [r for r in candidates if wanted.lower() in str(r).lower()]
    if len(matches) != 1:
        raise RuntimeError("reader must match exactly once")
    return matches[0]


def chosen_reader():
    from smartcard.System import readers
    return select_reader(readers(), os.environ.get("NURI_READER", "HID Global OMNIKEY 5422 Smartcard Reader"))


def open_fido():
    if importlib.metadata.version("fido2") != "2.2.1":
        raise RuntimeError("bridge requires python-fido2 2.2.1")
    nuri_pcsc = local_pcsc()
    nuri_pcsc.patch_fido2()
    from fido2.pcsc import CtapPcscDevice
    reader = chosen_reader()
    conn = reader.createConnection()
    try:
        return CtapPcscDevice(conn, str(reader))
    except BaseException:
        conn.disconnect()
        raise


def open_musig(pin):
    nuri_pcsc = local_pcsc()
    from nuri_musig2_card import MuSig2Card
    reader = chosen_reader()
    conn = reader.createConnection()
    select = nuri_pcsc.select_apdu(MUSIG2_AID)

    def probe(connection):
        _, sw = nuri_pcsc.transmit_raw(connection, select)
        return sw == 0x9000 or sw >> 8 == 0x61

    card = None
    try:
        protocol = nuri_pcsc.connect_ladder(conn, probe)
        applet = nuri_pcsc.Applet(conn, str(reader), protocol, MUSIG2_AID)
        card = MuSig2Card(applet=applet, pin_reader=lambda: pin.encode("ascii"))
        card.connect()
        if not card.pin_protocol:
            raise RuntimeError("requires PIN applet >=1.14")
        return card
    except BaseException:
        if card is not None:
            card.close()
        else:
            conn.disconnect()
        raise


def validate_fido_payload(payload, proof=False):
    if not isinstance(payload, dict):
        raise ValueError("payload required")
    allowed = {"credential", "rp_id", "origin"}
    if not proof:
        allowed.add("challenge")
    if set(payload) - allowed:
        raise ValueError("unexpected payload field")
    if payload.get("rp_id", RP_ID if proof else None) != RP_ID:
        raise ValueError("RP mismatch")
    if payload.get("origin", ORIGIN if proof else None) != ORIGIN:
        raise ValueError("origin mismatch")
    credential = decode_b64(payload.get("credential"))
    if not proof:
        decode_b64(payload.get("challenge"))
    return credential


def client_data(challenge):
    return json.dumps({"type": "webauthn.get", "challenge": challenge,
                       "origin": ORIGIN, "crossOrigin": False}, separators=(",", ":")).encode()


def validate_assertion(assertion, credential):
    # CTAP may omit the descriptor for a single-entry allow-list. If present,
    # the returned ID MUST be the requested credential, never another account.
    if assertion.credential and assertion.credential.get("id") != credential:
        raise RuntimeError("credential mismatch")
    if assertion.number_of_credentials not in (None, 1):
        raise RuntimeError("ambiguous assertion")
    if (assertion.auth_data.rp_id_hash != hashlib.sha256(RP_ID.encode()).digest()
            or int(assertion.auth_data.flags) & 5 != 5):
        raise RuntimeError("RP/UP/UV mismatch")


def assertion_with_prf(ctap, pin, credential, challenge, with_prf=False):
    from fido2.ctap2 import ClientPin
    data = client_data(challenge)
    digest = hashlib.sha256(data).digest()
    cp = ClientPin(ctap)
    # One fresh token per assertion. On legacy CTAP2.0 upstream may fall back
    # to an unscoped token; do not claim RP-scoped tokens on that firmware.
    token = cp.get_pin_token(pin, ClientPin.PERMISSION.GET_ASSERTION, RP_ID)
    processor = None
    extensions = None
    if with_prf:
        from fido2.ctap2.extensions import HmacSecretExtension
        from fido2.webauthn import PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions
        selected = PublicKeyCredentialDescriptor(type="public-key", id=credential)
        options = PublicKeyCredentialRequestOptions(
            challenge=decode_b64(challenge), rp_id=RP_ID, allow_credentials=[selected],
            user_verification="required", extensions={"prf": {"eval": {"first": PRF_SALT}}})
        # Upstream handles WebAuthn PRF domain hashing, ECDH shared secret,
        # saltEnc/saltAuth and result decryption. Never use the PIN token as
        # the hmac-secret encryption key, nor hash the salt twice ourselves.
        processor = HmacSecretExtension().get_assertion(ctap, options, cp.protocol)
        if processor is None:
            raise RuntimeError("hmac-secret unsupported")
        extensions = processor.prepare_inputs(selected, token)
        if not extensions or "hmac-secret" not in extensions:
            raise RuntimeError("hmac-secret input missing")
    assertion = ctap.get_assertion(
        RP_ID, digest, [{"type": "public-key", "id": credential}],
        extensions=extensions, options={"up": True},
        pin_uv_param=cp.protocol.authenticate(token, digest), pin_uv_protocol=cp.protocol.VERSION)
    validate_assertion(assertion, credential)
    prf = None
    if processor is not None:
        outputs = processor.prepare_outputs(assertion, token)
        result = outputs.get("prf") if outputs else None
        # Processor returns typed PRF outputs; Mapping access serializes bytes
        # to base64url, so use ATTRIBUTES for raw derivation input (2.2.1).
        prf = result.results.first if result and result.results else None
        if not isinstance(prf, bytes) or len(prf) != 32:
            raise RuntimeError("PRF result missing or malformed")
    return data, assertion, prf


def compressed_public(scalar):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return ec.derive_private_key(scalar, ec.SECP256K1()).public_key().public_bytes(
        Encoding.X962, PublicFormat.CompressedPoint)


def bip86_public(seed):
    """Minimal private BIP32 derivation; only the compressed public key escapes."""
    master = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    scalar, chain = int.from_bytes(master[:32], "big"), master[32:]
    if not 0 < scalar < SECP256K1_ORDER:
        raise ValueError("invalid BIP32 master")
    for index in (0x80000056, 0x80000000, 0x80000000, 0, 0):
        while True:
            prefix = (b"\0" + scalar.to_bytes(32, "big") if index & 0x80000000
                      else compressed_public(scalar))
            child = hmac.new(chain, prefix + index.to_bytes(4, "big"), hashlib.sha512).digest()
            left = int.from_bytes(child[:32], "big")
            candidate = (left + scalar) % SECP256K1_ORDER
            if left < SECP256K1_ORDER and candidate:
                scalar, chain = candidate, child[32:]
                break
            # BIP32's invalid-child retry, never a hardware/PIN retry.
            if index in (0x7FFFFFFF, 0xFFFFFFFF):
                raise ValueError("BIP32 child range exhausted")
            index += 1
    return compressed_public(scalar)


def derive_nuri_public(prf):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    if not isinstance(prf, bytes) or len(prf) != 32:
        raise ValueError("invalid PRF length")
    entropy = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=hashlib.sha256(b"app:nuri.com|wallet|v1").digest(),
                   info=b"app:nuri.com|wallet|v1|chain=bitcoin|fmt=taproot").derive(prf)
    return bip86_public(entropy)


def fido_operation(op, payload, pin):
    credential = validate_fido_payload(payload, proof=op == "prf-proof")
    device = open_fido()
    try:
        from fido2.ctap2 import Ctap2
        ctap = Ctap2(device)
        if op == "assert":
            data, assertion, _ = assertion_with_prf(ctap, pin, credential, payload["challenge"])
            return {"client_data_b64u": b64(data), "auth_data_b64u": b64(bytes(assertion.auth_data)),
                    "sig_b64u": b64(assertion.signature), "assertion_cred_id_b64u": payload["credential"]}
        _, _, first = assertion_with_prf(ctap, pin, credential, b64(os.urandom(32)), True)
        _, _, second = assertion_with_prf(ctap, pin, credential, b64(os.urandom(32)), True)
        if not isinstance(first, bytes) or not isinstance(second, bytes):
            raise RuntimeError("PRF result missing")
        deterministic = hmac.compare_digest(first, second)
        return {"client_pk33": derive_nuri_public(first).hex(),
                "prf_commitment_sha256": hashlib.sha256(first).hexdigest(),
                "deterministic": deterministic}
    finally:
        device.close()


def main():
    card = None
    try:
        if not re.fullmatch(r"(?:@[a-z0-9][a-z0-9-]{0,62}|ark1[0-9a-z]+|board)-(?:all|[1-9][0-9]*)", os.environ.get("NURI_SEND_CONFIRM", "")):
            raise RuntimeError("confirmation required")
        # Explicitly disable transport logging (APDUs/extension data may contain
        # secrets). No logging configuration or hardware imports at import time.
        logging.disable(sys.maxsize)
        pin = None
        for line in sys.stdin:
            req = json.loads(line)
            if not isinstance(req, dict) or req.get("op") not in OPS:
                raise ValueError("unknown operation")
            op = req["op"]
            if op in ("assert", "prf-proof"):
                validate_fido_payload(req.get("payload"), proof=op == "prf-proof")
                if card is not None:
                    raise RuntimeError("cannot select FIDO while MuSig2 session exists")
            finalize_payload = None
            if op == "finalize":
                finalize_payload = bytes.fromhex(req["payload"])
                if (card is None or len(finalize_payload) != 231 or card._token is None
                        or card._token != finalize_payload[97:101]):
                    raise ValueError("FINALIZE context mismatch")
            if pin is None:
                pin = read_pin()
            if op in ("assert", "prf-proof"):
                response = fido_operation(op, req["payload"], pin)
            else:
                if card is None:
                    card = open_musig(pin)
                if op == "pubkey":
                    response = {"pubkey": card.pubkey().hex()}
                elif op == "nonces":
                    if card._token is not None:
                        raise ValueError("nonce session already exists")
                    k1, k2 = card.nonces()
                    if card._token is None or len(card._token) != 4:
                        raise ValueError("nonce token missing")
                    response = {"publicNonce": (k1 + k2).hex(), "token": card._token.hex()}
                else:
                    if finalize_payload is None:
                        raise ValueError("FINALIZE payload missing")
                    p = finalize_payload
                    partial = card.finalize(p[:32], p[32:64], p[64], p[65:97],
                                            r_agg=p[101:166], p_agg=p[166:231])
                    response = {"partial": partial.hex()}
            print(json.dumps(response), flush=True)
        return 0
    except (Exception, KeyboardInterrupt):
        # Never serialize transport/provider exceptions, PIN, PRF or private key.
        print(json.dumps(ERROR), flush=True)
        return 1
    finally:
        if card is not None:
            card.close()


if __name__ == "__main__":
    sys.exit(main())
