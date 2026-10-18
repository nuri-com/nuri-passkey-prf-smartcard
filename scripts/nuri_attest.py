#!/usr/bin/env python3
"""NURI-ATT-V1 parser/verifier and host-issued, consume-once challenges.

Only public evidence is returned. verify_response is deliberately stateless: its
caller MUST supply the challenge it just issued, not a challenge from evidence.
Use ChallengeVerifier or issue_challenge/verify_saved_response for replay/age
policy. Offline signatures alone cannot establish freshness or physical custody.
Uses the repository's existing python-ecdsa dependency; no new crypto dependency.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import math
import os
import secrets
import stat
import subprocess
import threading
import time
from urllib.parse import unquote

from ecdsa import NIST256p, SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der

CA_DOMAIN = b"NURI-ATT-V1"
RESPONSE_DOMAIN = b"NURI-ATT-RESP-V1"
BINDING_DOMAIN = b"NHWV1"
ETH2_AID = bytes.fromhex("4E5552494554483201")
MUSIG2_AID = bytes.fromhex("4E5552494D554701")
VAULT_AID = bytes.fromhex("4E555249564C5401")


class VerificationError(ValueError):
    """Malformed, untrusted, stale, or replayed attestation evidence."""


def _require(ok, message):
    if not ok:
        raise VerificationError(message)


class _Reader:
    def __init__(self, data):
        _require(isinstance(data, bytes), "evidence must be bytes")
        self.data, self.pos = data, 0

    def take(self, n):
        _require(self.pos + n <= len(self.data), "truncated evidence")
        value = self.data[self.pos:self.pos + n]
        self.pos += n
        return value

    def byte(self):
        return self.take(1)[0]

    def end(self):
        _require(self.pos == len(self.data), "trailing evidence")


def _pub(raw, curve):
    length, prefix = (33, (2, 3)) if curve == SECP256k1 else (65, (4,))
    _require(isinstance(raw, bytes) and len(raw) == length and raw[0] in prefix,
             "noncanonical public key")
    try:
        return VerifyingKey.from_string(raw, curve=curve,
                                        valid_encodings={"compressed"} if length == 33 else {"uncompressed"})
    except Exception as error:
        raise VerificationError("invalid public key point") from error


def _signature(sig):
    _require(8 <= len(sig) <= 72, "invalid DER signature length")
    try:
        r, s = sigdecode_der(sig, NIST256p.order)
        _require(0 < r < NIST256p.order and 0 < s < NIST256p.order,
                 "signature scalar out of range")
        _require(sigencode_der(r, s, NIST256p.order) == sig, "noncanonical DER signature")
    except VerificationError:
        raise
    except Exception as error:
        raise VerificationError("invalid DER signature") from error
    return sig


def _parse_info(reader):
    version = reader.byte()
    _require(version == 1, "unsupported INFO version")
    card_id = reader.take(16)
    aid_len = reader.byte()
    _require(5 <= aid_len <= 16, "invalid AID length")
    aid = reader.take(aid_len)
    attestation_pub = reader.take(65)
    _pub(attestation_pub, NIST256p)
    sealed = reader.byte()
    _require(sealed in (0, 1), "invalid sealed flag")
    cert_len = reader.byte()
    cert = reader.take(cert_len)
    if cert:
        _signature(cert)
    _require(not sealed or bool(cert), "sealed INFO without certificate")
    return dict(version=version, card_id=card_id, aid=aid,
                attestation_pub=attestation_pub, sealed=bool(sealed), cert=cert)


def parse_info(info):
    """Strictly parse the entire INFO bytes, including unpersonalized INFO."""
    reader = _Reader(info)
    parsed = _parse_info(reader)
    reader.end()
    return parsed


def parse_response(response):
    reader = _Reader(response)
    parsed = _parse_info(reader)
    pub_len = reader.byte()
    _require(pub_len in (0, 33, 65), "invalid signing public key length")
    parsed["signing_pub"] = reader.take(pub_len)
    parsed["pin_state"] = reader.byte()
    _require(parsed["pin_state"] & ~15 == 0, "reserved PIN state bits")
    parsed["response_sig"] = _signature(reader.take(reader.byte()))
    binding = reader.take(reader.byte())
    if binding:
        _signature(binding)
    parsed["binding_sig"] = binding
    reader.end()
    return parsed


def ca_message(info):
    return CA_DOMAIN + info["card_id"] + info["aid"] + info["attestation_pub"]


def load_ca_pubkey(value):
    """P256 public pin from VerifyingKey, SEC1 bytes, PEM bytes, or hex text.

    Paths are intentionally handled explicitly by callers (e.g. the env path
    NURI_CARD_CA_PUBKEY), never guessed from evidence. Missing pins fail closed.
    """
    _require(value is not None, "CA public key pin is required; unverified")
    if isinstance(value, VerifyingKey):
        _require(value.curve == NIST256p, "CA must use P256")
        return value
    try:
        if isinstance(value, str):
            value = value.encode("ascii")
        if value.startswith(b"-----BEGIN PUBLIC KEY-----"):
            key = VerifyingKey.from_pem(value)
            _require(key.curve == NIST256p, "CA must use P256")
            return key
        if len(value) != 65:
            value = bytes.fromhex(value.decode("ascii").strip())
        return _pub(value, NIST256p)
    except VerificationError:
        raise
    except Exception as error:
        raise VerificationError("invalid CA public key pin") from error


def _verify(key, signature, message, label):
    try:
        _require(key.verify(signature, message, hashfunc=hashlib.sha256,
                            sigdecode=sigdecode_der), label + " signature invalid")
    except VerificationError:
        raise
    except Exception as error:
        raise VerificationError(label + " signature invalid") from error


def verify_response(response, ca_pubkey, challenge, expected_aid, expected_signing_pub):
    """Verify evidence against a caller-owned immediate fresh challenge32.

    This low-level API does NOT infer freshness from attacker-supplied evidence
    and does not track consumption. Long-lived/offline callers must use the
    consume-once APIs below. All byte values are raw bytes, not hex or APDU SW.
    Protocol boundary: the required INFO sealed flag is not in any signed
    message. Its authenticity requires trusted transport/personalization
    readback; these signature domains alone cannot prove irreversible sealing.
    """
    _require(isinstance(challenge, bytes) and len(challenge) == 32, "challenge must be 32 bytes")
    _require(isinstance(expected_aid, bytes) and 5 <= len(expected_aid) <= 16, "expected AID required")
    parsed = parse_response(response)
    _require(hmac.compare_digest(parsed["aid"], expected_aid), "AID mismatch")
    _require(parsed["sealed"], "attestation is not sealed")
    _require(bool(parsed["cert"]), "certificate missing")
    pub = parsed["signing_pub"]
    _require(isinstance(expected_signing_pub, bytes) and bool(expected_signing_pub), "expected signing key required")
    _require(hmac.compare_digest(pub, expected_signing_pub), "signing public key mismatch")
    if expected_aid == VAULT_AID:
        _pub(pub, NIST256p)
    else:
        _require(expected_aid in (ETH2_AID, MUSIG2_AID), "unsupported signing applet AID")
        _pub(pub, SECP256k1)
    _verify(load_ca_pubkey(ca_pubkey), parsed["cert"], ca_message(parsed), "CA certificate")
    key = _pub(parsed["attestation_pub"], NIST256p)
    _verify(key, parsed["response_sig"], RESPONSE_DOMAIN + challenge + pub + bytes([parsed["pin_state"]]), "response")
    _require(bool(parsed["binding_sig"]), "NHWV1 binding missing")
    _verify(key, parsed["binding_sig"], BINDING_DOMAIN + expected_aid + pub, "NHWV1 binding")
    return parsed


def _max_age(value):
    _require(isinstance(value, (float, int)) and math.isfinite(value) and value > 0,
             "max_age must be finite and positive")


class ChallengeVerifier:
    """Thread-safe in-memory issuer; attempts consume even invalid responses.

    State is intentionally process-local. For verification across process
    restarts use the locked, persistent state API instead.
    """
    def __init__(self, max_age=60):
        _max_age(max_age)
        self.max_age, self._pending, self._lock = max_age, {}, threading.Lock()

    def issue(self):
        with self._lock:
            now = time.monotonic()
            self._pending = {c: t for c, t in self._pending.items() if now - t <= self.max_age}
            challenge = secrets.token_bytes(32)
            self._pending[challenge] = now
            return challenge

    def verify(self, response, ca_pubkey, challenge, expected_aid, expected_signing_pub):
        with self._lock:
            issued = self._pending.pop(challenge, None)
        _require(issued is not None, "challenge not issued or already consumed")
        _require(0 <= time.monotonic() - issued <= self.max_age, "challenge expired")
        return verify_response(response, ca_pubkey, challenge, expected_aid, expected_signing_pub)


def _private_fd(path, create=False, readonly=False):
    flags = (os.O_RDONLY if readonly else os.O_RDWR) | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                 "file must be a regular exact-0600 file")
        _require(info.st_uid == os.getuid(), "file must be owned by current user")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_state(fd, state):
    raw = json.dumps(state, sort_keys=True).encode("ascii")
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    with os.fdopen(os.dup(fd), "wb", closefd=True) as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def issue_challenge(state_file, expected_aid, expected_signing_pub, max_age=60):
    """Create a NEW exact-0600 state file, never overwrite an old session.

    Host filesystem/clock integrity is trusted. Restoring old state from a
    backup can restore an unused challenge; an offline verifier is not a remote
    replay oracle or proof of current card possession.
    """
    _max_age(max_age)
    _require(isinstance(expected_aid, bytes) and 5 <= len(expected_aid) <= 16, "expected AID required")
    _require(isinstance(expected_signing_pub, bytes) and bool(expected_signing_pub), "expected signing key required")
    challenge = secrets.token_bytes(32)
    fd = _private_fd(state_file, create=True)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        _write_state(fd, dict(version=1, challenge=challenge.hex(), issued_at=time.time(),
                             max_age=max_age, aid=expected_aid.hex(),
                             signing_pub=expected_signing_pub.hex(), consumed=False))
    finally:
        os.close(fd)
    return challenge


def verify_saved_response(response, ca_pubkey, state_file, max_age=60):
    """Consume locked persistent state BEFORE any crypto/response validation.

    The age cap is the smaller of issuance policy and verification policy.
    Failed attempts burn the challenge; the state file remains a consumed
    tombstone. No --no-consume/replay bypass is provided.
    """
    _max_age(max_age)
    fd = _private_fd(state_file)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(4097)
        _require(len(raw) <= 4096, "oversized challenge state")
        try:
            state = json.loads(raw)
            _require(state["version"] == 1 and state["consumed"] is False,
                     "challenge not issued or already consumed")
            state["consumed"] = True
            _write_state(fd, state)
            _max_age(state["max_age"])
            age = time.time() - state["issued_at"]
            _require(math.isfinite(age) and 0 <= age <= min(max_age, state["max_age"]), "challenge expired or clock rolled back")
            challenge = bytes.fromhex(state["challenge"])
            aid = bytes.fromhex(state["aid"])
            pub = bytes.fromhex(state["signing_pub"])
        except VerificationError:
            raise
        except Exception as error:
            raise VerificationError("invalid challenge state") from error
    finally:
        os.close(fd)
    return verify_response(response, ca_pubkey, challenge, aid, pub)


def sign_certificate(info, ca_pubkey, ca_key_file=None, pkcs11_uri=None, openssl="openssl"):
    """Sign protocol CA message using an exact-0600 PEM or OpenSSL provider.

    PKCS11 is a provider adapter, not evidence of a tested HSM. PIN-bearing URIs
    are forbidden; provision authentication with the provider outside argv.
    Every result is verified against the independently pinned CA before use.
    """
    _require(bool(ca_key_file) != bool(pkcs11_uri), "choose one CA key source")
    message = ca_message(info)
    pin = load_ca_pubkey(ca_pubkey)
    if ca_key_file:
        fd = _private_fd(ca_key_file, readonly=True)
        with os.fdopen(fd, "rb") as stream:
            pem = stream.read(16385)
        _require(len(pem) <= 16384, "CA key file too large")
        try:
            key = SigningKey.from_pem(pem)
        except Exception as error:
            raise VerificationError("invalid unencrypted CA PEM key") from error
        _require(key.curve == NIST256p, "CA key must use P256")
        signature = key.sign_deterministic(message, hashfunc=hashlib.sha256, sigencode=sigencode_der)
    else:
        normalized = unquote(pkcs11_uri).lower()
        _require(normalized.startswith("pkcs11:") and "pin-value" not in normalized,
                 "PKCS11 URI must not contain PIN values")
        try:
            result = subprocess.run([openssl, "dgst", "-sha256", "-provider", "default",
                                     "-provider", "pkcs11", "-sign", pkcs11_uri],
                                    input=message, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError("OpenSSL PKCS11 signer unavailable") from error
        _require(result.returncode == 0, "OpenSSL PKCS11 signing failed")
        signature = result.stdout
    _signature(signature)
    _verify(pin, signature, message, "CA certificate")
    return signature


def card_command(applet, cla, ins, data=b""):
    _require(len(data) <= 255, "APDU data too long")
    apdu = bytes([cla, ins, 0, 0, len(data)]) + data
    response, sw = applet.transmit(apdu)
    _require(sw == 0x9000, f"attestation INS {ins:02x} failed: {sw:04x}")
    return response


class AttestationCommandError(VerificationError):
    """Failed attestation page, retaining SW for unsupported-applet callers."""
    def __init__(self, page, sw):
        self.page, self.sw = page, sw
        super().__init__(f"attestation page {page} failed: {sw:04x}")


def read_attestation(applet, cla, challenge):
    """Collect INFO + signed tail on one already-selected applet session.

    Both requests are case-4 SHORT APDUs with Le=00 (256), never extended
    APDUs. The exact caller-owned challenge32 is reused on both pages. No
    reconnect, SELECT, retries or provisioning is performed. Returned bytes
    retain the logical NURI-ATT-V1 evidence format; this is NOT verification.
    Call verify_response/ChallengeVerifier with the original challenge and
    independently pinned CA, AID and signing key before trusting the result.
    """
    _require(isinstance(challenge, bytes) and len(challenge) == 32, "challenge must be 32 bytes")
    _require(cla in (0, 0x80), "invalid attestation CLA")
    pages = []
    for page, limit in ((0, 170), (1, 214)):
        apdu = bytes([cla, 0x72, page, 0, 32]) + challenge + b"\x00"
        response, sw = applet.transmit(apdu)
        if sw != 0x9000:
            raise AttestationCommandError(page, sw)
        response = bytes(response)
        _require(0 < len(response) <= limit, f"invalid attestation page {page} length")
        if page == 0:
            parse_info(response)  # INFO must end at the page boundary.
        pages.append(response)
    evidence = b"".join(pages)
    parse_response(evidence)
    return evidence


def personalize(applet, expected_info, certificate, seal=False):
    """Execute write-once cert store and exact readback; seal only explicitly.

    A transport/readback error is an uncertain write, NOT authorization to retry.
    Re-read INFO before any future recovery attempt. No key generation or PIN
    operations are performed here.
    """
    before = parse_info(expected_info)
    _require(not before["sealed"] and not before["cert"], "already personalized or sealed")
    _signature(certificate)
    cla = 0 if before["aid"] == MUSIG2_AID else 0x80
    live = card_command(applet, cla, 0x70)
    _require(live == expected_info, "INFO changed since signing; refusing store")
    card_command(applet, cla, 0x71, certificate)
    after = parse_info(card_command(applet, cla, 0x70))
    wanted = dict(before, cert=certificate)
    _require(after == wanted, "certificate readback mismatch; write state uncertain")
    if seal:
        card_command(applet, cla, 0x73)
        after = parse_info(card_command(applet, cla, 0x70))
        _require(after == dict(wanted, sealed=True), "seal readback mismatch; write state uncertain")
    return after
