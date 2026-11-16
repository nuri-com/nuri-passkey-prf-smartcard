#!/usr/bin/env python3
"""Offline verification and explicit, write-once Nuri card personalization.

Evidence and challenge files contain raw protocol bytes (no APDU status word).
Dry-run personalization never imports PC/SC or connects to a reader. INFO can
be captured separately with `info --execute`. CA roots are deployment pins,
not a manufacturer endorsement; a valid cert is not a card-model/chip proof.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import secrets
import warnings

from ecdsa import NIST256p, SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der

import nuri_attest as attest

import os
from pathlib import Path
import sys

from nuri_attest import (ETH2_AID, MUSIG2_AID, VAULT_AID, VerificationError,
                         card_command, issue_challenge, load_ca_pubkey,
                         parse_info, personalize, read_attestation, sign_certificate,
                         verify_saved_response)


def hex_bytes(value):
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected hex bytes") from error


def aid_bytes(value):
    aid = hex_bytes(value)
    if aid not in (ETH2_AID, MUSIG2_AID, VAULT_AID):
        raise argparse.ArgumentTypeError("expected ETH2, MuSig2 or vault canonical applet AID")
    return aid


def public_json(fields):
    return {key: value.hex() if isinstance(value, bytes) else value
            for key, value in fields.items()}


def read_pin(args):
    path = args.ca_pubkey or os.environ.get("NURI_CARD_CA_PUBKEY")
    if not path:
        raise VerificationError("CA public key pin missing; set --ca-pubkey or NURI_CARD_CA_PUBKEY; unverified")
    return load_ca_pubkey(Path(path).read_bytes())


def open_card(args):
    import nuri_pcsc  # lazy: never reached in dry-run/offline paths
    return nuri_pcsc.open_applet(args.aid.hex(), reader=args.reader)


def wipe(buffer):
    """Best effort only: Python/getpass/PCSC may retain immutable secret copies."""
    buffer[:] = b"\x00" * len(buffer)


def prompt_secret(label, aid, puk=False):
    """No stdin/env/argv fallback, no echo, no automatic re-prompt on failure."""
    first, second = bytearray(), bytearray()
    try:
        with open("/dev/tty", "w") as terminal, warnings.catch_warnings():
            if not terminal.isatty():
                raise VerificationError("controlling terminal required")
            warnings.simplefilter("error", getpass.GetPassWarning)
            first.extend(getpass.getpass(label + ": ", stream=terminal).encode("utf-8"))
            second.extend(getpass.getpass("Confirm " + label + ": ", stream=terminal).encode("utf-8"))
        if not hmac.compare_digest(first, second):
            raise VerificationError("confirmation mismatch")
        if puk:
            valid = len(first) == 16
        elif aid == MUSIG2_AID:
            valid = 4 <= len(first) <= 12 and all(48 <= c <= 57 for c in first)
        else:
            valid = 4 <= len(first) <= 16
        if not valid:
            raise VerificationError("invalid secret length or format")
        result = first
        first = bytearray()  # ownership transfers to the caller for wiping
        return result
    finally:
        wipe(first)
        wipe(second)


def secret_command(applet, cla, ins, payload):
    """Wipe the locally owned APDU, including failed or uncertain transmissions."""
    apdu = bytearray([cla, ins, 0, 0, len(payload)])
    try:
        apdu.extend(payload)
        response, sw = applet.transmit(apdu)
        if sw != 0x9000 or response:
            raise VerificationError("PIN command failed; no retry attempted")
    finally:
        wipe(apdu)


def identity_signature(public, signature, message):
    """Self-consistency only, NOT CA/manufacturer verification."""
    key = VerifyingKey.from_string(public, curve=NIST256p,
                                   valid_encodings={"uncompressed"})
    if not key.verify(signature, message, hashfunc=hashlib.sha256, sigdecode=sigdecode_der):
        raise VerificationError("identity signature mismatch")


def provisioning_response(applet, cla, aid, public=None):
    challenge = secrets.token_bytes(32)
    parsed = attest.parse_response(read_attestation(applet, cla, challenge))
    if parsed["aid"] != aid:
        raise VerificationError("AID mismatch")
    identity_signature(public or parsed["attestation_pub"], parsed["response_sig"],
                       attest.RESPONSE_DOMAIN + challenge + parsed["signing_pub"]
                       + bytes([parsed["pin_state"]]))
    return parsed


class ProvisioningTransport:
    """No 6C command replay, even for a lost/uncertain provisioning response.

    Keep the shared PC/SC helper unchanged. GET RESPONSE drains 61xx only;
    unlike a 6C resend, it never re-executes SET_PIN, VERIFY or KEYGEN.
    """
    def __init__(self, applet):
        self.applet = applet

    def transmit(self, apdu):
        conn = getattr(self.applet, "conn", None)
        if conn is None:  # injectable fake transport, with the same no-retry contract
            return self.applet.transmit(apdu)
        command = list(apdu)
        try:
            data, sw1, sw2 = conn.transmit(command)
        finally:
            command[:] = [0] * len(command)
        response = bytearray(data)
        for _ in range(64):
            if sw1 != 0x61:
                return bytes(response), (sw1 << 8) | sw2
            data, sw1, sw2 = conn.transmit([0, 0xC0, 0, 0, sw2])
            response.extend(data)
        raise VerificationError("GET RESPONSE limit exceeded; no command replay")

    def close(self):
        self.applet.close()


def init_key(args):
    """First-use provisioning of a physically trusted blank spare, CA UNVERIFIED.

    No certificate or seal is created/verified here. Authenticate the card later
    with a separately pinned CA. A failed/uncertain write is never retried.
    """
    if args.with_puk and args.aid != ETH2_AID:
        raise VerificationError("--with-puk is only supported by ETH2")
    if not args.execute:
        return dict(dry_run=True, hardware_accessed=False, ca_verified=False,
                    action="unverified first-use provisioning of a trusted blank spare")
    applet = None
    pin, puk, payload = bytearray(), bytearray(), bytearray()
    cla = 0 if args.aid == MUSIG2_AID else 0x80
    try:
        applet = ProvisioningTransport(open_card(args))
        before = provisioning_response(applet, cla, args.aid)
        # Exactly required=1, unset/unvalidated/unblocked; no configured/demo keys.
        if (before["pin_state"] != 1 or before["signing_pub"] or before["binding_sig"]
                or before["sealed"] or before["cert"]):
            raise VerificationError("not a mandatory-PIN blank spare; refusing provisioning")
        pin = prompt_secret("New PIN (MuSig2: 4..12 digits; ETH2/vault: 4..16 UTF-8 bytes)", args.aid)
        if args.with_puk:
            puk = prompt_secret("New PUK (exactly 16 UTF-8 bytes)", args.aid, puk=True)
        if args.aid == ETH2_AID:
            payload.append(len(pin))
        payload.extend(pin)
        if args.with_puk:
            payload.append(len(puk))
            payload.extend(puk)
        secret_command(applet, cla, 0x10 if args.aid == VAULT_AID else 0x21, payload)
        wipe(payload)
        secret_command(applet, cla, 0x20, pin)
        wipe(pin)
        wipe(puk)
        generated = card_command(applet, cla, 0x04 if args.aid == MUSIG2_AID else 0x03)
        public = card_command(applet, cla, 0x03 if args.aid == MUSIG2_AID else 0x02)
        if generated != public:
            raise VerificationError("keygen/public readback mismatch")
        curve = NIST256p if args.aid == VAULT_AID else SECP256k1
        encoding = "compressed" if args.aid == MUSIG2_AID else "uncompressed"
        key = VerifyingKey.from_string(public, curve=curve, valid_encodings={encoding})
        canonical = key.to_string("uncompressed" if args.aid == VAULT_AID else "compressed")
        binding = card_command(applet, cla, 0x74)
        identity_signature(before["attestation_pub"], binding,
                           attest.BINDING_DOMAIN + args.aid + canonical)
        after = provisioning_response(applet, cla, args.aid, before["attestation_pub"])
        for field in ("version", "card_id", "aid", "attestation_pub", "sealed", "cert"):
            if after[field] != before[field]:
                raise VerificationError("attestation identity readback mismatch")
        if (after["pin_state"] != 7 or after["signing_pub"] != canonical
                or after["binding_sig"] != binding):
            raise VerificationError("keyed attestation readback mismatch")
        return {"signing_pub": canonical.hex()}
    finally:
        wipe(pin)
        wipe(puk)
        wipe(payload)
        if applet is not None:
            try:
                # Explicit re-SELECT clears applet PIN authorization; disconnect
                # alone does not prove logout. Even error paths attempt this.
                _, sw = applet.transmit(bytes([0, 0xA4, 4, 0, len(args.aid)]) + args.aid)
                if sw != 0x9000:
                    raise VerificationError("logout unconfirmed; remove card")
            finally:
                applet.close()


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init-key", help="trusted blank spare only; CA-unverified provisioning, dry-run by default")
    init.add_argument("--aid", type=aid_bytes, required=True)
    init.add_argument("--reader")
    init.add_argument("--execute", action="store_true", help="required to connect and set PIN/generate a key")
    init.add_argument("--with-puk", action="store_true", help="ETH2 only: also prompt twice for a 16-byte PUK")
    info = commands.add_parser("info", help="explicitly capture public INFO from a card")
    info.add_argument("--aid", type=aid_bytes, required=True)
    info.add_argument("--reader")
    info.add_argument("--execute", action="store_true", help="required to connect to PC/SC")
    info.add_argument("--out", type=Path, required=True, help="raw INFO output (new file)")

    personal = commands.add_parser("personalize", help="dry-run default; --execute stores a cert")
    personal.add_argument("--aid", type=aid_bytes, required=True)
    personal.add_argument("--info-file", type=Path, help="offline raw INFO; live INFO must match before writing")
    personal.add_argument("--ca-pubkey", help="pinned PEM/hex/SEC1 public key file; env NURI_CARD_CA_PUBKEY")
    source = personal.add_mutually_exclusive_group(required=True)
    source.add_argument("--ca-key", type=Path, help="unencrypted P256 CA PEM, regular file mode exactly 0600")
    source.add_argument("--pkcs11-uri", help="OpenSSL pkcs11 provider key URI, no pin-value (HSM path unproven)")
    personal.add_argument("--openssl", default="openssl", help="OpenSSL 3 executable with pkcs11 provider")
    personal.add_argument("--reader")
    personal.add_argument("--cert-out", type=Path, help="save DER CA signature to a new file")
    personal.add_argument("--execute", action="store_true", help="connect and store after exact INFO recheck")
    personal.add_argument("--seal", action="store_true", help="also irreversibly seal, checking INFO readback")

    challenge = commands.add_parser("challenge", help="issue random32 with new consume-once state")
    challenge.add_argument("--state", type=Path, required=True, help="NEW private session file; do not restore old state")
    challenge.add_argument("--expected-aid", type=aid_bytes, required=True)
    challenge.add_argument("--expected-signing-pub", type=hex_bytes, required=True)
    challenge.add_argument("--max-age", type=float, default=60, help="seconds; default 60")
    challenge.add_argument("--out", type=Path, help="raw challenge32 output (new file); hex always printed")

    capture = commands.add_parser("capture-response", help="capture two short-APDU pages as raw logical evidence")
    capture.add_argument("--challenge-file", type=Path, required=True, help="caller-issued raw challenge32")
    capture.add_argument("--out", type=Path, required=True, help="raw logical evidence output (new file)")
    capture.add_argument("--aid", type=aid_bytes, required=True)
    capture.add_argument("--reader")
    capture.add_argument("--execute", action="store_true", help="required to connect to PC/SC; capture does not verify")

    verify = commands.add_parser("verify", help="offline verify, consuming saved challenge even on failure")
    verify.add_argument("--response-file", type=Path, required=True)
    verify.add_argument("--state", type=Path, required=True)
    verify.add_argument("--ca-pubkey", help="pinned public key file; env NURI_CARD_CA_PUBKEY")
    verify.add_argument("--max-age", type=float, default=60, help="additional age cap, never extends issuance policy")
    return root


def write_new(path, data):
    with path.open("xb") as stream:
        stream.write(data)


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == "init-key":
        try:
            print(json.dumps(init_key(args), sort_keys=True))
            return 0
        except (Exception, KeyboardInterrupt):
            # Transport exceptions may include complete secret APDUs. Never
            # interpolate exception text or emit a traceback on this path.
            print("init-key failed; no retry attempted; state may have changed. "
                  "Remove the card if logout was not confirmed.", file=sys.stderr)
            return 1
    try:
        if args.command == "challenge":
            challenge = issue_challenge(args.state, args.expected_aid,
                                        args.expected_signing_pub, args.max_age)
            if args.out:
                write_new(args.out, challenge)
            print(json.dumps({"challenge": challenge.hex(), "state": str(args.state),
                              "max_age": args.max_age, "consumed": False}))
        elif args.command == "verify":
            # Read public evidence and the configured pin before burning state;
            # once verification starts, every attempt (including invalid DER)
            # consumes state. No arbitrary --challenge/replay acceptance option.
            pin = read_pin(args)
            evidence = args.response_file.read_bytes()
            result = verify_saved_response(evidence, pin, args.state, args.max_age)
            print(json.dumps(dict(public_json(result), verified=True,
                                  freshness="host-issued-age-limited-consumed"), sort_keys=True))
        elif args.command == "capture-response":
            if not args.execute:
                raise VerificationError("capture-response requires explicit --execute to connect; no hardware accessed")
            challenge = args.challenge_file.read_bytes()
            if len(challenge) != 32:
                raise VerificationError("challenge must be 32 bytes")
            if args.out.exists() or args.out.is_symlink():
                raise VerificationError("response output already exists; refusing overwrite")
            with open_card(args) as applet:
                raw = read_attestation(applet, 0 if args.aid == MUSIG2_AID else 0x80, challenge)
            # Capture is intentionally separate from trust/freshness verification.
            # The offline verify command consumes the original issuance state.
            write_new(args.out, raw)
            print(json.dumps({"captured": True, "verified": False, "pages": 2,
                              "response_file": str(args.out), "bytes": len(raw)}, sort_keys=True))
        elif args.command == "info":
            if not args.execute:
                raise VerificationError("info requires explicit --execute to connect; no hardware accessed")
            with open_card(args) as applet:
                raw = card_command(applet, 0 if args.aid == MUSIG2_AID else 0x80, 0x70)
            result = parse_info(raw)
            if result["aid"] != args.aid:
                raise VerificationError("INFO AID mismatch")
            write_new(args.out, raw)
            print(json.dumps(public_json(result), sort_keys=True))
        else:
            if not args.execute and not args.info_file:
                print(json.dumps({"dry_run": True, "hardware_accessed": False,
                                  "action": "capture INFO separately with info --execute, then use --info-file",
                                  "would_store_certificate": True, "would_seal": args.seal}))
                return 0
            pin = read_pin(args)
            applet = None
            try:
                if args.info_file:
                    raw = args.info_file.read_bytes()
                else:
                    applet = open_card(args)
                    raw = card_command(applet, 0 if args.aid == MUSIG2_AID else 0x80, 0x70)
                info = parse_info(raw)
                if info["aid"] != args.aid:
                    raise VerificationError("INFO AID mismatch")
                if info["sealed"] or info["cert"]:
                    raise VerificationError("already personalized or sealed; no overwrite attempted")
                certificate = sign_certificate(info, pin, args.ca_key, args.pkcs11_uri, args.openssl)
                if args.cert_out:
                    write_new(args.cert_out, certificate)
                if args.execute:
                    if applet is None:
                        applet = open_card(args)
                    result = personalize(applet, raw, certificate, seal=args.seal)
                    output = dict(public_json(result), executed=True, readback_verified=True)
                else:
                    output = dict(public_json(info), dry_run=True, hardware_accessed=False,
                                  certificate=certificate.hex(), would_seal=args.seal)
                print(json.dumps(output, sort_keys=True))
            finally:
                if applet is not None:
                    applet.close()
        return 0
    except (VerificationError, OSError, ValueError) as error:
        print(f"attestation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
