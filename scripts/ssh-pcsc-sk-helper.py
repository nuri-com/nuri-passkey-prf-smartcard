#!/usr/bin/env python3
import argparse
import hashlib
import os
import sys

from fido2.cose import ES256
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.pcsc import CtapPcscDevice

SSH_SK_USER_PRESENCE_REQD = 0x01
SSH_SK_USER_VERIFICATION_REQD = 0x04
SSH_SK_RESIDENT_KEY = 0x20


def kv(**items):
    for key, value in items.items():
        if value is not None:
            print(f"{key}={value}")


def fail(code, message):
    kv(status="ERR", error=code, message=str(message).replace("\n", " "))
    return 1


def device():
    devices = list(CtapPcscDevice.list_devices())
    if not devices:
        raise RuntimeError("NO_DEVICE: no PC/SC FIDO2 device found")
    index = int(os.environ.get("FIDO2_PCSC_INDEX", os.environ.get("FIDO2_DEVICE_INDEX", "0")))
    return devices[index]


def ctap_options(flags):
    opts = {"up": bool(flags & SSH_SK_USER_PRESENCE_REQD)}
    if flags & SSH_SK_RESIDENT_KEY:
        opts["rk"] = True
    if flags & SSH_SK_USER_VERIFICATION_REQD:
        opts["uv"] = True
    return opts


def public_key_bytes(cose_key):
    return b"\x04" + cose_key[-2] + cose_key[-3]


def der_len(buf, off):
    n = buf[off]
    off += 1
    if n < 0x80:
        return n, off
    size = n & 0x7F
    return int.from_bytes(buf[off : off + size], "big"), off + size


def der_ecdsa_rs(sig):
    if sig[0] != 0x30:
        raise ValueError("bad DER signature")
    _, off = der_len(sig, 1)
    if sig[off] != 0x02:
        raise ValueError("bad DER r")
    r_len, off = der_len(sig, off + 1)
    r = sig[off : off + r_len].lstrip(b"\0") or b"\0"
    off += r_len
    if sig[off] != 0x02:
        raise ValueError("bad DER s")
    s_len, off = der_len(sig, off + 1)
    s = sig[off : off + s_len].lstrip(b"\0") or b"\0"
    return r, s


def enroll(args):
    flags = int(args.flags, 0)
    att = Ctap2(device()).make_credential(
        hashlib.sha256(bytes.fromhex(args.challenge_hex)).digest(),
        {"id": args.application, "name": args.application},
        {"id": bytes.fromhex(args.user_hex), "name": "openssh", "displayName": "openssh"},
        [{"type": "public-key", "alg": ES256.ALGORITHM}],
        options=ctap_options(flags),
    )
    credential = att.auth_data.credential_data
    kv(
        status="OK",
        flags=f"{flags & 0xff:02x}",
        public_key=public_key_bytes(credential.public_key).hex(),
        key_handle=credential.credential_id.hex(),
        signature=att.att_stmt.get("sig", b"").hex(),
        authdata=bytes(att.auth_data).hex(),
    )
    return 0


def sign(args):
    flags = int(args.flags, 0)
    assertion = Ctap2(device()).get_assertion(
        args.application,
        hashlib.sha256(bytes.fromhex(args.data_hex)).digest(),
        [{"type": "public-key", "id": bytes.fromhex(args.key_handle_hex)}],
        options=ctap_options(flags),
    )
    r, s = der_ecdsa_rs(assertion.signature)
    kv(
        status="OK",
        flags=f"{int(assertion.auth_data.flags) & 0xff:02x}",
        counter=str(assertion.auth_data.counter),
        sig_r=r.hex(),
        sig_s=s.hex(),
    )
    return 0


def parser():
    p = argparse.ArgumentParser(description="PC/SC CTAP2 bridge for OpenSSH SecurityKeyProvider")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll")
    e.add_argument("--application", required=True)
    e.add_argument("--challenge-hex", required=True)
    e.add_argument("--flags", required=True)
    e.add_argument("--user-hex", required=True)
    e.set_defaults(func=enroll)
    s = sub.add_parser("sign")
    s.add_argument("--application", required=True)
    s.add_argument("--data-hex", required=True)
    s.add_argument("--key-handle-hex", required=True)
    s.add_argument("--flags", required=True)
    s.set_defaults(func=sign)
    return p


def main():
    try:
        args = parser().parse_args()
        return args.func(args)
    except RuntimeError as e:
        msg = str(e)
        return fail("NO_DEVICE" if msg.startswith("NO_DEVICE") else "GENERAL", msg)
    except (CtapError, ValueError, IndexError) as e:
        return fail("GENERAL", e)


if __name__ == "__main__":
    sys.exit(main())
