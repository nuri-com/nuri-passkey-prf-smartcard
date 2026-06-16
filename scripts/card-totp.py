#!/usr/bin/env python3
"""On-card OATH-TOTP host tool.

The card stores the secret and computes HMAC-SHA1; this host feeds the time
counter and does the public TOTP truncation. The secret never leaves the card.

  card-totp.py put  "HETZNER BASE32 SECRET"   # provision once
  card-totp.py code                            # print current 6-digit code
  card-totp.py --selfcheck                      # offline math check, no card

Reuses pyscard (already used by the other card scripts).
"""
import argparse
import base64
import hmac
import hashlib
import struct
import sys
import time

AID = bytes.fromhex("4E555249544F5450")  # "NURITOTP"
INS_PUT = 0x01
INS_CALC = 0x02


def truncate(digest: bytes, digits: int = 6) -> str:
    o = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[o:o + 4])[0] & 0x7FFFFFFF
    return f"{code % (10 ** digits):0{digits}d}"


def counter_bytes(step: int = 30, t: float | None = None) -> bytes:
    return struct.pack(">Q", int((t if t is not None else time.time()) // step))


def selfcheck() -> None:
    # RFC 6238 SHA-1 test vector: secret "12345678901234567890", T=59 -> 94287082.
    secret = b"12345678901234567890"
    digest = hmac.new(secret, struct.pack(">Q", 59 // 30), hashlib.sha1).digest()
    assert truncate(digest, 8) == "94287082", truncate(digest, 8)
    assert truncate(digest, 6) == "287082", truncate(digest, 6)
    print("SELFCHECK_OK")


def connect():
    from smartcard.System import readers  # lazy import so --selfcheck needs no reader
    rs = readers()
    if not rs:
        sys.exit("no PC/SC reader")
    # Pick whichever reader has a card that answers our AID (contact vs contactless varies).
    for r in rs:
        try:
            conn = r.createConnection()
            conn.connect()
        except Exception:
            continue
        _, sw1, sw2 = transmit(conn, [0x00, 0xA4, 0x04, 0x00, len(AID), *AID])
        if (sw1, sw2) == (0x90, 0x00):
            return conn
    sys.exit("TOTP applet not found on any reader (SELECT failed)")


def transmit(conn, apdu):
    data, sw1, sw2 = conn.transmit(apdu)
    return data, sw1, sw2


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", choices=["put", "code"])
    ap.add_argument("secret", nargs="?")
    ap.add_argument("--step", type=int, default=30)
    ap.add_argument("--digits", type=int, default=6)
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args()

    if args.selfcheck:
        selfcheck()
        return
    if not args.cmd:
        ap.error("cmd required (put|code) or --selfcheck")

    conn = connect()

    if args.cmd == "put":
        if not args.secret:
            ap.error("put needs a base32 secret")
        raw = base64.b32decode(args.secret.replace(" ", "").upper() + "=" * (-len(args.secret.replace(" ", "")) % 8))
        _, sw1, sw2 = transmit(conn, [0x00, INS_PUT, 0x00, 0x00, len(raw), *raw])
        if (sw1, sw2) != (0x90, 0x00):
            sys.exit(f"PUT failed: {sw1:02X}{sw2:02X}")
        print("provisioned")
        return

    ctr = counter_bytes(args.step)
    digest, sw1, sw2 = transmit(conn, [0x00, INS_CALC, 0x00, 0x00, len(ctr), *ctr, 0x00])
    if (sw1, sw2) != (0x90, 0x00):
        sys.exit(f"CALC failed: {sw1:02X}{sw2:02X}")
    print(truncate(bytes(digest), args.digits))


if __name__ == "__main__":
    main()
