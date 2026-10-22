#!/usr/bin/env python3
"""On-card OATH-TOTP host tool.

The card stores the secret and computes HMAC-SHA1; this host feeds the time
counter and does the public TOTP truncation. The secret never leaves the card.

  card-totp.py put  "HETZNER BASE32 SECRET"   # provision; prompts for the admin PIN
  card-totp.py code                            # print current 6-digit code
  card-totp.py status                          # provisioned / HMAC engine / PIN tries
  card-totp.py --selfcheck                      # offline math check, no card

PUT wire format (applet >= 1.1): [pinLen][pin 4..16][secret]. The first PUT
chooses the admin PIN; later PUTs must present it (5 tries, then PUT is blocked
until the applet is reinstalled). NURI_TOTP_PIN skips the prompt. CALC is not
PIN-gated: holding the card still means reading codes.

Reuses pyscard (already used by the other card scripts).
"""
import argparse
import base64
import getpass
import hmac
import hashlib
import struct
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

AID = bytes.fromhex("4E555249544F5450")  # "NURITOTP"
INS_PUT = 0x01
INS_CALC = 0x02
INS_STATUS = 0x03
PIN_MIN, PIN_MAX = 4, 16


def truncate(digest: bytes, digits: int = 6) -> str:
    o = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[o:o + 4])[0] & 0x7FFFFFFF
    return f"{code % (10 ** digits):0{digits}d}"


def counter_bytes(step: int = 30, t: float | None = None) -> bytes:
    return struct.pack(">Q", int((t if t is not None else time.time()) // step))


def put_apdu(pin: bytes, secret: bytes) -> list[int]:
    """Build the INS_PUT APDU: [pinLen][pin][secret] (card/totp/NuriOathTotp.java put())."""
    if not PIN_MIN <= len(pin) <= PIN_MAX:
        raise ValueError(f"PIN must be {PIN_MIN}..{PIN_MAX} bytes")
    if not 1 <= len(secret) <= 64:
        raise ValueError("secret must be 1..64 bytes")
    body = bytes([len(pin)]) + pin + secret
    return [0x00, INS_PUT, 0x00, 0x00, len(body), *body]


def selfcheck() -> None:
    # RFC 6238 SHA-1 test vectors: secret "12345678901234567890" (Appendix B).
    secret = b"12345678901234567890"
    for t, code in ((59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")):
        digest = hmac.new(secret, struct.pack(">Q", t // 30), hashlib.sha1).digest()
        assert truncate(digest, 8) == code, (t, truncate(digest, 8))
    assert truncate(hmac.new(secret, struct.pack(">Q", 1), hashlib.sha1).digest(), 6) == "287082"
    apdu = put_apdu(b"1234", secret)
    assert apdu[:5] == [0x00, INS_PUT, 0x00, 0x00, 25] and apdu[5] == 4 and bytes(apdu[6:10]) == b"1234"
    print("SELFCHECK_OK")


def read_pin(prompt: str) -> bytes:
    env = os.environ.get("NURI_TOTP_PIN")
    pin = env if env is not None else getpass.getpass(prompt)
    raw = pin.encode()
    if not PIN_MIN <= len(raw) <= PIN_MAX:
        sys.exit(f"PIN must be {PIN_MIN}..{PIN_MAX} characters")
    return raw


def connect():
    import nuri_pcsc  # lazy import so --selfcheck needs no reader
    # Pick whichever reader/protocol has a card that answers our AID (contact vs contactless varies).
    try:
        return nuri_pcsc.open_applet(AID.hex())
    except nuri_pcsc.CardError as error:
        if error.code == "NO_READER":
            sys.exit(f"no PC/SC reader ({error})")
        sys.exit(f"TOTP applet not found on any reader (SELECT failed: {error})")


def transmit(conn, apdu):
    data, sw = conn.transmit(bytes(apdu))
    return list(data), sw >> 8, sw & 0xFF


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", choices=["put", "code", "status"])
    ap.add_argument("secret", nargs="?")
    ap.add_argument("--step", type=int, default=30)
    ap.add_argument("--digits", type=int, default=6)
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args()

    if args.selfcheck:
        selfcheck()
        return
    if not args.cmd:
        ap.error("cmd required (put|code|status) or --selfcheck")

    conn = connect()

    if args.cmd == "status":
        print("REAL_CARD_TOTP_SELECT_OK")
        data, sw1, sw2 = transmit(conn, [0x00, INS_STATUS, 0x00, 0x00, 0x00])
        if (sw1, sw2) == (0x90, 0x00) and len(data) == 3:
            engine = {0: "native ALG_HMAC_SHA1", 1: "software HMAC-SHA1 (MessageDigest.ALG_SHA)"}.get(data[1], "?")
            print(f"provisioned={bool(data[0])} engine={engine} pin_tries_left={data[2]}")
        elif (sw1, sw2) == (0x6D, 0x00):
            print("applet 1.0 (no STATUS, unauthenticated PUT); reinstall dist/nuri-oath-totp.cap")
        else:
            sys.exit(f"STATUS failed: {sw1:02X}{sw2:02X}")
        return

    if args.cmd == "put":
        if not args.secret:
            ap.error("put needs a base32 secret")
        raw = base64.b32decode(args.secret.replace(" ", "").upper() + "=" * (-len(args.secret.replace(" ", "")) % 8))
        pin = read_pin("TOTP admin PIN (chosen on first PUT, required after): ")
        _, sw1, sw2 = transmit(conn, put_apdu(pin, raw))
        if sw1 == 0x63 and sw2 & 0xF0 == 0xC0:
            sys.exit(f"PUT rejected: wrong PIN, {sw2 & 0x0F} tries left")
        if (sw1, sw2) == (0x69, 0x83):
            sys.exit("PUT blocked: PIN tries exhausted; reinstall the applet (TOTP_REINSTALL=YES) to reprovision")
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
