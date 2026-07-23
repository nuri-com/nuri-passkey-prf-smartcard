#!/usr/bin/env python3
"""PKCS#11 helper for Nuri smartcard — translates PKCS#11 operations to card APDUs.

Modes:
  --card         Use the real card over PC/SC (needs ETH applet installed)
  --sim          Software simulation for host-side testing (no card needed)

Protocol: stdin/stdout line-based key=value, one command per line.
Commands: INIT, SLOTS, OPEN_SESSION, FIND_KEY, SIGN, CLOSE_SESSION, FINALIZE
"""

import argparse
import hashlib
import os
import sys
import json

# --- Software simulation (no card needed) ---
SIM_KEY = None
SIM_PUBKEY = None

def sim_init():
    global SIM_KEY, SIM_PUBKEY
    from ecdsa import SigningKey, SECP256k1
    SIM_KEY = SigningKey.generate(curve=SECP256k1)
    SIM_PUBKEY = SIM_KEY.get_verifying_key()
    return "OK"

def sim_sign(hash_hex):
    sig = SIM_KEY.sign_digest(bytes.fromhex(hash_hex), sigencode=lambda r, s, order: r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
    # Determine v (recovery id) - simplified: try both
    from ecdsa import VerifyingKey, SECP256k1
    vk = SIM_PUBKEY
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')
    # Try v=0 and v=1
    for v in range(2):
        try:
            vk.from_public_key_recovery(bytes.fromhex(hash_hex), r, s, v, SECP256k1, hashfunc=hashlib.sha256)
            return sig.hex(), v
        except:
            continue
    return sig.hex(), 0

def sim_pubkey():
    vk = SIM_PUBKEY
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return (prefix + x.to_bytes(32, 'big')).hex()

# --- Real card (PC/SC) ---
def card_select(conn, aid_hex):
    aid = bytes.fromhex(aid_hex)
    apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid)
    data, sw1, sw2 = conn.transmit(apdu)
    sw = (sw1 << 8) | sw2
    if sw != 0x9000:
        raise RuntimeError(f"SELECT {aid_hex} failed: SW={sw:04X}")
    return True

def card_sign(conn, hash_hex):
    h = bytes.fromhex(hash_hex)
    apdu = [0x00, 0x04, 0x00, 0x00, 0x20] + list(h)
    data, sw1, sw2 = conn.transmit(apdu)
    sw = (sw1 << 8) | sw2
    if sw != 0x9000:
        raise RuntimeError(f"SIGN failed: SW={sw:04X}")
    sig = bytes(data)
    return sig[:64].hex(), sig[64]

def card_pubkey(conn):
    data, sw1, sw2 = conn.transmit([0x00, 0x02, 0x00, 0x00, 0x00])
    sw = (sw1 << 8) | sw2
    if sw != 0x9000:
        raise RuntimeError(f"GET_PUBKEY failed: SW={sw:04X}")
    return bytes(data).hex()

def card_init():
    from smartcard.System import readers
    from smartcard.CardConnection import CardConnection
    rs = readers()
    for r in rs:
        try:
            c = r.createConnection()
            c.connect(protocol=CardConnection.T0_protocol)
            card_select(c, '4E55524945544801')
            return c
        except:
            try:
                c.disconnect()
            except:
                pass
    raise RuntimeError("No card with ETH applet found")

# --- Main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--card', action='store_true', help='Use real card over PC/SC')
    parser.add_argument('--sim', action='store_true', help='Use software simulation')
    args = parser.parse_args()

    mode = 'sim' if args.sim else ('card' if args.card else 'sim')
    conn = None

    if mode == 'sim':
        sim_init()
    else:
        conn = card_init()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        parts = line.split(' ', 1)
        cmd = parts[0]
        arg = parts[1] if len(parts) > 1 else ''

        try:
            if cmd == 'INIT':
                print('status=OK')
            elif cmd == 'SLOTS':
                print('slots=1')
                print('slot_0_label=Nuri Smartcard (ETH)')
                print('slot_0_flags=1')  # CKF_TOKEN_PRESENT
            elif cmd == 'OPEN_SESSION':
                print('session=1')
            elif cmd == 'FIND_KEY':
                if mode == 'sim':
                    pk = sim_pubkey()
                else:
                    pk = card_pubkey(conn)
                print(f'key_handle=1')
                print(f'key_type=EC')
                print(f'key_pubkey={pk}')
            elif cmd == 'SIGN':
                hash_hex = arg
                if mode == 'sim':
                    sig_hex, v = sim_sign(hash_hex)
                else:
                    sig_hex, v = card_sign(conn, hash_hex)
                print(f'signature={sig_hex}')
                print(f'recovery_id={v}')
            elif cmd == 'CLOSE_SESSION':
                print('status=OK')
            elif cmd == 'FINALIZE':
                print('status=OK')
                break
            else:
                print(f'error=UNKNOWN_COMMAND: {cmd}')
        except Exception as e:
            print(f'error={str(e).replace(chr(10), " ")}')

    if conn:
        try:
            conn.disconnect()
        except:
            pass

if __name__ == '__main__':
    main()
