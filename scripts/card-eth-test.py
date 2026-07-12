#!/usr/bin/env python3
"""Test the NuriEcdsaSigner applet on the real card.

Flow:
1. SELECT the NURIETH1 applet
2. INS_GET_VERSION
3. INS_KEYGEN → get compressed pubkey
4. INS_SIGN with a known hash → get (r, s, v)
5. Verify: ecrecover(r, s, v) == pubkey
"""
import argparse
import hashlib
from smartcard.System import readers
from smartcard.CardConnection import CardConnection

APPLET_AID = bytes.fromhex("4E55524945544801")

def transmit(conn, apdu_bytes):
    res = conn.transmit(list(apdu_bytes))
    data, sw1, sw2 = res
    sw = (sw1 << 8) | sw2
    if sw != 0x9000:
        raise RuntimeError(f"APDU failed: SW={sw:04X}, data={bytes(data).hex()}")
    return bytes(data)

def select(conn):
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(APPLET_AID)]) + APPLET_AID
    return transmit(conn, apdu)

def get_version(conn):
    return transmit(conn, bytes([0x00, 0x01, 0x00, 0x00, 0x00]))

def keygen(conn):
    return transmit(conn, bytes([0x00, 0x03, 0x00, 0x00, 0x00]))

def get_pubkey(conn):
    return transmit(conn, bytes([0x00, 0x02, 0x00, 0x00, 0x00]))

def sign(conn, hash32):
    assert len(hash32) == 32
    apdu = bytes([0x00, 0x04, 0x00, 0x00, 0x20]) + hash32
    return transmit(conn, apdu)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="destructively replace the existing on-card ETH key before testing",
    )
    args = parser.parse_args()

    rs = readers()
    conn = None
    # Find the reader whose inserted card actually exposes the ETH applet.
    for i, r in enumerate(rs):
        candidate = None
        try:
            candidate = r.createConnection()
            # ponytail: OMNIKEY 5422 contact slot fails T=1 transmits; card speaks T=0
            candidate.connect(CardConnection.T0_protocol)
            select(candidate)
            conn = candidate
            print(f"Reader {i}: {r}")
            break
        except Exception:
            try:
                if candidate is not None:
                    candidate.disconnect()
            except Exception:
                pass
            continue

    if conn is None:
        raise SystemExit("Nuri ETH applet not found on any reader")

    print("\n=== SELECT NURIETH1 ===")
    print("OK")

    print("\n=== GET_VERSION ===")
    ver = get_version(conn)
    print(f"Version: {ver[0]}.{ver[1]}, build: {ver[3:7].decode()}")

    if args.regenerate:
        print("\n=== KEYGEN (DESTRUCTIVE) ===")
        pubkey33 = keygen(conn)
    else:
        print("\n=== EXISTING KEY ===")
        try:
            pubkey33 = get_pubkey(conn)
        except RuntimeError as error:
            raise SystemExit(
                f"No existing ETH key. Run once with --regenerate on a new/test card: {error}"
            ) from error
    print(f"Compressed pubkey: {pubkey33.hex()}")

    # Derive Ethereum address (host-side keccak256)
    # We need to decompress the pubkey first
    # secp256k1 params
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    G = (GX, GY)

    def modinv(a, m=P):
        return pow(a, -1, m)

    def decompress(pub33):
        prefix = pub33[0]
        x = int.from_bytes(pub33[1:], "big")
        y_sq = (pow(x, 3, P) + 7) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if (y & 1) != (prefix & 1):
            y = P - y
        return x, y

    px, py = decompress(pubkey33)
    print(f"Uncompressed: x={px:064x}")
    print(f"             y={py:064x}")

    # Ethereum address = keccak256(uncompressed_pubkey[1:])[12:]
    # We don't have keccak in Python stdlib, but we can verify the signature.
    # For now, just print the pubkey coords.
    # The address derivation will be done in the ethers.js integration.

    print("\n=== SIGN a test hash ===")
    test_hash = hashlib.sha256(b"nuri-card-eth-test").digest()
    print(f"Hash: {test_hash.hex()}")
    print("Tap the card if required...")

    sig = sign(conn, test_hash)
    r = sig[:32]
    s = sig[32:64]
    v = sig[64]
    print(f"r: {r.hex()}")
    print(f"s: {s.hex()}")
    print(f"v: {v}")

    # Verify: recover pubkey from signature
    # ECDSA recover: given (r, s, v, hash), find Q
    def ecrecover(r_val, s_val, v_val, msg_hash):
        """Recover public key from ECDSA signature."""
        # r, s are ints
        r_int = r_val
        s_int = s_val

        # R = (r, y) where y is determined by v
        y_sq = (pow(r_int, 3, P) + 7) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if (y & 1) != v_val:
            y = P - y
        R = (r_int, y)

        # Q = r⁻¹ (s·R - z·G)
        z = int.from_bytes(msg_hash, "big")
        r_inv = modinv(r_int, N)

        # s·R
        sR_x = (s_int * R[0]) % P
        sR_y = (s_int * R[1]) % P
        # This needs EC point arithmetic
        # s·R = point_mul(s, R)
        def point_add(a, b):
            if a is None: return b
            if b is None: return a
            if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
            lam = ((3 * a[0] * a[0]) * modinv((2 * a[1]) % P, P)) % P if a == b else ((b[1] - a[1]) * modinv((b[0] - a[0]) % P, P)) % P
            x3 = (lam * lam - a[0] - b[0]) % P
            return (x3, (lam * (a[0] - x3) - a[1]) % P)

        def point_mul(k, pt):
            k %= N
            if k == 0 or pt is None: return None
            result = None
            addend = pt
            while k:
                if k & 1: result = point_add(result, addend)
                addend = point_add(addend, addend)
                k >>= 1
            return result

        sR = point_mul(s_int, R)
        zG = point_mul(z, G)
        neg_zG = (zG[0], (-zG[1]) % P)
        # Q = r⁻¹ (s·R - z·G) = r⁻¹ * point_add(sR, neg_zG)
        sum_pt = point_add(sR, neg_zG)
        Q = point_mul(r_inv, sum_pt)
        return Q

    r_int = int.from_bytes(r, "big")
    s_int = int.from_bytes(s, "big")
    v_int = v

    recovered = ecrecover(r_int, s_int, v_int, test_hash)
    if recovered:
        rx, ry = recovered
        print(f"\nRecovered pubkey:")
        print(f"  x={rx:064x}")
        print(f"  y={ry:064x}")
        # Compress and compare
        recovered_prefix = 0x02 if (ry & 1) == 0 else 0x03
        recovered_pub = bytes([recovered_prefix]) + rx.to_bytes(32, "big")
        print(f"  compressed: {recovered_pub.hex()}")
        if recovered_pub == pubkey33:
            print("\n✅ ECDSA SIGNATURE VERIFIED — recovered pubkey matches card pubkey!")
            print("REAL_CARD_ETH_SIGN_FLOW_OK")
        else:
            print("\n❌ MISMATCH — recovered pubkey does not match card pubkey")
            print(f"  card:     {pubkey33.hex()}")
            print(f"  recovered:{recovered_pub.hex()}")
    else:
        print("\n❌ ECDSA recovery failed (point at infinity)")

    conn.disconnect()
    print("\n=== DONE ===")

if __name__ == "__main__":
    main()
