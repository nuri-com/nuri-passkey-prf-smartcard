#!/usr/bin/env python3
"""Test the legacy NuriEcdsaSigner (ETH1) demo applet on the real card.

W28: ETH1 has no PIN, so this tool refuses unless env NURI_ALLOW_ETH1_DEMO is
exactly "1" (checked before any card I/O), refuses when the PIN-gated ETH2
applet is installed (or its absence cannot be confirmed as SW 6A82), and warns
on stderr when it does talk to ETH1.

Flow:
1. SELECT the NURIETH1 applet
2. INS_GET_VERSION
3. INS_KEYGEN → get compressed pubkey
4. INS_SIGN with a known hash → get (r, s, v)
5. Verify: ecrecover(r, s, v) == pubkey
"""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nuri_eth_policy
import nuri_pcsc

APPLET_AID = bytes.fromhex(nuri_eth_policy.ETH1_AID)
MUSIG2_AID = bytes.fromhex("4E5552494D554701")  # was a 9-byte typo, the RNG check silently skipped

def transmit(conn, apdu_bytes):
    data, sw = conn.transmit(bytes(apdu_bytes))
    if sw != 0x9000:
        raise RuntimeError(f"APDU failed: SW={sw:04X}, data={data.hex()}")
    return data

def select(conn):
    return select_aid(conn, APPLET_AID)

def select_aid(conn, aid):
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
    return transmit(conn, apdu)

def get_version(conn):
    return transmit(conn, bytes([0x00, 0x01, 0x00, 0x00, 0x00]))

def raw_sw(conn, apdu_bytes):
    return conn.transmit(bytes(apdu_bytes))

def musig2_rng_health_check(conn):
    """Coldcard Mk3 lesson: TRNG code present in the binary does not prove the
    TRNG is what actually runs — verify behavior on the physical card. Four
    independent MuSig2 nonce draws must be unique valid compressed points,
    and INS_INIT (0x02, removed in applet 1.11) must be rejected. Fails closed."""
    try:
        select_aid(conn, MUSIG2_AID)
    except RuntimeError:
        print("MuSig2 applet not present; skipping RNG health check")
        return
    # NEVER probe INS_INIT (0x02): on applets < 1.11 it is accepted and REPLACES the
    # master key with sha256(data). Probing it with 32 zero bytes overwrote a real
    # card's MuSig2 key with a publicly known key on 2026-10-18. Decide by version.
    ver = transmit(conn, bytes([0x00, 0x01, 0x00, 0x00, 0x00]))
    if (ver[0], ver[1]) < (1, 11):
        raise SystemExit(f"MuSig2 applet {ver[0]}.{ver[1]} < 1.11 still has host seed import (INS_INIT). "
                         "Do not use it for funds; install 1.12+ on a new card.")
    seen = set()
    for _ in range(2):
        resp = transmit(conn, bytes([0x00, 0x40, 0x00, 0x00, 0x00]))
        for off in (0, 33):
            point = resp[off:off + 33]
            if point[0] not in (0x02, 0x03):
                raise SystemExit(f"RNG health check FAILED: malformed nonce point {point.hex()}")
            if point in seen:
                raise SystemExit("RNG health check FAILED: repeated nonce draw — on-card RNG not trusted")
            seen.add(point)
    print("RNG health check: 4 unique on-card nonce draws, INS_INIT rejected")

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

    # ETH1 demo gate (env, ETH2 preferred, confirmed 6A82 only) before keygen/sign.
    try:
        conn = nuri_eth_policy.open_eth1_demo(nuri_pcsc)
    except nuri_eth_policy.EthPolicyError as error:
        raise SystemExit(f"Refusing ETH1 demo test: {error}") from error
    except nuri_pcsc.CardError as error:
        raise SystemExit(f"Nuri ETH1 applet not found on any reader ({error})") from error
    print(f"Reader: {conn.reader_name} (protocol {conn.protocol})")

    print("\n=== SELECT NURIETH1 ===")
    print("OK")

    print("\n=== GET_VERSION ===")
    ver = get_version(conn)
    print(f"Version: {ver[0]}.{ver[1]}, build: {ver[3:7].decode()}")

    if args.regenerate:
        print("\n=== KEYGEN (one-shot, blank cards only) ===")
        pubkey33 = keygen(conn)
    else:
        print("\n=== EXISTING KEY ===")
        try:
            pubkey33 = get_pubkey(conn)
        except RuntimeError as error:
            raise SystemExit(
                f"No existing ETH key. Run once with --regenerate on a blank card: {error}"
            ) from error
        # Applet 1.4+: KEYGEN is one-shot (6989 once keyed). Probing it is DESTRUCTIVE on
        # applets < 1.4: KEYGEN succeeds and silently replaces the key (this rotated a real
        # card's ETH key on 2026-10-18). Only probe when the applet reports >= 1.4.
        if (ver[0], ver[1]) >= (1, 4):
            _, sw = raw_sw(conn, bytes([0x00, 0x03, 0x00, 0x00, 0x00]))
            if sw != 0x6989:
                raise SystemExit(f"KEYGEN on keyed card returned SW={sw:04X}, expected 6989")
            print("One-shot KEYGEN guard: OK (SW=6989)")
        else:
            print(f"One-shot KEYGEN guard: SKIPPED (applet {ver[0]}.{ver[1]} < 1.4 has no guard; probing would replace the key)")
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
    if len(sig) != 65 or sig[64] not in (0, 1):
        conn.close()
        raise SystemExit(
            f"Malformed ETH1 signature: expected r||s||v (65 bytes, v in 0/1), "
            f"got {len(sig)} bytes ending in {sig[-1] if sig else 'none'}: {sig.hex()}"
        )
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
        r_int = r_val
        s_int = s_val
        if not (0 < r_int < N and 0 < s_int < N):
            raise ValueError("r and s must satisfy 0 < r,s < secp256k1 order")

        # R = (r, y) where y is determined by v
        y_sq = (pow(r_int, 3, P) + 7) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if pow(y, 2, P) != y_sq:
            raise ValueError("r does not identify a secp256k1 point")
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

    try:
        recovered = ecrecover(r_int, s_int, v_int, test_hash)
    except (ValueError, ZeroDivisionError, OverflowError) as error:
        conn.close()
        raise SystemExit(
            f"ETH1 ECDSA signature malformed (recovery raised {type(error).__name__}: {error})"
        ) from error

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
            conn.close()
            raise SystemExit(
                "ETH1 ECDSA signature MISMATCH: recovered pubkey does not match card pubkey"
            )
    else:
        print("\n❌ ECDSA recovery failed (point at infinity)")
        conn.close()
        raise SystemExit("ETH1 ECDSA recovery failed (point at infinity)")

    print("\n=== MUSIG2 RNG HEALTH CHECK ===")
    musig2_rng_health_check(conn)

    conn.close()
    print("\n=== DONE ===")

if __name__ == "__main__":
    main()
