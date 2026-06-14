#!/usr/bin/env python3
"""
Real-card 2-of-2 MuSig2/BIP340 cosign proof.

This talks to the installed NuriMuSig2 Java Card applet over PC/SC for the
card partial signature. The client partial is computed locally, then the final
aggregate BIP340 signature is verified against the aggregate x-only key.
"""

import argparse
import hashlib
import json
import secrets
import sys
from smartcard.System import readers


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

APPLET_AID = bytes.fromhex("4E5552494D554701")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + data)


def int_from_bytes(data: bytes) -> int:
    return int.from_bytes(data, "big")


def bytes_from_int(value: int) -> bytes:
    return value.to_bytes(32, "big")


def mod_inv(value: int, modulus: int) -> int:
    return pow(value, -1, modulus)


def mod_sqrt(value: int):
    if value == 0:
        return 0
    root = pow(value, (P + 1) // 4, P)
    if (root * root - value) % P == 0:
        return root
    return None


def lift_x_even_y(x: int):
    y = mod_sqrt((pow(x, 3, P) + 7) % P)
    if y is None:
        raise ValueError("x is not on secp256k1")
    if y & 1:
        y = (-y) % P
    return (x, y)


def lift_compressed(comp: bytes):
    if len(comp) != 33 or comp[0] not in (2, 3):
        raise ValueError("bad compressed public key")
    point = lift_x_even_y(int_from_bytes(comp[1:]))
    if (point[1] & 1) != (comp[0] & 1):
        point = (point[0], (-point[1]) % P)
    return point


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        lam = (3 * x1 * x1) * mod_inv((2 * y1) % P, P) % P
    else:
        lam = (y2 - y1) * mod_inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_neg(point):
    return (point[0], (-point[1]) % P)


def point_mul(k: int, point):
    if k % N == 0 or point is None:
        return None
    result = None
    addend = point
    k %= N
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def compress_point(point) -> bytes:
    prefix = b"\x02" if point[1] % 2 == 0 else b"\x03"
    return prefix + bytes_from_int(point[0])


def normalize_secret_even_y(secret: int):
    point = point_mul(secret, G)
    if point[1] & 1:
        secret = (-secret) % N
        point = point_neg(point)
    return secret, point


def random_secret_even_y():
    while True:
        secret = int_from_bytes(secrets.token_bytes(32)) % N
        if secret:
            return normalize_secret_even_y(secret)


def bip340_verify(signature: bytes, msg32: bytes, pubkey_x32: bytes) -> bool:
    if len(signature) != 64 or len(msg32) != 32 or len(pubkey_x32) != 32:
        return False
    rx = int_from_bytes(signature[:32])
    s = int_from_bytes(signature[32:])
    if rx >= P or s >= N:
        return False
    pubkey = lift_x_even_y(int_from_bytes(pubkey_x32))
    e = int_from_bytes(tagged_hash("BIP0340/challenge", signature[:32] + pubkey_x32 + msg32)) % N
    r = point_add(point_mul(s, G), point_neg(point_mul(e, pubkey)))
    if r is None:
        return False
    return (r[1] % 2 == 0) and r[0] == rx


def partial_verify(partial: bytes, pub_nonce1: bytes, pub_nonce2: bytes, b: bytes, parity: int, e: bytes, coeff: bytes, pubkey33: bytes) -> bool:
    s = int_from_bytes(partial) % N
    b_int = int_from_bytes(b) % N
    e_int = int_from_bytes(e) % N
    coeff_int = int_from_bytes(coeff) % N
    k1_point = lift_compressed(pub_nonce1)
    k2_point = lift_compressed(pub_nonce2)
    nonce_point = point_add(k1_point, point_mul(b_int, k2_point))
    if parity == 1:
        nonce_point = point_neg(nonce_point)
    p_i = lift_x_even_y(int_from_bytes(pubkey33[1:]))
    rhs = point_add(nonce_point, point_mul((e_int * coeff_int) % N, p_i))
    return point_mul(s, G) == rhs


class NuriMuSig2Card:
    def __init__(self):
        self.conn = None
        self.reader = None

    def connect(self):
        select = [0x00, 0xA4, 0x04, 0x00, len(APPLET_AID)] + list(APPLET_AID)
        for idx, reader in enumerate(readers()):
            try:
                conn = reader.createConnection()
                conn.connect()
                _, sw1, sw2 = conn.transmit(select)
                if ((sw1 << 8) | sw2) == 0x9000:
                    self.conn = conn
                    self.reader = f"{idx}:{reader}"
                    return
                conn.disconnect()
            except Exception:
                pass
        raise RuntimeError("No NuriMuSig2 card found")

    def disconnect(self):
        if self.conn:
            self.conn.disconnect()

    def transmit_ok(self, apdu):
        response, sw1, sw2 = self.conn.transmit(apdu)
        status = (sw1 << 8) | sw2
        if status != 0x9000:
            raise RuntimeError(f"APDU failed: SW={status:04X}")
        return bytes(response)

    def version(self):
        response = self.transmit_ok([0x00, 0x01, 0x00, 0x00, 0x00])
        return {
            "version": f"{response[0]}.{response[1]}",
            "build": response[3:7].decode("ascii", errors="ignore"),
        }

    def init_seed(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self.transmit_ok([0x00, 0x02, 0x00, 0x00, 0x20] + list(seed))

    def pubkey(self) -> bytes:
        return self.transmit_ok([0x00, 0x03, 0x00, 0x00, 0x00])

    def keygen(self) -> bytes:
        response = self.transmit_ok([0x00, 0x04, 0x00, 0x00, 0x00])
        if len(response) != 33:
            raise RuntimeError(f"unexpected keygen pubkey length: {len(response)}")
        return response

    def nonces(self):
        response = self.transmit_ok([0x00, 0x40, 0x00, 0x00, 0x00])
        if len(response) != 66:
            raise RuntimeError(f"unexpected nonce response length: {len(response)}")
        return response[:33], response[33:]

    def finalize(self, coeff: bytes, b: bytes, parity: int, e: bytes) -> bytes:
        payload = coeff + b + bytes([parity]) + e
        response = self.transmit_ok([0x00, 0x41, 0x00, 0x00, len(payload)] + list(payload) + [0x20])
        if len(response) != 32:
            raise RuntimeError(f"unexpected partial length: {len(response)}")
        return response


def key_agg_coefficients(pubkeys33):
    xonly_sorted = sorted([pk[1:] for pk in pubkeys33])
    key_list_hash = tagged_hash("KeyAgg list", b"".join(xonly_sorted))
    coeffs = {}
    aggregate = None
    for pk in pubkeys33:
        xonly = pk[1:]
        coeff = int_from_bytes(tagged_hash("KeyAgg coefficient", key_list_hash + xonly)) % N
        if coeff == 0:
            coeff = 1
        coeffs[xonly.hex()] = coeff
        aggregate = point_add(aggregate, point_mul(coeff, lift_x_even_y(int_from_bytes(xonly))))
    return coeffs, aggregate


def run(args):
    msg32 = bytes.fromhex(args.msg32) if args.msg32 else sha256(args.message.encode())
    if len(msg32) != 32:
        raise ValueError("msg32 must be 32 bytes")

    card = NuriMuSig2Card()
    card.connect()
    try:
        version = card.version()

        # Prefer real on-card KEYGEN. Keep INIT(seed) as an explicit fallback for
        # old v1.9 applets only; production should use KEYGEN.
        use_init_seed = args.use_init_seed
        card_pubkey = None
        client_secret = None
        client_point = None
        coeffs = None
        aggregate = None

        if use_init_seed:
            for _ in range(128):
                card.init_seed(secrets.token_bytes(32))
                candidate_card_pubkey = card.pubkey()
                if candidate_card_pubkey[0] == 0x02:
                    card_pubkey = candidate_card_pubkey
                    break
            if card_pubkey is None:
                raise RuntimeError("could not provision even-y card key through INIT(seed)")
        else:
            card_pubkey = card.keygen()
            if card_pubkey[0] != 0x02:
                raise RuntimeError("KEYGEN did not return an even-y compressed public key")

        for _ in range(128):
            candidate_client_secret, candidate_client_point = random_secret_even_y()
            candidate_client_pubkey = compress_point(candidate_client_point)
            candidate_coeffs, candidate_aggregate = key_agg_coefficients([candidate_client_pubkey, card_pubkey])
            if candidate_aggregate and candidate_aggregate[1] % 2 == 0:
                client_secret = candidate_client_secret
                client_point = candidate_client_point
                coeffs = candidate_coeffs
                aggregate = candidate_aggregate
                break
        if client_secret is None:
            if use_init_seed:
                raise RuntimeError("could not find even-y aggregate proof keys after retries")
            # A new card key is cheap in this test applet; retry the full keygen
            # once more if client-only retries did not produce even aggregate.
            card_pubkey = card.keygen()
            if card_pubkey[0] != 0x02:
                raise RuntimeError("KEYGEN retry did not return an even-y compressed public key")
            for _ in range(128):
                candidate_client_secret, candidate_client_point = random_secret_even_y()
                candidate_client_pubkey = compress_point(candidate_client_point)
                candidate_coeffs, candidate_aggregate = key_agg_coefficients([candidate_client_pubkey, card_pubkey])
                if candidate_aggregate and candidate_aggregate[1] % 2 == 0:
                    client_secret = candidate_client_secret
                    client_point = candidate_client_point
                    coeffs = candidate_coeffs
                    aggregate = candidate_aggregate
                    break
        if client_secret is None:
            raise RuntimeError("could not find even-y aggregate proof keys after retries")

        client_pubkey = compress_point(client_point)
        aggregate_xonly = bytes_from_int(aggregate[0])
        client_coeff_int = coeffs[client_pubkey[1:].hex()]
        card_coeff_int = coeffs[card_pubkey[1:].hex()]
        client_coeff = bytes_from_int(client_coeff_int)
        card_coeff = bytes_from_int(card_coeff_int)

        client_k1, client_k1_point = random_secret_even_y()
        client_k2, client_k2_point = random_secret_even_y()
        client_nonce1 = compress_point(client_k1_point)
        client_nonce2 = compress_point(client_k2_point)
        card_nonce1, card_nonce2 = card.nonces()

        r1 = point_add(lift_compressed(client_nonce1), lift_compressed(card_nonce1))
        r2 = point_add(lift_compressed(client_nonce2), lift_compressed(card_nonce2))
        r1_x = bytes_from_int(r1[0])
        r2_x = bytes_from_int(r2[0])
        b = tagged_hash("MuSig/noncecoef", r1_x + r2_x + aggregate_xonly + msg32)
        b_int = int_from_bytes(b) % N
        aggregate_r = point_add(r1, point_mul(b_int, r2))
        parity = 0 if aggregate_r[1] % 2 == 0 else 1
        r_even = aggregate_r if parity == 0 else point_neg(aggregate_r)
        r_even_x = bytes_from_int(r_even[0])
        e = tagged_hash("BIP0340/challenge", r_even_x + aggregate_xonly + msg32)
        e_int = int_from_bytes(e) % N

        card_partial = card.finalize(card_coeff, b, parity, e)

        client_r = (client_k1 + b_int * client_k2) % N
        if parity == 1:
            client_r = (-client_r) % N
        client_partial_int = (client_r + e_int * client_coeff_int * client_secret) % N
        client_partial = bytes_from_int(client_partial_int)

        final_s = (int_from_bytes(card_partial) + int_from_bytes(client_partial)) % N
        final_signature = r_even_x + bytes_from_int(final_s)
        final_ok = bip340_verify(final_signature, msg32, aggregate_xonly)
        card_partial_ok = partial_verify(card_partial, card_nonce1, card_nonce2, b, parity, e, card_coeff, card_pubkey)
        client_partial_ok = partial_verify(client_partial, client_nonce1, client_nonce2, b, parity, e, client_coeff, client_pubkey)

        return {
            "status": "REAL_CARD_COSIGN_FLOW_OK" if final_ok and card_partial_ok and client_partial_ok else "REAL_CARD_COSIGN_FLOW_FAILED",
            "real_card": True,
            "backend": "real-nuri-musig2-v20-keygen-apdu" if not use_init_seed else "real-nuri-musig2-legacy-init-apdu",
            "card_aid": APPLET_AID.hex().upper(),
            "reader": card.reader,
            "card_version": version,
            "key_origin": "host_seed_imported_into_real_card_current_v19_applet" if use_init_seed else "on_card_keygen_non_exportable",
            "production_keygen_supported_by_current_applet": not use_init_seed,
            "keygen_gap": "Using explicit legacy INIT(seed) fallback." if use_init_seed else None,
            "msg32": msg32.hex(),
            "client_pk33": client_pubkey.hex(),
            "card_pk33": card_pubkey.hex(),
            "aggregate_xonly32": aggregate_xonly.hex(),
            "client_pub_nonce66": (client_nonce1 + client_nonce2).hex(),
            "card_pub_nonce66": (card_nonce1 + card_nonce2).hex(),
            "noncecoef_b32": b.hex(),
            "parity": parity,
            "challenge_e32": e.hex(),
            "client_keyagg_coeff32": client_coeff.hex(),
            "card_keyagg_coeff32": card_coeff.hex(),
            "client_partial32": client_partial.hex(),
            "card_partial32": card_partial.hex(),
            "final_signature64": final_signature.hex(),
            "client_partial_verified": client_partial_ok,
            "card_partial_verified": card_partial_ok,
            "final_signature_verified": final_ok,
            "broadcast_note": "This is a valid BIP340 signature for msg32 and aggregate_xonly32. For Bitcoin broadcast, msg32 must be the Taproot sighash for a funded transaction whose output key commits to aggregate_xonly32.",
        }
    finally:
        card.disconnect()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--message", default="nuri real card cosign proof")
    parser.add_argument("--msg32", default="")
    parser.add_argument("--use-init-seed", action="store_true", help="legacy fallback for pre-KEYGEN applets")
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "REAL_CARD_COSIGN_FLOW_OK" else 1


if __name__ == "__main__":
    sys.exit(main())
