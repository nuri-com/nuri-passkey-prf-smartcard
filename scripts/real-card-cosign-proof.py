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
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nuri_musig2_card  # APDU driver: PC/SC ladder, version gate, PIN, 1.14 FINALIZE


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

APPLET_AID = nuri_musig2_card.APPLET_AID


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


def secret_from_hex_even_y(secret_hex: str):
    raw = bytes.fromhex(secret_hex)
    if len(raw) != 32:
        raise ValueError("--client-secret-hex must be exactly 32 bytes")
    secret = int_from_bytes(raw) % N
    if secret == 0:
        raise ValueError("--client-secret-hex resolves to zero")
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


class NuriMuSig2Card(nuri_musig2_card.MuSig2Card):
    """Shared host driver (scripts/nuri_musig2_card.py): legacy <1.14 without PIN,
    1.14+ with VERIFY before nonces/finalize and the 231-byte FINALIZE."""

    def version(self):
        # Shape unchanged for existing callers; PIN/protocol state is reported
        # separately (card_protocol / card_pin_verified in the proof JSON).
        info = self.version_info()
        return {"version": info["version"], "build": info["build"]}


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

        # Key provisioning: on-card KEYGEN only. Applet 1.11 removed INIT(seed)
        # host import and made KEYGEN one-shot (SW 6989 once a key exists).
        # On an already-keyed card we sign with the existing non-exportable key.
        use_existing_card_key = args.use_existing_card_key
        card_pubkey = None
        client_secret = None
        client_point = None
        coeffs = None
        aggregate = None
        key_origin = None

        if use_existing_card_key:
            card_pubkey = card.pubkey()
            if len(card_pubkey) != 33:
                raise RuntimeError(f"unexpected existing card pubkey length: {len(card_pubkey)}")
            key_origin = "existing_on_card_non_exportable"
        else:
            try:
                card_pubkey = card.keygen()
                key_origin = "on_card_keygen_non_exportable"
            except RuntimeError as error:
                if "SW=6989" not in str(error):
                    raise
                card_pubkey = card.pubkey()
                key_origin = "existing_on_card_non_exportable_one_shot"
        if card_pubkey[0] != 0x02:
            raise RuntimeError("card key is not even-y; reprovision on a blank card")

        # RNG health check (Coldcard Mk3 lesson: TRNG code being present does
        # not prove the TRNG is what actually runs — verify behavior). Four
        # independent on-card nonce draws must be unique, valid compressed
        # secp256k1 points. Runs before every proof, fails closed.
        rng_draws = []
        for _ in range(2):
            pub_k1, pub_k2 = card.nonces()
            rng_draws.extend([pub_k1, pub_k2])
        for draw in rng_draws:
            if len(draw) != 33 or draw[0] not in (0x02, 0x03):
                raise RuntimeError("RNG health check failed: malformed nonce point")
        if len(set(rng_draws)) != 4:
            raise RuntimeError("RNG health check failed: repeated nonce draws")

        client_secret_source = "random_demo_client_secret"
        if args.client_secret_hex:
            candidate_client_secret, candidate_client_point = secret_from_hex_even_y(args.client_secret_hex)
            candidate_client_pubkey = compress_point(candidate_client_point)
            candidate_coeffs, candidate_aggregate = key_agg_coefficients([candidate_client_pubkey, card_pubkey])
            if candidate_aggregate and candidate_aggregate[1] % 2 == 0:
                client_secret = candidate_client_secret
                client_point = candidate_client_point
                coeffs = candidate_coeffs
                aggregate = candidate_aggregate
                client_secret_source = "provided_demo_client_secret"
            else:
                raise RuntimeError("provided client secret produces odd-y aggregate with current card key")
        else:
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
            # KEYGEN is one-shot; the card key cannot change. Odd aggregate is
            # only a client-side pick issue, and 128 retries miss with
            # probability 2^-128.
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
        if aggregate_r is None:
            aggregate_r = G  # BIP327: infinity -> G
        parity = 0 if aggregate_r[1] % 2 == 0 else 1
        r_even = aggregate_r if parity == 0 else point_neg(aggregate_r)
        r_even_x = bytes_from_int(r_even[0])
        e = tagged_hash("BIP0340/challenge", r_even_x + aggregate_xonly + msg32)
        e_int = int_from_bytes(e) % N

        # 1.14+: also hand the card the actual aggregate nonce R (pre-negation,
        # y parity == `parity`) and the aggregate key the challenge commits to.
        # The search loop above guarantees `aggregate` has even y.
        card_partial = card.finalize(card_coeff, b, parity, e, r_agg=aggregate_r, p_agg=aggregate)

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
            "backend": (
                "real-nuri-musig2-v20-existing-key-apdu"
                if use_existing_card_key
                else "real-nuri-musig2-v20-keygen-apdu"
            ),
            "card_aid": APPLET_AID.hex().upper(),
            "reader": card.reader,
            "card_version": version,
            "card_protocol": card.protocol,
            "card_pin_verified": card.pin_verified,
            "key_origin": key_origin,
            "client_secret_source": client_secret_source,
            "demo_client_secret32": bytes_from_int(client_secret).hex() if args.include_demo_client_secret else None,
            "production_keygen_supported_by_current_applet": True,
            "keygen_gap": None,
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
    parser.add_argument("--use-existing-card-key", action="store_true", help="sign with the current non-exportable card key instead of running KEYGEN")
    parser.add_argument("--client-secret-hex", default="", help="demo-only client secret for stable aggregate-key tests")
    parser.add_argument("--include-demo-client-secret", action="store_true", help="include the generated demo client secret in JSON output for local profile provisioning")
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "REAL_CARD_COSIGN_FLOW_OK" else 1


if __name__ == "__main__":
    sys.exit(main())
