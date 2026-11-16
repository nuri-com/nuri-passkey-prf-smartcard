#!/usr/bin/env python3
"""Taproot-tweaked 2-of-2 MuSig2 cosign with the real card (BIP327-compatible).

The card applet does plain MuSig2 (s = k_adj + e*a*sk, no tweak). BIP327 puts a
Taproot tweak in two host-side places, NOT in each partial:
  - a per-signer factor g*gAcc multiplied onto the secret  -> folded into the
    coefficient `a` we already send to the card (so the card needs no change);
  - a single term e*g*tweakAcc added at final aggregation.

This builds the exact Nuri wallet tweak (Taproot key-path over musig2(client,
card) with a client CSV recovery leaf), signs with the physical card, and
verifies the final BIP340 signature against the TWEAKED output key. That output
key / address is what the Nuri client and sign.nuri.com use.
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
CSV_BLOCKS = 52500  # Nuri client recovery window


def sha256(d): return hashlib.sha256(d).digest()
def tagged_hash(tag, d): h = sha256(tag.encode()); return sha256(h + h + d)
def i2b(v): return v.to_bytes(32, "big")
def b2i(d): return int.from_bytes(d, "big")
def inv(v, m=P): return pow(v, -1, m)


def msqrt(v):
    if v == 0: return 0
    r = pow(v, (P + 1) // 4, P)
    return r if (r * r - v) % P == 0 else None


def lift_x(x):
    y = msqrt((pow(x, 3, P) + 7) % P)
    if y is None: raise ValueError("x not on curve")
    return (x, y if y % 2 == 0 else (-y) % P)


def lift_comp(c):
    if len(c) != 33 or c[0] not in (2, 3): raise ValueError("bad pubkey")
    x, y = lift_x(b2i(c[1:]))
    return (x, y) if (y & 1) == (c[0] & 1) else (x, (-y) % P)


def padd(a, b):
    if a is None: return b
    if b is None: return a
    x1, y1 = a; x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0: return None
    lam = ((3 * x1 * x1) * inv((2 * y1) % P)) % P if a == b else ((y2 - y1) * inv((x2 - x1) % P)) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def pneg(p): return (p[0], (-p[1]) % P)


def pmul(k, pt):
    k %= N
    if k == 0 or pt is None: return None
    r = None; a = pt
    while k:
        if k & 1: r = padd(r, a)
        a = padd(a, a); k >>= 1
    return r


def compress(pt): return (b"\x02" if pt[1] % 2 == 0 else b"\x03") + i2b(pt[0])


def norm_even(sk):
    pt = pmul(sk, G)
    return ((-sk) % N, pneg(pt)) if pt[1] & 1 else (sk, pt)


def rand_even():
    while True:
        sk = b2i(secrets.token_bytes(32)) % N
        if sk: return norm_even(sk)


def bip340_verify(sig, msg, px):
    if len(sig) != 64: return False
    rx, s = b2i(sig[:32]), b2i(sig[32:])
    if rx >= P or s >= N: return False
    Pk = lift_x(b2i(px))
    e = b2i(tagged_hash("BIP0340/challenge", sig[:32] + px + msg)) % N
    R = padd(pmul(s, G), pneg(pmul(e, Pk)))
    return R is not None and R[1] % 2 == 0 and R[0] == rx


def keyagg(pubs33):
    # BIP327 KeyAgg: sort + hash the FULL 33-byte keys; secondKey gets coeff 1.
    keys = sorted(pubs33)
    L = tagged_hash("KeyAgg list", b"".join(keys))
    second = next((k for k in keys[1:] if k != keys[0]), None)
    coeffs, agg = {}, None
    for pk in keys:
        a = 1 if (second is not None and pk == second) else b2i(tagged_hash("KeyAgg coefficient", L + pk)) % N
        coeffs[pk.hex()] = a
        agg = padd(agg, pmul(a, lift_comp(pk)))
    return coeffs, agg


def script_num(n):
    if n == 0: return b""
    out = bytearray()
    while n: out.append(n & 0xFF); n >>= 8
    if out[-1] & 0x80: out.append(0x00)
    return bytes(out)


def csv_leaf_script(client_xonly):
    csv = script_num(CSV_BLOCKS)
    return bytes([0x20]) + client_xonly + bytes([0xAD]) + bytes([len(csv)]) + csv + bytes([0xB2])


def taproot_tweak(internal_xonly, client_xonly):
    # Default Nuri wallet tweak: key-path over musig2(client,card) with a
    # client CSV recovery leaf. (--script-root overrides this for Arkade rounds.)
    leaf = csv_leaf_script(client_xonly)
    leaf_hash = tagged_hash("TapLeaf", bytes([0xC0, len(leaf)]) + leaf)
    return b2i(tagged_hash("TapTweak", internal_xonly + leaf_hash)) % N


def arkade_script_root_tweak(internal_xonly, script_root32):
    # Arkade tree-round tweak: TapTweak(internal || scriptRoot). The scriptRoot
    # is the Ark VTXO tree root returned by the ASP, NOT our CSV leaf.
    return b2i(tagged_hash("TapTweak", internal_xonly + script_root32)) % N


# Card = the shared NuriMuSig2 host driver (legacy <1.14 and PIN-gated 1.14+).
# Kept under the old name: real-card-arkade-signer-proof.py, card-arkade-claim-signer.py
# and read-musig2-card-key.py import this module as `core` and use core.Card.
Card = nuri_musig2_card.MuSig2Card


def run(args):
    msg = bytes.fromhex(args.msg32) if args.msg32 else sha256(args.message.encode())
    if len(msg) != 32: raise ValueError("msg32 must be 32 bytes")

    card = Card(); card.connect()
    try:
        ver = card.version()
        card_pk = card.pubkey()
        if len(card_pk) != 33: raise RuntimeError("bad card pubkey")

        if args.client_secret_hex:
            sk = b2i(bytes.fromhex(args.client_secret_hex)) % N
            client_sk, client_pt = norm_even(sk)
        else:
            client_sk, client_pt = rand_even()
        client_pk = compress(client_pt)

        coeffs, Q = keyagg([client_pk, card_pk])      # untweaked aggregate (real parity)
        internal_xonly = i2b(Q[0])
        client_xonly = client_pk[1:]

        # BIP327 ApplyTweak (single x-only Taproot tweak)
        if args.script_root:
            t = arkade_script_root_tweak(internal_xonly, bytes.fromhex(args.script_root))
            tweak_mode = "arkade-script-root-tree-round"
        else:
            t = taproot_tweak(internal_xonly, client_xonly)
            tweak_mode = "taproot-keypath-with-client-csv-leaf"
        g0 = 1 if Q[1] % 2 == 0 else N - 1            # parity of untweaked Q (xonly tweak)
        Qt = padd(pmul(g0, Q), pmul(t, G))            # tweaked output key
        g_acc = g0
        tweak_acc = t
        output_xonly = i2b(Qt[0])
        g = 1 if Qt[1] % 2 == 0 else N - 1            # parity of TWEAKED key (used in sign + agg)
        fold = (g * g_acc) % N                         # multiplies each signer's secret/coeff

        a_card = coeffs[card_pk.hex()]
        a_client = coeffs[client_pk.hex()]

        # Nonces
        ck1, ck1p = rand_even(); ck2, ck2p = rand_even()
        cn1, cn2 = compress(ck1p), compress(ck2p)
        kn1, kn2 = card.nonces()

        R1 = padd(lift_comp(cn1), lift_comp(kn1))
        R2 = padd(lift_comp(cn2), lift_comp(kn2))
        b = tagged_hash("MuSig/noncecoef", i2b(R1[0]) + i2b(R2[0]) + output_xonly + msg)
        bi = b2i(b) % N
        R = padd(R1, pmul(bi, R2))
        if R is None: R = G  # BIP327 NonceAgg/Sign: infinity -> G
        parity = 0 if R[1] % 2 == 0 else 1
        Re = R if parity == 0 else pneg(R)
        rx = i2b(Re[0])
        e = tagged_hash("BIP0340/challenge", rx + output_xonly + msg)
        ei = b2i(e) % N

        # Card partial: fold g*gAcc into the coefficient -> no applet change.
        card_coeff = i2b((a_card * fold) % N)
        # 1.14+: the card also gets the actual aggregate nonce R (pre-negation,
        # its y parity == `parity`) and the signing key the challenge commits to
        # (tweaked output key Qt). Legacy applets ignore both.
        card_partial = card.finalize(card_coeff, b, parity, e, r_agg=R, p_agg=Qt)
        cpi = b2i(card_partial) % N

        # Client partial (software), same g*gAcc fold.
        cr = (ck1 + bi * ck2) % N
        if parity == 1: cr = (-cr) % N
        client_partial = (cr + ei * ((a_client * fold) % N) * client_sk) % N

        # Final aggregation: + e*g*tweakAcc (the only place the tweak enters).
        final_s = (cpi + client_partial + ei * g * tweak_acc) % N
        sig = rx + i2b(final_s)
        ok = bip340_verify(sig, msg, output_xonly)

        return {
            "status": "REAL_CARD_TWEAKED_COSIGN_OK" if ok else "REAL_CARD_TWEAKED_COSIGN_FAILED",
            "real_card": True,
            "tweak_mode": tweak_mode,
            "csv_blocks": CSV_BLOCKS,
            "reader": card.reader,
            "card_version": ver,
            "card_protocol": card.protocol,
            "card_pin_verified": card.pin_verified,
            "client_pk33": client_pk.hex(),
            "card_pk33": card_pk.hex(),
            "internal_aggregate_xonly32": internal_xonly.hex(),
            "tweaked_output_xonly32": output_xonly.hex(),
            "taproot_tweak32": i2b(t).hex(),
            "msg32": msg.hex(),
            "final_signature64": sig.hex(),
            "final_signature_verified_against_output_key": ok,
            "demo_client_secret32": i2b(client_sk).hex() if args.include_demo_client_secret else None,
            "note": "final_signature64 is a valid BIP340 key-path signature for tweaked_output_xonly32 (the Nuri Taproot address output key).",
        }
    finally:
        card.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--message", default="nuri real card tweaked cosign")
    ap.add_argument("--msg32", default="")
    ap.add_argument("--client-secret-hex", default="")
    ap.add_argument("--script-root", default="", help="32-hex Ark VTXO scriptRoot; switches to Arkade tree-round tweak (no CSV leaf)")
    ap.add_argument("--include-demo-client-secret", action="store_true")
    args = ap.parse_args()
    res = run(args)
    print(json.dumps(res, indent=2))
    return 0 if res["status"] == "REAL_CARD_TWEAKED_COSIGN_OK" else 1


if __name__ == "__main__":
    sys.exit(main())
