#!/usr/bin/env python3
"""Real-card Arkade client-signer proof over the current PC/SC MuSig2 APDU.

This is intentionally an adapter proof:

- the card is labelled as the Arkade client signer;
- a local software key simulates the Arkade ASP/server signer;
- the host computes the BIP327/scure-style session values;
- the current card applet receives only the reduced APDU input it supports:
  folded signer coefficient, nonce coefficient, aggregate-nonce parity, and
  BIP340 challenge.

The clean app-facing signer contract is implemented in
src/musig2/arkade-client-signer.js. This file proves the same role assignment
against the real card over PC/SC without changing the applet.
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path


CORE_PATH = Path(__file__).with_name("card-cosign-tweaked.py")
CORE_SPEC = importlib.util.spec_from_file_location("card_cosign_tweaked", CORE_PATH)
core = importlib.util.module_from_spec(CORE_SPEC)
CORE_SPEC.loader.exec_module(core)


class ProofCard(core.Card):
    def _tx(self, apdu):
        response, sw1, sw2 = self.conn.transmit(apdu)
        if sw1 == 0x6C:
            retry = list(apdu)
            retry[-1] = sw2
            response, sw1, sw2 = self.conn.transmit(retry)
        if (sw1 << 8 | sw2) != 0x9000:
            raise RuntimeError(f"APDU SW={sw1:02X}{sw2:02X}")
        return bytes(response)


def bytes_from_hex32(value: str, name: str) -> bytes:
    raw = bytes.fromhex(value)
    if len(raw) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")
    return raw


def secret_from_hex_even(value: str):
    raw = bytes_from_hex32(value, "--asp-secret-hex")
    sk = core.b2i(raw) % core.N
    if sk == 0:
        raise ValueError("--asp-secret-hex resolves to zero")
    return core.norm_even(sk)


def tap_tweak_raw(internal_xonly: bytes, script_root32: bytes):
    raw = core.tagged_hash("TapTweak", internal_xonly + script_root32)
    tweak_int = core.b2i(raw)
    if tweak_int >= core.N:
        raise ValueError("TapTweak hash is outside the secp256k1 scalar range; rerun with another script root")
    return tweak_int, raw


def nonce_aggregate(pubnonce_a: bytes, pubnonce_b: bytes):
    a1, a2 = pubnonce_a[:33], pubnonce_a[33:]
    b1, b2 = pubnonce_b[:33], pubnonce_b[33:]
    r1 = core.padd(core.lift_comp(a1), core.lift_comp(b1))
    r2 = core.padd(core.lift_comp(a2), core.lift_comp(b2))
    if r1 is None or r2 is None:
        raise RuntimeError("aggregate nonce hit infinity; rerun the proof")
    return core.compress(r1) + core.compress(r2), r1, r2


def partial_verify(partial: bytes, pubnonce66: bytes, b32: bytes, aggregate_nonce_parity: int, e32: bytes, coeff32: bytes, pubkey33: bytes) -> bool:
    s = core.b2i(partial) % core.N
    b = core.b2i(b32) % core.N
    e = core.b2i(e32) % core.N
    coeff = core.b2i(coeff32) % core.N
    r1 = core.lift_comp(pubnonce66[:33])
    r2 = core.lift_comp(pubnonce66[33:])
    signer_nonce = core.padd(r1, core.pmul(b, r2))
    if aggregate_nonce_parity == 1:
        signer_nonce = core.pneg(signer_nonce)
    signer_pubkey = core.lift_comp(pubkey33)
    rhs = core.padd(signer_nonce, core.pmul((e * coeff) % core.N, signer_pubkey))
    return core.pmul(s, core.G) == rhs


def asp_partial_sign(asp_k1: int, asp_k2: int, b32: bytes, aggregate_nonce_parity: int, e32: bytes, coeff32: bytes, asp_secret: int) -> bytes:
    b = core.b2i(b32) % core.N
    e = core.b2i(e32) % core.N
    coeff = core.b2i(coeff32) % core.N
    nonce = (asp_k1 + b * asp_k2) % core.N
    if aggregate_nonce_parity == 1:
        nonce = (-nonce) % core.N
    return core.i2b((nonce + e * coeff * asp_secret) % core.N)


def session_keys(card_pk33: bytes, asp_pk33: bytes, mode: str, script_root32: bytes):
    coeffs, internal_q = core.keyagg([card_pk33, asp_pk33])
    internal_xonly = core.i2b(internal_q[0])
    if mode == "untweaked":
        session_q = internal_q
        signing_xonly = internal_xonly
        tweak_int = 0
        tweak32 = None
        g_acc = 1
        tweak_mode = "none"
    else:
        tweak_int, tweak32 = tap_tweak_raw(internal_xonly, script_root32)
        g_acc = 1 if internal_q[1] % 2 == 0 else core.N - 1
        session_q = core.padd(core.pmul(g_acc, internal_q), core.pmul(tweak_int, core.G))
        if session_q is None:
            raise RuntimeError("tweaked aggregate key hit infinity")
        signing_xonly = core.i2b(session_q[0])
        tweak_mode = "arkade-script-root-taptweak-xonly"
    g = 1 if session_q[1] % 2 == 0 else core.N - 1
    fold = (g * g_acc) % core.N
    return {
        "coeffs": coeffs,
        "internal_xonly": internal_xonly,
        "signing_xonly": signing_xonly,
        "tweak_int": tweak_int,
        "tweak32": tweak32,
        "tweak_mode": tweak_mode,
        "fold": fold,
        "final_tweak_term_sign": g,
    }


def run_case(card, args, mode: str, card_pk33: bytes, asp_secret: int, asp_pk33: bytes):
    msg32 = bytes.fromhex(args.msg32) if args.msg32 else core.sha256(f"{args.message}:{mode}".encode())
    if len(msg32) != 32:
        raise ValueError("msg32 must be exactly 32 bytes")
    script_root32 = bytes_from_hex32(args.script_root32, "--script-root32")
    keys = session_keys(card_pk33, asp_pk33, mode, script_root32)

    card_pubnonce66 = b"".join(card.nonces())
    asp_k1, asp_k1_point = core.rand_even()
    asp_k2, asp_k2_point = core.rand_even()
    asp_pubnonce66 = core.compress(asp_k1_point) + core.compress(asp_k2_point)
    aggregate_nonce66, r1, r2 = nonce_aggregate(card_pubnonce66, asp_pubnonce66)

    b32 = core.tagged_hash("MuSig/noncecoef", aggregate_nonce66 + keys["signing_xonly"] + msg32)
    b = core.b2i(b32) % core.N
    aggregate_r = core.padd(r1, core.pmul(b, r2))
    if aggregate_r is None:
        aggregate_r = core.G
    aggregate_nonce_parity = 0 if aggregate_r[1] % 2 == 0 else 1
    aggregate_r_even = aggregate_r if aggregate_nonce_parity == 0 else core.pneg(aggregate_r)
    challenge32 = core.tagged_hash("BIP0340/challenge", core.i2b(aggregate_r_even[0]) + keys["signing_xonly"] + msg32)
    e = core.b2i(challenge32) % core.N

    card_coeff32 = core.i2b((keys["coeffs"][card_pk33.hex()] * keys["fold"]) % core.N)
    asp_coeff32 = core.i2b((keys["coeffs"][asp_pk33.hex()] * keys["fold"]) % core.N)
    card_partial32 = card.finalize(card_coeff32, b32, aggregate_nonce_parity, challenge32)
    asp_partial32 = asp_partial_sign(asp_k1, asp_k2, b32, aggregate_nonce_parity, challenge32, asp_coeff32, asp_secret)

    card_partial_ok = partial_verify(
        card_partial32,
        card_pubnonce66,
        b32,
        aggregate_nonce_parity,
        challenge32,
        card_coeff32,
        card_pk33,
    )
    asp_partial_ok = partial_verify(
        asp_partial32,
        asp_pubnonce66,
        b32,
        aggregate_nonce_parity,
        challenge32,
        asp_coeff32,
        asp_pk33,
    )
    final_s = (
        core.b2i(card_partial32)
        + core.b2i(asp_partial32)
        + e * keys["final_tweak_term_sign"] * keys["tweak_int"]
    ) % core.N
    final_signature64 = core.i2b(aggregate_r_even[0]) + core.i2b(final_s)
    final_ok = core.bip340_verify(final_signature64, msg32, keys["signing_xonly"])

    ok = card_partial_ok and asp_partial_ok and final_ok
    return {
        "status": "REAL_CARD_ARKADE_CLIENT_SIGNER_CASE_OK" if ok else "REAL_CARD_ARKADE_CLIENT_SIGNER_CASE_FAILED",
        "case": mode,
        "real_card": True,
        "backend": "real-nuri-musig2-current-pcsc-apdu",
        "card_role": "arkade-client-signer",
        "asp_role": "local-software-asp-simulator",
        "current_apdu_note": "GET_PUBKEY + GET_NONCES + FINALIZE(a_i,b,parity,e); clean app interface is higher-level",
        "card_client_pk33": card_pk33.hex(),
        "asp_pk33": asp_pk33.hex(),
        "sorted_pubkeys33": sorted([card_pk33.hex(), asp_pk33.hex()]),
        "internal_aggregate_xonly32": keys["internal_xonly"].hex(),
        "tweak_mode": keys["tweak_mode"],
        "script_root32": script_root32.hex() if mode != "untweaked" else None,
        "tweak32": keys["tweak32"].hex() if keys["tweak32"] else None,
        "signing_xonly32": keys["signing_xonly"].hex(),
        "msg32": msg32.hex(),
        "card_client_pub_nonce66": card_pubnonce66.hex(),
        "asp_pub_nonce66": asp_pubnonce66.hex(),
        "aggregate_nonce66": aggregate_nonce66.hex(),
        "noncecoef_b32": b32.hex(),
        "aggregate_nonce_parity": aggregate_nonce_parity,
        "challenge_e32": challenge32.hex(),
        "card_client_coeff32": card_coeff32.hex(),
        "asp_coeff32": asp_coeff32.hex(),
        "card_client_partial32": card_partial32.hex(),
        "asp_partial32": asp_partial32.hex(),
        "final_signature64": final_signature64.hex(),
        "card_client_partial_verified": card_partial_ok,
        "asp_partial_verified": asp_partial_ok,
        "final_signature_verified": final_ok,
    }


def run(args):
    card = ProofCard()
    card.connect()
    try:
        version = card.version()
        card_pk33 = card.pubkey()
        if len(card_pk33) != 33:
            raise RuntimeError(f"unexpected card pubkey length: {len(card_pk33)}")

        if args.asp_secret_hex:
            asp_secret, asp_point = secret_from_hex_even(args.asp_secret_hex)
            asp_secret_source = "provided_demo_asp_secret"
        else:
            asp_secret, asp_point = core.rand_even()
            asp_secret_source = "random_demo_asp_secret"
        asp_pk33 = core.compress(asp_point)

        modes = ["untweaked", "tweaked"] if args.case == "all" else [args.case]
        cases = [run_case(card, args, mode, card_pk33, asp_secret, asp_pk33) for mode in modes]
        ok = all(case["status"].endswith("_OK") for case in cases)
        return {
            "status": "REAL_CARD_ARKADE_CLIENT_SIGNER_PROOF_OK" if ok else "REAL_CARD_ARKADE_CLIENT_SIGNER_PROOF_FAILED",
            "real_card": True,
            "card_aid": core.APPLET_AID.hex().upper(),
            "reader": card.reader,
            "card_version": version,
            "asp_secret_source": asp_secret_source,
            "demo_asp_secret32": core.i2b(asp_secret).hex() if args.include_demo_asp_secret else None,
            "model": "card is the Arkade client signer; ASP/server remains the second signer and payment infrastructure",
            "cases": cases,
        }
    finally:
        card.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--message", default="nuri real card Arkade client signer proof")
    parser.add_argument("--msg32", default="")
    parser.add_argument("--case", choices=["all", "untweaked", "tweaked"], default="all")
    parser.add_argument("--script-root32", default=core.sha256(b"nuri arkade vtxo script root proof").hex())
    parser.add_argument("--asp-secret-hex", default="", help="demo-only ASP secret for reproducible local proofs")
    parser.add_argument("--include-demo-asp-secret", action="store_true")
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, indent=2))
    return 0 if result["status"].endswith("_OK") else 1


if __name__ == "__main__":
    sys.exit(main())
