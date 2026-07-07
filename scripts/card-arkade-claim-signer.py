#!/usr/bin/env python3
"""Live Arkade claim signer.

Produces a real 2-of-2 BIP340 signature for an Arkade VHTLC-claim input:
  - client partial   = the physical card (MuSig2 applet, GET_NONCES + FINALIZE)
  - server partial    = the live Nuri Arkade signer via POST /arkade/sign
  - host              = BIP327/scure session math, aggregation, BIP340 verify

The claim leaf is a script-path CHECKSIG against the untweaked 2-of-2 aggregate
key, so this is exactly the "untweaked" MuSig2 case the proof already covers
(no taptweak term). All the session/aggregation helpers are reused verbatim
from real-card-arkade-signer-proof.py; the only new part is that the second
signer is the live server instead of a local software ASP.

The card holds its secret nonce on-card between GET_NONCES and FINALIZE, so the
whole round (nonce -> server -> finalize) runs inside one card session here.

Subcommands:
  self-test    card + a *simulated* server, verifies the aggregate BIP340 sig.
               No network, no funds, no FIDO2 -- proves the card + host math.
  sign-input   card + the *live* /arkade/sign, given an approval_token + msg32.
               Moves nothing by itself; it just returns a signature.
"""

import argparse
import importlib.util
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

PROOF_PATH = Path(__file__).with_name("real-card-arkade-signer-proof.py")
_spec = importlib.util.spec_from_file_location("real_card_arkade_signer_proof", PROOF_PATH)
proof = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(proof)
core = proof.core

ZERO32 = b"\x00" * 32


def aggregate_pubkey33(card_pk33: bytes, server_pk33: bytes) -> bytes:
    """Compressed 2-of-2 MuSig2 aggregate (== the reverse-swap claimPublicKey)."""
    _coeffs, internal_q = core.keyagg([card_pk33, server_pk33])
    return core.compress(internal_q)


def musig2_round(card, msg32: bytes, card_pk33: bytes, get_server):
    """One MuSig2 signing round. get_server(msg32, card_pubnonce66) -> dict with
    server_pubkey / server_pub_nonce66 / server_partial32 (hex)."""
    if len(msg32) != 32:
        raise ValueError("msg32 must be exactly 32 bytes")

    # Card nonce first: the server needs the client pubnonce to build its partial.
    card_pubnonce66 = b"".join(card.nonces())
    server = get_server(msg32, card_pubnonce66)
    server_pk33 = bytes.fromhex(server["server_pubkey"])
    server_pubnonce66 = bytes.fromhex(server["server_pub_nonce66"])
    server_partial = bytes.fromhex(server["server_partial32"])

    keys = proof.session_keys(card_pk33, server_pk33, "untweaked", ZERO32)
    signing_xonly = keys["signing_xonly"]
    aggregate_nonce66, r1, r2 = proof.nonce_aggregate(card_pubnonce66, server_pubnonce66)

    b32 = core.tagged_hash("MuSig/noncecoef", aggregate_nonce66 + signing_xonly + msg32)
    b = core.b2i(b32) % core.N
    aggregate_r = core.padd(r1, core.pmul(b, r2))
    if aggregate_r is None:
        aggregate_r = core.G
    parity = 0 if aggregate_r[1] % 2 == 0 else 1
    aggregate_r_even = aggregate_r if parity == 0 else core.pneg(aggregate_r)
    challenge32 = core.tagged_hash(
        "BIP0340/challenge", core.i2b(aggregate_r_even[0]) + signing_xonly + msg32
    )

    card_coeff32 = core.i2b((keys["coeffs"][card_pk33.hex()] * keys["fold"]) % core.N)
    server_coeff32 = core.i2b((keys["coeffs"][server_pk33.hex()] * keys["fold"]) % core.N)
    card_partial = card.finalize(card_coeff32, b32, parity, challenge32)

    card_ok = proof.partial_verify(
        card_partial, card_pubnonce66, b32, parity, challenge32, card_coeff32, card_pk33
    )
    server_ok = proof.partial_verify(
        server_partial, server_pubnonce66, b32, parity, challenge32, server_coeff32, server_pk33
    )
    # untweaked => no e*g*tweak term
    final_s = (core.b2i(card_partial) + core.b2i(server_partial)) % core.N
    sig64 = core.i2b(aggregate_r_even[0]) + core.i2b(final_s)
    final_ok = core.bip340_verify(sig64, msg32, signing_xonly)

    return {
        "msg32": msg32.hex(),
        "card_client_pk33": card_pk33.hex(),
        "server_pk33": server_pk33.hex(),
        "aggregate_pubkey33": aggregate_pubkey33(card_pk33, server_pk33).hex(),
        "signing_xonly32": signing_xonly.hex(),
        "card_pub_nonce66": card_pubnonce66.hex(),
        "server_pub_nonce66": server_pubnonce66.hex(),
        "card_partial_verified": card_ok,
        "server_partial_verified": server_ok,
        "final_signature64": sig64.hex(),
        "final_signature_verified": final_ok,
    }


def make_local_server(card_pk33: bytes, secret_hex: str = ""):
    """A locally-held Arkade cosigner: same BIP327 partial the live server would
    return, but the second key is a secret WE hold. With `secret_hex` the key is
    deterministic (pure-Arkade wallet: card + local key, zero Nuri); without it a
    fresh random key is used (self-test only)."""
    if secret_hex:
        server_secret, server_point = proof.secret_from_hex_even(secret_hex)
    else:
        server_secret, server_point = core.rand_even()
    server_pk33 = core.compress(server_point)

    def get_server(msg32: bytes, card_pubnonce66: bytes):
        k1, p1 = core.rand_even()
        k2, p2 = core.rand_even()
        server_pubnonce66 = core.compress(p1) + core.compress(p2)
        keys = proof.session_keys(card_pk33, server_pk33, "untweaked", ZERO32)
        aggregate_nonce66, r1, r2 = proof.nonce_aggregate(card_pubnonce66, server_pubnonce66)
        b32 = core.tagged_hash(
            "MuSig/noncecoef", aggregate_nonce66 + keys["signing_xonly"] + msg32
        )
        b = core.b2i(b32) % core.N
        aggregate_r = core.padd(r1, core.pmul(b, r2)) or core.G
        parity = 0 if aggregate_r[1] % 2 == 0 else 1
        aggregate_r_even = aggregate_r if parity == 0 else core.pneg(aggregate_r)
        challenge32 = core.tagged_hash(
            "BIP0340/challenge", core.i2b(aggregate_r_even[0]) + keys["signing_xonly"] + msg32
        )
        server_coeff32 = core.i2b((keys["coeffs"][server_pk33.hex()] * keys["fold"]) % core.N)
        partial = proof.asp_partial_sign(
            k1, k2, b32, parity, challenge32, server_coeff32, server_secret
        )
        return {
            "server_pubkey": server_pk33.hex(),
            "server_pub_nonce66": server_pubnonce66.hex(),
            "server_partial32": partial.hex(),
        }

    return get_server


def make_http_server(sign_url: str, approval_token: str, client_pk33_hex: str):
    """Live server: POST /arkade/sign with the approval token from receive/claim/approve."""

    def get_server(msg32: bytes, card_pubnonce66: bytes):
        payload = json.dumps(
            {
                "approval_token": approval_token,
                "msg32": msg32.hex(),
                "client_pk33": client_pk33_hex,
                "client_pub_nonce": card_pubnonce66.hex(),
                "tweak32": "",
            }
        ).encode()
        req = urllib.request.Request(
            sign_url,
            data=payload,
            method="POST",
            headers={
                "content-type": "application/json",
                "accept": "application/json",
                "x-arkade-client": "nuri-card-browser-demo",
                "x-arkade-sdk": "nuri-card-browser-demo",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
        server_pk = body.get("server_pubkey") or body.get("server_pubkey33")
        pubnonce = body.get("server_pub_nonce66") or body.get("server_pubnonce66")
        partial = body.get("server_partial32")
        if not (server_pk and pubnonce and partial):
            raise RuntimeError(f"/arkade/sign response missing fields: {body}")
        return {
            "server_pubkey": server_pk,
            "server_pub_nonce66": pubnonce,
            "server_partial32": partial,
        }

    return get_server


def make_send_cosign_server(cosign_url: str, context: dict):
    """Nuri native send: POST /v4/arkade/send/cosign. `context` carries the
    challenge_token, the full send package, the WebAuthn assertion (first cosign
    only), the server pubkey, and the input_index this msg32 belongs to. The card
    provides the client nonce; the server returns its BIP327 partial + nonce."""

    def get_server(msg32: bytes, card_pubnonce66: bytes):
        cosign_request = {
            "kind": "direct",
            "input_index": context["input_index"],
            "msg32": msg32.hex(),
            "client_pk33": context["client_pk33"],
            "client_pub_nonce": card_pubnonce66.hex(),
        }
        body = dict(context.get("send_package") or {})
        body["challenge_token"] = context["challenge_token"]
        body["cosign_requests"] = [cosign_request]
        if context.get("assertion"):
            body.update(context["assertion"])  # client_data_b64u / auth_data_b64u / sig_b64u
        payload = json.dumps(body).encode()
        req = urllib.request.Request(
            cosign_url,
            data=payload,
            method="POST",
            headers={"content-type": "application/json", "accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                res = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            detail = e.read().decode() if hasattr(e, "read") else str(e)
            raise RuntimeError(f"send/cosign HTTP {e.code}: {detail}")
        sig = (res.get("signatures") or [None])[0] or res
        pubnonce = sig.get("server_pub_nonce66") or res.get("server_pub_nonce66")
        partial = sig.get("server_partial32") or res.get("server_partial32")
        if not (pubnonce and partial):
            raise RuntimeError(f"send/cosign response missing fields: {res}")
        return {
            "server_pubkey": context["server_pk33"],
            "server_pub_nonce66": pubnonce,
            "server_partial32": partial,
        }

    return get_server


def with_card(fn):
    card = proof.ProofCard()
    card.connect()
    try:
        version = card.version()
        card_pk33 = card.pubkey()
        if len(card_pk33) != 33:
            raise RuntimeError(f"unexpected card pubkey length: {len(card_pk33)}")
        return fn(card, card_pk33, version)
    finally:
        card.close()


def cmd_self_test(args):
    def body(card, card_pk33, version):
        msg32 = bytes.fromhex(args.msg32) if args.msg32 else core.sha256(b"nuri arkade claim self-test")
        result = musig2_round(card, msg32, card_pk33, make_local_server(card_pk33))
        ok = result["card_partial_verified"] and result["server_partial_verified"] and result["final_signature_verified"]
        return {
            "status": "NURI_CARD_ARKADE_CLAIM_SELFTEST_OK" if ok else "NURI_CARD_ARKADE_CLAIM_SELFTEST_FAILED",
            "reader": card.reader,
            "card_version": version,
            **result,
        }

    return with_card(body)


def cmd_sign_input(args):
    def body(card, card_pk33, version):
        if args.client_pk33 and args.client_pk33.lower() != card_pk33.hex():
            raise RuntimeError("card pubkey does not match --client-pk33")
        msg32 = bytes.fromhex(args.msg32)
        get_server = make_http_server(args.sign_url, args.approval_token, card_pk33.hex())
        result = musig2_round(card, msg32, card_pk33, get_server)
        ok = result["final_signature_verified"]
        if args.expect_aggregate and result["aggregate_pubkey33"].lower() != args.expect_aggregate.lower():
            raise RuntimeError(
                f"aggregate mismatch: got {result['aggregate_pubkey33']} expected {args.expect_aggregate}"
            )
        return {
            "status": "NURI_CARD_ARKADE_CLAIM_SIGN_OK" if ok else "NURI_CARD_ARKADE_CLAIM_SIGN_FAILED",
            "reader": card.reader,
            "card_version": version,
            **result,
        }

    return with_card(body)


def cmd_sign_input_send(args):
    with open(args.context_file, "r", encoding="utf-8") as fh:
        context = json.load(fh)

    def body(card, card_pk33, version):
        if args.client_pk33 and args.client_pk33.lower() != card_pk33.hex():
            raise RuntimeError("card pubkey does not match --client-pk33")
        msg32 = bytes.fromhex(args.msg32)
        context["client_pk33"] = card_pk33.hex()
        context["input_index"] = int(args.input_index)
        context["server_pk33"] = args.server_pk33
        get_server = make_send_cosign_server(args.cosign_url, context)
        result = musig2_round(card, msg32, card_pk33, get_server)
        ok = result["final_signature_verified"]
        if args.expect_aggregate and result["aggregate_pubkey33"].lower() != args.expect_aggregate.lower():
            raise RuntimeError(
                f"aggregate mismatch: got {result['aggregate_pubkey33']} expected {args.expect_aggregate}"
            )
        return {
            "status": "NURI_CARD_ARKADE_SEND_SIGN_OK" if ok else "NURI_CARD_ARKADE_SEND_SIGN_FAILED",
            "reader": card.reader,
            "card_version": version,
            **result,
        }

    return with_card(body)


def cmd_sign_input_local(args):
    def body(card, card_pk33, version):
        if args.client_pk33 and args.client_pk33.lower() != card_pk33.hex():
            raise RuntimeError("card pubkey does not match --client-pk33")
        msg32 = bytes.fromhex(args.msg32)
        get_server = make_local_server(card_pk33, args.asp_secret_hex)
        result = musig2_round(card, msg32, card_pk33, get_server)
        ok = result["final_signature_verified"]
        if args.expect_aggregate and result["aggregate_pubkey33"].lower() != args.expect_aggregate.lower():
            raise RuntimeError(
                f"aggregate mismatch: got {result['aggregate_pubkey33']} expected {args.expect_aggregate}"
            )
        return {
            "status": "NURI_CARD_ARKADE_LOCAL_SIGN_OK" if ok else "NURI_CARD_ARKADE_LOCAL_SIGN_FAILED",
            "reader": card.reader,
            "card_version": version,
            **result,
        }

    return with_card(body)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    st = sub.add_parser("self-test")
    st.add_argument("--msg32", default="")
    st.set_defaults(fn=cmd_self_test)

    si = sub.add_parser("sign-input")
    si.add_argument("--msg32", required=True)
    si.add_argument("--approval-token", dest="approval_token", required=True)
    si.add_argument("--sign-url", dest="sign_url", required=True)
    si.add_argument("--client-pk33", dest="client_pk33", default="")
    si.add_argument("--expect-aggregate", dest="expect_aggregate", default="")
    si.set_defaults(fn=cmd_sign_input)

    ss = sub.add_parser("sign-input-send")
    ss.add_argument("--msg32", required=True)
    ss.add_argument("--input-index", dest="input_index", required=True)
    ss.add_argument("--cosign-url", dest="cosign_url", required=True)
    ss.add_argument("--context-file", dest="context_file", required=True)
    ss.add_argument("--server-pk33", dest="server_pk33", required=True)
    ss.add_argument("--client-pk33", dest="client_pk33", default="")
    ss.add_argument("--expect-aggregate", dest="expect_aggregate", default="")
    ss.set_defaults(fn=cmd_sign_input_send)

    sl = sub.add_parser("sign-input-local")
    sl.add_argument("--msg32", required=True)
    sl.add_argument("--asp-secret-hex", dest="asp_secret_hex", required=True)
    sl.add_argument("--client-pk33", dest="client_pk33", default="")
    sl.add_argument("--expect-aggregate", dest="expect_aggregate", default="")
    sl.set_defaults(fn=cmd_sign_input_local)

    args = parser.parse_args()
    result = args.fn(args)
    print(json.dumps(result, indent=2))
    return 0 if result["status"].endswith("_OK") else 1


if __name__ == "__main__":
    sys.exit(main())
