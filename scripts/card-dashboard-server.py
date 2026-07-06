#!/usr/bin/env python3
"""Nuri card dashboard — minimal HTTP server that talks to the card via PC/SC.

Endpoints (all JSON):
  GET  /api/card/status       — ATR + which applets SELECT-respond
  GET  /api/eth/version       — ETH applet version
  GET  /api/eth/pubkey        — current on-card ETH pubkey (33B compressed) + ETH/BTC addresses
  POST /api/eth/keygen        — generate fresh on-card key, return pubkey + addresses
  POST /api/eth/sign          — body {hash: hex(32)} -> {r, s, v, pubkey, verified}
  POST /api/btc/sign          — body {message: str} -> double-SHA256, sign, verify (BTC P2PKH)
  GET  /api/musig2/version    — MuSig2 applet version
  GET  /api/totp/select       — SELECT OATH-TOTP applet
  GET  /api/fido2/select      — SELECT FIDO2 applet
  GET  /api/eth/selftest      — cross-check on-card modInverse against python pow(a,-1,n)

Serves web/dashboard.html at /.

Host-side crypto uses PROVEN LIBRARIES, not hand-rolled code:
  - ecdsa (python-ecdsa): ecrecover + signature verification (independent
    witness — the card signs, this library verifies, so "verified:true"
    means libsecp256k1-equivalent math agrees, not my code agreeing with
    itself)
  - pycryptodome: keccak256 (Ethereum address derivation)
  - hashlib: sha256 + ripemd160 (stdlib, correct)
  - base58: base58check encoding (BTC P2PKH addresses)

The card is the only signer. The host only hashes + verifies.

Reader: forces T=0 (OMNIKEY 5422 + this card fails T=1 with 0x80100016).
"""
import json
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from smartcard.System import readers
from smartcard.CardConnection import CardConnection

from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_string
from Crypto.Hash import keccak
import base58

AID_FIDO2   = bytes.fromhex("A0000006472F0001")
AID_MUSIG2  = bytes.fromhex("4E5552494D554701")
AID_TOTP    = bytes.fromhex("4E555249544F5450")
AID_ETH     = bytes.fromhex("4E55524945544801")

# secp256k1 field prime (only for decompression; ecrecover/verify go through ecdsa lib)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


# --- proven-library crypto helpers --------------------------------------------

def keccak256(data: bytes) -> bytes:
    """Ethereum's keccak256 (pycryptodome). Verified against
    keccak256("") == c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470."""
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()

def decompress_pubkey(pub33: bytes) -> bytes:
    """Decompress a 33-byte compressed secp256k1 pubkey to 64 bytes (x||y)."""
    x = int.from_bytes(pub33[1:], "big")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y & 1) != (pub33[0] & 1):
        y = P - y
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")

def eth_address(pub33: bytes) -> str:
    """Ethereum address = keccak256(uncompressed_pubkey)[-20:]."""
    uncomp = decompress_pubkey(pub33)
    return "0x" + keccak256(uncomp)[-20:].hex()

def hash160(data: bytes) -> bytes:
    """Bitcoin hash160 = ripemd160(sha256(data)). Both from hashlib (stdlib)."""
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

def btc_p2pkh_address(pub33: bytes, network="mainnet") -> str:
    """BTC P2PKH (Legacy, 1...) address via base58 library."""
    h160 = hash160(pub33)
    version = b"\x00" if network == "mainnet" else b"\x6f"
    return base58.b58encode_check(version + h160).decode()

def ecdsa_verify(pub33: bytes, sig_rs: bytes, msg_hash: bytes) -> bool:
    """Verify a 64-byte r||s signature against the card's pubkey, INDEPENDENTLY
    of our own code (python-ecdsa library). This is the real "verified:true"."""
    pub64 = decompress_pubkey(pub33)
    try:
        vk = VerifyingKey.from_string(pub64, curve=SECP256k1)
        return vk.verify_digest(sig_rs, msg_hash, sigdecode=sigdecode_string)
    except Exception:
        return False

def ecdsa_ecrecover(pub33: bytes, sig_rs: bytes, msg_hash: bytes) -> bool:
    """Recover the pubkey from (r||s, hash) using python-ecdsa, and confirm it
    matches the card's pubkey. Independent cross-check of ecrecover."""
    try:
        recovered = VerifyingKey.from_public_key_recovery_with_digest(
            sig_rs, msg_hash, curve=SECP256k1,
            hashfunc=hashlib.sha256, sigdecode=sigdecode_string)
        pub64 = decompress_pubkey(pub33)
        return any(k.to_string() == pub64 for k in recovered)
    except Exception:
        return False


# --- card communication ------------------------------------------------------

_conn = None

def get_connection():
    global _conn
    if _conn is not None:
        try:
            _conn.transmit(list(bytes([0x00, 0xA4, 0x04, 0x00, len(AID_ETH)]) + AID_ETH))
            return _conn
        except Exception:
            try: _conn.disconnect()
            except: pass
            _conn = None
    rs = readers()
    for r in rs:
        try:
            c = r.createConnection()
            c.connect(CardConnection.T0_protocol)
            _conn = c
            return _conn
        except Exception:
            continue
    raise RuntimeError("no card found in any reader")

def transmit(apdu):
    conn = get_connection()
    data, sw1, sw2 = conn.transmit(list(apdu))
    return bytes(data), (sw1 << 8) | sw2

def select_aid(aid):
    return transmit(bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid)


# --- HTTP ---------------------------------------------------------------------

def json_resp(handler, status, payload):
    body = json.dumps(payload, indent=2).encode()
    handler.send_response(status)
    handler.send_header("content-type", "application/json; charset=utf-8")
    handler.send_header("cache-control", "no-store")
    handler.send_header("access-control-allow-origin", "*")
    handler.end_headers()
    handler.wfile.write(body)

def read_body(handler):
    n = int(handler.headers.get("content-length", 0))
    if n == 0: return {}
    return json.loads(handler.rfile.read(n))

def verify_card_signature(pub, sig):
    """Run BOTH independent checks (ecdsa.verify + ecdsa.ecrecover) and return
    a verdict dict. The card signs, python-ecdsa verifies — no self-rolled EC."""
    sig_rs = sig[:64]
    # We need the hash that was signed; both endpoints pass it back via the
    # caller. Here we just return helpers; endpoints do the hashing.
    return None

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        try:
            if self.path == "/":
                self.serve_html()
            elif self.path == "/api/card/status":
                self.card_status()
            elif self.path == "/api/eth/version":
                select_aid(AID_ETH)
                data, sw = transmit(bytes([0x00, 0x01, 0x00, 0x00, 0x00]))
                json_resp(self, 200, {"sw": f"{sw:04X}", "major": data[0], "minor": data[1], "build": data[3:7].decode("ascii", "replace")})
            elif self.path == "/api/eth/pubkey":
                select_aid(AID_ETH)
                data, sw = transmit(bytes([0x00, 0x02, 0x00, 0x00, 0x00]))
                json_resp(self, 200, {
                    "sw": f"{sw:04X}", "pubkey_hex": data.hex(),
                    "eth_address": eth_address(data),
                    "btc_p2pkh_address": btc_p2pkh_address(data, "mainnet"),
                    "btc_hash160_hex": hash160(data).hex(),
                })
            elif self.path == "/api/eth/selftest":
                # Regression guard: cross-check on-card modInverse (INS 0x06) against
                # python pow(a, -1, n) for 10 random values. Catches on-card bignum
                # breakage immediately, so we don't debug a wrong signature for hours.
                select_aid(AID_ETH)
                N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                import secrets
                passed, failed = 0, 0
                for _ in range(10):
                    a = secrets.randbelow(N - 1) + 1
                    a_bytes = a.to_bytes(32, "big")
                    data, sw = transmit(bytes([0x00, 0x06, 0x00, 0x00, 0x20]) + a_bytes)
                    if sw != 0x9000:
                        failed += 1; continue
                    card_inv = int.from_bytes(data, "big")
                    host_inv = pow(a, -1, N)
                    if card_inv == host_inv: passed += 1
                    else: failed += 1
                json_resp(self, 200, {"modinv_passed": passed, "modinv_failed": failed, "ok": failed == 0})
            elif self.path == "/api/musig2/version":
                select_aid(AID_MUSIG2)
                data, sw = transmit(bytes([0x80, 0x01, 0x00, 0x00, 0x00]))
                json_resp(self, 200, {"sw": f"{sw:04X}", "version_hex": data.hex()})
            elif self.path == "/api/totp/select":
                _, sw = select_aid(AID_TOTP)
                json_resp(self, 200, {"sw": f"{sw:04X}", "selected": sw == 0x9000})
            elif self.path == "/api/fido2/select":
                _, sw = select_aid(AID_FIDO2)
                json_resp(self, 200, {"sw": f"{sw:04X}", "selected": sw == 0x9000})
            else:
                json_resp(self, 404, {"error": "not found"})
        except Exception as e:
            json_resp(self, 500, {"error": str(e)})

    def do_POST(self):
        try:
            if self.path == "/api/eth/keygen":
                select_aid(AID_ETH)
                data, sw = transmit(bytes([0x00, 0x03, 0x00, 0x00, 0x00]))
                json_resp(self, 200, {
                    "sw": f"{sw:04X}", "pubkey_hex": data.hex(),
                    "eth_address": eth_address(data),
                    "btc_p2pkh_address": btc_p2pkh_address(data, "mainnet"),
                    "btc_hash160_hex": hash160(data).hex(),
                })
            elif self.path == "/api/eth/sign":
                # ETH-style: card signs the caller-supplied 32-byte hash directly.
                # (Host would normally keccak256 the tx before sending; here the
                #  caller passes the hash so the dashboard can sign arbitrary
                #  pre-hashed payloads. For a real tx, hash = keccak256(RLP(tx)).)
                body = read_body(self)
                h = bytes.fromhex(body["hash"])
                if len(h) != 32: raise ValueError("hash must be 32 bytes hex")
                select_aid(AID_ETH)
                pub, _ = transmit(bytes([0x00, 0x02, 0x00, 0x00, 0x00]))
                sig, sw = transmit(bytes([0x00, 0x04, 0x00, 0x00, 0x20]) + h)
                r = int.from_bytes(sig[:32], "big")
                s = int.from_bytes(sig[32:64], "big")
                v = sig[64]
                sig_rs = sig[:64]
                verified_verify = ecdsa_verify(pub, sig_rs, h)
                verified_recover = ecdsa_ecrecover(pub, sig_rs, h)
                json_resp(self, 200, {
                    "sw": f"{sw:04X}", "r": f"{r:064x}", "s": f"{s:064x}", "v": v,
                    "pubkey_hex": pub.hex(),
                    "verified": verified_verify and verified_recover,
                    "ecdsa_verify": verified_verify,
                    "ecdsa_ecrecover": verified_recover,
                    "verifier": "python-ecdsa (independent of host code)",
                })
            elif self.path == "/api/btc/sign":
                # Bitcoin message signing: sign double-SHA256(message). The same
                # on-card secp256k1 key signs BTC and ETH; only the host-side
                # hash differs. Verify with python-ecdsa (independent).
                body = read_body(self)
                msg = body["message"].encode()
                z = hashlib.sha256(hashlib.sha256(msg).digest()).digest()
                select_aid(AID_ETH)
                pub, _ = transmit(bytes([0x00, 0x02, 0x00, 0x00, 0x00]))
                sig, sw = transmit(bytes([0x00, 0x04, 0x00, 0x00, 0x20]) + z)
                r = int.from_bytes(sig[:32], "big")
                s = int.from_bytes(sig[32:64], "big")
                v = sig[64]
                sig_rs = sig[:64]
                verified_verify = ecdsa_verify(pub, sig_rs, z)
                verified_recover = ecdsa_ecrecover(pub, sig_rs, z)
                json_resp(self, 200, {
                    "sw": f"{sw:04X}", "r": f"{r:064x}", "s": f"{s:064x}", "v": v,
                    "pubkey_hex": pub.hex(),
                    "verified": verified_verify and verified_recover,
                    "ecdsa_verify": verified_verify,
                    "ecdsa_ecrecover": verified_recover,
                    "verifier": "python-ecdsa (independent of host code)",
                    "z_hash": z.hex(),
                    "btc_p2pkh_address": btc_p2pkh_address(pub, "mainnet"),
                    "hash160_hex": hash160(pub).hex(),
                })
            else:
                json_resp(self, 404, {"error": "not found"})
        except Exception as e:
            json_resp(self, 500, {"error": str(e)})

    def card_status(self):
        rs = readers()
        reader_names = [str(r) for r in rs]
        atr = None
        try:
            conn = get_connection()
            atr = "".join("%02x" % b for b in conn.getATR())
        except Exception as e:
            atr = f"error: {e}"
        applets = {}
        for name, aid in [("fido2", AID_FIDO2), ("musig2", AID_MUSIG2), ("totp", AID_TOTP), ("eth", AID_ETH)]:
            try:
                _, sw = select_aid(aid)
                applets[name] = {"sw": f"{sw:04X}", "present": sw == 0x9000}
            except Exception as e:
                applets[name] = {"sw": "error", "present": False, "error": str(e)}
        json_resp(self, 200, {"readers": reader_names, "atr": atr, "applets": applets})

    def serve_html(self):
        try:
            with open("web/dashboard.html", "rb") as f:
                html = f.read()
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(html)
        except FileNotFoundError:
            json_resp(self, 404, {"error": "web/dashboard.html not found"})

def main():
    port = 8788
    print(f"Nuri card dashboard: http://127.0.0.1:{port}/")
    print("Card signs, python-ecdsa + pycryptodome verify (no hand-rolled host crypto).")
    print("Reader must have the card inserted (T=0 forced).")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()

if __name__ == "__main__":
    main()