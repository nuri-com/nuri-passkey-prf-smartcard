#!/usr/bin/env python3
"""Nuri card dashboard — minimal HTTP server that talks to the card via PC/SC.

Endpoints (all JSON):
  GET  /api/card/status       — ATR + which applets SELECT-respond
  GET  /api/eth/version       — ETH applet version
  GET  /api/eth/pubkey        — current on-card ETH pubkey (33B compressed) + ETH/BTC addresses
  POST /api/eth/keygen        — DISABLED by default. Only with NURI_ALLOW_KEYGEN=1 AND applet >= 1.4
                                (on ETH applet < 1.4 KEYGEN silently REPLACES the key; a real card
                                 key was rotated that way on 2026-10-18)
  POST /api/eth/sign          — body {hash: hex(32)} -> {r, s, v, pubkey, verified}
  POST /api/btc/sign          — body {message: str} -> double-SHA256, sign, verify (BTC P2PKH)
  GET  /api/musig2/version    — MuSig2 applet version
  GET  /api/totp/select       — SELECT OATH-TOTP applet
  GET  /api/fido2/select      — SELECT FIDO2 applet
  GET  /api/eth/selftest      — cross-check on-card modInverse against python pow(a,-1,n)
  GET  /api/session           — {paired, auth, expires_in} for the current browser session
  POST /pair                  — body {code} -> session cookie (see below); no credential needed

Serves web/dashboard.html at / and web/helper-pair.js at /helper-pair.js. The page carries NO
credential: helper-pair.js asks for the one-time pairing code this server prints in its
terminal, POSTs it to /pair and gets a random session cookie nuri_dashboard_session
(HttpOnly, SameSite=Strict, Path=/api/, absolute 12 h, memory only).

Access control (scripts/nuri_helper_auth.py, docs/helper-servers-security.md):
loopback bind only (no remote mode), Host allow-list, Origin must equal http://<Host>,
Content-Type application/json on POST, /api/* needs the session cookie (browser) or
Authorization: Bearer <dashboard token> (CLI; NURI_DASHBOARD_TOKEN or
~/.nuri-card/dashboard.token, never printed), no CORS, CSP + frame-ancestors 'none'.
Framing before auth: Content-Length must be a plain non-negative integer <= 1 MiB (413),
Transfer-Encoding is refused (501), and the whole request (headers + body) must arrive
within an absolute REQUEST_DEADLINE_S (408). Error responses close the connection.
Env: NURI_DASHBOARD_TOKEN, NURI_DASHBOARD_TOKEN_FILE, NURI_CARD_PORT (default 8788),
NURI_CARD_HOST (loopback names only), NURI_ALLOW_KEYGEN=1.

Host-side crypto uses PROVEN LIBRARIES, not hand-rolled code:
  - ecdsa (python-ecdsa): ecrecover + signature verification (independent
    witness — the card signs, this library verifies, so "verified:true"
    means libsecp256k1-equivalent math agrees, not my code agreeing with
    itself)
  - pycryptodome: keccak256 (Ethereum address derivation)
  - hashlib: sha256 + ripemd160 (stdlib, correct)
  - base58: base58check encoding (BTC P2PKH addresses)

The card is the only signer. The host only hashes + verifies.

Reader: scripts/nuri_pcsc.py picks the reader and protocol (default, then T=0,
then T=1; env NURI_READER / NURI_PCSC_PROTOCOL) and handles 61XX/6CXX.
"""
import json
import hashlib
import io
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nuri_pcsc
import nuri_helper_auth

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

_applet = None

def get_connection():
    """Cached nuri_pcsc.Applet (ETH applet selected); reconnects if the card went away."""
    global _applet
    if _applet is not None:
        try:
            _applet.transmit(bytes([0x00, 0xA4, 0x04, 0x00, len(AID_ETH)]) + AID_ETH)
            return _applet
        except Exception:
            _applet.close()
            _applet = None
    try:
        _applet = nuri_pcsc.open_applet(AID_ETH.hex())
    except nuri_pcsc.CardError as e:
        raise RuntimeError(f"no card found in any reader ({e})") from e
    return _applet

def transmit(apdu):
    return get_connection().transmit(bytes(apdu))

def select_aid(aid):
    return transmit(bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid)


# --- HTTP ---------------------------------------------------------------------

# Filled in by main(); tests set them directly. Token '' and pairing None = every /api call is 401.
AUTH = {"token": "", "port": 8788, "pairing": None}
MAX_BODY = 1 << 20            # 1 MiB request body cap (413 above it)
REQUEST_DEADLINE_S = 10.0     # absolute: request line + headers + body, never extended (408)
WRITE_TIMEOUT_S = 10.0        # per send() once the request has been read
MAX_CONNECTIONS = 16          # concurrent connections; extra ones are closed at once
CARD_LOCK = threading.Lock()  # one card conversation at a time
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web")


class RequestDeadline(Exception):
    """The absolute per-request read deadline expired."""


class HTTPError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class _DeadlineReader(io.RawIOBase):
    """Socket reader whose every recv() only gets the time left until one fixed deadline,
    so a client that trickles bytes cannot keep the request alive (no per-recv idle reset)."""

    def __init__(self, sock, deadline):
        self._sock = sock
        self._deadline = deadline

    def readable(self):
        return True

    def readinto(self, b):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise RequestDeadline()
        self._sock.settimeout(remaining)
        try:
            return self._sock.recv_into(b)
        except TimeoutError:
            raise RequestDeadline() from None


def _send(handler, status, body, content_type, extra_headers=()):
    handler._responded = True
    if status >= 400:
        handler.close_connection = True
        handler._rejected = True
    try:
        handler.connection.settimeout(WRITE_TIMEOUT_S)
    except OSError:
        pass
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    for k, v in nuri_helper_auth.SECURITY_HEADERS:
        handler.send_header(k, v)
    for k, v in extra_headers:
        handler.send_header(k, v)
    if handler.close_connection:
        handler.send_header("Connection", "close")
    # No access-control-allow-origin on purpose: browsers must not read or send cross-site.
    handler.end_headers()
    if handler.command != "HEAD":
        handler.wfile.write(body)


def json_resp(handler, status, payload, extra_headers=()):
    _send(handler, status, json.dumps(payload, indent=2).encode(), "application/json; charset=utf-8", extra_headers)


def read_body(handler, cap=MAX_BODY):
    """Read exactly the validated Content-Length (already checked by begin()) within the deadline."""
    n = handler._content_length
    if n > cap:
        raise HTTPError(413, f"body too large (max {cap} bytes)")
    if n == 0:
        return {}
    data = handler.rfile.read(n)
    handler._body_read = True
    if len(data) != n:
        raise HTTPError(400, "request body shorter than Content-Length")
    try:
        body = json.loads(data)
    except (ValueError, RecursionError):
        raise HTTPError(400, "body must be valid JSON") from None
    if not isinstance(body, dict):
        raise HTTPError(400, "body must be a JSON object")
    return body


def begin(handler):
    """Framing checks before auth, then the shared guard. On denial answer and return False."""
    denied, n = nuri_helper_auth.check_framing(handler.headers, MAX_BODY)
    if denied is None and n and handler.command in ("GET", "HEAD", "OPTIONS"):
        denied = (400, f"{handler.command} must not have a body")
    if denied is None:
        handler._content_length = n
        denied = nuri_helper_auth.guard_request(
            handler.command, handler.path, handler.headers,
            port=AUTH["port"], token=AUTH["token"], pairing=AUTH["pairing"])
    else:
        handler._content_length = 0
        handler._bad_framing = True
    if denied is None:
        return True
    json_resp(handler, denied[0], {"error": denied[1]})
    return False


# Kept for callers of the old name.
guard = begin


def eth_applet_version():
    """(major, minor) of the selected ETH applet via INS 0x01."""
    select_aid(AID_ETH)
    data, sw = transmit(bytes([0x00, 0x01, 0x00, 0x00, 0x00]))
    if sw != 0x9000 or len(data) < 2:
        raise RuntimeError(f"ETH version failed: sw={sw:04X}")
    return data[0], data[1]

def verify_card_signature(pub, sig):
    """Run BOTH independent checks (ecdsa.verify + ecdsa.ecrecover) and return
    a verdict dict. The card signs, python-ecdsa verifies — no self-rolled EC."""
    sig_rs = sig[:64]
    # We need the hash that was signed; both endpoints pass it back via the
    # caller. Here we just return helpers; endpoints do the hashing.
    return None

class Handler(BaseHTTPRequestHandler):
    # HTTP/1.0: one request per connection, so the connection deadline is the request deadline.
    protocol_version = "HTTP/1.0"

    def log_message(self, *a): pass

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler otherwise emits an unguarded HTML error page
        # for unsupported methods/parser errors. Never echo attacker input.
        self.close_connection = True
        json_resp(self, code, {"error": "HTTP request rejected"})

    def setup(self):
        super().setup()
        self.command, self.path, self.requestline, self.request_version = "", "", "", "HTTP/1.0"
        self._responded = self._rejected = self._body_read = False
        self._content_length = 0
        deadline = time.monotonic() + REQUEST_DEADLINE_S
        self.rfile.close()  # drop the makefile() reader so the socket really closes in finish
        self.rfile = io.BufferedReader(_DeadlineReader(self.connection, deadline), 65536)

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except RequestDeadline:
            self.close_connection = True
            if not self._responded:
                try:
                    json_resp(self, 408, {"error": f"request not received within {REQUEST_DEADLINE_S:g} s"})
                except OSError:
                    pass

    def finish(self):
        try:
            super().finish()
        finally:
            # Discard only what has ALREADY arrived (never wait) so close() does not RST the response.
            try:
                self.connection.setblocking(False)
                for _ in range(64):
                    if not self.connection.recv(65536):
                        break
            except OSError:
                pass

    def _run(self, fn):
        try:
            fn()
        except RequestDeadline:
            raise
        except HTTPError as e:
            json_resp(self, e.status, {"error": e.message})
        except Exception as e:
            json_resp(self, 500, {"error": str(e)})

    def do_OPTIONS(self):
        begin(self)  # always 403: no CORS preflight is ever granted

    def do_GET(self):
        if not begin(self): return
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._run(self.serve_html)
        elif path == "/helper-pair.js":
            self._run(self.serve_pair_js)
        elif path == "/api/session":
            self._run(self.session_info)
        elif path.startswith("/api/"):
            with CARD_LOCK:
                self._run(lambda: self.get_api(path))
        else:
            json_resp(self, 404, {"error": "not found"})

    def do_POST(self):
        if not begin(self): return
        path = self.path.split("?", 1)[0]
        if path == "/pair":
            self._run(self.pair)
        elif path.startswith("/api/"):
            def run():
                body = read_body(self)  # authenticated caller; bounded + deadline, before the card lock
                with CARD_LOCK:
                    self.post_api(path, body)
            self._run(run)
        else:
            json_resp(self, 404, {"error": "not found"})

    def pair(self):
        body = read_body(self, cap=1024)
        pairing = AUTH["pairing"]
        session = pairing.pair(body.get("code")) if pairing is not None else None
        if session is None:
            raise HTTPError(401, "wrong or already used pairing code; use the code shown in the dashboard terminal")
        json_resp(self, 200, {"paired": True, "expires_in": int(nuri_helper_auth.SESSION_TTL_S)},
                  extra_headers=(("Set-Cookie", pairing.set_cookie(session)),))

    def session_info(self):
        pairing = AUTH["pairing"]
        left = pairing.remaining(self.headers.get("cookie")) if pairing is not None else 0
        json_resp(self, 200, {"paired": True, "auth": "session" if left else "bearer",
                              "expires_in": left or None})

    def get_api(self, path):
        if path == "/api/card/status":
            self.card_status()
        elif path == "/api/eth/version":
            select_aid(AID_ETH)
            data, sw = transmit(bytes([0x00, 0x01, 0x00, 0x00, 0x00]))
            json_resp(self, 200, {"sw": f"{sw:04X}", "major": data[0], "minor": data[1], "build": data[3:7].decode("ascii", "replace")})
        elif path == "/api/eth/pubkey":
            select_aid(AID_ETH)
            data, sw = transmit(bytes([0x00, 0x02, 0x00, 0x00, 0x00]))
            json_resp(self, 200, {
                "sw": f"{sw:04X}", "pubkey_hex": data.hex(),
                "eth_address": eth_address(data),
                "btc_p2pkh_address": btc_p2pkh_address(data, "mainnet"),
                "btc_hash160_hex": hash160(data).hex(),
            })
        elif path == "/api/eth/selftest":
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
        elif path == "/api/musig2/version":
            select_aid(AID_MUSIG2)
            data, sw = transmit(bytes([0x80, 0x01, 0x00, 0x00, 0x00]))
            json_resp(self, 200, {"sw": f"{sw:04X}", "version_hex": data.hex()})
        elif path == "/api/totp/select":
            _, sw = select_aid(AID_TOTP)
            json_resp(self, 200, {"sw": f"{sw:04X}", "selected": sw == 0x9000})
        elif path == "/api/fido2/select":
            _, sw = select_aid(AID_FIDO2)
            json_resp(self, 200, {"sw": f"{sw:04X}", "selected": sw == 0x9000})
        else:
            json_resp(self, 404, {"error": "not found"})

    def post_api(self, path, body):
        if path == "/api/eth/keygen":
            # Double gate. On ETH applet < 1.4, INS 0x03 REPLACES the existing key with no
            # confirmation (BRIEF-COMMON.md: a real card key was rotated this way on 2026-10-18).
            if os.environ.get("NURI_ALLOW_KEYGEN") != "1":
                json_resp(self, 403, {"error": "keygen disabled: start the server with NURI_ALLOW_KEYGEN=1 (and only on an ETH applet >= 1.4)"})
                return
            major, minor = eth_applet_version()
            if (major, minor) < (1, 4):
                json_resp(self, 403, {"error": f"keygen refused: ETH applet {major}.{minor} < 1.4 replaces the existing key"})
                return
            select_aid(AID_ETH)
            data, sw = transmit(bytes([0x00, 0x03, 0x00, 0x00, 0x00]))
            json_resp(self, 200, {
                "sw": f"{sw:04X}", "pubkey_hex": data.hex(),
                "eth_address": eth_address(data),
                "btc_p2pkh_address": btc_p2pkh_address(data, "mainnet"),
                "btc_hash160_hex": hash160(data).hex(),
            })
        elif path == "/api/eth/sign":
            # ETH-style: card signs the caller-supplied 32-byte hash directly.
            # (Host would normally keccak256 the tx before sending; here the
            #  caller passes the hash so the dashboard can sign arbitrary
            #  pre-hashed payloads. For a real tx, hash = keccak256(RLP(tx)).)
            hx = body.get("hash")
            if not isinstance(hx, str) or not re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", hx):
                raise HTTPError(400, "hash must be exactly 32 bytes of hex")
            h = bytes.fromhex(hx[2:] if hx.startswith("0x") else hx)
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
        elif path == "/api/btc/sign":
            # Bitcoin message signing: sign double-SHA256(message). The same
            # on-card secp256k1 key signs BTC and ETH; only the host-side
            # hash differs. Verify with python-ecdsa (independent).
            if not isinstance(body.get("message"), str):
                raise HTTPError(400, "message must be a string")
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

    def card_status(self):
        reader_names = nuri_pcsc.reader_names()
        atr = None
        try:
            applet = get_connection()
            atr = applet.atr().hex()
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

    def serve_static(self, name, content_type, transform=None):
        try:
            with open(os.path.join(WEB_DIR, name), "rb") as f:
                data = f.read()
        except FileNotFoundError:
            raise HTTPError(404, f"web/{name} not found") from None
        if transform is not None:
            data = transform(data.decode("utf-8")).encode("utf-8")
        _send(self, 200, data, content_type)

    def serve_html(self):
        # The page carries no credential; helper-pair.js pairs the browser via POST /pair.
        self.serve_static("dashboard.html", "text/html; charset=utf-8", nuri_helper_auth.inject_pair_script)

    def serve_pair_js(self):
        self.serve_static("helper-pair.js", "text/javascript; charset=utf-8")


class DashboardServer(ThreadingHTTPServer):
    """Threaded so one slow client cannot block others (each request has its own absolute
    deadline); card access is still serialized by CARD_LOCK. Connections beyond
    MAX_CONNECTIONS are closed immediately."""
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *a, **kw):
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(*a, **kw)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def main():
    port = int(os.environ.get("NURI_CARD_PORT") or 8788)
    host = os.environ.get("NURI_CARD_HOST") or "127.0.0.1"
    nuri_helper_auth.check_bind(host)  # loopback only, no override
    try:
        token, source = nuri_helper_auth.load_or_create_token("dashboard", log=print)
    except nuri_helper_auth.TokenError as e:
        sys.exit(f"card dashboard: {e}")
    print(f"Nuri card dashboard: http://{'[::1]' if host == '::1' else host}:{port}/")
    AUTH.update(token=token, port=port, pairing=nuri_helper_auth.Pairing(log=print))
    print(f"CLI API auth: Authorization: Bearer <dashboard token> ({'NURI_DASHBOARD_TOKEN' if source == 'env' else source}); "
          f"Host must be 127.0.0.1:{port} or localhost:{port}; no CORS.")
    print(f"/api/eth/keygen: {'ENABLED (NURI_ALLOW_KEYGEN=1, applet >= 1.4 only)' if os.environ.get('NURI_ALLOW_KEYGEN') == '1' else 'disabled'}")
    print("Card signs, python-ecdsa + pycryptodome verify (no hand-rolled host crypto).")
    print("Reader must have the card inserted (protocol ladder: default, T=0, T=1; see docs/reader-compatibility.md).")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    srv_cls = type("Srv", (DashboardServer,), {"address_family": family})
    srv_cls((host.strip("[]"), port), Handler).serve_forever()


if __name__ == "__main__":
    main()
