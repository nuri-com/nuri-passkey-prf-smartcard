#!/usr/bin/env python3
"""Nuri card dashboard — minimal HTTP server that talks to the card via PC/SC.

Endpoints (all JSON):
  GET  /api/card/status       — ATR + which applets SELECT-respond
  GET  /api/eth/version       — ETH applet version
  GET  /api/eth/pubkey        — current on-card ETH pubkey (33B compressed)
  POST /api/eth/keygen        — generate fresh on-card key, return pubkey
  POST /api/eth/sign           — body {hash: hex(32)} -> {r, s, v, pubkey, verified}
  POST /api/btc/sign          — body {message: str} -> signs double-SHA256(msg), returns BTC-tx-style sig
  GET  /api/musig2/version    — MuSig2 applet version
  GET  /api/totp/select       — SELECT OATH-TOTP applet

Serves web/dashboard.html at /.

Reader: forces T=0 (OMNIKEY 5422 + this card fails T=1 with 0x80100016).
"""
import json
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from smartcard.System import readers
from smartcard.CardConnection import CardConnection

AID_FIDO2   = bytes.fromhex("A0000006472F0001")
AID_MUSIG2  = bytes.fromhex("4E5552494D554701")
AID_TOTP    = bytes.fromhex("4E555249544F5450")
AID_ETH     = bytes.fromhex("4E55524945544801")

# secp256k1 + ecrecover (host-side verification)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

def modinv(a, m=P): return pow(a, -1, m)
def point_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0]==b[0] and (a[1]+b[1])%P==0: return None
    lam = ((3*a[0]*a[0])*modinv((2*a[1])%P,P))%P if a==b else ((b[1]-a[1])*modinv((b[0]-a[0])%P,P))%P
    x3 = (lam*lam - a[0] - b[0])%P
    return (x3, (lam*(a[0]-x3)-a[1])%P)
def point_mul(k, pt):
    k %= N
    if k==0 or pt is None: return None
    r=None; a=pt
    while k:
        if k&1: r=point_add(r,a)
        a=point_add(a,a); k>>=1
    return r
def decompress(pub33):
    prefix = pub33[0]; x = int.from_bytes(pub33[1:], "big")
    y_sq = (pow(x,3,P)+7)%P; y = pow(y_sq, (P+1)//4, P)
    if (y&1) != (prefix&1): y = P-y
    return x, y
def ecrecover(r, s, v, z):
    y_sq = (pow(r,3,P)+7)%P
    y = pow(y_sq, (P+1)//4, P)
    if (y&1) != v: y = P-y
    R = (r, y)
    r_inv = modinv(r, N)
    sR = point_mul(s, R)
    zG = point_mul(z % N, G)
    neg_zG = (zG[0], (-zG[1])%P)
    return point_mul(r_inv, point_add(sR, neg_zG))
def eth_address(pub33):
    # keccak256(uncompressed[1:])[-20:] — pure-python keccak, no external dep.
    x, y = decompress(pub33)
    uncomp = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    h = keccak256(uncomp)
    return "0x" + h[-20:].hex()


# --- pure-python RIPEMD-160 (fallback) ----------------------------------------
# hashlib on this platform provides ripemd160; if not, this pure-python
# fallback (RFC-aligned) is used. Verified against
# RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31.

def ripemd160(msg):
    try:
        h = hashlib.new("ripemd160")
        h.update(msg)
        return h.digest()
    except (ValueError, TypeError):
        return _ripemd160_pure(msg)

def _ripemd160_pure(msg):
    h0,h1,h2,h3,h4 = 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0
    M = 0xFFFFFFFF
    RL = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
          7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
          1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    RR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
          6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
          8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    SL = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
          7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
          11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    SR = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
          9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
          15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    KL = [0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E]
    KR = [0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000]
    def rol(x,n): return ((x<<n)|(x>>(32-n)))&M
    mp = bytearray(msg); ml = len(msg)*8; mp.append(0x80)
    while len(mp)%64!=56: mp.append(0)
    mp += ml.to_bytes(8,"little")
    for off in range(0,len(mp),64):
        X=[int.from_bytes(mp[off+i*4:off+i*4+4],"little") for i in range(16)]
        al,bl,cl,dl,el = h0,h1,h2,h3,h4
        ar,br,cr,dr,er = h0,h1,h2,h3,h4
        for j in range(80):
            r=j//16
            if r==0: fl=bl^cl^dl
            elif r==1: fl=(bl&cl)|((~bl&M)&dl)
            elif r==2: fl=(bl|(~cl&M))^dl
            elif r==3: fl=(bl&dl)|(cl&(~dl&M))
            else: fl=bl^(cl|(~dl&M))
            T=(rol((al+fl+X[RL[j]]+KL[r])&M,SL[j])+el)&M
            al,bl,cl,dl,el=el,T,bl,rol(cl,10),dl
            if r==0: fr=(br&cr)|((~br&M)&dr)
            elif r==1: fr=br^(cr|(~dr&M))
            elif r==2: fr=(br|(~cr&M))^dr
            elif r==3: fr=(br&dr)|(cr&(~dr&M))
            else: fr=br^cr^dr
            Tr=(rol((ar+fr+X[RR[j]]+KR[r])&M,SR[j])+er)&M
            ar,br,cr,dr,er=er,Tr,br,rol(cr,10),dr
        T=(h1+cl+dr)&M
        h1=(h2+dl+er)&M; h2=(h3+el+ar)&M; h3=(h4+al+br)&M; h4=(h0+bl+cr)&M; h0=T
    return b"".join(x.to_bytes(4,"little") for x in [h0,h1,h2,h3,h4])

def hash160(data):
    return ripemd160(hashlib.sha256(data).digest())

# Base58check encoding (no external dep) for BTC P2PKH addresses.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def base58check(payload):
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    full = payload + chk
    n = int.from_bytes(full, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    for b in full:
        if b == 0: out = "1" + out
        else: break
    return out

def btc_p2pkh_address(pub33, network="mainnet"):
    """P2PKH (Legacy, 1...) address from a compressed pubkey."""
    h160 = hash160(pub33)
    version = b"\x00" if network == "mainnet" else b"\x6f"
    return base58check(version + h160)


# --- pure-python Keccak-256 ---------------------------------------------------
# Adapted from the public-domain Keccak reference (PySHA3 style), verified
# against the empty-string vector c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
# and used by Ethereum for address derivation.
_KECCAK_RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
              0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
              0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
              0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
              0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
              0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]

_KECCAK_R = [[0, 36, 3, 41, 18],
             [1, 44, 10, 45, 2],
             [62, 6, 43, 15, 61],
             [28, 55, 25, 21, 56],
             [27, 20, 39, 8, 14]]

def _rotl64(x, n):
    n &= 63
    if n == 0: return x
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

def _keccak_f(s):
    for rnd in range(24):
        # theta
        c = [s[x][0] ^ s[x][1] ^ s[x][2] ^ s[x][3] ^ s[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                s[x][y] ^= d[x]
        # rho + pi
        b = [[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2*x + 3*y) % 5] = _rotl64(s[x][y], _KECCAK_R[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                s[x][y] = b[x][y] ^ ((~b[(x+1) % 5][y]) & b[(x+2) % 5][y])
        # iota
        s[0][0] ^= _KECCAK_RC[rnd]

def keccak256(msg):
    rate = 136  # 1088 bits
    # state as 5x5 list of 64-bit lanes
    s = [[0]*5 for _ in range(5)]
    # pad: 0x01 ... 0x80 (Ethereum domain separation)
    m = bytearray(msg)
    m.append(0x01)
    while len(m) % rate != rate - 1:
        m.append(0x00)
    m.append(0x80)
    # absorb
    for off in range(0, len(m), rate):
        block = m[off:off+rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i*8:i*8+8], "little")
            x = i % 5
            y = i // 5
            s[x][y] ^= lane
        _keccak_f(s)
    # squeeze 32 bytes (4 lanes from row 0)
    out = bytearray()
    for i in range(4):
        out += s[i][0].to_bytes(8, "little")
    return bytes(out[:32])

_conn = None

def get_connection():
    global _conn
    if _conn is not None:
        try:
            # ping with a harmless SELECT on ETH
            _conn.transmit(list(bytes([0x00,0xA4,0x04,0x00,len(AID_ETH)])+AID_ETH))
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
    return bytes(data), (sw1<<8)|sw2

def select_aid(aid):
    return transmit(bytes([0x00,0xA4,0x04,0x00,len(aid)])+aid)

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
                data, sw = transmit(bytes([0x00,0x01,0x00,0x00,0x00]))
                json_resp(self, 200, {"sw": f"{sw:04X}", "major": data[0], "minor": data[1], "build": data[3:7].decode("ascii", "replace")})
            elif self.path == "/api/eth/pubkey":
                select_aid(AID_ETH)
                data, sw = transmit(bytes([0x00,0x02,0x00,0x00,0x00]))
                json_resp(self, 200, {"sw": f"{sw:04X}", "pubkey_hex": data.hex(), "eth_address": eth_address(data), "btc_p2pkh_address": btc_p2pkh_address(data, "mainnet"), "btc_hash160_hex": hash160(data).hex()})
            elif self.path == "/api/musig2/version":
                select_aid(AID_MUSIG2)
                data, sw = transmit(bytes([0x80,0x01,0x00,0x00,0x00]))
                json_resp(self, 200, {"sw": f"{sw:04X}", "version_hex": data.hex()})
            elif self.path == "/api/totp/select":
                _, sw = select_aid(AID_TOTP)
                json_resp(self, 200, {"sw": f"{sw:04X}", "selected": sw==0x9000})
            elif self.path == "/api/fido2/select":
                _, sw = select_aid(AID_FIDO2)
                json_resp(self, 200, {"sw": f"{sw:04X}", "selected": sw==0x9000})
            else:
                json_resp(self, 404, {"error": "not found"})
        except Exception as e:
            json_resp(self, 500, {"error": str(e)})

    def do_POST(self):
        try:
            if self.path == "/api/eth/keygen":
                select_aid(AID_ETH)
                data, sw = transmit(bytes([0x00,0x03,0x00,0x00,0x00]))
                json_resp(self, 200, {"sw": f"{sw:04X}", "pubkey_hex": data.hex(), "eth_address": eth_address(data), "btc_p2pkh_address": btc_p2pkh_address(data, "mainnet"), "btc_hash160_hex": hash160(data).hex()})
            elif self.path == "/api/eth/sign":
                body = read_body(self)
                h = bytes.fromhex(body["hash"])
                if len(h) != 32: raise ValueError("hash must be 32 bytes hex")
                select_aid(AID_ETH)
                # GET_PUBKEY first (so we can verify)
                pub, _ = transmit(bytes([0x00,0x02,0x00,0x00,0x00]))
                sig, sw = transmit(bytes([0x00,0x04,0x00,0x00,0x20]) + h)
                r = int.from_bytes(sig[:32], "big")
                s = int.from_bytes(sig[32:64], "big")
                v = sig[64]
                z = int.from_bytes(h, "big")
                Q = ecrecover(r, s, v, z)
                qx, qy = Q
                q_pub = bytes([0x02 if (qy&1)==0 else 0x03]) + qx.to_bytes(32,"big")
                verified = q_pub == pub
                json_resp(self, 200, {"sw": f"{sw:04X}", "r": f"{r:064x}", "s": f"{s:064x}", "v": v, "pubkey_hex": pub.hex(), "verified": verified})
            elif self.path == "/api/btc/sign":
                # Bitcoin message signing: double-SHA256 of message (BIP-322 simple format
                # would be more correct; for demo we sign sha256(sha256(msg))).
                body = read_body(self)
                msg = body["message"].encode()
                z = hashlib.sha256(hashlib.sha256(msg).digest()).digest()
                select_aid(AID_ETH)
                pub, _ = transmit(bytes([0x00,0x02,0x00,0x00,0x00]))
                sig, sw = transmit(bytes([0x00,0x04,0x00,0x00,0x20]) + z)
                r = int.from_bytes(sig[:32], "big")
                s = int.from_bytes(sig[32:64], "big")
                v = sig[64]
                z_int = int.from_bytes(z, "big")
                Q = ecrecover(r, s, v, z_int)
                qx, qy = Q
                q_pub = bytes([0x02 if (qy&1)==0 else 0x03]) + qx.to_bytes(32,"big")
                verified = q_pub == pub
                btc_addr = btc_p2pkh_address(pub, "mainnet")
                json_resp(self, 200, {"sw": f"{sw:04X}", "r": f"{r:064x}", "s": f"{s:064x}", "v": v, "pubkey_hex": pub.hex(), "verified": verified, "z_hash": z.hex(), "btc_p2pkh_address": btc_addr, "hash160_hex": hash160(pub).hex()})
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
    print("Reader must have the card inserted (T=0 forced).")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()

if __name__ == "__main__":
    main()