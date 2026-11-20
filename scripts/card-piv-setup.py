#!/usr/bin/env python3
"""Provision and verify Nuri PIV (NIST SP 800-73-4, ECC P-256) on any PC/SC reader.

Works over both T=1 (OMNIKEY 5422) and T=0 (ACS ACR39U) via nuri_pcsc.connect_ladder
without needing yubico-piv-tool. Generates P-256 keys on-card in slots 9A (Auth) and
9D (Key Management), signs X.509 v3 certificates on-card, imports them, and verifies
live ECDSA + ECDH so macOS CryptoTokenKit (pivtoken / sc_auth / sudo) sees the card.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers import Cipher, modes
try:
    from cryptography.hazmat.decrepit.ciphers import algorithms as _des_algorithms
except ImportError:
    from cryptography.hazmat.primitives.ciphers import algorithms as _des_algorithms
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from smartcard.System import readers as pcsc_readers

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nuri_pcsc  # noqa: E402
import card_fingerprint  # noqa: E402

PIV_AID = bytes.fromhex("A000000308000010000100")
DEFAULT_ADMIN_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")
DEFAULT_PIN = "123456"

OBJ_CHUID = bytes.fromhex("5FC102")
OBJ_CCC = bytes.fromhex("5FC107")
OBJ_CERT_9A = bytes.fromhex("5FC105")
OBJ_CERT_9D = bytes.fromhex("5FC10B")


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _tlv(tag: int, val: bytes) -> bytes:
    tb = bytes([(tag >> 8) & 0xFF, tag & 0xFF]) if tag > 0xFF else bytes([tag])
    return tb + _ber_len(len(val)) + val


def _pad_pin(pin: str) -> bytes:
    raw = pin.encode("ascii")
    if not (6 <= len(raw) <= 8):
        raise ValueError("PIV PIN must be 6-8 ASCII characters")
    return raw + b"\xFF" * (8 - len(raw))


def _des3_ecb(key: bytes, block: bytes, decrypt: bool = False) -> bytes:
    c = Cipher(_des_algorithms.TripleDES(key), modes.ECB())
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(block) + op.finalize()


def _parse_asn1_sig(resp: bytes) -> bytes:
    # 7C <len> 82 <siglen> <der>
    if len(resp) < 6 or resp[0] != 0x7C:
        raise RuntimeError(f"Bad GEN_AUTH response: {resp.hex()}")
    i = 1
    if resp[i] == 0x81:
        i += 2
    else:
        i += 1
    if resp[i] != 0x82:
        raise RuntimeError(f"Missing 0x82 tag: {resp.hex()}")
    i += 1
    if resp[i] == 0x81:
        slen = resp[i + 1]
        i += 2
    else:
        slen = resp[i]
        i += 1
    return resp[i : i + slen]


class PivCard:
    def __init__(self, reader_hint: str):
        all_r = list(pcsc_readers())
        exact = [r for r in all_r if str(r).lower() == reader_hint.lower()]
        matched = exact or [r for r in all_r if reader_hint.lower() in str(r).lower()]
        if not matched:
            raise RuntimeError(f"No reader matching {reader_hint!r}; found {[str(x) for x in all_r]}")
        # Prefer contact slot (without '01') when substring matches both slots
        matched.sort(key=lambda r: ("01" in str(r), len(str(r))))
        self.reader = matched[0]
        self.conn = self.reader.createConnection()
        self.proto = nuri_pcsc.connect_ladder(
            self.conn,
            lambda c: nuri_pcsc.transmit_raw(c, bytes([0x00, 0xA4, 0x04, 0x00, len(PIV_AID)]) + PIV_AID)[1]
            in (0x9000, 0x6100),
        )
        # Read CPLC before selecting PIV
        self.serial = "UNKNOWN"
        nuri_pcsc.transmit_raw(self.conn, bytes.fromhex("00A4040000"))
        cplc, sw = nuri_pcsc.transmit_raw(self.conn, bytes.fromhex("80CA9F7F00"))
        if sw == 0x9000 and len(cplc) >= 19 and cplc[:3] == bytes.fromhex("9F7F2A"):
            self.serial = cplc[15:19].hex().upper()
        elif sw == 0x9000 and len(cplc) >= 16:
            self.serial = cplc[12:16].hex().upper()
        self.select()

    def tx(self, apdu: bytes) -> tuple[bytes, int]:
        return nuri_pcsc.transmit_raw(self.conn, apdu)

    def tx_chained(self, cla: int, ins: int, p1: int, p2: int, data: bytes) -> tuple[bytes, int]:
        chunk_max = 220
        off = 0
        while off < len(data):
            chunk = data[off : off + chunk_max]
            more = (off + len(chunk)) < len(data)
            c = (cla | 0x10) if more else cla
            apdu = bytes([c, ins, p1, p2, len(chunk)]) + chunk
            rsp, sw = self.tx(apdu)
            if sw != 0x9000:
                return rsp, sw
            off += len(chunk)
        return rsp, sw

    def select(self) -> bytes:
        rsp, sw = self.tx(bytes([0x00, 0xA4, 0x04, 0x00, len(PIV_AID)]) + PIV_AID)
        if sw != 0x9000:
            raise RuntimeError(f"SELECT PIV failed: {sw:04X}")
        return rsp

    def get_version(self) -> str:
        rsp, sw = self.tx(bytes.fromhex("00FD000000"))
        return ".".join(str(b) for b in rsp) if sw == 0x9000 else "unknown"

    def get_data(self, obj: bytes) -> bytes | None:
        body = _tlv(0x5C, obj)
        rsp, sw = self.tx(bytes([0x00, 0xCB, 0x3F, 0xFF, len(body)]) + body)
        if sw == 0x6A82:
            return None
        if sw != 0x9000:
            raise RuntimeError(f"GET DATA {obj.hex()} failed: {sw:04X}")
        return rsp

    def put_data(self, obj: bytes, val_tlv_53: bytes) -> None:
        payload = _tlv(0x5C, obj) + val_tlv_53
        _, sw = self.tx_chained(0x00, 0xDB, 0x3F, 0xFF, payload)
        if sw != 0x9000:
            raise RuntimeError(f"PUT DATA {obj.hex()} failed: {sw:04X}")

    def pin_tries_left(self) -> int:
        _, sw = self.tx(bytes.fromhex("00200080"))
        if sw == 0x9000:
            return 5
        if (sw & 0xFFF0) == 0x63C0:
            return sw & 0x0F
        if sw == 0x6983:
            return 0
        return -1

    def get_cert_9a_pubkey_sha1(self) -> str | None:
        raw = self.get_data(OBJ_CERT_9A)
        if not raw:
            return None
        # Find 0x70 TLV inside 0x53 wrapper
        i = 0
        if raw[i] != 0x53:
            return None
        i += 1
        if raw[i] == 0x81:
            i += 2
        elif raw[i] == 0x82:
            i += 3
        else:
            i += 1
        if i >= len(raw) or raw[i] != 0x70:
            return None
        i += 1
        if raw[i] == 0x81:
            clen = raw[i + 1]
            i += 2
        elif raw[i] == 0x82:
            clen = (raw[i + 1] << 8) | raw[i + 2]
            i += 3
        else:
            clen = raw[i]
            i += 1
        cert = x509.load_der_x509_certificate(raw[i : i + clen])
        pub = cert.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pt = pub.public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )
            return hashlib.sha1(pt).hexdigest().upper()
        return None

    def verify_pin(self, pin: str) -> None:
        p = _pad_pin(pin)
        _, sw = self.tx(bytes([0x00, 0x20, 0x00, 0x80, 0x08]) + p)
        if sw != 0x9000:
            raise RuntimeError(f"VERIFY PIN failed: {sw:04X}")

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        body = _pad_pin(old_pin) + _pad_pin(new_pin)
        _, sw = self.tx(bytes([0x00, 0x24, 0x00, 0x80, 0x10]) + body)
        if sw == 0x6983:
            raise RuntimeError("PIV PIN is blocked (0 tries left; use PUK to unblock)")
        if (sw & 0xFFF0) == 0x63C0:
            raise RuntimeError(f"Wrong current PIN ({sw & 0x0F} tries left)")
        if sw != 0x9000:
            raise RuntimeError(f"CHANGE PIN failed: {sw:04X}")

    def auth_admin(self, admin_key: bytes = DEFAULT_ADMIN_KEY) -> None:
        # Mutual auth: request witness
        rsp, sw = self.tx(bytes.fromhex("0087039B047C028000"))
        if sw != 0x9000 or len(rsp) != 12 or rsp[:4] != bytes.fromhex("7C0A8008"):
            raise RuntimeError(f"Admin auth step 1 failed: {sw:04X} {rsp.hex()}")
        enc_wit = rsp[4:12]
        wit = _des3_ecb(admin_key, enc_wit, decrypt=True)
        host_chal = secrets.token_bytes(8)
        body = _tlv(0x7C, _tlv(0x80, wit) + _tlv(0x81, host_chal))
        rsp2, sw = self.tx(bytes([0x00, 0x87, 0x03, 0x9B, len(body)]) + body)
        if sw != 0x9000 or len(rsp2) != 12 or rsp2[:4] != bytes.fromhex("7C0A8208"):
            raise RuntimeError(f"Admin auth step 2 failed: {sw:04X} {rsp2.hex()}")
        expected = _des3_ecb(admin_key, host_chal, decrypt=False)
        if rsp2[4:12] != expected:
            raise RuntimeError("Card failed mutual admin challenge check")

    def generate_p256(self, slot: int) -> ec.EllipticCurvePublicKey:
        body = bytes.fromhex("AC03800111")
        rsp, sw = self.tx(bytes([0x00, 0x47, 0x00, slot, len(body)]) + body)
        if sw != 0x9000 or len(rsp) < 70 or rsp[:5] != bytes.fromhex("7F49438641"):
            raise RuntimeError(f"GEN_ASYM slot {slot:02X} failed: {sw:04X} {rsp.hex()}")
        w = rsp[5:70]
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), w)

    def sign_hash(self, slot: int, digest32: bytes) -> bytes:
        body = _tlv(0x7C, _tlv(0x82, b"") + _tlv(0x81, digest32))
        rsp, sw = self.tx(bytes([0x00, 0x87, 0x11, slot, len(body)]) + body)
        if sw != 0x9000:
            raise RuntimeError(f"SIGN slot {slot:02X} failed: {sw:04X}")
        return _parse_asn1_sig(rsp)

    def ecdh(self, slot: int, peer_pub_uncompressed: bytes) -> bytes:
        body = _tlv(0x7C, _tlv(0x82, b"") + _tlv(0x85, peer_pub_uncompressed))
        rsp, sw = self.tx(bytes([0x00, 0x87, 0x11, slot, len(body)]) + body)
        if sw != 0x9000:
            raise RuntimeError(f"ECDH slot {slot:02X} failed: {sw:04X}")
        return _parse_asn1_sig(rsp)


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_seq(content: bytes) -> bytes:
    return b"\x30" + _der_len(len(content)) + content


def _der_bitstring(data: bytes) -> bytes:
    return b"\x03" + _der_len(len(data) + 1) + b"\x00" + data


def build_selfsigned_cert_on_card(
    card: PivCard, slot: int, pub: ec.EllipticCurvePublicKey, cn: str, is_auth: bool
) -> bytes:
    """Build a valid X.509 v3 cert whose signature is computed on-card."""
    # Construct TBS via cryptography with a throwaway key, then replace SubjectPublicKeyInfo?
    # Better: build TBS with real pubkey by signing with dummy key? No, cryptography validates pubkey matches signer.
    # Instead: use a minimal dummy signer subclass or re-assemble TBS cleanly from cryptography's CertificateBuilder!
    dummy = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if is_auth:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SMARTCARD_LOGON,
            ]),
            critical=False,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    # Cryptography signs TBS with dummy key, leaving TBS bytes carrying the REAL card pubkey!
    tmp_cert = builder.sign(dummy, hashes.SHA256())
    tbs = tmp_cert.tbs_certificate_bytes
    digest = hashlib.sha256(tbs).digest()
    card_sig = card.sign_hash(slot, digest)
    # Verify card signature against real card public key before importing!
    pub.verify(card_sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    # Re-wrap: SEQUENCE { tbsCertificate, signatureAlgorithm (ecdsa-with-SHA256), signatureValue }
    sig_alg_oid_ecdsa_sha256 = bytes.fromhex("300A06082A8648CE3D040302")
    cert_der = _der_seq(tbs + sig_alg_oid_ecdsa_sha256 + _der_bitstring(card_sig))
    # Parse back with cryptography to guarantee strict DER validity
    parsed = x509.load_der_x509_certificate(cert_der)
    parsed.public_key().verify(parsed.signature, parsed.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    return cert_der


def list_all_piv_cards() -> list[dict]:
    # Scan contact readers before contactless ('Reader 01') so dual-interface cards
    # inserted in OMNIKEY contact slot aren't duplicated by the top RF pad.
    ordered = sorted(pcsc_readers(), key=lambda r: ("01" in str(r), str(r)))
    found = []
    seen_serials: set[str] = set()
    for r in ordered:
        name = str(r)
        try:
            card = PivCard(name)
            if card.serial != "UNKNOWN" and card.serial in seen_serials:
                continue
            if card.serial != "UNKNOWN":
                seen_serials.add(card.serial)
            chuid = card.get_data(OBJ_CHUID)
            guid = ""
            if chuid and b"\x34\x10" in chuid:
                pos = chuid.index(b"\x34\x10") + 2
                guid = chuid[pos : pos + 16].hex().upper()
            item = {
                "reader": str(card.reader),
                "protocol": card.proto,
                "card_serial": card.serial,
                "piv_version": card.get_version(),
                "chuid_guid": guid,
                "pin_tries_left": card.pin_tries_left(),
                "auth_hash": card.get_cert_9a_pubkey_sha1() or "",
            }
            # ACR39U can invalidate the first session when the second one opens.
            # Finish every PIV read before probing the fingerprint applet.
            try:
                item.update(card_fingerprint.status(name))
            except Exception:
                # A sensor/second-session failure must never hide a working PIV card.
                item.update({"fingerprint_supported": False, "fingerprint_count": 0, "fingerprint_backend": ""})
            found.append(item)
        except Exception:
            continue
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description="Provision & verify Nuri PIV on a physical card")
    ap.add_argument("--list-piv", action="store_true", help="List all connected PIV cards as JSON")
    ap.add_argument("--reader", help="Reader name substring (e.g. OMNIKEY or ACR39U)")
    ap.add_argument("--pin", default=DEFAULT_PIN, help="Current PIV PIN (default 123456)")
    ap.add_argument("--new-pin", help="Optionally change PIV PIN after verification")
    ap.add_argument(
        "--change-pin-stdin",
        action="store_true",
        help="Read 'old_pin\\nnew_pin\\n' from stdin and change PIV PIN (avoids argv exposure)",
    )
    ap.add_argument("--provision", action="store_true", help="Generate 9A+9D P-256 keys & self-signed certs")
    ap.add_argument("--out", help="Write sanitized JSON proof receipt")
    args = ap.parse_args()

    if args.list_piv:
        print(json.dumps(list_all_piv_cards(), indent=2))
        return 0

    if not args.reader:
        ap.error("--reader is required unless --list-piv is set")

    if args.change_pin_stdin:
        lines = sys.stdin.read().splitlines()
        if len(lines) < 2:
            print(json.dumps({"ok": False, "error": "Expected old_pin and new_pin on stdin"}))
            return 1
        old_pin, new_pin = lines[0], lines[1]
        try:
            card = PivCard(args.reader)
            card.change_pin(old_pin, new_pin)
            print(json.dumps({
                "ok": True,
                "card_serial": card.serial,
                "reader": str(card.reader),
                "pin_tries_left": card.pin_tries_left(),
            }))
            return 0
        except Exception as e:
            print(json.dumps({"ok": False, "error": str(e)}))
            return 1

    card = PivCard(args.reader)
    version = card.get_version()
    chuid = card.get_data(OBJ_CHUID)
    ccc = card.get_data(OBJ_CCC)
    guid = ""
    if chuid and b"\x34\x10" in chuid:
        pos = chuid.index(b"\x34\x10") + 2
        guid = chuid[pos : pos + 16].hex().upper()

    result = {
        "date": datetime.date.today().isoformat(),
        "reader": str(card.reader),
        "protocol": card.proto,
        "card_serial": card.serial,
        "piv_aid": PIV_AID.hex().upper(),
        "piv_version": version,
        "chuid_guid": guid,
        "has_ccc": ccc is not None,
    }

    if args.provision:
        card.auth_admin()
        card.verify_pin(args.pin)

        pub_9a = card.generate_p256(0x9A)
        cert_9a = build_selfsigned_cert_on_card(
            card, 0x9A, pub_9a, f"Nuri Card {card.serial} Auth", is_auth=True
        )
        card.put_data(OBJ_CERT_9A, _tlv(0x53, _tlv(0x70, cert_9a) + bytes.fromhex("710100FE00")))

        pub_9d = card.generate_p256(0x9D)
        cert_9d = build_selfsigned_cert_on_card(
            card, 0x9D, pub_9d, f"Nuri Card {card.serial} KeyMgmt", is_auth=False
        )
        card.put_data(OBJ_CERT_9D, _tlv(0x53, _tlv(0x70, cert_9d) + bytes.fromhex("710100FE00")))

        # Readback + live ECDSA + live ECDH verification
        rb_9a = card.get_data(OBJ_CERT_9A)
        rb_9d = card.get_data(OBJ_CERT_9D)
        assert rb_9a and cert_9a in rb_9a, "9A cert readback mismatch"
        assert rb_9d and cert_9d in rb_9d, "9D cert readback mismatch"

        challenge = hashlib.sha256(b"nuri-piv-ecdsa-verify-" + secrets.token_bytes(16)).digest()
        sig = card.sign_hash(0x9A, challenge)
        pub_9a.verify(sig, challenge, ec.ECDSA(Prehashed(hashes.SHA256())))

        eph = ec.generate_private_key(ec.SECP256R1())
        eph_pub_bytes = eph.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        card_shared = card.ecdh(0x9D, eph_pub_bytes)
        host_shared = eph.exchange(ec.ECDH(), pub_9d)
        assert card_shared == host_shared, "9D ECDH shared secret mismatch"

        result["slot_9a_cert_sha256"] = hashlib.sha256(cert_9a).hexdigest()
        result["slot_9a_pubkey_sha1"] = hashlib.sha1(
            pub_9a.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        ).hexdigest().upper()
        result["slot_9d_cert_sha256"] = hashlib.sha256(cert_9d).hexdigest()
        result["checks"] = {
            "admin_3des_mutual_auth": "PASS",
            "pin_verify": "PASS",
            "gen_p256_9a_9d": "PASS",
            "selfsign_cert_on_card": "PASS",
            "cert_chained_put_and_get": "PASS",
            "ecdsa_9a_verify": "PASS",
            "ecdh_9d_verify": "PASS",
        }
        result["result"] = "REAL_CARD_NURI_PIV_VERIFIED"

    if args.new_pin:
        card.change_pin(args.pin, args.new_pin)
        result["pin_changed"] = True

    out_json = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(out_json + "\n")
    print(out_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
