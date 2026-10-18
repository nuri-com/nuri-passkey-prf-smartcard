#!/usr/bin/env python3
"""Tests for host/nuri_card_host.py: framing, sim signing, PIN flow, sim gating.

Run:  <venv>/bin/python host/test_host.py
Sim + fake nuri_pcsc only. Never touches a reader, a card or the network.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nuri_card_host as host  # noqa: E402

SIM_PUBKEY = "0x03bcd83232b6276e8856605cfd877f7795536a5099555684422fe82f2b6adb95e2"
CARD_PUBKEY = "031f0f76cf2da4d2c679130f1accfb1e3b149c20ea15291a49b643e350cc63c4b1"
CARD_ADDRESS = "0x77bab29aa61949f03f233118ebc0a263f61cc385"


def frame(obj) -> bytes:
    body = json.dumps(obj).encode()
    return struct.pack("<I", len(body)) + body


def unframe_all(data: bytes) -> list:
    out = []
    pos = 0
    while pos + 4 <= len(data):
        (n,) = struct.unpack("<I", data[pos:pos + 4])
        out.append(json.loads(data[pos + 4:pos + 4 + n]))
        pos += 4 + n
    return out


def recover_address(digest: bytes, r: int, s: int, y_parity: int) -> str:
    """Independent ecrecover (not via the host's recovery helper)."""
    from ecdsa import SECP256k1, VerifyingKey
    from ecdsa.ellipticcurve import PointJacobi
    from ecdsa.numbertheory import square_root_mod_prime, inverse_mod
    curve = SECP256k1.curve
    G = SECP256k1.generator
    n = SECP256k1.order
    p = curve.p()
    alpha = (pow(r, 3, p) + curve.a() * r + curve.b()) % p
    beta = square_root_mod_prime(alpha, p)
    y = beta if (beta % 2) == y_parity else p - beta
    R = PointJacobi(curve, r, y, 1, n)
    e = int.from_bytes(digest, "big")
    rinv = inverse_mod(r, n)
    Q = (R * s + G * (-e % n)) * rinv
    vk = VerifyingKey.from_public_point(Q, curve=SECP256k1)
    return host.pubkey_to_address(vk.to_string("compressed"))


class AddressTests(unittest.TestCase):
    def test_card_pubkey_to_address_matches_known_card(self):
        addr = host.pubkey_to_address(bytes.fromhex(CARD_PUBKEY))
        self.assertEqual(addr.lower(), CARD_ADDRESS)
        self.assertNotEqual(addr, CARD_ADDRESS, "expected EIP-55 mixed case")

    def test_keccak_known_vector(self):
        self.assertEqual(host.keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")


def attestation_response(ca_key, attestation_key, signing_pub, challenge, mutation=None):
    """Independent wire fixture: real P256 signatures, no verifier mocked."""
    from ecdsa import NIST256p, SECP256k1, SigningKey
    from ecdsa.util import sigencode_der
    aid = bytes.fromhex(host.AID_ETH_V2)
    if mutation == "aid":
        aid = bytes.fromhex("4E5552494D554701")
    if mutation == "money_key":
        signing_pub = SigningKey.from_secret_exponent(0xBAD, curve=SECP256k1).verifying_key.to_string("compressed")
    att_pub = attestation_key.verifying_key.to_string("uncompressed")
    card_id = bytes.fromhex("00112233445566778899aabbccddeeff")

    def sign(key, message):
        return key.sign_deterministic(message, hashfunc=hashlib.sha256, sigencode=sigencode_der)

    cert_key = SigningKey.from_secret_exponent(0xBADCA, curve=NIST256p) if mutation == "certificate" else ca_key
    cert = sign(cert_key, b"NURI-ATT-V1" + card_id + aid + att_pub)
    sealed = 0 if mutation == "unsealed" else 1
    info = b"\x01" + card_id + bytes([len(aid)]) + aid + att_pub + bytes([sealed, len(cert)]) + cert
    signed_challenge = b"\x00" * 32 if mutation == "challenge" else challenge
    response = sign(attestation_key, b"NURI-ATT-RESP-V1" + signed_challenge + signing_pub + b"\x03")
    if mutation == "response":
        response = response[:-1] + bytes([response[-1] ^ 1])
    binding = sign(attestation_key, (b"NHWV0" if mutation == "binding" else b"NHWV1") + aid + signing_pub)
    if mutation == "missing_binding":
        binding = b""
    pin_state = 0x01 if mutation == "pin_state" else 0x03
    return info + bytes([len(signing_pub)]) + signing_pub + bytes([pin_state, len(response)]) + response + bytes([len(binding)]) + binding


def reset_host():
    host._SIGNER = None
    host._INFO = None
    host._SIM_ACK = False
    host._SIM_FLAG = False


class SimSignTests(unittest.TestCase):
    def setUp(self):
        os.environ["NURI_CARD_SIM"] = "1"
        reset_host()

    def test_info(self):
        resp = host.handle({"id": 1, "method": "info"})
        self.assertTrue(resp["ok"], resp)
        res = resp["result"]
        self.assertEqual(res["mode"], "sim")
        self.assertEqual(res["applet"], "eth1")
        self.assertIs(res["pin_set"], False)
        self.assertIsNone(res["pin_tries_left"])
        self.assertEqual(res["pubkey"], SIM_PUBKEY)
        self.assertTrue(res["address"].startswith("0x") and len(res["address"]) == 42)
        self.assertEqual(res["address"], host.pubkey_to_address(bytes.fromhex(SIM_PUBKEY[2:])))

    def test_sim_attestation_never_verified_even_with_ca_configured(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"NURI_CARD_CA_PUBKEY": "/nonexistent/public-ca.pem"}):
            info = host.handle({"id": 1, "method": "info"})
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["result"]["attestation"], {"verified": False, "reason": "unverified"})

    def test_sign_hash_round_trip_recovers_sim_address(self):
        info = host.handle({"id": 1, "method": "info"})["result"]
        for i in range(8):
            digest = hashlib.sha256(f"nuri test vector {i}".encode()).digest()
            resp = host.handle({"id": 2 + i, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})
            self.assertTrue(resp["ok"], resp)
            res = resp["result"]
            r = int(res["r"], 16)
            s = int(res["s"], 16)
            self.assertLessEqual(s, host.curve_order() // 2, "s must be low-s")
            self.assertIn(res["yParity"], (0, 1))
            self.assertEqual(len(res["signature"]), 2 + 130)
            self.assertEqual(res["signature"][-2:], "1b" if res["yParity"] == 0 else "1c")
            self.assertEqual(res["signature"][2:66], res["r"][2:])
            self.assertEqual(res["signature"][66:130], res["s"][2:])
            self.assertEqual(recover_address(digest, r, s, res["yParity"]), info["address"])
            # the other parity must NOT recover the sim address
            self.assertNotEqual(recover_address(digest, r, s, 1 - res["yParity"]), info["address"])

    def test_bad_requests(self):
        for malformed in ("00 " * 21 + " ", "00" * 32, "0x" + "gg" * 32, "0x" + "00" * 31):
            self.assertEqual(host.handle({"id": 1, "method": "sign_hash", "params": {"hash": malformed}})["error"]["code"], "BAD_REQUEST")
        self.assertEqual(host.handle({"id": 1, "method": "nope"})["error"]["code"], "BAD_REQUEST")
        self.assertEqual(host.handle({"id": 1, "method": "sign_hash", "params": {"hash": "0x1234"}})["error"]["code"], "BAD_REQUEST")
        self.assertEqual(host.handle({"id": 1, "method": "sign_hash", "params": {"hash": "zz" * 32}})["error"]["code"], "BAD_REQUEST")
        self.assertEqual(host.handle({"id": 1, "method": "sign_hash"})["error"]["code"], "BAD_REQUEST")
        self.assertEqual(host.handle([1, 2])["error"]["code"], "BAD_REQUEST")

    def test_parse_hash_is_strict_full_match_32_bytes(self):
        ok = ["0x" + "ab" * 32, "0X" + "AB" * 32, "cd" * 32]
        for v in ok:
            self.assertEqual(len(host.parse_hash(v)), 32, v)
        bad = [
            "00 " * 21 + " ",            # 64 chars, bytes.fromhex -> 21 bytes (W13 R11)
            "0x" + "00 " * 21 + " ",
            "0x" + "00" * 31 + " 0",     # embedded whitespace
            "0x" + "00" * 32 + "\n",     # trailing newline
            " 0x" + "00" * 32,
            "0x" + "00" * 31,            # 31 bytes
            "0x" + "00" * 33,            # 33 bytes
            "0x" + "0" * 63,             # odd length
            "0x" + "\uff10" * 64,        # non-ASCII digits
            "0x0x" + "00" * 31,
            "", "0x", None, 123, ["00" * 32], b"\x00" * 32,
        ]
        for v in bad:
            with self.assertRaises(host.HostError, msg=repr(v)) as ctx:
                host.parse_hash(v)
            self.assertEqual(ctx.exception.code, "BAD_REQUEST")
        resp = host.handle({"id": 3, "method": "sign_hash", "params": {"hash": "00 " * 21 + " "}})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "BAD_REQUEST")

    def test_verify_failed_on_tampered_signer(self):
        class Bad(host.SimSigner):
            def sign_digest(self, digest, expected=None):
                r, s = super().sign_digest(digest)
                return r, (s + 1) % host.curve_order()
        host.handle({"id": 1, "method": "info"})
        host._SIGNER = Bad()
        resp = host.handle({"id": 9, "method": "sign_hash", "params": {"hash": "0x" + "11" * 32}})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "VERIFY_FAILED")

    def test_high_s_from_signer_is_normalized(self):
        class HighS(host.SimSigner):
            def sign_digest(self, digest, expected=None):
                r, s = super().sign_digest(digest)
                return r, host.curve_order() - s  # same signature, high-s form
        info = host.handle({"id": 1, "method": "info"})["result"]
        host._SIGNER = HighS()
        digest = b"\x42" * 32
        resp = host.handle({"id": 9, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})
        self.assertTrue(resp["ok"], resp)
        self.assertLessEqual(int(resp["result"]["s"], 16), host.curve_order() // 2)
        self.assertEqual(recover_address(digest, int(resp["result"]["r"], 16), int(resp["result"]["s"], 16),
                                         resp["result"]["yParity"]),
                         info["address"])


class FakePcscCardTests(unittest.TestCase):
    """Card mode against a fake nuri_pcsc module (C1 shape). No reader, no card."""

    def _install_fake(self, applets: set, sim_key, eth2_format="der", eth2_echo_key=None, pin=None, tries=5):
        """eth2_format: "der" (legacy fake) or "rspub" (real applet: r||s||pub65, 129 B).

        pin: ETH2 OwnerPIN (bytes) or None; validation is per open session like
        card/eth2/NuriEthSignerV2.java:188-191,213-218,415-425.
        """
        import types
        from ecdsa.util import sigencode_string, sigencode_der
        calls = []
        card = types.SimpleNamespace(key=sim_key, echo=eth2_echo_key, pin=pin, tries=tries,
                                     applets=set(applets), opened=[], fail_transmit=None, attestation=None)
        self.card = card

        class CardError(Exception):
            def __init__(self, code, msg=""):
                super().__init__(msg or code)
                self.code = code

        class Applet:
            def __init__(self, aid):
                self.aid = aid
                self.reader_name = "Fake Reader 00 00"
                self.protocol = "T0"
                self.closed = False
                self.validated = False

            def transmit(self, apdu):
                assert not self.closed, "transmit on closed applet"
                raw = bytes(apdu)
                ins = raw[1]
                calls.append("80200000<pin>" if ins == 0x20 else raw.hex())
                if card.fail_transmit and ins == card.fail_transmit[0]:
                    raise card.fail_transmit[1]
                vk = card.key.get_verifying_key()
                eth2 = self.aid == host.AID_ETH_V2
                if ins == 0x01:
                    if not eth2:
                        return b"\x01\x03\x01ETH1", 0x9000
                    state = 0x01 | (0x02 if card.pin is not None else 0)
                    left = card.tries if card.pin is not None else 5
                    return b"\x02\x00\x00ETH2" + bytes([state, left]), 0x9000
                if ins == 0x02:
                    return (vk.to_string("uncompressed") if eth2 else vk.to_string("compressed")), 0x9000
                if ins == 0x72 and card.attestation is not None:
                    assert eth2 and len(raw) == 38 and raw[:2] == b"\x80\x72"
                    assert raw[2] in (0, 1) and raw[3:5] == b"\x00\x20" and raw[-1] == 0
                    if raw[2] == 0:
                        return card.attestation_info, 0x9000
                    logical = card.attestation(raw[5:37])
                    return logical[len(card.attestation_info):], 0x9000
                if ins == 0x20:
                    if not eth2 or card.pin is None:
                        return b"", 0x6985
                    if card.tries == 0:
                        return b"", 0x6983
                    if raw[5:5 + raw[4]] == card.pin:
                        card.tries = 5
                        self.validated = True
                        return b"", 0x9000
                    card.tries -= 1
                    return b"", (0x6983 if card.tries == 0 else 0x63C0 | card.tries)
                if ins == 0x04:
                    digest = raw[5:37]
                    if not eth2:
                        sig = card.key.sign_digest_deterministic(digest, sigencode=sigencode_string)
                        return sig + b"\x00", 0x9000  # v byte is deliberately wrong; host must recover it
                    if card.pin is not None and not self.validated:
                        return b"", 0x6982
                    if eth2_format == "der":
                        return card.key.sign_digest_deterministic(digest, sigencode=sigencode_der), 0x9000
                    sig = card.key.sign_digest_deterministic(digest, sigencode=sigencode_string)
                    echo = (card.echo or card.key).get_verifying_key()
                    return sig + echo.to_string("uncompressed"), 0x9000
                return b"", 0x6D00

            def close(self):
                self.closed = True
                self.validated = False

        def open_applet(aid_hex, reader=None):
            if aid_hex not in card.applets:
                raise CardError("NO_APPLET", f"SELECT {aid_hex} failed")
            a = Applet(aid_hex)
            card.opened.append(a)
            return a

        mod = types.ModuleType("nuri_pcsc")
        mod.CardError = CardError
        mod.Applet = Applet
        mod.open_applet = open_applet
        sys.modules["nuri_pcsc"] = mod
        return calls

    def assertAllClosed(self):
        self.assertTrue(self.card.opened, "no session opened")
        self.assertTrue(all(a.closed for a in self.card.opened), "a card session was left open")

    def setUp(self):
        from ecdsa import SigningKey, SECP256k1
        self.key = SigningKey.from_secret_exponent(0x1234567, curve=SECP256k1)
        self.saved_env = os.environ.pop("NURI_CARD_SIM", None)
        self.saved_ca = os.environ.pop("NURI_CARD_CA_PUBKEY", None)
        reset_host()

    def tearDown(self):
        sys.modules.pop("nuri_pcsc", None)
        reset_host()
        os.environ.pop("NURI_CARD_CA_PUBKEY", None)
        if self.saved_ca is not None:
            os.environ["NURI_CARD_CA_PUBKEY"] = self.saved_ca
        if self.saved_env is not None:
            os.environ["NURI_CARD_SIM"] = self.saved_env

    def _attestation_card(self, mutation=None, configured=True, pem=True):
        from ecdsa import NIST256p, SigningKey
        self.ca_key = SigningKey.from_secret_exponent(0xCA25, curve=NIST256p)
        self.attestation_key = SigningKey.from_secret_exponent(0xA725, curve=NIST256p)
        calls = self._install_fake({host.AID_ETH_V2}, self.key)
        self.card.attestation = lambda challenge: attestation_response(
            self.ca_key, self.attestation_key, self.card.key.verifying_key.to_string("compressed"), challenge, mutation)
        fixture = self.card.attestation(b"\x00" * 32)
        sealed_offset = 18 + fixture[17] + 65
        info_length = sealed_offset + 2 + fixture[sealed_offset + 1]
        self.card.attestation_info = fixture[:info_length]
        if configured:
            directory = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
            self.addCleanup(shutil.rmtree, directory, True)
            path = os.path.join(directory, "ca.pub")
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
                key = self.ca_key.verifying_key
                stream.write(key.to_pem() if pem else key.to_string("uncompressed").hex().encode())
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            os.environ["NURI_CARD_CA_PUBKEY"] = path
        return calls

    def test_attestation_ca_unset_is_unverified_and_never_sends_challenge(self):
        calls = self._attestation_card(configured=False)
        info = host.handle({"id": 1, "method": "info"})
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["result"]["attestation"], {"verified": False, "reason": "unverified"})
        self.assertFalse(any(c.startswith("8072") for c in calls))
        self.assertAllClosed()

    def test_attestation_genuine_pem_and_hex_ca_on_same_selected_session(self):
        for pem in (True, False):
            with self.subTest(pem=pem):
                calls = self._attestation_card(pem=pem)
                info = host.handle({"id": 1, "method": "info"})
                self.assertTrue(info["ok"], info)
                self.assertEqual(info["result"]["attestation"], {"verified": True, "reason": "verified"})
                self.assertEqual(len(self.card.opened), 1, "identity and evidence must share the selected applet")
                self.assertEqual(calls[:2], ["8001000000", "8002000000"])
                page0, page1 = (bytes.fromhex(raw) for raw in calls[2:])
                self.assertEqual(page0[:5], b"\x80\x72\x00\x00\x20")
                self.assertEqual(page1[:5], b"\x80\x72\x01\x00\x20")
                self.assertEqual(page0[5:37], page1[5:37], "one issued challenge must be reused on both pages")
                self.assertEqual((len(page0), len(page1), page0[-1], page1[-1]), (38, 38, 0, 0))
                self.assertEqual(len(calls), 4, "attestation must be read-only, no provisioning/PIN/keygen")
                self.assertAllClosed()

    def test_attestation_page1_challenge_substitution_is_nonfatal_false(self):
        self._attestation_card()
        Applet = sys.modules["nuri_pcsc"].Applet
        original = Applet.transmit
        seen = []

        def substitute(applet, apdu):
            raw = bytes(apdu)
            if raw[1] == 0x72:
                seen.append(raw)
                if raw[2] == 1:
                    changed = bytes([raw[5] ^ 1]) + raw[6:37]
                    raw = raw[:5] + changed + raw[-1:]
            return original(applet, raw)

        Applet.transmit = substitute
        info = host.handle({"id": 1, "method": "info"})
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["result"]["attestation"], {"verified": False, "reason": "verification_failed"})
        self.assertEqual([raw[2] for raw in seen], [0, 1])
        self.assertEqual(seen[0][5:37], seen[1][5:37], "host must issue exactly one challenge")
        self.assertAllClosed()

    def test_attestation_page1_transport_status_and_unsupported_never_verify(self):
        for sw in (0x6985, 0x6D00, 0x6E00):
            with self.subTest(sw=hex(sw)):
                calls = self._attestation_card()
                Applet = sys.modules["nuri_pcsc"].Applet
                original = Applet.transmit
                def fail_tail(applet, apdu):
                    if apdu[1:3] == b"\x72\x01":
                        return b"", sw
                    return original(applet, apdu)
                Applet.transmit = fail_tail
                info = host.handle({"id": 1, "method": "info"})
                self.assertTrue(info["ok"], info)
                self.assertEqual(info["result"]["attestation"], {
                    "verified": False,
                    "reason": "verification_failed" if sw == 0x6985 else "unsupported"})
                self.assertEqual(sum(c.startswith("8072") for c in calls), 1, "only INFO page reaches the fake")
                self.assertAllClosed()

    def test_attestation_noncanonical_selected_aid_is_never_verified(self):
        from unittest.mock import patch
        with patch.object(host, "AID_ETH_V2", "4E5552494554483202"):
            calls = self._attestation_card()
            info = host.handle({"id": 1, "method": "info"})
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["result"]["attestation"], {"verified": False, "reason": "unsupported"})
        self.assertFalse(any(c.startswith("8072") for c in calls))
        self.assertAllClosed()

    def test_attestation_tampering_and_binding_mismatches_are_nonfatal_false(self):
        for mutation in ("certificate", "response", "challenge", "aid", "money_key", "binding",
                         "missing_binding", "pin_state", "unsealed"):
            with self.subTest(mutation=mutation):
                self._attestation_card(mutation=mutation)
                info = host.handle({"id": 1, "method": "info"})
                self.assertTrue(info["ok"], info)
                self.assertEqual(info["result"]["attestation"], {"verified": False, "reason": "verification_failed"})
                self.assertAllClosed()
                signed = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "22" * 32}})
                self.assertTrue(signed["ok"], signed)
                self.assertAllClosed()

    def test_attestation_fresh_challenge_each_info_rejects_replayed_response(self):
        self._attestation_card()
        challenges, responses = [], []
        genuine = self.card.attestation

        def replay(challenge):
            challenges.append(challenge)
            if not responses:
                responses.append(genuine(challenge))
            return responses[0]

        self.card.attestation = replay
        first = host.handle({"id": 1, "method": "info"})
        second = host.handle({"id": 2, "method": "info"})
        self.assertIs(first["result"]["attestation"]["verified"], True)
        self.assertIs(second["result"]["attestation"]["verified"], False)
        self.assertEqual(len(challenges), 2)
        self.assertEqual([len(c) for c in challenges], [32, 32])
        self.assertNotEqual(challenges[0], challenges[1])
        self.assertAllClosed()

    def test_attestation_unsupported_eth2_and_v1_are_nonfatal_false(self):
        self._attestation_card()
        self.card.attestation = None
        info = host.handle({"id": 1, "method": "info"})
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["result"]["attestation"], {"verified": False, "reason": "unsupported"})
        calls = self._install_fake({host.AID_ETH_V1}, self.key)
        info = host.handle({"id": 2, "method": "info"})
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["result"]["attestation"], {"verified": False, "reason": "unsupported"})
        self.assertFalse(any(c.startswith("8072") for c in calls), "legacy must not receive unknown attestation INS")
        self.assertAllClosed()

    def test_attestation_invalid_ca_transport_and_malformed_response_are_nonfatal_false(self):
        for failure in ("missing_file", "invalid_ca", "wrong_ca", "transport", "malformed", "status"):
            with self.subTest(failure=failure):
                self._attestation_card()
                if failure == "missing_file":
                    os.environ["NURI_CARD_CA_PUBKEY"] += ".missing"
                elif failure == "invalid_ca":
                    with open(os.environ["NURI_CARD_CA_PUBKEY"], "wb") as stream:
                        stream.write(b"invalid pin")
                elif failure == "wrong_ca":
                    with open(os.environ["NURI_CARD_CA_PUBKEY"], "wb") as stream:
                        stream.write(self.attestation_key.verifying_key.to_pem())
                elif failure == "transport":
                    self.card.fail_transmit = (0x72, RuntimeError("private transport diagnostic"))
                elif failure == "malformed":
                    self.card.attestation = lambda challenge: b"\x01"
                else:
                    self.card.attestation = None  # force an unsupported result to a different failing SW
                    transmit = sys.modules["nuri_pcsc"].Applet.transmit
                    sys.modules["nuri_pcsc"].Applet.transmit = lambda applet, apdu: (b"", 0x6985) if apdu[1] == 0x72 else transmit(applet, apdu)
                info = host.handle({"id": 1, "method": "info"})
                self.assertTrue(info["ok"], info)
                self.assertEqual(info["result"]["attestation"], {"verified": False, "reason": "verification_failed"})
                self.assertNotIn("private transport diagnostic", json.dumps(info))
                self.assertAllClosed()

    def test_attestation_native_framing_ca_unset_genuine_tamper_unsupported(self):
        bootstrap = '''import sys
sys.path.insert(0, sys.argv[1])
import test_host as tests
fake = tests.FakePcscCardTests()
fake.setUp()
try:
    scenario = sys.argv[2]
    fake._attestation_card(mutation="binding" if scenario == "tamper" else None, configured=scenario != "unset")
    if scenario == "unsupported":
        fake.card.attestation = None
    raise SystemExit(tests.host.main([]))
finally:
    fake.tearDown()
    fake.doCleanups()
'''
        for scenario, verified, reason in (("unset", False, "unverified"), ("genuine", True, "verified"),
                                            ("tamper", False, "verification_failed"), ("unsupported", False, "unsupported")):
            with self.subTest(scenario=scenario):
                proc = subprocess.run([sys.executable, "-c", bootstrap, HERE, scenario],
                                      input=frame({"id": 1, "method": "info"}) + frame({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "33" * 32}}),
                                      capture_output=True, env=dict(os.environ, NURI_CARD_HOST_LOG=""), timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stderr.decode())
                self.assertEqual(proc.stderr, b"")
                responses = unframe_all(proc.stdout)
                self.assertEqual([r["id"] for r in responses], [1, 2])
                self.assertTrue(all(r["ok"] for r in responses), responses)
                self.assertEqual(responses[0]["result"]["attestation"], {"verified": verified, "reason": reason})

    def test_eth1_fallback_signs_and_recovers(self):
        calls = self._install_fake({host.AID_ETH_V1}, self.key)
        info = host.handle({"id": 1, "method": "info"})
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["result"]["applet"], "eth1")
        self.assertEqual(info["result"]["applet_version"], "1.3.1")
        self.assertEqual(info["result"]["mode"], "card")
        self.assertEqual(info["result"]["reader"], "Fake Reader 00 00")
        self.assertEqual(info["result"]["pubkey"], "0x" + self.key.get_verifying_key().to_string("compressed").hex())
        digest = b"\x77" * 32
        resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})
        self.assertTrue(resp["ok"], resp)
        res = resp["result"]
        self.assertEqual(recover_address(digest, int(res["r"], 16), int(res["s"], 16), res["yParity"]), info["result"]["address"])
        self.assertIn("8004000020" + digest.hex(), calls)
        self.assertIn("8001000000", calls)
        self.assertIn("8002000000", calls)

    def test_eth2_preferred_der_signature(self):
        self._install_fake({host.AID_ETH_V1, host.AID_ETH_V2}, self.key)
        info = host.handle({"id": 1, "method": "info"})
        self.assertEqual(info["result"]["applet"], "eth2")
        self.assertEqual(info["result"]["applet_version"], "2.0.0")
        digest = hashlib.sha256(b"eth2").digest()
        res = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})["result"]
        self.assertEqual(recover_address(digest, int(res["r"], 16), int(res["s"], 16), res["yParity"]), info["result"]["address"])

    def test_eth2_native_rs_pub_signature(self):
        """Real ETH2 output: r(32)||s(32)||pub(65). Host must parse, verify and recover v."""
        calls = self._install_fake({host.AID_ETH_V2}, self.key, eth2_format="rspub")
        info = host.handle({"id": 1, "method": "info"})
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["result"]["applet"], "eth2")
        digest = hashlib.sha256(b"eth2-rspub").digest()
        resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})
        self.assertTrue(resp["ok"], resp)
        res = resp["result"]
        self.assertLessEqual(int(res["s"], 16), host.curve_order() // 2)
        self.assertEqual(recover_address(digest, int(res["r"], 16), int(res["s"], 16), res["yParity"]), info["result"]["address"])
        self.assertIn("8004000020" + digest.hex(), calls)

    def test_eth2_echoed_pubkey_mismatch_is_verify_failed(self):
        from ecdsa import SigningKey, SECP256k1
        other = SigningKey.from_secret_exponent(0x7654321, curve=SECP256k1)
        self._install_fake({host.AID_ETH_V2}, self.key, eth2_format="rspub", eth2_echo_key=other)
        host.handle({"id": 1, "method": "info"})
        resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "11" * 32}})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "VERIFY_FAILED")

    def test_eth2_parse_rejects_garbage(self):
        with self.assertRaises(host.HostError) as ctx:
            host.parse_eth2_signature(b"\x00" * 40)
        self.assertEqual(ctx.exception.code, "CARD_ERROR")

    def test_no_applet_error_code(self):
        self._install_fake(set(), self.key)
        resp = host.handle({"id": 1, "method": "info"})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "NO_APPLET")

    def test_missing_nuri_pcsc_is_card_error(self):
        sys.modules.pop("nuri_pcsc", None)
        if os.path.exists(os.path.join(os.path.dirname(HERE), "scripts", "nuri_pcsc.py")):
            self.skipTest("nuri_pcsc.py present on this branch")
        resp = host.handle({"id": 1, "method": "info"})
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "CARD_ERROR")
        self.assertIn("nuri_pcsc", resp["error"]["message"])

    # -- W21: PIN flow ------------------------------------------------------
    def _pin_card(self, **kw):
        calls = self._install_fake({host.AID_ETH_V1, host.AID_ETH_V2}, self.key, eth2_format="rspub",
                                   pin=b"123456", **kw)
        info = host.handle({"id": 1, "method": "info"})
        self.assertTrue(info["ok"], info)
        return calls, info["result"]

    def _vp(self, pin, digest, address, req_id=5):
        req = {"id": req_id, "method": "verify_pin", "params": {"pin": pin, "hash": "0x" + digest.hex(), "address": address}}
        resp = host.handle(req)
        self.assertNotIn("pin", req["params"], "request params must be scrubbed")
        self.assertNotIn(pin, json.dumps(resp), "PIN echoed in response")
        return resp

    def test_info_reports_pin_state(self):
        _, info = self._pin_card(tries=4)
        self.assertEqual(info["applet"], "eth2")
        self.assertIs(info["pin_set"], True)
        self.assertEqual(info["pin_tries_left"], 4)
        self.assertAllClosed()

    def test_sign_hash_on_pin_eth2_is_pin_required_and_sends_no_sign(self):
        calls, _ = self._pin_card()
        resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "11" * 32}})
        self.assertEqual(resp["error"]["code"], "PIN_REQUIRED")
        self.assertFalse(any(c.startswith("80040000") for c in calls))
        self.assertAllClosed()

    def test_verify_pin_signs_in_same_session(self):
        calls, info = self._pin_card()
        before = len(self.card.opened)
        digest = hashlib.sha256(b"approved tx").digest()
        resp = self._vp("123456", digest, info["address"])
        self.assertTrue(resp["ok"], resp)
        res = resp["result"]
        self.assertEqual(set(res), {"r", "s", "yParity", "signature"})
        self.assertEqual(recover_address(digest, int(res["r"], 16), int(res["s"], 16), res["yParity"]), info["address"])
        self.assertEqual(len(self.card.opened), before + 1, "VERIFY_PIN and SIGN must share one session")
        tail = calls[-4:]
        self.assertEqual(tail, ["8001000000", "8002000000", "80200000<pin>", "8004000020" + digest.hex()])
        self.assertAllClosed()
        # validation is not cached: the next plain sign_hash is refused again
        self.assertEqual(host.handle({"id": 6, "method": "sign_hash", "params": {"hash": "0x" + digest.hex()}})["error"]["code"],
                         "PIN_REQUIRED")

    def test_wrong_pin_maps_tries_then_blocked(self):
        _, info = self._pin_card(tries=3)
        digest = b"\x55" * 32
        r1 = self._vp("000000", digest, info["address"])
        self.assertEqual(r1["error"]["code"], "PIN_WRONG")
        self.assertEqual(r1["error"]["tries_left"], 2)
        r2 = self._vp("000000", digest, info["address"])
        self.assertEqual((r2["error"]["code"], r2["error"]["tries_left"]), ("PIN_WRONG", 1))
        r3 = self._vp("000000", digest, info["address"])
        self.assertEqual((r3["error"]["code"], r3["error"]["tries_left"]), ("PIN_BLOCKED", 0))
        r4 = self._vp("123456", digest, info["address"])
        self.assertEqual(r4["error"]["code"], "PIN_BLOCKED")
        self.assertAllClosed()

    def test_wrong_then_correct_resets_tries(self):
        _, info = self._pin_card()
        digest = b"\x56" * 32
        self.assertEqual(self._vp("999999", digest, info["address"])["error"]["tries_left"], 4)
        self.assertTrue(self._vp("123456", digest, info["address"])["ok"])
        self.assertEqual(self.card.tries, 5)

    def test_sw_mapping(self):
        for sw, code, left in ((0x6982, "PIN_REQUIRED", None), (0x6983, "PIN_BLOCKED", 0),
                               (0x63C2, "PIN_WRONG", 2), (0x63C0, "PIN_WRONG", 0), (0x6A80, "CARD_ERROR", None)):
            with self.assertRaises(host.HostError) as ctx:
                host._check_sw(sw, "VERIFY PIN")
            self.assertEqual(ctx.exception.code, code, hex(sw))
            self.assertEqual(ctx.exception.extra.get("tries_left"), left, hex(sw))
        host._check_sw(0x9000, "x")

    def test_verify_pin_param_validation(self):
        _, info = self._pin_card()
        addr = info["address"]
        bad = [
            {"pin": "12", "hash": "0x" + "11" * 32, "address": addr},
            {"pin": 123456, "hash": "0x" + "11" * 32, "address": addr},
            {"pin": "123456", "hash": "11" * 32, "address": addr},
            {"pin": "123456", "hash": "0x" + "11" * 31, "address": addr},
            {"pin": "123456", "hash": "0x" + "11" * 32, "address": addr.lower()},
            {"pin": "123456", "hash": "0x" + "11" * 32},
        ]
        for params in bad:
            resp = host.handle({"id": 9, "method": "verify_pin", "params": params})
            self.assertEqual(resp["error"]["code"], "BAD_REQUEST", params)
            self.assertNotIn("pin", params)
        self.assertEqual(self.card.tries, 5, "no VERIFY_PIN APDU may be sent for a bad request")

    def test_verify_pin_address_mismatch(self):
        from ecdsa import SigningKey, SECP256k1
        _, info = self._pin_card()
        other = host.pubkey_to_address(SigningKey.from_secret_exponent(99, curve=SECP256k1).get_verifying_key().to_string("compressed"))
        resp = self._vp("123456", b"\x01" * 32, other)
        self.assertEqual(resp["error"]["code"], "ADDRESS_MISMATCH")
        self.assertEqual(self.card.tries, 5)

    def test_card_swap_is_refused_before_pin_or_sign(self):
        from ecdsa import SigningKey, SECP256k1
        calls, info = self._pin_card()
        self.card.key = SigningKey.from_secret_exponent(0xBEEF, curve=SECP256k1)  # different card in the reader
        resp = self._vp("123456", b"\x02" * 32, info["address"])
        self.assertEqual(resp["error"]["code"], "CARD_CHANGED")
        self.assertNotIn("80200000<pin>", calls)
        self.assertAllClosed()
        # session state cleared: a new info is required before any sign
        resp = host.handle({"id": 7, "method": "sign_hash", "params": {"hash": "0x" + "02" * 32}})
        self.assertEqual(resp["error"]["code"], "INFO_REQUIRED")

    def test_card_swap_on_eth1_sign_hash(self):
        from ecdsa import SigningKey, SECP256k1
        calls = self._install_fake({host.AID_ETH_V1}, self.key)
        host.handle({"id": 1, "method": "info"})
        self.card.key = SigningKey.from_secret_exponent(0xBEEF, curve=SECP256k1)
        resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "03" * 32}})
        self.assertEqual(resp["error"]["code"], "CARD_CHANGED")
        self.assertFalse(any(c.startswith("80040000") for c in calls))

    def test_applet_swap_eth2_to_eth1_refused(self):
        self._install_fake({host.AID_ETH_V1, host.AID_ETH_V2}, self.key, eth2_format="rspub")
        host.handle({"id": 1, "method": "info"})
        self.card.applets = {host.AID_ETH_V1}  # same key, but only the unprotected v1 is there now
        resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "04" * 32}})
        self.assertEqual(resp["error"]["code"], "CARD_CHANGED")

    def test_verify_pin_on_eth1_is_pin_not_set(self):
        self._install_fake({host.AID_ETH_V1}, self.key)
        info = host.handle({"id": 1, "method": "info"})["result"]
        self.assertIs(info["pin_set"], False)
        self.assertIsNone(info["pin_tries_left"])
        resp = self._vp("123456", b"\x05" * 32, info["address"])
        self.assertEqual(resp["error"]["code"], "PIN_NOT_SET")
        self.assertAllClosed()

    def test_unexpected_error_closes_wipes_and_hides_message(self):
        _, info = self._pin_card()
        captured = []
        real_wipe = host._wipe

        def spy(buf):
            if isinstance(buf, bytearray):
                captured.append(buf)
            real_wipe(buf)
        host._wipe = spy
        try:
            self.card.fail_transmit = (0x20, RuntimeError("transport died with apdu 80200000063132333435 / 123456"))
            req = {"id": 5, "method": "verify_pin", "params": {"pin": "123456", "hash": "0x" + "06" * 32, "address": info["address"]}}
            resp = host.handle(req)
        finally:
            host._wipe = real_wipe
        self.assertEqual(resp["error"]["code"], "CARD_ERROR")
        self.assertNotIn("123456", json.dumps(resp))
        self.assertNotIn("3132333435", json.dumps(resp))
        self.assertNotIn("pin", req["params"])
        self.assertAllClosed()
        self.assertTrue(captured, "PIN/APDU buffers were not wiped")
        self.assertTrue(all(not any(b) for b in captured), "a buffer still holds non-zero bytes")

    def test_sign_hash_without_info_refused(self):
        self._install_fake({host.AID_ETH_V1}, self.key)
        resp = host.handle({"id": 1, "method": "sign_hash", "params": {"hash": "0x" + "07" * 32}})
        self.assertEqual(resp["error"]["code"], "INFO_REQUIRED")

    def test_failed_info_revokes_signing(self):
        calls = self._install_fake({host.AID_ETH_V1}, self.key)
        self.assertTrue(host.handle({"id": 1, "method": "info"})["ok"])
        self.card.applets = set()
        self.assertEqual(host.handle({"id": 2, "method": "info"})["error"]["code"], "NO_APPLET")
        self.card.applets = {host.AID_ETH_V1}
        self.assertEqual(host.handle({"id": 3, "method": "sign_hash", "params": {"hash": "0x" + "08" * 32}})["error"]["code"],
                         "INFO_REQUIRED")

    def test_unknown_pcsc_code_is_card_error_not_sim(self):
        self._install_fake({host.AID_ETH_V1}, self.key)
        mod = sys.modules["nuri_pcsc"]

        def boom(aid_hex, reader=None):
            raise mod.CardError("TRANSPORT", "bus error")
        mod.open_applet = boom
        resp = host.handle({"id": 1, "method": "info"})
        self.assertEqual(resp["error"]["code"], "CARD_ERROR")
        self.assertIsNone(host._INFO)


class SimGateTests(unittest.TestCase):
    """Sim must be explicit: env exactly "1" AND a successful sim info in this process."""

    def setUp(self):
        self.saved_env = os.environ.pop("NURI_CARD_SIM", None)
        reset_host()

    def tearDown(self):
        reset_host()
        os.environ.pop("NURI_CARD_SIM", None)
        if self.saved_env is not None:
            os.environ["NURI_CARD_SIM"] = self.saved_env

    def test_sim_sign_without_info_refused(self):
        os.environ["NURI_CARD_SIM"] = "1"
        host._SIGNER = host.SimSigner()  # even a pre-built sim signer is not authorization
        resp = host.handle({"id": 1, "method": "sign_hash", "params": {"hash": "0x" + "11" * 32}})
        self.assertEqual(resp["error"]["code"], "INFO_REQUIRED")

    def test_env_removed_after_info_refuses(self):
        os.environ["NURI_CARD_SIM"] = "1"
        self.assertTrue(host.handle({"id": 1, "method": "info"})["ok"])
        os.environ.pop("NURI_CARD_SIM")
        sys.modules["nuri_pcsc"] = None  # card mode import must fail, not fall back
        try:
            resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "11" * 32}})
        finally:
            sys.modules.pop("nuri_pcsc", None)
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "INFO_REQUIRED")

    def test_ack_flag_required(self):
        os.environ["NURI_CARD_SIM"] = "1"
        self.assertTrue(host.handle({"id": 1, "method": "info"})["ok"])
        host._SIM_ACK = False
        resp = host.handle({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "11" * 32}})
        self.assertEqual(resp["error"]["code"], "SIM_NOT_AUTHORIZED")

    def test_non_exact_env_values_fail_closed(self):
        for val in ("true", "yes", "1 ", " 1", "01", "2"):
            os.environ["NURI_CARD_SIM"] = val
            reset_host()
            resp = host.handle({"id": 1, "method": "info"})
            self.assertEqual(resp["error"]["code"], "CONFIG_ERROR", val)
            self.assertIsNone(host._INFO)

    def test_sim_flag_without_env_does_not_authorize(self):
        host._SIM_FLAG = True
        resp = host.handle({"id": 1, "method": "info"})
        self.assertEqual(resp["error"]["code"], "CONFIG_ERROR")
        self.assertNotIn("NURI_CARD_SIM", os.environ)

    def test_verify_pin_in_sim_is_pin_not_set(self):
        os.environ["NURI_CARD_SIM"] = "1"
        info = host.handle({"id": 1, "method": "info"})["result"]
        resp = host.handle({"id": 2, "method": "verify_pin", "params": {"pin": "123456", "hash": "0x" + "11" * 32, "address": info["address"]}})
        self.assertEqual(resp["error"]["code"], "PIN_NOT_SET")

    def test_subprocess_sim_flag_alone_refused(self):
        env = {k: v for k, v in os.environ.items() if k != "NURI_CARD_SIM"}
        proc = subprocess.run([sys.executable, os.path.join(HERE, "nuri_card_host.py"), "--sim", "chrome-extension://test/"],
                              input=frame({"id": 1, "method": "info"}) + frame({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "ab" * 32}}),
                              capture_output=True, env=env, timeout=30)
        msgs = unframe_all(proc.stdout)
        self.assertEqual([m["error"]["code"] for m in msgs], ["CONFIG_ERROR", "CONFIG_ERROR"])


class FramingTests(unittest.TestCase):
    def setUp(self):
        self.saved_env = os.environ.get("NURI_CARD_SIM")
        os.environ["NURI_CARD_SIM"] = "1"
        reset_host()

    def tearDown(self):
        reset_host()
        if self.saved_env is None:
            os.environ.pop("NURI_CARD_SIM", None)
        else:
            os.environ["NURI_CARD_SIM"] = self.saved_env

    def test_timeout_configuration_cannot_disable_the_read_deadline(self):
        from unittest.mock import patch
        for value in ("inf", "nan", "0", "-1", "999999", "invalid"):
            with self.subTest(value=value), patch.dict(os.environ, {"NURI_CARD_HOST_FRAME_TIMEOUT": value}):
                self.assertEqual(host.frame_timeout_from_env(), host.DEFAULT_FRAME_TIMEOUT)
        with patch.dict(os.environ, {"NURI_CARD_HOST_FRAME_TIMEOUT": "0.1"}):
            self.assertEqual(host.frame_timeout_from_env(), 0.1)

    def test_serve_in_process(self):
        stdin = io.BytesIO(frame({"id": 1, "method": "info"}) + frame({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "00" * 32}}) + frame({"id": 3, "method": "x"}))
        stdout = io.BytesIO()
        host.serve(stdin, stdout)
        msgs = unframe_all(stdout.getvalue())
        self.assertEqual([m["id"] for m in msgs], [1, 2, 3])
        self.assertTrue(msgs[0]["ok"] and msgs[1]["ok"] and not msgs[2]["ok"])

    # -- framing hardening (W13 R11) -------------------------------------- #

    def _serve_bytes(self, data: bytes, **kw):
        host._SIGNER = None
        stdout = io.BytesIO()
        rc = host.serve(io.BytesIO(data), stdout, **kw)
        return rc, unframe_all(stdout.getvalue())

    TRAILER = frame({"id": 99, "method": "info"})  # must never be answered after a framing error

    def _assert_closed(self, data: bytes, needle: str):
        rc, msgs = self._serve_bytes(data + self.TRAILER)
        self.assertEqual(rc, 1, msgs)
        self.assertEqual(len(msgs), 1, msgs)
        self.assertFalse(msgs[0]["ok"])
        self.assertIsNone(msgs[0]["id"])
        self.assertEqual(msgs[0]["error"]["code"], "BAD_REQUEST")
        self.assertIn(needle, msgs[0]["error"]["message"])
        self.assertNotIn(99, [m["id"] for m in msgs])

    def test_oversized_length_closes_without_reading_trailer(self):
        self._assert_closed(struct.pack("<I", host.MAX_MESSAGE_BYTES + 1), "too large")
        self._assert_closed(struct.pack("<I", 0xFFFFFFFF), "too large")

    def test_oversized_with_embedded_frame_in_body_is_not_parsed(self):
        # The old host kept framing at offset 4, i.e. inside the rejected body.
        smuggled = frame({"id": 42, "method": "sign_hash", "params": {"hash": "0x" + "00" * 32}})
        rc, msgs = self._serve_bytes(struct.pack("<I", host.MAX_MESSAGE_BYTES + 1) + smuggled)
        self.assertEqual(rc, 1)
        self.assertEqual([m["id"] for m in msgs], [None])

    def test_exactly_max_size_is_accepted(self):
        head = b'{"id":5,"method":"info","pad":"'
        tail = b'"}'
        body = head + b"x" * (host.MAX_MESSAGE_BYTES - len(head) - len(tail)) + tail
        self.assertEqual(len(body), host.MAX_MESSAGE_BYTES)
        rc, msgs = self._serve_bytes(struct.pack("<I", len(body)) + body + self.TRAILER)
        self.assertEqual(rc, 0)
        self.assertEqual([m["id"] for m in msgs], [5, 99])
        self.assertTrue(msgs[0]["ok"], msgs[0])

    def test_zero_length_closes(self):
        self._assert_closed(struct.pack("<I", 0), "length 0")

    def test_invalid_json_closes(self):
        bad = b"{not json"
        self._assert_closed(struct.pack("<I", len(bad)) + bad, "invalid JSON")

    def test_invalid_utf8_closes(self):
        bad = b'{"id":1,"method":"\xff\xfe"}'
        self._assert_closed(struct.pack("<I", len(bad)) + bad, "UTF-8")

    def test_deeply_nested_json_recursion_closes(self):
        bad = b"[" * 200000 + b"]" * 200000
        self.assertLess(len(bad), host.MAX_MESSAGE_BYTES)
        self._assert_closed(struct.pack("<I", len(bad)) + bad, "nested too deeply")
        bad_obj = b'{"a":' * 150000 + b"1" + b"}" * 150000
        self._assert_closed(struct.pack("<I", len(bad_obj)) + bad_obj, "nested too deeply")

    def test_huge_integer_literal_closes(self):
        bad = b'{"id":' + b"9" * 50000 + b',"method":"info"}'
        self._assert_closed(struct.pack("<I", len(bad)) + bad, "invalid JSON")

    def test_truncated_header_after_valid_frame(self):
        rc, msgs = self._serve_bytes(frame({"id": 1, "method": "info"}) + b"\x05\x00")
        self.assertEqual(rc, 1)
        self.assertEqual([m["id"] for m in msgs], [1, None])
        self.assertTrue(msgs[0]["ok"])
        self.assertIn("truncated header", msgs[1]["error"]["message"])

    def test_truncated_body_closes(self):
        body = json.dumps({"id": 1, "method": "info"}).encode()
        rc, msgs = self._serve_bytes(struct.pack("<I", len(body) + 10) + body)
        self.assertEqual(rc, 1)
        self.assertEqual(len(msgs), 1)
        self.assertIn("truncated body", msgs[0]["error"]["message"])

    def test_clean_eof_and_empty_stream(self):
        self.assertEqual(self._serve_bytes(b""), (0, []))
        rc, msgs = self._serve_bytes(frame({"id": 1, "method": "info"}))
        self.assertEqual((rc, [m["id"] for m in msgs]), (0, [1]))

    def test_non_object_json_is_request_error_and_session_continues_with_logging(self):
        with tempfile.TemporaryDirectory() as d:
            log_path = os.path.join(d, "host.log")
            old = os.environ.get("NURI_CARD_HOST_LOG")
            os.environ["NURI_CARD_HOST_LOG"] = log_path
            try:
                rc, msgs = self._serve_bytes(
                    frame([1, 2]) + frame("str") + frame(None) + frame(7)
                    + frame({"id": {"x": 1}, "method": ["m"], "params": {"hash": "0x" + "ab" * 32}})
                    + frame({"id": 7, "method": "info"})  # W21 R8: signing requires info on this connection
                    + frame({"id": 8, "method": "sign_hash", "params": {"hash": "0x" + "ab" * 32}})
                )
            finally:
                if old is None:
                    os.environ.pop("NURI_CARD_HOST_LOG", None)
                else:
                    os.environ["NURI_CARD_HOST_LOG"] = old
            with open(log_path) as fh:
                lines = [json.loads(line) for line in fh]
        self.assertEqual(rc, 0)
        self.assertEqual(len(msgs), 7)
        for m in msgs[:5]:
            self.assertEqual(m["error"]["code"], "BAD_REQUEST", m)
        self.assertTrue(msgs[5]["ok"], msgs[5])
        self.assertTrue(msgs[6]["ok"], msgs[6])
        self.assertEqual(len(lines), 7)
        self.assertEqual(lines[0]["invalid"], "list")
        self.assertEqual(lines[4]["request"], {"id": None, "method": None})
        self.assertEqual(lines[6]["request"], {"id": 8, "method": "sign_hash"})
        self.assertNotIn("ab" * 32, json.dumps(lines))  # params never logged

    def _spawn(self, timeout="0.5"):
        env = dict(os.environ, NURI_CARD_SIM="1", NURI_CARD_HOST_FRAME_TIMEOUT=timeout)
        env.pop("NURI_CARD_HOST_LOG", None)
        return subprocess.Popen(
            [sys.executable, os.path.join(HERE, "nuri_card_host.py"), "chrome-extension://test/"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )

    def test_subprocess_oversized_then_valid_exits_1_without_answering(self):
        proc = self._spawn()
        out, err = proc.communicate(struct.pack("<I", host.MAX_MESSAGE_BYTES + 1) + self.TRAILER, timeout=30)
        self.assertEqual(proc.returncode, 1, err.decode())
        msgs = unframe_all(out)
        self.assertEqual(len(msgs), 1)
        self.assertIn("too large", msgs[0]["error"]["message"])
        self.assertEqual(err, b"")  # no traceback

    def test_subprocess_deep_nesting_exits_1_no_traceback(self):
        bad = b"[" * 300000 + b"]" * 300000
        proc = self._spawn()
        out, err = proc.communicate(struct.pack("<I", len(bad)) + bad + self.TRAILER, timeout=30)
        self.assertEqual(proc.returncode, 1, err.decode())
        self.assertEqual(len(unframe_all(out)), 1)
        self.assertEqual(err, b"")

    def test_subprocess_stalled_frame_hits_deadline(self):
        for partial in (b"\x10", frame({"id": 1, "method": "info"})[:-3]):
            proc = self._spawn("0.5")
            proc.stdin.write(partial)
            proc.stdin.flush()  # pipe stays open: a stalled sender, not EOF
            t0 = time.monotonic()
            try:
                rc = proc.wait(timeout=10)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
            elapsed = time.monotonic() - t0
            out = proc.stdout.read()
            proc.stdin.close(); proc.stdout.close(); proc.stderr.close()
            self.assertEqual(rc, 1)
            self.assertLess(elapsed, 5)
            msgs = unframe_all(out)
            self.assertEqual(len(msgs), 1)
            self.assertIn("stalled", msgs[0]["error"]["message"])

    def test_subprocess_idle_host_is_not_timed_out(self):
        proc = self._spawn("0.3")
        try:
            time.sleep(1.2)  # idle 4x the frame deadline before the first byte
            self.assertIsNone(proc.poll(), "idle host must keep waiting for a request")
            body = frame({"id": 1, "method": "info"})
            proc.stdin.write(body[:2]); proc.stdin.flush()
            time.sleep(0.05)  # split frame, completed well within the deadline
            proc.stdin.write(body[2:] + frame({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "cd" * 32}}))
            proc.stdin.flush()
            time.sleep(1.0)  # idle again between frames
            self.assertIsNone(proc.poll())
            out, err = proc.communicate(frame({"id": 3, "method": "info"}), timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.assertEqual(proc.returncode, 0, err.decode())
        msgs = unframe_all(out)
        self.assertEqual([m["id"] for m in msgs], [1, 2, 3])
        self.assertTrue(all(m["ok"] for m in msgs), msgs)

    def test_subprocess_round_trip(self):
        env = dict(os.environ, NURI_CARD_SIM="1")
        proc = subprocess.run(
            [sys.executable, os.path.join(HERE, "nuri_card_host.py"), "chrome-extension://test/"],
            input=frame({"id": 1, "method": "info"}) + frame({"id": 2, "method": "sign_hash", "params": {"hash": "0x" + "ab" * 32}}),
            capture_output=True, env=env, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        msgs = unframe_all(proc.stdout)
        self.assertEqual(len(msgs), 2)
        self.assertEqual(msgs[0]["result"]["pubkey"], SIM_PUBKEY)
        self.assertTrue(msgs[1]["ok"], msgs[1])
        res = msgs[1]["result"]
        self.assertEqual(recover_address(bytes.fromhex("ab" * 32), int(res["r"], 16), int(res["s"], 16), res["yParity"]),
                         msgs[0]["result"]["address"])

    def test_log_never_contains_pin_or_params(self):
        tmp = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        try:
            log_path = os.path.join(tmp, "host.log")
            env = dict(os.environ, NURI_CARD_SIM="1", NURI_CARD_HOST_LOG=log_path)
            info_addr = host.pubkey_to_address(bytes.fromhex(SIM_PUBKEY[2:]))
            secret = "73915042"
            proc = subprocess.run(
                [sys.executable, os.path.join(HERE, "nuri_card_host.py"), "chrome-extension://test/"],
                input=frame({"id": 1, "method": "info"})
                + frame({"id": 2, "method": "verify_pin", "params": {"pin": secret, "hash": "0x" + "ab" * 32, "address": info_addr}})
                + frame({"id": 3, "method": "verify_pin", "params": {"pin": secret, "hash": "bad", "address": info_addr}})
                + frame({"id": 4, "method": "sign_hash", "params": {"hash": "0x" + "ab" * 32}, "pin": secret}),
                capture_output=True, env=env, timeout=30,
            )
            msgs = unframe_all(proc.stdout)
            self.assertEqual([m["id"] for m in msgs], [1, 2, 3, 4])
            self.assertEqual(msgs[1]["error"]["code"], "PIN_NOT_SET")
            self.assertEqual(msgs[2]["error"]["code"], "BAD_REQUEST")
            self.assertTrue(msgs[3]["ok"], msgs[3])
            with open(log_path) as fh:
                log = fh.read()
            self.assertNotIn(secret, log)
            self.assertNotIn(secret, proc.stdout.decode("utf-8", "replace"))
            self.assertNotIn(secret, proc.stderr.decode("utf-8", "replace"))
            self.assertNotIn("params", log)
            self.assertEqual(len(log.strip().splitlines()), 4)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_invalid_json_frame_with_pin_not_echoed(self):
        bad = b'{"id":1,"method":"verify_pin","params":{"pin":"55443322"'
        stdout = io.BytesIO()
        host.serve(io.BytesIO(struct.pack("<I", len(bad)) + bad), stdout)
        out = stdout.getvalue().decode()
        self.assertIn("BAD_REQUEST", out)
        self.assertNotIn("55443322", out)


class InstallerLauncherTests(unittest.TestCase):
    """host/install-macos.sh launcher only (test hook): no venv, pip, manifest or network."""

    def _launcher(self, *args):
        home = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        self.addCleanup(shutil.rmtree, home, True)
        env = dict(os.environ, HOME=home, NURI_HOST_INSTALL_LAUNCHER_ONLY="1")
        proc = subprocess.run(["bash", os.path.join(HERE, "install-macos.sh"), *args], env=env,
                              capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertFalse(os.path.exists(os.path.join(home, "Library")), "launcher-only must not write the manifest")
        with open(os.path.join(home, ".nuri-card-host", "run.sh")) as fh:
            return fh.read()

    def test_normal_launcher_never_enables_sim(self):
        text = self._launcher()
        self.assertIn("unset NURI_CARD_SIM", text)
        self.assertNotIn("NURI_CARD_SIM=1", text)
        self.assertNotIn("--sim", text)

    def test_installed_snapshot_packages_attestation_verifier_and_checksums_offline(self):
        # Fake only the dependency installer. Exercise actual copying, checksums,
        # manifest and native SIM framing with our already-approved interpreter.
        with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as home:
            from pathlib import Path
            venv = Path(home) / ".nuri-card-host-venv" / "bin"
            venv.mkdir(parents=True)
            import shlex
            (venv / "python").write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + ' "$@"\n')
            (venv / "python").chmod(0o700)
            (venv / "pip").write_text("#!/bin/sh\nexit 0\n")
            (venv / "pip").chmod(0o700)
            env = dict(os.environ, HOME=home, NURI_CARD_HOST_LOG="", NURI_CARD_CA_PUBKEY="")
            env.pop("NURI_HOST_INSTALL_LAUNCHER_ONLY", None)
            proc = subprocess.run(["bash", os.path.join(HERE, "install-macos.sh"), "--sim", "--python", sys.executable],
                                  env=env, capture_output=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr.decode())
            self.assertIn(b'"attestation":{"verified":false,"reason":"unverified"}', proc.stdout)
            installed = Path(home) / ".nuri-card-host"
            with (installed / "run.sh").open() as stream:
                self.assertIn(str(installed / "host" / "nuri_card_host.py"), stream.read())
            with (Path(home) / "Library/Application Support/Google/Chrome/NativeMessagingHosts/com.nuri.card.json").open() as stream:
                manifest = json.load(stream)
            self.assertEqual(manifest["path"], str(installed / "run.sh"))
            expected = {"host/nuri_card_host.py", "scripts/nuri_pcsc.py", "scripts/nuri_attest.py"}
            with (installed / "SHA256SUMS").open() as stream:
                checksums = dict((parts[1], parts[0]) for parts in (line.split() for line in stream))
            self.assertEqual(set(checksums), expected)
            repo = Path(HERE).parent
            for name in expected:
                with (installed / name).open("rb") as stream:
                    copied = stream.read()
                with (repo / name).open("rb") as stream:
                    self.assertEqual(copied, stream.read(), name)
                self.assertEqual(hashlib.sha256(copied).hexdigest(), checksums[name])
            # -I removes cwd/PYTHONPATH: verifier must really import from the
            # installed scripts directory, not quietly fall back to the repo.
            probe = subprocess.run([sys.executable, "-I", "-c",
                                    "import sys; sys.path.insert(0, sys.argv[1]); import nuri_attest; print(nuri_attest.__file__)",
                                    str(installed / "scripts")], cwd=home, env=env, capture_output=True, timeout=30)
            self.assertEqual(probe.returncode, 0, probe.stderr.decode())
            self.assertEqual(probe.stdout.decode().strip(), str(installed / "scripts/nuri_attest.py"))

    def test_sim_launcher_exports_explicitly(self):
        text = self._launcher("--sim")
        self.assertIn("export NURI_CARD_SIM=1", text)
        self.assertIn('nuri_card_host.py" --sim', text)
        self.assertNotIn("unset NURI_CARD_SIM", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
