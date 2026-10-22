#!/usr/bin/env python3
"""Offline cryptographic, freshness, personalization and CLI tests. NO hardware."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from ecdsa import NIST256p, SECP256k1, SigningKey
from ecdsa.util import sigencode_der

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import nuri_attest as att

spec = importlib.util.spec_from_file_location("attest_card_cli", ROOT / "scripts/attest-card.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def sign(key, message):
    return key.sign_deterministic(message, hashfunc=hashlib.sha256, sigencode=sigencode_der)


def encode_info(info):
    return (b"\x01" + info["card_id"] + bytes([len(info["aid"])]) + info["aid"]
            + info["attestation_pub"] + bytes([info["sealed"], len(info["cert"])]) + info["cert"])


class Evidence:
    def __init__(self, aid=att.ETH2_AID):
        self.ca = SigningKey.generate(curve=NIST256p)
        self.device = SigningKey.generate(curve=NIST256p)
        curve = NIST256p if aid == att.VAULT_AID else SECP256k1
        self.wallet = SigningKey.generate(curve=curve)
        self.pub = self.wallet.verifying_key.to_string("uncompressed" if curve == NIST256p else "compressed")
        self.info = dict(card_id=os.urandom(16), aid=aid,
                         attestation_pub=self.device.verifying_key.to_string("uncompressed"),
                         sealed=True, cert=b"")
        self.info["cert"] = sign(self.ca, att.ca_message(self.info))
        self.challenge = os.urandom(32)

    def response(self, challenge=None, info=None, pub=None, pin_state=7, binding=None, response_sig=None):
        challenge = self.challenge if challenge is None else challenge
        info = self.info if info is None else info
        pub = self.pub if pub is None else pub
        if response_sig is None:
            response_sig = sign(self.device, att.RESPONSE_DOMAIN + challenge + pub + bytes([pin_state]))
        if binding is None:
            binding = sign(self.device, att.BINDING_DOMAIN + info["aid"] + pub)
        return (encode_info(info) + bytes([len(pub)]) + pub + bytes([pin_state, len(response_sig)])
                + response_sig + bytes([len(binding)]) + binding)

    def verify(self, response=None, **kwargs):
        args = dict(response=self.response() if response is None else response,
                    ca_pubkey=self.ca.verifying_key, challenge=self.challenge,
                    expected_aid=self.info["aid"], expected_signing_pub=self.pub)
        args.update(kwargs)
        return att.verify_response(**args)


class FakeCard:
    def __init__(self, info, bad_cert=False, bad_seal=False, fail_store=False):
        self.info, self.calls = dict(info), []
        self.bad_cert, self.bad_seal, self.fail_store = bad_cert, bad_seal, fail_store
        self.closed = False

    def transmit(self, apdu):
        self.calls.append(apdu)
        cla, ins, p1, p2, length = apdu[:5]
        assert cla == (0 if self.info["aid"] == att.MUSIG2_AID else 0x80)
        assert p1 == p2 == 0
        assert len(apdu) == 5 + length
        if ins == 0x70:
            return encode_info(self.info), 0x9000
        if ins == 0x71:
            if self.fail_store:
                return b"", 0x6985
            assert not self.info["cert"] and not self.info["sealed"]
            if not self.bad_cert:
                self.info["cert"] = apdu[5:]
            return b"", 0x9000
        if ins == 0x73:
            assert self.info["cert"]
            if not self.bad_seal:
                self.info["sealed"] = True
            return b"", 0x9000
        raise AssertionError(f"unexpected instruction {ins:02x}")

    def close(self):
        self.closed = True


class PagedCard:
    """Short case-4 wire fake; signing happens only for page 1's challenge."""
    def __init__(self, evidence, fail_page=None, tail_challenge=None):
        self.evidence = evidence
        self.fail_page, self.tail_challenge = fail_page, tail_challenge
        self.calls, self.pages, self.closed = [], [], False

    def transmit(self, apdu):
        assert not self.closed
        raw = bytes(apdu)
        self.calls.append(raw)
        cla = 0 if self.evidence.info["aid"] == att.MUSIG2_AID else 0x80
        assert len(raw) == 38 and raw[:2] == bytes([cla, 0x72])
        assert raw[2] in (0, 1) and raw[3:5] == b"\x00\x20" and raw[-1] == 0
        page = raw[2]
        if page == self.fail_page:
            return b"", 0x6985
        info = encode_info(self.evidence.info)
        if page == 0:
            response = info
        else:
            logical = self.evidence.response(challenge=self.tail_challenge or raw[5:37])
            response = logical[len(info):]
        self.pages.append(response)
        return response, 0x9000

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class PagedTransportTests(unittest.TestCase):
    def test_two_short_pages_preserve_logical_bytes_for_every_applet(self):
        for aid in (att.ETH2_AID, att.MUSIG2_AID, att.VAULT_AID):
            with self.subTest(aid=aid.hex()):
                e = Evidence(aid)
                card = PagedCard(e)
                raw = att.read_attestation(card, 0 if aid == att.MUSIG2_AID else 0x80, e.challenge)
                self.assertEqual(raw, e.response())
                self.assertEqual(e.verify(raw)["signing_pub"], e.pub)
                self.assertEqual([c[2] for c in card.calls], [0, 1])
                self.assertEqual([c[5:37] for c in card.calls], [e.challenge, e.challenge])
                self.assertLessEqual(len(card.pages[0]), 170)
                self.assertLessEqual(len(card.pages[1]), 214)
                self.assertGreater(len(raw), 256, "logical evidence is not one short response")
                self.assertFalse(card.closed, "the caller owns the session")

    def test_page1_different_challenge_fails_original_challenge_verification(self):
        e = Evidence()
        other_challenge = bytes([e.challenge[0] ^ 1]) + e.challenge[1:]
        card = PagedCard(e, tail_challenge=other_challenge)
        raw = att.read_attestation(card, 0x80, e.challenge)
        with self.assertRaisesRegex(att.VerificationError, "response signature"):
            e.verify(raw)
        self.assertEqual([c[5:37] for c in card.calls], [e.challenge, e.challenge])

    def test_status_on_either_page_rejects_without_retry_or_partial_result(self):
        for page in (0, 1):
            with self.subTest(page=page):
                e = Evidence()
                card = PagedCard(e, fail_page=page)
                with self.assertRaises(att.AttestationCommandError) as error:
                    att.read_attestation(card, 0x80, e.challenge)
                self.assertEqual((error.exception.page, error.exception.sw), (page, 0x6985))
                self.assertEqual([c[2] for c in card.calls], list(range(page + 1)))

    def test_invalid_challenge_or_cla_never_transmits(self):
        e = Evidence()
        card = PagedCard(e)
        for challenge in (b"", b"x" * 31, b"x" * 33, bytearray(32), "x" * 32):
            with self.assertRaisesRegex(att.VerificationError, "32 bytes"):
                att.read_attestation(card, 0x80, challenge)
        with self.assertRaisesRegex(att.VerificationError, "CLA"):
            att.read_attestation(card, 1, e.challenge)
        self.assertEqual(card.calls, [])

    def test_empty_oversized_truncated_or_cross_boundary_pages_rejected(self):
        e = Evidence()
        info = encode_info(e.info)
        tail = e.response()[len(info):]
        cases = ((b"", tail), (b"x" * 171, tail), (info + b"x", tail),
                 (info[:-1], tail), (info, b""), (info, b"x" * 215),
                 (info, tail[:-1]), (info, tail + b"x"))
        for pages in cases:
            with self.subTest(lengths=[len(p) for p in pages]):
                card = mock.Mock()
                card.transmit.side_effect = [(page, 0x9000) for page in pages]
                with self.assertRaises(att.VerificationError):
                    att.read_attestation(card, 0x80, e.challenge)

    def test_swapped_page1_identity_cannot_verify_with_page0_key(self):
        e, other = Evidence(), Evidence()
        card = mock.Mock()
        card.transmit.side_effect = [(encode_info(e.info), 0x9000),
                                    (other.response(challenge=e.challenge)[len(encode_info(other.info)):], 0x9000)]
        raw = att.read_attestation(card, 0x80, e.challenge)
        with self.assertRaisesRegex(att.VerificationError, "response signature"):
            e.verify(raw, expected_signing_pub=other.pub)


class AttestationTests(unittest.TestCase):
    def setUp(self):
        self.e = Evidence()

    def test_valid_each_applet_and_pin_format(self):
        for aid in (att.ETH2_AID, att.MUSIG2_AID, att.VAULT_AID):
            e = Evidence(aid)
            with self.subTest(aid=aid.hex()):
                parsed = e.verify()
                self.assertEqual(parsed["signing_pub"], e.pub)
                self.assertTrue(parsed["sealed"])
                for pin in (e.ca.verifying_key.to_pem(),
                            e.ca.verifying_key.to_string("uncompressed"),
                            e.ca.verifying_key.to_string("uncompressed").hex()):
                    self.assertEqual(e.verify(ca_pubkey=pin)["cert"], e.info["cert"])

    def test_parse_unpersonalized_info(self):
        info = dict(self.e.info, cert=b"", sealed=False)
        self.assertEqual(att.parse_info(encode_info(info))["cert"], b"")

    def test_missing_or_wrong_ca_pin(self):
        for pin in (None, b"", b"garbage", SigningKey.generate(curve=NIST256p).verifying_key,
                    SigningKey.generate(curve=SECP256k1).verifying_key):
            with self.subTest(pin_type=type(pin).__name__), self.assertRaises(att.VerificationError):
                self.e.verify(ca_pubkey=pin)

    def test_tampered_certificate(self):
        cert = sign(SigningKey.generate(curve=NIST256p), att.ca_message(self.e.info))
        with self.assertRaisesRegex(att.VerificationError, "CA certificate"):
            self.e.verify(self.e.response(info=dict(self.e.info, cert=cert)))

    def test_wrong_challenge(self):
        with self.assertRaisesRegex(att.VerificationError, "response signature"):
            self.e.verify(challenge=os.urandom(32))
        with self.assertRaisesRegex(att.VerificationError, "32 bytes"):
            self.e.verify(challenge=b"short")

    def test_wrong_expected_aid(self):
        with self.assertRaisesRegex(att.VerificationError, "AID mismatch"):
            self.e.verify(expected_aid=att.MUSIG2_AID)

    def test_tampered_aid_even_when_expected_matches(self):
        evidence = self.e.response(info=dict(self.e.info, aid=att.MUSIG2_AID))
        with self.assertRaisesRegex(att.VerificationError, "CA certificate"):
            self.e.verify(evidence, expected_aid=att.MUSIG2_AID)

    def test_wrong_expected_signing_pub(self):
        pub = SigningKey.generate(curve=SECP256k1).verifying_key.to_string("compressed")
        with self.assertRaisesRegex(att.VerificationError, "public key mismatch"):
            self.e.verify(expected_signing_pub=pub)

    def test_wallet_key_substitution_cannot_reuse_binding(self):
        other = SigningKey.generate(curve=SECP256k1).verifying_key.to_string("compressed")
        old_binding = sign(self.e.device, att.BINDING_DOMAIN + self.e.info["aid"] + self.e.pub)
        # A response freshly signed over a substituted key still needs NHWV1.
        evidence = self.e.response(pub=other, binding=old_binding)
        with self.assertRaisesRegex(att.VerificationError, "NHWV1 binding signature"):
            self.e.verify(evidence, expected_signing_pub=other)

    def test_bad_response_signature(self):
        signature = sign(SigningKey.generate(curve=NIST256p), b"unrelated")
        with self.assertRaisesRegex(att.VerificationError, "response signature"):
            self.e.verify(self.e.response(response_sig=signature))

    def test_ca_binds_card_id_and_attestation_key(self):
        for change in (dict(card_id=os.urandom(16)),
                       dict(attestation_pub=SigningKey.generate(curve=NIST256p).verifying_key.to_string("uncompressed"))):
            with self.subTest(field=next(iter(change))), self.assertRaisesRegex(att.VerificationError, "CA certificate"):
                self.e.verify(self.e.response(info=dict(self.e.info, **change)))

    def test_response_authenticates_pin_state(self):
        signature = sign(self.e.device, att.RESPONSE_DOMAIN + self.e.challenge + self.e.pub + b"\x07")
        with self.assertRaisesRegex(att.VerificationError, "response signature"):
            self.e.verify(self.e.response(pin_state=3, response_sig=signature))

    def test_sealed_without_certificate_is_structurally_invalid(self):
        with self.assertRaisesRegex(att.VerificationError, "sealed INFO without certificate"):
            att.parse_info(encode_info(dict(self.e.info, cert=b"", sealed=True)))

    def test_cert_and_seal_required(self):
        for info in (dict(self.e.info, cert=b"", sealed=False), dict(self.e.info, sealed=False)):
            with self.assertRaises(att.VerificationError):
                self.e.verify(self.e.response(info=info))

    def test_binding_required_and_no_key_rejected(self):
        with self.assertRaisesRegex(att.VerificationError, "binding missing"):
            self.e.verify(self.e.response(binding=b""))
        with self.assertRaises(att.VerificationError):
            self.e.verify(self.e.response(pub=b""), expected_signing_pub=b"")

    def test_strict_info_and_response_lengths(self):
        raw = encode_info(self.e.info)
        for data in (b"", b"\x02" + raw[1:], raw + b"x", raw[:17] + b"\xff" + raw[18:],
                     raw[:18 + len(self.e.info["aid"])] + b"\x02" + raw[19 + len(self.e.info["aid"]):]):
            with self.subTest(data=data[:20].hex()), self.assertRaises(att.VerificationError):
                att.parse_info(data)
        response = self.e.response()
        for i in range(len(response)):
            with self.subTest(truncate=i), self.assertRaises(att.VerificationError):
                att.parse_response(response[:i])
        with self.assertRaisesRegex(att.VerificationError, "trailing"):
            self.e.verify(response + b"\x00")

    def test_reserved_flags_noncanonical_keys_and_der(self):
        with self.assertRaisesRegex(att.VerificationError, "PIN state"):
            self.e.verify(self.e.response(pin_state=0x87))
        for cert in (b"\x30\x06\x02\x01\x00\x02\x01\x01", b"\x30\x07\x02\x02\x00\x01\x02\x01\x01"):
            with self.assertRaises(att.VerificationError):
                att.parse_info(encode_info(dict(self.e.info, cert=cert)))
        raw = encode_info(dict(self.e.info, attestation_pub=b"\x04" + b"\0" * 64))
        with self.assertRaisesRegex(att.VerificationError, "public key point"):
            att.parse_info(raw)
        with self.assertRaisesRegex(att.VerificationError, "sealed flag"):
            att.parse_info(encode_info(dict(self.e.info, sealed=2)))


class FreshnessTests(unittest.TestCase):
    def setUp(self):
        self.e = Evidence()
        self.tmp = tempfile.TemporaryDirectory(prefix="attestation-")
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "challenge.json"

    def verify_saved(self, response, **kwargs):
        return att.verify_saved_response(response, self.e.ca.verifying_key, self.state, **kwargs)

    def issue_saved(self, **kwargs):
        return att.issue_challenge(self.state, self.e.info["aid"], self.e.pub, **kwargs)

    def test_in_memory_cryptographic_issuance_and_consume_once(self):
        verifier = att.ChallengeVerifier()
        with mock.patch.object(att.secrets, "token_bytes", wraps=att.secrets.token_bytes) as random:
            challenge = verifier.issue()
        random.assert_called_once_with(32)
        response = self.e.response(challenge=challenge)
        verifier.verify(response, self.e.ca.verifying_key, challenge, self.e.info["aid"], self.e.pub)
        with self.assertRaisesRegex(att.VerificationError, "already consumed"):
            verifier.verify(response, self.e.ca.verifying_key, challenge, self.e.info["aid"], self.e.pub)
        with self.assertRaisesRegex(att.VerificationError, "not issued"):
            verifier.verify(self.e.response(), self.e.ca.verifying_key, self.e.challenge, self.e.info["aid"], self.e.pub)

    def test_in_memory_expiry_and_failure_burn(self):
        verifier = att.ChallengeVerifier(max_age=1)
        with mock.patch.object(att.time, "monotonic", return_value=10):
            challenge = verifier.issue()
        with mock.patch.object(att.time, "monotonic", return_value=12):
            with self.assertRaisesRegex(att.VerificationError, "expired"):
                verifier.verify(self.e.response(challenge=challenge), self.e.ca.verifying_key,
                                challenge, self.e.info["aid"], self.e.pub)
        challenge = verifier.issue()
        with self.assertRaises(att.VerificationError):
            verifier.verify(b"", self.e.ca.verifying_key, challenge, self.e.info["aid"], self.e.pub)
        with self.assertRaisesRegex(att.VerificationError, "already consumed"):
            verifier.verify(self.e.response(challenge=challenge), self.e.ca.verifying_key,
                            challenge, self.e.info["aid"], self.e.pub)

    def test_saved_issuance_and_persistent_replay(self):
        with mock.patch.object(att.secrets, "token_bytes", wraps=att.secrets.token_bytes) as random:
            challenge = self.issue_saved()
        random.assert_called_once_with(32)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        response = self.e.response(challenge=challenge)
        self.verify_saved(response)
        self.assertTrue(json.loads(self.state.read_text())["consumed"])
        with self.assertRaisesRegex(att.VerificationError, "already consumed"):
            self.verify_saved(response)
        with self.assertRaises(FileExistsError):
            self.issue_saved()

    def test_saved_invalid_evidence_consumes(self):
        challenge = self.issue_saved()
        with self.assertRaises(att.VerificationError):
            self.verify_saved(b"bad")
        with self.assertRaisesRegex(att.VerificationError, "already consumed"):
            self.verify_saved(self.e.response(challenge=challenge))

    def test_saved_expiry_and_clock_rollback(self):
        for issued, now, cap in ((10, 13, 2), (10, 9, 60), (10, 12, 1)):
            if self.state.exists():
                self.state.unlink()
            with mock.patch.object(att.time, "time", return_value=issued):
                challenge = self.issue_saved(max_age=2)
            with mock.patch.object(att.time, "time", return_value=now):
                with self.assertRaisesRegex(att.VerificationError, "expired or clock"):
                    self.verify_saved(self.e.response(challenge=challenge), max_age=cap)
            self.assertTrue(json.loads(self.state.read_text())["consumed"])

    def test_max_age_invalid(self):
        for value in (0, -1, float("nan"), float("inf")):
            with self.assertRaises(att.VerificationError):
                att.ChallengeVerifier(value)
            with self.assertRaises(att.VerificationError):
                self.issue_saved(max_age=value)

    def test_concurrent_consumers_only_one_succeeds(self):
        challenge = self.issue_saved()
        evidence = self.e.response(challenge=challenge)
        results = []
        def consume():
            try:
                self.verify_saved(evidence)
                results.append("ok")
            except att.VerificationError:
                results.append("rejected")
        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertCountEqual(results, ["ok", "rejected"])

    def test_state_mode_and_symlinks(self):
        self.issue_saved()
        self.state.chmod(0o644)
        with self.assertRaisesRegex(att.VerificationError, "exact-0600"):
            self.verify_saved(b"")
        link = self.state.with_name("link")
        link.symlink_to(self.state)
        with self.assertRaises(OSError):
            att.verify_saved_response(b"", self.e.ca.verifying_key, link)


class PersonalizationTests(unittest.TestCase):
    def setUp(self):
        self.e = Evidence()
        self.info = dict(self.e.info, sealed=False, cert=b"")
        self.raw = encode_info(self.info)
        self.tmp = tempfile.TemporaryDirectory(prefix="attestation-ca-")
        self.addCleanup(self.tmp.cleanup)
        self.key = Path(self.tmp.name) / "throwaway-ca.pem"
        self.key.write_bytes(self.e.ca.to_pem())
        self.key.chmod(0o600)

    def certificate(self):
        return att.sign_certificate(self.info, self.e.ca.verifying_key, ca_key_file=self.key)

    def test_throwaway_ca_exact_message_and_no_secret_return(self):
        cert = self.certificate()
        self.assertEqual(cert, sign(self.e.ca, att.CA_DOMAIN + self.info["card_id"]
                                   + self.info["aid"] + self.info["attestation_pub"]))
        self.assertEqual(att.parse_info(self.raw), self.info | {"version": 1})
        self.assertNotIn(self.e.ca.to_string(), cert)

    def test_file_mode_symlink_wrong_curve_and_wrong_pin(self):
        for mode in (0o644, 0o400, 0o700):
            self.key.chmod(mode)
            with self.assertRaisesRegex(att.VerificationError, "exact-0600"):
                self.certificate()
        self.key.chmod(0o600)
        link = self.key.with_name("link")
        link.symlink_to(self.key)
        with self.assertRaises(OSError):
            att.sign_certificate(self.info, self.e.ca.verifying_key, ca_key_file=link)
        with self.assertRaisesRegex(att.VerificationError, "CA certificate"):
            att.sign_certificate(self.info, SigningKey.generate(curve=NIST256p).verifying_key,
                                 ca_key_file=self.key)
        self.key.write_bytes(SigningKey.generate(curve=SECP256k1).to_pem())
        with self.assertRaisesRegex(att.VerificationError, "P256"):
            self.certificate()

    def test_mock_pkcs11_provider_protocol_not_real_hsm(self):
        cert = sign(self.e.ca, att.ca_message(self.info))
        result = subprocess.CompletedProcess([], 0, stdout=cert, stderr=b"")
        with mock.patch.object(att.subprocess, "run", return_value=result) as run:
            got = att.sign_certificate(self.info, self.e.ca.verifying_key,
                                      pkcs11_uri="pkcs11:object=test-ca;type=private")
        self.assertEqual(got, cert)
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["openssl", "dgst", "-sha256", "-provider", "default", "-provider",
                                "pkcs11", "-sign", "pkcs11:object=test-ca;type=private"])
        self.assertEqual(run.call_args.kwargs["input"], att.ca_message(self.info))
        self.assertNotIn(self.e.ca.to_pem(), run.call_args.kwargs.values())

    def test_pkcs11_pin_argv_and_wrong_signature_rejected(self):
        for uri in ("pkcs11:object=x?pin-value=1234", "pkcs11:object=x?pin%2dvalue=1234", "not-pkcs11"):
            with mock.patch.object(att.subprocess, "run") as run:
                with self.assertRaises(att.VerificationError):
                    att.sign_certificate(self.info, self.e.ca.verifying_key, pkcs11_uri=uri)
                run.assert_not_called()
        result = subprocess.CompletedProcess([], 0, stdout=sign(self.e.ca, b"wrong"), stderr=b"")
        with mock.patch.object(att.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(att.VerificationError, "CA certificate"):
                att.sign_certificate(self.info, self.e.ca.verifying_key, pkcs11_uri="pkcs11:object=x")

    def test_exact_write_readback_and_explicit_seal(self):
        cert = self.certificate()
        for seal in (False, True):
            card = FakeCard(self.info)
            result = att.personalize(card, self.raw, cert, seal=seal)
            self.assertEqual(result["cert"], cert)
            self.assertEqual(result["sealed"], seal)
            self.assertEqual([c[1] for c in card.calls], [0x70, 0x71, 0x70] + ([0x73, 0x70] if seal else []))

    def test_bad_readbacks_and_status_fail_closed(self):
        cert = self.certificate()
        for params, message in ((dict(bad_cert=True), "certificate readback"),
                                (dict(bad_seal=True), "seal readback"),
                                (dict(fail_store=True), "INS 71 failed")):
            card = FakeCard(self.info, **params)
            with self.subTest(params=params), self.assertRaisesRegex(att.VerificationError, message):
                att.personalize(card, self.raw, cert, seal=True)
            if params.get("bad_cert") or params.get("fail_store"):
                self.assertNotIn(0x73, [c[1] for c in card.calls])

    def test_info_change_no_store_and_existing_cert_no_write(self):
        cert = self.certificate()
        card = FakeCard(dict(self.info, card_id=os.urandom(16)))
        with self.assertRaisesRegex(att.VerificationError, "INFO changed"):
            att.personalize(card, self.raw, cert)
        self.assertEqual([c[1] for c in card.calls], [0x70])
        card = FakeCard(self.info)
        with self.assertRaisesRegex(att.VerificationError, "already personalized"):
            att.personalize(card, encode_info(dict(self.info, cert=cert)), cert)
        self.assertEqual(card.calls, [])

    def test_cli_dry_run_offline_and_no_capture_without_execute(self):
        info_file = Path(self.tmp.name) / "info.bin"
        pin = Path(self.tmp.name) / "ca-pub.pem"
        info_file.write_bytes(self.raw)
        pin.write_bytes(self.e.ca.verifying_key.to_pem())
        base = ["personalize", "--aid", self.info["aid"].hex(), "--ca-key", str(self.key)]
        with mock.patch.object(cli, "open_card", side_effect=AssertionError("hardware forbidden")):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(base), 0)
            self.assertTrue(json.loads(output.getvalue())["dry_run"])
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(base + ["--info-file", str(info_file), "--ca-pubkey", str(pin), "--seal"]), 0)
            result = json.loads(output.getvalue())
            self.assertTrue(result["would_seal"])
            self.assertFalse(result["hardware_accessed"])
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["info", "--aid", self.info["aid"].hex(),
                                           "--out", str(info_file.with_name("capture"))]), 1)

    def test_cli_execute_uses_fake_and_closes(self):
        info_file = Path(self.tmp.name) / "info.bin"
        pin = Path(self.tmp.name) / "ca-pub.pem"
        info_file.write_bytes(self.raw)
        pin.write_bytes(self.e.ca.verifying_key.to_pem())
        card = FakeCard(self.info)
        with mock.patch.object(cli, "open_card", return_value=card), contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(["personalize", "--aid", self.info["aid"].hex(), "--ca-key", str(self.key),
                             "--info-file", str(info_file), "--ca-pubkey", str(pin), "--execute", "--seal"])
        self.assertEqual(code, 0)
        self.assertTrue(card.closed)
        self.assertTrue(json.loads(output.getvalue())["readback_verified"])

    def test_cli_capture_then_offline_verify_and_replay_every_applet(self):
        for aid in (att.ETH2_AID, att.MUSIG2_AID, att.VAULT_AID):
            with self.subTest(aid=aid.hex()), tempfile.TemporaryDirectory() as directory:
                e = Evidence(aid)
                root = Path(directory)
                state, challenge_path = root / "state.json", root / "challenge.bin"
                response_path, pin_path = root / "response.bin", root / "ca.pem"
                pin_path.write_bytes(e.ca.verifying_key.to_pem())
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(["challenge", "--state", str(state), "--expected-aid", aid.hex(),
                                               "--expected-signing-pub", e.pub.hex(), "--out", str(challenge_path)]), 0)
                card = PagedCard(e)
                with mock.patch.object(cli, "open_card", return_value=card) as opened, contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(cli.main(["capture-response", "--aid", aid.hex(), "--challenge-file", str(challenge_path),
                                               "--out", str(response_path), "--execute"]), 0)
                self.assertEqual(opened.call_count, 1)
                self.assertTrue(card.closed)
                self.assertEqual(response_path.read_bytes(), e.response(challenge=challenge_path.read_bytes()))
                result = json.loads(output.getvalue())
                self.assertEqual((result["captured"], result["verified"], result["pages"]), (True, False, 2))
                self.assertFalse(json.loads(state.read_text())["consumed"], "capture must not consume verification state")
                args = ["verify", "--state", str(state), "--ca-pubkey", str(pin_path), "--response-file", str(response_path)]
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(cli.main(args), 0)
                self.assertTrue(json.loads(output.getvalue())["verified"])
                with contextlib.redirect_stderr(io.StringIO()) as error:
                    self.assertEqual(cli.main(args), 1)
                self.assertIn("already consumed", error.getvalue())

    def test_cli_capture_requires_execute_challenge32_and_new_output(self):
        challenge_path = Path(self.tmp.name) / "challenge.bin"
        response_path = Path(self.tmp.name) / "response.bin"
        base = ["capture-response", "--aid", att.ETH2_AID.hex(), "--challenge-file", str(challenge_path),
                "--out", str(response_path)]
        challenge_path.write_bytes(self.e.challenge)
        with mock.patch.object(cli, "open_card", side_effect=AssertionError("hardware forbidden")) as opened:
            with contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(cli.main(base), 1)
            self.assertIn("--execute", error.getvalue())
            for challenge in (b"short", b"x" * 33):
                challenge_path.write_bytes(challenge)
                with contextlib.redirect_stderr(io.StringIO()) as error:
                    self.assertEqual(cli.main(base + ["--execute"]), 1)
                self.assertIn("32 bytes", error.getvalue())
            challenge_path.write_bytes(self.e.challenge)
            response_path.write_bytes(b"do not overwrite")
            with contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(cli.main(base + ["--execute"]), 1)
            self.assertIn("already exists", error.getvalue())
            self.assertEqual(response_path.read_bytes(), b"do not overwrite")
            opened.assert_not_called()

    def test_cli_capture_failed_page_closes_without_output(self):
        challenge_path = Path(self.tmp.name) / "challenge.bin"
        response_path = Path(self.tmp.name) / "response.bin"
        challenge_path.write_bytes(self.e.challenge)
        for fail_page in (0, 1):
            card = PagedCard(self.e, fail_page=fail_page)
            with mock.patch.object(cli, "open_card", return_value=card), contextlib.redirect_stderr(io.StringIO()) as error:
                code = cli.main(["capture-response", "--aid", att.ETH2_AID.hex(),
                                 "--challenge-file", str(challenge_path), "--out", str(response_path), "--execute"])
            self.assertEqual(code, 1)
            self.assertIn(f"page {fail_page} failed", error.getvalue())
            self.assertFalse(response_path.exists())
            self.assertTrue(card.closed)

    def test_cli_challenge_verify_subprocess_and_replay(self):
        state = Path(self.tmp.name) / "challenge.json"
        raw_challenge = Path(self.tmp.name) / "challenge.bin"
        pin = Path(self.tmp.name) / "pub.pem"
        evidence = Path(self.tmp.name) / "response.bin"
        pin.write_bytes(self.e.ca.verifying_key.to_pem())
        command = [sys.executable, str(ROOT / "scripts/nuri_attest.py")]
        issued = subprocess.run(command + ["challenge", "--state", str(state),
                                "--expected-aid", self.e.info["aid"].hex(),
                                "--expected-signing-pub", self.e.pub.hex(), "--out", str(raw_challenge)],
                                capture_output=True, text=True, check=True)
        challenge = bytes.fromhex(json.loads(issued.stdout)["challenge"])
        self.assertEqual(challenge, raw_challenge.read_bytes())
        evidence.write_bytes(self.e.response(challenge=challenge))
        args = command + ["verify", "--state", str(state), "--ca-pubkey", str(pin), "--response-file", str(evidence)]
        verified = subprocess.run(args, capture_output=True, text=True, check=True)
        self.assertTrue(json.loads(verified.stdout)["verified"])
        replay = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(replay.returncode, 1)
        self.assertIn("already consumed", replay.stderr)


class InitCard:
    """Stateful fake with genuine signatures; never imports PC/SC or hardware."""
    def __init__(self, aid=att.ETH2_AID, initial_state=1, keyed=False, fault=None):
        self.e = Evidence(aid)
        self.e.info.update(sealed=False, cert=b"")
        self.state, self.keyed, self.fault = initial_state, keyed, fault
        self.calls, self.secret_buffers = [], []
        self.closed, self.logged_out = False, False
        self.attest_reads = 0
        self.raw_pub = self.e.wallet.verifying_key.to_string(
            "compressed" if aid == att.MUSIG2_AID else "uncompressed")
        self.binding = sign(self.e.device, att.BINDING_DOMAIN + aid + self.e.pub)
        if fault == "binding":
            # Keep 74 and later attestation mutually consistent: only NHWV1
            # verification (not a second readback inequality) can reject this.
            self.binding = sign(self.e.device, b"wrong binding")
        if fault == "invalid_public":
            self.raw_pub = (b"\x02" + b"\x00" * 32 if aid == att.MUSIG2_AID
                            else b"\x04" + b"\x00" * 64)
        elif fault == "public_encoding":
            self.raw_pub = self.e.wallet.verifying_key.to_string(
                "uncompressed" if aid == att.MUSIG2_AID else "compressed")
        elif fault == "public_length":
            self.raw_pub = self.raw_pub[:-1]

    def transmit(self, apdu):
        assert not self.closed
        raw = bytes(apdu)
        self.calls.append(raw)
        aid = self.e.info["aid"]
        cla = 0 if aid == att.MUSIG2_AID else 0x80
        if raw[1] == 0xA4:
            assert raw == bytes([0, 0xA4, 4, 0, len(aid)]) + aid
            self.logged_out = True
            self.state &= ~4
            if self.fault == "logout":
                return b"", 0x6985
            return b"", 0x9000
        assert raw[0] == cla and raw[3] == 0
        ins = raw[1]
        if ins == 0x72:
            assert len(raw) == 38 and raw[2] in (0, 1)
            assert raw[4] == 32 and raw[-1] == 0
            if raw[2] == 0:
                self.attest_reads += 1
            info = dict(self.e.info)
            if self.attest_reads == 2 and self.fault == "identity":
                info["card_id"] = b"x" * 16
            pub = self.e.pub if self.keyed else b""
            state = self.state
            binding = self.binding if self.keyed else b""
            if self.attest_reads == 2:
                if self.fault == "readback_pub":
                    pub = SigningKey.generate(curve=self.e.wallet.curve).verifying_key.to_string(
                        "uncompressed" if aid == att.VAULT_AID else "compressed")
                elif self.fault == "readback_state":
                    state = 3
                elif self.fault == "readback_binding":
                    binding = sign(self.e.device, b"wrong binding")
            response_sig = None
            if self.fault == "before_signature" or (self.attest_reads == 2 and self.fault == "after_signature"):
                response_sig = sign(self.e.device, b"wrong challenge")
            logical = self.e.response(challenge=raw[5:37], info=info, pub=pub,
                                      pin_state=state, binding=binding, response_sig=response_sig)
            split = len(encode_info(info))
            return (logical[:split] if raw[2] == 0 else logical[split:]), 0x9000
        assert raw[2] == 0 and len(raw) == 5 + raw[4]
        if ins == (0x10 if aid == att.VAULT_AID else 0x21):
            self.secret_buffers.append(apdu)
            assert self.state == 1 and not self.keyed
            if self.fault == "set_pin":
                return b"", 0x6985
            self.pin = raw[6:6 + raw[5]] if aid == att.ETH2_AID else raw[5:]
            self.state = 3
            return b"", 0x9000
        if ins == 0x20:
            self.secret_buffers.append(apdu)
            assert raw[5:] == self.pin
            if self.fault == "transport_secret":
                raise RuntimeError("secret APDU " + raw.hex() + " " + self.pin.decode())
            if self.fault == "verify":
                return b"", 0x63C2
            self.state = 7
            return b"", 0x9000
        if ins == (0x04 if aid == att.MUSIG2_AID else 0x03):
            assert self.state == 7 and not self.keyed
            self.keyed = True
            return self.raw_pub, 0x9000
        if ins == (0x03 if aid == att.MUSIG2_AID else 0x02):
            assert self.keyed
            if self.fault == "public":
                return b"\x04" + b"x" * 64, 0x9000
            return self.raw_pub, 0x9000
        if ins == 0x74:
            assert self.keyed
            return self.binding, 0x9000
        raise AssertionError("unexpected instruction")

    def close(self):
        assert self.logged_out, "must explicitly select/logout before disconnect"
        self.closed = True


class InitKeyTests(unittest.TestCase):
    def invoke(self, card, execute=True, puk=False, answers=None):
        args = ["init-key", "--aid", card.e.info["aid"].hex()]
        if execute:
            args += ["--execute"]
        if puk:
            args += ["--with-puk"]
        terminal = mock.MagicMock()
        terminal.__enter__.return_value.isatty.return_value = True
        answers = answers if answers is not None else ["2468", "2468"] + (["abcdefghijklmnop"] * 2 if puk else [])
        with (mock.patch.object(cli, "open_card", return_value=card) as opened,
              mock.patch("builtins.open", return_value=terminal) as tty,
              mock.patch.object(cli.getpass, "getpass", side_effect=answers) as prompt,
              contextlib.redirect_stdout(io.StringIO()) as output,
              contextlib.redirect_stderr(io.StringIO()) as error):
            status = cli.main(args)
        return status, output.getvalue(), error.getvalue(), opened, prompt, tty

    def test_all_applets_precise_order_apdus_canonical_public_and_wiping(self):
        for aid in (att.ETH2_AID, att.MUSIG2_AID, att.VAULT_AID):
            with self.subTest(aid=aid.hex()):
                card = InitCard(aid)
                code, output, error, opened, prompt, tty = self.invoke(card)
                self.assertEqual((code, error), (0, ""))
                self.assertEqual(json.loads(output), {"signing_pub": card.e.pub.hex()})
                opened.assert_called_once()
                self.assertEqual(prompt.call_count, 2)
                tty.assert_called_once_with("/dev/tty", "w")
                cla = 0 if aid == att.MUSIG2_AID else 0x80
                setup_ins = 0x10 if aid == att.VAULT_AID else 0x21
                kg, gp = (4, 3) if aid == att.MUSIG2_AID else (3, 2)
                self.assertEqual([c[1] for c in card.calls], [0x72, 0x72, setup_ins, 0x20, kg, gp, 0x74, 0x72, 0x72, 0xA4])
                payload = b"\x04" + b"2468" if aid == att.ETH2_AID else b"2468"
                self.assertEqual(card.calls[2], bytes([cla, setup_ins, 0, 0, len(payload)]) + payload)
                self.assertEqual(card.calls[3], bytes([cla, 0x20, 0, 0, 4]) + b"2468")
                for call, ins in zip(card.calls[4:7], (kg, gp, 0x74)):
                    self.assertEqual(call, bytes([cla, ins, 0, 0, 0]))
                self.assertEqual(card.calls[0][5:37], card.calls[1][5:37])
                self.assertEqual(card.calls[7][5:37], card.calls[8][5:37])
                self.assertNotEqual(card.calls[0][5:37], card.calls[7][5:37])
                self.assertTrue(card.closed and card.logged_out)
                self.assertTrue(all(not any(buf) for buf in card.secret_buffers))

    def test_dry_run_no_reader_no_tty_no_prompt(self):
        for aid in (att.ETH2_AID, att.MUSIG2_AID, att.VAULT_AID):
            code, out, err, opened, prompt, tty = self.invoke(InitCard(aid), execute=False)
            self.assertEqual((code, err), (0, ""))
            self.assertTrue(json.loads(out)["dry_run"])
            self.assertFalse(json.loads(out)["ca_verified"])
            opened.assert_not_called()
            prompt.assert_not_called()
            tty.assert_not_called()

    def test_nonblank_demo_blocked_configured_keyed_refused_before_prompt(self):
        for aid in (att.ETH2_AID, att.MUSIG2_AID, att.VAULT_AID):
            for state, keyed, configured in ((0, False, False), (3, False, False), (9, False, False),
                                             (5, False, False), (1, True, False), (1, False, True)):
                with self.subTest(aid=aid.hex(), state=state, keyed=keyed, configured=configured):
                    card = InitCard(aid, state, keyed)
                    if configured:
                        card.e.info["cert"] = sign(card.e.ca, att.ca_message(card.e.info))
                    code, out, _, _, prompt, tty = self.invoke(card)
                    self.assertEqual((code, out), (1, ""))
                    prompt.assert_not_called()
                    tty.assert_not_called()
                    self.assertEqual([c[1] for c in card.calls], [0x72, 0x72, 0xA4])
                    self.assertTrue(card.closed)

    def test_wrong_verify_never_retries_or_generates_key_and_wipes(self):
        for fault, expected in (("set_pin", [0x72, 0x72, 0x21, 0xA4]),
                                ("verify", [0x72, 0x72, 0x21, 0x20, 0xA4]),
                                ("transport_secret", [0x72, 0x72, 0x21, 0x20, 0xA4])):
            card = InitCard(fault=fault)
            code, out, err, _, prompt, _ = self.invoke(card)
            self.assertEqual((code, out), (1, ""))
            self.assertEqual([c[1] for c in card.calls], expected)
            self.assertIn("no retry", err)
            self.assertNotIn("2468", err)
            self.assertNotIn(b"2468".hex(), err)
            self.assertTrue(card.closed)
            self.assertTrue(all(not any(buf) for buf in card.secret_buffers))
            self.assertEqual(prompt.call_count, 2)

    def test_public_binding_identity_state_signature_readback_failures(self):
        for fault in ("public", "binding", "identity", "readback_pub", "readback_state",
                      "readback_binding", "before_signature", "after_signature", "logout"):
            with self.subTest(fault=fault):
                card = InitCard(fault=fault)
                code, out, _, _, prompt, _ = self.invoke(card)
                self.assertEqual((code, out), (1, ""))
                self.assertTrue(card.closed and card.logged_out)
                if fault == "before_signature":
                    prompt.assert_not_called()
                self.assertLessEqual([c[1] for c in card.calls].count(0x20), 1)

    def test_eth2_optional_puk_exact_payload_and_other_applets_rejected(self):
        card = InitCard()
        code, _, error, _, prompt, _ = self.invoke(card, puk=True)
        self.assertEqual((code, error), (0, ""))
        payload = b"\x04" + b"2468" + b"\x10" + b"abcdefghijklmnop"
        self.assertEqual(card.calls[2], bytes([0x80, 0x21, 0, 0, len(payload)]) + payload)
        self.assertEqual(prompt.call_count, 4)
        self.assertTrue(all(not any(buf) for buf in card.secret_buffers))
        for aid in (att.MUSIG2_AID, att.VAULT_AID):
            code, _, _, opened, prompt, _ = self.invoke(InitCard(aid), puk=True)
            self.assertEqual(code, 1)
            opened.assert_not_called()
            prompt.assert_not_called()

    def test_secret_formats_confirmation_utf8_and_no_writes_on_bad_input(self):
        cases = [(att.ETH2_AID, "abc", "abc"), (att.ETH2_AID, "x" * 17, "x" * 17),
                 (att.VAULT_AID, "é" * 9, "é" * 9), (att.VAULT_AID, "abcd", "abce"),
                 (att.MUSIG2_AID, "12a4", "12a4"), (att.MUSIG2_AID, "１２３４", "１２３４"),
                 (att.MUSIG2_AID, "1" * 13, "1" * 13)]
        for aid, first, second in cases:
            card = InitCard(aid)
            code, out, err, _, prompt, _ = self.invoke(card, answers=[first, second])
            self.assertEqual((code, out), (1, ""))
            self.assertEqual([c[1] for c in card.calls], [0x72, 0x72, 0xA4])
            self.assertEqual(prompt.call_count, 2)
            self.assertNotIn(first, err)
        for aid, secret in ((att.ETH2_AID, "éé"), (att.VAULT_AID, "é" * 8),
                            (att.MUSIG2_AID, "1" * 12)):
            card = InitCard(aid)
            self.assertEqual(self.invoke(card, answers=[secret, secret])[0], 0)
        card = InitCard()
        code, _, _, _, prompt, _ = self.invoke(card, puk=True, answers=["2468", "2468", "short", "short"])
        self.assertEqual(code, 1)
        self.assertEqual(prompt.call_count, 4)
        self.assertEqual([c[1] for c in card.calls], [0x72, 0x72, 0xA4])

    def test_terminal_failure_and_getpass_fallback_fail_closed(self):
        args = ["init-key", "--aid", att.ETH2_AID.hex(), "--execute"]
        for failure in (OSError("private secret"), cli.getpass.GetPassWarning("private secret")):
            card = InitCard()
            with (mock.patch.object(cli, "open_card", return_value=card),
                  mock.patch("builtins.open", side_effect=failure),
                  mock.patch.object(cli.getpass, "getpass") as prompt,
                  contextlib.redirect_stdout(io.StringIO()) as out,
                  contextlib.redirect_stderr(io.StringIO()) as err):
                self.assertEqual(cli.main(args), 1)
            prompt.assert_not_called()
            self.assertEqual(out.getvalue(), "")
            self.assertNotIn("private secret", err.getvalue())
            self.assertTrue(card.closed)
        card = InitCard()
        terminal = mock.MagicMock()
        terminal.__enter__.return_value.isatty.return_value = True
        def fallback(*args, **kwargs):
            import warnings
            warnings.warn("echo unavailable", cli.getpass.GetPassWarning)
            raise AssertionError("fallback must not read stdin")
        with (mock.patch.object(cli, "open_card", return_value=card),
              mock.patch("builtins.open", return_value=terminal),
              mock.patch.object(cli.getpass, "getpass", side_effect=fallback),
              contextlib.redirect_stderr(io.StringIO())):
            self.assertEqual(cli.main(args), 1)
        self.assertEqual([c[1] for c in card.calls], [0x72, 0x72, 0xA4])

    def test_identical_malformed_keygen_and_readback_keys_rejected(self):
        for aid in (att.ETH2_AID, att.MUSIG2_AID, att.VAULT_AID):
            for fault in ("invalid_public", "public_encoding", "public_length"):
                with self.subTest(aid=aid.hex(), fault=fault):
                    card = InitCard(aid, fault=fault)
                    code, out, _, _, _, _ = self.invoke(card)
                    self.assertEqual((code, out), (1, ""))
                    self.assertNotIn(0x74, [c[1] for c in card.calls])
                    self.assertTrue(card.closed)

    def test_underlying_pcsc_never_replays_6c_provisioning_commands(self):
        from nuri_pcsc import Applet
        for aid in (att.ETH2_AID, att.MUSIG2_AID, att.VAULT_AID):
            cla = 0 if aid == att.MUSIG2_AID else 0x80
            for ins in (0x10 if aid == att.VAULT_AID else 0x21, 0x20,
                        0x04 if aid == att.MUSIG2_AID else 0x03):
                conn = mock.Mock()
                conn.transmit.return_value = ([], 0x6C, 0x41)
                transport = cli.ProvisioningTransport(Applet(conn, "fake", "T0", aid.hex()))
                command_refs = []
                def raw_send(command):
                    command_refs.append(command)
                    return [], 0x6C, 0x41
                conn.transmit.side_effect = raw_send
                if ins in (0x10, 0x21, 0x20):
                    with self.assertRaises(att.VerificationError):
                        cli.secret_command(transport, cla, ins, bytearray(b"2468"))
                else:
                    with self.assertRaises(att.VerificationError):
                        cli.card_command(transport, cla, ins)
                self.assertEqual(conn.transmit.call_count, 1)
                self.assertTrue(all(not any(command) for command in command_refs))

    def test_underlying_pcsc_drains_61_without_resending_original(self):
        from nuri_pcsc import Applet
        conn = mock.Mock()
        sent = []
        replies = iter([([1], 0x61, 2), ([2, 3], 0x90, 0)])
        def raw_send(command):
            sent.append(bytes(command))
            return next(replies)
        conn.transmit.side_effect = raw_send
        transport = cli.ProvisioningTransport(Applet(conn, "fake", "T0", att.ETH2_AID.hex()))
        self.assertEqual(cli.card_command(transport, 0x80, 3), b"\x01\x02\x03")
        self.assertEqual(sent, [b"\x80\x03\x00\x00\x00", b"\x00\xc0\x00\x00\x02"])

    def test_only_canonical_aids_accepted(self):
        for aid in ("4E55524945544801", "eth2", "00", "garbage"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cli.parser().parse_args(["init-key", "--aid", aid])


if __name__ == "__main__":
    unittest.main()
