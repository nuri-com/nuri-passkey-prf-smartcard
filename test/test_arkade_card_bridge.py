"""Cloud-CI-only bridge tests. No PC/SC enumeration or physical card access.

CI: pip install 'fido2==2.2.1' cryptography
    python -m unittest discover -s test -p test_arkade_card_bridge.py -v

Uses the REAL python-fido2 2.2.1 extension + PIN protocol against SoftCtap2Device;
the software fixture has an existing, unfunded synthetic credential, never a
makeCredential ceremony. The bridge's only hardware edge is replaced with it.
"""
import hashlib
import hmac
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("arkade_card_bridge", ROOT / "scripts/send/bridge.py")
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)
sys.path.insert(0, str(ROOT / "host"))
from soft_ctap2 import SoftCtap2Device  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from fido2.ctap2 import Ctap2, ClientPin  # noqa: E402

PIN = "314159"
CREDENTIAL = b"synthetic-existing-nuri-credential"
PAYLOAD = {"credential": bridge.b64(CREDENTIAL)}


class Reader:
    def __init__(self, name):
        self.name = name
        self.createConnection = Mock()

    def __str__(self):
        return self.name


class BridgeTests(unittest.TestCase):
    def run_main(self, requests, **env):
        output = io.StringIO()
        level = logging.root.manager.disable
        self.addCleanup(logging.disable, level)
        with patch.dict(os.environ, {"NURI_SEND_CONFIRM": "@emino-546", "NURI_FIDO_PIN": PIN, **env}), \
                patch.object(sys, "stdin", io.StringIO("".join(json.dumps(r) + "\n" for r in requests))), \
                patch.object(sys, "stdout", output):
            code = bridge.main()
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_exact_reader_wins_over_substring(self):
        exact, other = Reader("OMNIKEY"), Reader("OMNIKEY 5422")
        self.assertIs(bridge.select_reader([other, exact], "OMNIKEY"), exact)
        exact.createConnection.assert_not_called()
        other.createConnection.assert_not_called()

    def test_substring_fallback_case_insensitive_and_ambiguous_rejected(self):
        one, two = Reader("OMNIKEY 5422"), Reader("OMNIKEY 3121")
        self.assertIs(bridge.select_reader([one], "omnikey"), one)
        for names, wanted in (([one, two], "OMNIKEY"), ([], "OMNIKEY"), ([one], ""),
                              ([one, one], "OMNIKEY 5422")):
            with self.assertRaises(RuntimeError):
                bridge.select_reader(names, wanted)
        one.createConnection.assert_not_called()
        two.createConnection.assert_not_called()

    def test_repository_import_path(self):
        self.assertEqual(bridge.SCRIPTS, ROOT / "scripts")

    def test_pin_environment_popped_and_validated(self):
        with patch.dict(os.environ, {"NURI_FIDO_PIN": PIN}):
            self.assertEqual(bridge.read_pin(), PIN)
            self.assertNotIn("NURI_FIDO_PIN", os.environ)
        for bad in ("", "123", "1234567890123", "abcd", "１２３４", "1234\n"):
            with patch.dict(os.environ, {"NURI_FIDO_PIN": bad}), self.assertRaises(RuntimeError):
                bridge.read_pin()

    def test_pin_file_exact_mode_and_symlink(self):
        # Test files contain only synthetic PINs and stay inside the CI sandbox.
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            pinfile = home / ".hermes/cache/scratch/.card_pin"
            pinfile.parent.mkdir(parents=True)
            pinfile.write_text(PIN + "\n")
            saved = home / "synthetic-pin"
            with patch.dict(os.environ, {}, clear=True), patch.object(Path, "home", return_value=home):
                pinfile.chmod(0o600)
                self.assertEqual(bridge.read_pin(), PIN)
                for mode in (0o644, 0o400, 0o700):
                    pinfile.chmod(mode)
                    with self.assertRaises(RuntimeError):
                        bridge.read_pin()
                pinfile.chmod(0o600)
                pinfile.rename(saved)
                pinfile.symlink_to(saved)
                with self.assertRaises(OSError):
                    bridge.read_pin()

    def test_invalid_requests_never_open_hardware(self):
        bad_requests = [
            {"op": "reset"}, {"op": "make-credential"}, {"op": "finalize", "payload": "00"},
            {"op": "prf-proof", "payload": {"credential": ""}},
            {"op": "prf-proof", "payload": {"credential": "YQ="}},
            {"op": "prf-proof", "payload": {**PAYLOAD, "rp_id": "evil.com"}},
            {"op": "prf-proof", "payload": {**PAYLOAD, "origin": "https://evil.com"}},
            {"op": "prf-proof", "payload": {**PAYLOAD, "salt": "custom-not-allowed"}},
        ]
        with patch.object(bridge, "open_fido") as fido, patch.object(bridge, "open_musig") as musig:
            for req in bad_requests:
                code, responses = self.run_main([req])
                self.assertEqual((code, responses), (1, [bridge.ERROR]))
            fido.assert_not_called()
            musig.assert_not_called()

    def test_confirmation_gate_does_not_read_pin_or_hardware(self):
        with patch.object(bridge, "read_pin") as read, patch.object(bridge, "open_fido") as fido:
            code, responses = self.run_main([{"op": "prf-proof", "payload": PAYLOAD}], NURI_SEND_CONFIRM="no")
        self.assertEqual((code, responses), (1, [bridge.ERROR]))
        read.assert_not_called()
        fido.assert_not_called()

    def test_eof_does_not_read_pin_or_hardware(self):
        with patch.object(bridge, "read_pin") as read, patch.object(bridge, "open_musig") as musig:
            self.assertEqual(self.run_main([]), (0, []))
        read.assert_not_called()
        musig.assert_not_called()

    def test_musig_blocks_fido_and_closes_session(self):
        card = Mock(_token=None)
        card.pubkey.return_value = b"\x02" + b"p" * 32
        with patch.object(bridge, "open_musig", return_value=card), patch.object(bridge, "fido_operation") as fido:
            code, responses = self.run_main([{"op": "pubkey"}, {"op": "prf-proof", "payload": PAYLOAD}])
        self.assertEqual(code, 1)
        self.assertEqual(responses[-1], bridge.ERROR)
        fido.assert_not_called()
        card.close.assert_called_once()

    def test_231_byte_finalize_preserved(self):
        token = b"abcd"
        payload = b"\0" * 97 + token + b"\x04" + b"r" * 64 + b"\x04" + b"p" * 64
        card = Mock(_token=token)
        card.pubkey.return_value = b"\x02" + b"p" * 32
        card.finalize.return_value = b"s" * 32
        with patch.object(bridge, "open_musig", return_value=card):
            code, responses = self.run_main([{"op": "pubkey"}, {"op": "finalize", "payload": payload.hex()}])
        self.assertEqual(code, 0)
        self.assertEqual(responses[-1], {"partial": (b"s" * 32).hex()})
        card.finalize.assert_called_once_with(payload[:32], payload[32:64], payload[64], payload[65:97],
                                               r_agg=payload[101:166], p_agg=payload[166:231])
        card.close.assert_called_once()

    def test_secret_exception_never_serialized_and_no_retry(self):
        with patch.object(bridge, "fido_operation", side_effect=RuntimeError("PRF private PIN 314159")) as op:
            code, responses = self.run_main([{"op": "prf-proof", "payload": PAYLOAD}])
        self.assertEqual((code, responses), (1, [bridge.ERROR]))
        op.assert_called_once()

    def test_bip86_official_vector(self):
        # bitcoin/bips bip-0086.mediawiki: mnemonic abandon*11 + about,
        # empty passphrase, first receiving internal key (NOT tweaked output).
        mnemonic = " ".join(["abandon"] * 11 + ["about"])
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048, 64)
        key = bridge.bip86_public(seed)
        self.assertEqual(len(key), 33)
        self.assertEqual(key[1:].hex(), "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115")
        self.assertIn(key[0], (2, 3))

    def test_nuri_hkdf_matches_existing_js_domains(self):
        prf = bytes(range(32))
        extract = hmac.new(hashlib.sha256(b"app:nuri.com|wallet|v1").digest(), prf, hashlib.sha256).digest()
        entropy = hmac.new(extract, b"app:nuri.com|wallet|v1|chain=bitcoin|fmt=taproot\x01", hashlib.sha256).digest()
        with patch.object(bridge, "bip86_public", return_value=b"public") as derive:
            self.assertEqual(bridge.derive_nuri_public(prf), b"public")
        derive.assert_called_once_with(entropy)


class FidoIntegrationTests(unittest.TestCase):
    def fixture(self):
        device = SoftCtap2Device(PIN)
        device.creds[CREDENTIAL] = {
            "rp": "nuri.com", "user": {"id": b"synthetic-user"},
            "key": ec.generate_private_key(ec.SECP256R1()), "cred_random": bytes(range(32))}
        device.close = Mock()
        return device

    def test_real_221_extension_shared_secret_twice_public_only(self):
        self.assertEqual(bridge.importlib.metadata.version("fido2"), "2.2.1")
        device = self.fixture()
        commands = []
        original_call = device.call

        def record(cmd, data=b"", *args, **kwargs):
            commands.append(data[0])
            return original_call(cmd, data, *args, **kwargs)

        device.call = record
        with patch.object(bridge, "open_fido", return_value=device):
            result = bridge.fido_operation("prf-proof", PAYLOAD, PIN)
        salt = hashlib.sha256(b"WebAuthn PRF\0nuri-prf-salt-v1").digest()
        expected = device.expected_hmac(CREDENTIAL, salt)
        self.assertEqual(set(result), {"client_pk33", "prf_commitment_sha256", "deterministic"})
        self.assertTrue(result["deterministic"])
        self.assertEqual(result["prf_commitment_sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual(result["client_pk33"], bridge.derive_nuri_public(expected).hex())
        self.assertEqual(commands.count(0x02), 2)
        self.assertEqual(commands.count(0x01), 0)  # NEVER enroll
        self.assertEqual(commands.count(0x07), 0)  # NEVER reset
        self.assertNotIn(expected.hex(), json.dumps(result))
        device.close.assert_called_once()

    def test_assert_contract_preserved(self):
        device = self.fixture()
        payload = {**PAYLOAD, "rp_id": "nuri.com", "origin": bridge.ORIGIN, "challenge": bridge.b64(b"challenge")}
        with patch.object(bridge, "open_fido", return_value=device):
            result = bridge.fido_operation("assert", payload, PIN)
        self.assertEqual(set(result), {"client_data_b64u", "auth_data_b64u", "sig_b64u", "assertion_cred_id_b64u"})
        self.assertEqual(result["assertion_cred_id_b64u"], PAYLOAD["credential"])
        data = json.loads(bridge.decode_b64(result["client_data_b64u"]))
        self.assertEqual(data["origin"], bridge.ORIGIN)
        device.close.assert_called_once()

    def test_wrong_pin_attempted_once_and_closed(self):
        device = self.fixture()
        with patch.object(bridge, "open_fido", return_value=device), self.assertRaises(Exception):
            bridge.fido_operation("prf-proof", PAYLOAD, "271828")
        self.assertEqual(device.retries, 7)
        device.close.assert_called_once()

    def test_prf_missing_extension_fails_closed(self):
        device = self.fixture()
        original = device._info
        device._info = lambda args: {**original(args), 2: []}
        with patch.object(bridge, "open_fido", return_value=device), self.assertRaises(RuntimeError):
            bridge.fido_operation("prf-proof", PAYLOAD, PIN)
        self.assertEqual(device.counter, 0)
        device.close.assert_called_once()

    def test_nondeterminism_reported_not_hidden(self):
        device = self.fixture()
        original_get = device._get

        def rotate(args):
            response = original_get(args)
            device.creds[CREDENTIAL]["cred_random"] = b"z" * 32
            return response

        device._get = rotate
        with patch.object(bridge, "open_fido", return_value=device):
            result = bridge.fido_operation("prf-proof", PAYLOAD, PIN)
        self.assertFalse(result["deterministic"])
        device.close.assert_called_once()

    def test_wrong_credential_rp_or_uv_rejected(self):
        good = SimpleNamespace(credential={"id": CREDENTIAL}, number_of_credentials=None,
                               auth_data=SimpleNamespace(rp_id_hash=hashlib.sha256(b"nuri.com").digest(), flags=5))
        bridge.validate_assertion(good, CREDENTIAL)
        for change in ("credential", "rp", "uv", "count"):
            candidate = SimpleNamespace(credential=good.credential, number_of_credentials=None,
                                        auth_data=SimpleNamespace(**vars(good.auth_data)))
            if change == "credential":
                candidate.credential = {"id": b"different"}
            elif change == "rp":
                candidate.auth_data.rp_id_hash = b"x" * 32
            elif change == "uv":
                candidate.auth_data.flags = 1
            else:
                candidate.number_of_credentials = 2
            with self.assertRaises(RuntimeError):
                bridge.validate_assertion(candidate, CREDENTIAL)


if __name__ == "__main__":
    unittest.main()
