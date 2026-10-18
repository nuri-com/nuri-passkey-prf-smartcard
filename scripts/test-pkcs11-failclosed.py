#!/usr/bin/env python3
"""PKCS#11 policy regression: mocked PC/SC + built native module; NEVER hardware.

Run with the shared launch Python (ecdsa) after scripts/build-pkcs11.sh.
Native card-mode dispatch is redirected to a task-owned fake helper, not PC/SC.
"""
import contextlib
import ctypes as C
import importlib.util
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pkcs11_helper_under_test', ROOT / 'scripts/pkcs11-helper.py')
assert spec is not None and spec.loader is not None
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
PUBKEY = '03bcd83232b6276e8856605cfd877f7795536a5099555684422fe82f2b6adb95e2'
PKCS11_TOOL = shutil.which('pkcs11-tool')


class CardError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class FakeCard:
    def __init__(self, aid):
        self.aid_hex = aid
        self.apdus = []
        self.closed = False

    def transmit(self, apdu):
        self.apdus.append(apdu)
        if apdu[1] == 2:
            return bytes.fromhex(PUBKEY), 0x9000
        if apdu[1] == 4:
            return bytes(64) + b'\x00', 0x9000
        raise AssertionError('Unexpected APDU')

    def close(self):
        self.closed = True


class HelperPolicy(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()

    def tearDown(self):
        self.env.stop()

    @contextlib.contextmanager
    def fake_transport(self, open_fn):
        # Selection unit tests isolate the additional strict-absence probe;
        # test_real_transport_mapping_* below exercise it with actual transport code.
        with patch.dict(sys.modules, {'nuri_pcsc': types.SimpleNamespace(CardError=CardError, open_applet=open_fn)}), patch.object(helper, 'require_eth2_absent'):
            yield

    def test_real_transport_mapping_rejects_ambiguous_absence(self):
        import nuri_pcsc
        class Wire:
            def __init__(self, result):
                self.result = result
            def connect(self, *args):
                pass
            def disconnect(self):
                pass
            def transmit(self, apdu):
                if bytes(apdu).endswith(bytes.fromhex(helper.ETH1_AID)):
                    return [], 0x90, 0
                if self.result == 'exception':
                    raise OSError('synthetic SELECT transport fault')
                return [], self.result >> 8, self.result & 255
        class Reader:
            def __init__(self, result):
                self.result = result
            def createConnection(self):
                return Wire(self.result)
        os.environ['NURI_ALLOW_ETH1_DEMO'] = '1'
        for results in (['exception'], [0x6985], [0x6A82, 'exception']):
            with patch.object(nuri_pcsc, '_list_readers', return_value=[Reader(result) for result in results]):
                with self.assertRaisesRegex(RuntimeError, 'Refusing ETH1 downgrade'):
                    helper.card_init()
        with patch.object(nuri_pcsc, '_list_readers', return_value=[Reader(0x6A82)]), contextlib.redirect_stderr(io.StringIO()):
            card = helper.card_init()
            self.assertEqual(card.aid_hex, helper.ETH1_AID)
            card.close()
        with patch.object(nuri_pcsc, '_list_readers', return_value=[Reader(0x6A82), Reader(0x9000)]):
            card = helper.card_init()
            self.assertEqual(card.aid_hex, helper.ETH2_AID)
            card.close()

    def test_mode_default_and_exact_sim(self):
        self.assertEqual(helper.selected_mode(), 'card')
        for mode in ('', 'SIM', 'sim ', 'typo', 'CARD'):
            os.environ['NURI_PKCS11_MODE'] = mode
            with self.assertRaises(ValueError):
                helper.selected_mode()
        os.environ['NURI_PKCS11_MODE'] = 'sim'
        self.assertEqual(helper.selected_mode(), 'sim')

    def test_eth2_preferred_even_when_demo_armed(self):
        os.environ['NURI_ALLOW_ETH1_DEMO'] = '1'
        calls = []
        def open_fn(aid):
            calls.append(aid)
            return FakeCard(aid)
        with self.fake_transport(open_fn):
            card = helper.card_init()
        self.assertEqual(calls, [helper.ETH2_AID])
        self.assertEqual(card.aid_hex, helper.ETH2_AID)

    def test_eth1_requires_exact_optin(self):
        for optin in (None, '', 'true', '01', '1 '):
            calls = []
            def open_fn(aid):
                calls.append(aid)
                raise CardError('NO_APPLET')
            os.environ.pop('NURI_ALLOW_ETH1_DEMO', None)
            if optin is not None:
                os.environ['NURI_ALLOW_ETH1_DEMO'] = optin
            with self.fake_transport(open_fn), self.assertRaisesRegex(RuntimeError, 'NURI_ALLOW_ETH1_DEMO=1'):
                helper.card_init()
            self.assertEqual(calls, [helper.ETH2_AID])

    def test_eth1_demo_warns(self):
        os.environ['NURI_ALLOW_ETH1_DEMO'] = '1'
        calls = []
        def open_fn(aid):
            calls.append(aid)
            if aid == helper.ETH2_AID:
                raise CardError('NO_APPLET')
            return FakeCard(aid)
        stderr = io.StringIO()
        with self.fake_transport(open_fn), contextlib.redirect_stderr(stderr):
            card = helper.card_init()
        self.assertEqual(calls, [helper.ETH2_AID, helper.ETH1_AID])
        self.assertEqual(card.aid_hex, helper.ETH1_AID)
        self.assertIn('ETH1 DEMO', stderr.getvalue())

    def test_transport_errors_do_not_downgrade(self):
        os.environ['NURI_ALLOW_ETH1_DEMO'] = '1'
        for code in ('NO_READER', 'NO_CARD', 'TRANSPORT'):
            calls = []
            def open_fn(aid):
                calls.append(aid)
                raise CardError(code)
            with self.fake_transport(open_fn), self.assertRaises(CardError):
                helper.card_init()
            self.assertEqual(calls, [helper.ETH2_AID])

    def test_eth2_sign_never_sends_apdu_or_bypasses_pin(self):
        os.environ['NURI_ALLOW_ETH1_DEMO'] = '1'
        card = FakeCard(helper.ETH2_AID)
        with self.assertRaisesRegex(RuntimeError, 'ETH2 PIN required'):
            helper.card_sign(card, '00' * 32)
        self.assertEqual(card.apdus, [])
        helper.card_pubkey(card)
        self.assertEqual(card.apdus, [bytes.fromhex('0002010000')])

    def test_eth1_sign_checks_optin_again(self):
        card = FakeCard(helper.ETH1_AID)
        with self.assertRaisesRegex(RuntimeError, 'NURI_ALLOW_ETH1_DEMO=1'):
            helper.card_sign(card, '00' * 32)
        self.assertEqual(card.apdus, [])
        os.environ['NURI_ALLOW_ETH1_DEMO'] = '1'
        self.assertEqual(len(helper.card_sign(card, '00' * 32)[0]), 128)
        with self.assertRaises(ValueError):
            helper.card_sign(card, '00' * 31)

    def test_json_always_includes_mode_and_closes_eth2(self):
        card = FakeCard(helper.ETH2_AID)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(helper, 'card_init', return_value=card), patch.object(sys, 'argv', ['helper', '--json']), patch.object(sys, 'stdin', io.StringIO('INIT\nSIGN ' + '00' * 32 + '\n')), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(helper.main(), 1)
        replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertTrue(all(reply['mode'] == 'card' for reply in replies))
        self.assertEqual(replies[0]['pin_required'], 1)
        self.assertIn('ETH2 PIN required', replies[-1]['error'])
        self.assertTrue(card.closed)
        self.assertEqual(card.apdus, [])

    def test_openssl_wrapper_rejects_unarmed_or_unknown_mode(self):
        for mode, args in ((None, []), ('card', []), ('unknown', []), ('', []), ('sim', ['--card']), (None, ['--card'])):
            env = {} if mode is None else {'NURI_PKCS11_MODE': mode}
            p = subprocess.run(['/bin/bash', str(ROOT / 'scripts/hsm-openssl-selftest.sh'), *args], env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(p.returncode, 64, p.stderr)

    def test_cli_sim_requires_env_and_warns(self):
        for env, args, expected in (({}, ['--sim'], 1), ({'NURI_PKCS11_MODE': 'sim'}, ['--sim'], 0), ({'NURI_PKCS11_MODE': 'sim'}, [], 0), ({'NURI_PKCS11_MODE': 'bogus'}, [], 1)):
            p = subprocess.run([sys.executable, str(ROOT / 'scripts/pkcs11-helper.py'), '--json', *args], input='INIT\nSLOTS\nFINALIZE\n', text=True, capture_output=True, env=env, timeout=20)
            self.assertEqual(p.returncode, expected, p.stderr)
            replies = [json.loads(line) for line in p.stdout.splitlines()]
            self.assertTrue(replies)
            self.assertTrue(all('mode' in reply for reply in replies))
            if not expected:
                self.assertIn('SIMULATOR', p.stderr)
                self.assertIn('SIMULATOR', replies[1]['slot_0_label'])


U = C.c_ulong
P = C.c_void_p
class FunctionList(C.Structure):
    _fields_ = [('version', C.c_ubyte * 2), ('functions', P * 68)]
class Mechanism(C.Structure):
    _fields_ = [('mechanism', U), ('parameter', P), ('length', U)]

FAKE_HELPER = '''import os, sys
mode = 'sim' if '--sim' in sys.argv else 'card'
case = os.environ.get('FAKE_CASE', 'ok')
applet = os.environ.get('FAKE_APPLET', 'ETH2') if mode == 'card' else 'SIMULATOR'
with open(os.environ['FAKE_LOG'], 'a') as log:
    log.write(mode + '\\n')
print('mode=' + ('sim' if case == 'wrongmode' else mode))
print('applet=' + applet)
print('pin_required=' + ('1' if applet == 'ETH2' and case != 'pinbypass' else '0'))
if case != 'missingkey':
    print('key_pubkey=' + ('bad' if case == 'badkey' else PUBKEY))
print('signature=' + ('zz' * 64 if case == 'badsig' else '00' * 64))
if case == 'error':
    print('error=denied')
sys.exit(1 if case == 'exitfail' else 0)
'''.replace('PUBKEY', repr(PUBKEY))


class NativePolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = os.environ.get('NURI_PKCS11_MODULE', str(ROOT / 'dist/pkcs11-nuri.so'))
        cls.lib = C.CDLL(cls.module)
        table = C.POINTER(FunctionList)()
        cls.lib.C_GetFunctionList(C.byref(table))
        cls.functions = table.contents.functions

    def call(self, index, types, *args):
        return C.CFUNCTYPE(U, *types)(self.functions[index])(*args)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.path = Path(self.temp.name)
        fake = self.path / 'fake-helper.py'
        fake.write_text(FAKE_HELPER)
        self.env = patch.dict(os.environ, {'NURI_PKCS11_HELPER': str(fake), 'NURI_PKCS11_PYTHON': sys.executable, 'FAKE_LOG': str(self.path / 'log'), 'TMPDIR': str(self.path)}, clear=True)
        self.env.start()
        self.call(1, [P], None)

    def tearDown(self):
        self.call(1, [P], None)
        self.env.stop()
        self.temp.cleanup()

    def init(self):
        return self.call(0, [P], None)

    def test_default_dispatches_card_and_eth2_pin_fails_closed(self):
        self.assertEqual(self.init(), 0)
        self.assertEqual((self.path / 'log').read_text(), 'card\n')
        session = U()
        self.assertEqual(self.call(12, [U, U, P, P, C.POINTER(U)], 1, 4, None, None, C.byref(session)), 0)
        self.assertEqual(self.call(18, [U, U, P, U], session, 1, b'1234', 4), 0x101)
        mechanism = Mechanism(0x1041, None, 0)
        self.assertEqual(self.call(42, [U, C.POINTER(Mechanism), U], session, C.byref(mechanism), 1), 0x101)
        data = C.create_string_buffer(bytes(32))
        signature, length = C.create_string_buffer(64), U(64)
        self.assertEqual(self.call(43, [U, P, U, P, C.POINTER(U)], session, data, 32, signature, C.byref(length)), 0x101)
        self.assertEqual((self.path / 'log').read_text(), 'card\n')

    @unittest.skipUnless(PKCS11_TOOL, 'pkcs11-tool not installed')
    def test_eth2_parent_qualification_with_fake_helper(self):
        os.environ['PKCS11_TOOL'] = PKCS11_TOOL
        os.environ['NURI_PKCS11_MODULE'] = self.module
        os.environ['NURI_PKCS11_MODE'] = 'card'
        p = subprocess.run([sys.executable, str(ROOT / 'scripts/test-pkcs11-e2e.py'), '--expect-pin-required'], text=True, capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('ETH2_PIN_FAILCLOSED_OK', p.stdout)

    def test_unknown_modes_rejected_before_helper(self):
        for mode in ('', 'SIM', 'sim ', 'bogus'):
            os.environ['NURI_PKCS11_MODE'] = mode
            self.assertEqual(self.init(), 7)
        self.assertFalse((self.path / 'log').exists())

    def test_no_reader_or_bad_helper_is_not_empty_success(self):
        for case in ('exitfail', 'missingkey', 'badkey', 'wrongmode', 'error', 'pinbypass'):
            os.environ['FAKE_CASE'] = case
            self.assertNotEqual(self.init(), 0, case)
        os.environ['FAKE_CASE'] = 'ok'
        self.assertEqual(self.init(), 0)

    def test_native_eth1_requires_exact_optin(self):
        os.environ['FAKE_APPLET'] = 'ETH1'
        for optin in ('', 'true', '1 '):
            os.environ['NURI_ALLOW_ETH1_DEMO'] = optin
            self.assertNotEqual(self.init(), 0)
        os.environ['NURI_ALLOW_ETH1_DEMO'] = '1'
        self.assertEqual(self.init(), 0)

    def test_mode_change_after_init_does_not_switch_to_sim(self):
        os.environ['FAKE_APPLET'] = 'ETH1'
        os.environ['NURI_ALLOW_ETH1_DEMO'] = '1'
        self.assertEqual(self.init(), 0)
        os.environ['NURI_PKCS11_MODE'] = 'sim'
        # Frozen native dispatch continues --card; no software fallback.
        signature, length = C.create_string_buffer(64), U(64)
        self.assertEqual(self.call(43, [U, P, U, P, C.POINTER(U)], 1, bytes(32), 32, signature, C.byref(length)), 0)
        self.assertEqual((self.path / 'log').read_text(), 'card\ncard\n')

    def test_malformed_signature_rejected(self):
        os.environ['NURI_PKCS11_MODE'] = 'sim'
        self.assertEqual(self.init(), 0)
        os.environ['FAKE_CASE'] = 'badsig'
        signature, length = C.create_string_buffer(64), U(64)
        self.assertNotEqual(self.call(43, [U, P, U, P, C.POINTER(U)], 1, bytes(32), 32, signature, C.byref(length)), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
