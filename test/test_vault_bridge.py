"""End-to-end Python card backend -> actual Java applet in jCardSim, no PC/SC."""
import contextlib
import hashlib
import hmac
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import nuri_pcsc
spec = importlib.util.spec_from_file_location('vault_bridge_cli', ROOT / 'scripts/card-secrets.py')
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)

class Stdin(io.TextIOWrapper):
    def __init__(self, value): super().__init__(io.BytesIO(value))
    def isatty(self): return False

class Connection:
    def __init__(self, bridge): self.bridge, self.closed = bridge, False
    def transmit(self, apdu):
        assert not self.closed
        return self.bridge.tx(apdu)
    def close(self): self.closed = True

class VaultBridgeTest(unittest.TestCase):
    def setUp(self):
        build = Path(os.environ.get('VAULT_SIM_BUILD', ROOT / '.build/vault-sim'))
        jar = build / 'jcardsim-3.0.5.11.jar'
        self.assertTrue(jar.exists(), 'run bash scripts/test-vault-sim.sh first (no silent skip)')
        self.bridge = subprocess.Popen(['java', '-cp', str(build / 'classes') + os.pathsep + str(jar), 'test.vault.VaultApduBridge'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.cleanup_bridge)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.apdus = []

    def cleanup_bridge(self):
        self.bridge.stdin.close()
        self.bridge.wait(timeout=10)
        errors = self.bridge.stderr.read()
        self.bridge.stdout.close()
        self.bridge.stderr.close()
        self.assertEqual(self.bridge.returncode, 0, errors)

    def tx(self, apdu):
        self.apdus.append(bytes(apdu))
        self.bridge.stdin.write(bytes(apdu).hex() + '\n')
        self.bridge.stdin.flush()
        raw = bytes.fromhex(self.bridge.stdout.readline().strip())
        self.assertGreaterEqual(len(raw), 2)
        return raw[:-2], int.from_bytes(raw[-2:], 'big')

    def open(self, aid):
        self.assertEqual(aid, cs.VAULT_AID)
        self.assertEqual(self.tx(nuri_pcsc.select_apdu(aid))[1], 0x9000)
        return Connection(self)

    def cli(self, *args, value=b'', pins=('123456',)):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(nuri_pcsc, 'open_applet', side_effect=self.open), patch.object(cs.getpass, 'getpass', side_effect=pins), patch.object(sys, 'argv', ['card-secrets.py', '--backend', 'card', *args]), patch.object(sys, 'stdin', Stdin(value)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cs.main()
        return code, out.getvalue(), err.getvalue()

    def test_broker_contract_against_actual_applet(self):
        code, out, err = self.cli('init', pins=('123456', '123456'))
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)['initialized'])
        key = bytes(range(64))
        self.assertEqual(self.cli('put', 'SIGN', '--kind', 'hmac', value=key)[0], 0)
        self.assertEqual(self.cli('put', 'TOKEN', value=b'bridge-bearer-sentinel')[0], 0)
        code, out, err = self.cli('list')
        self.assertEqual(code, 0, err)
        self.assertEqual({x['name']: x['kind'] for x in json.loads(out)}, {'SIGN': 'hmac', 'TOKEN': 'bearer'})
        message = self.tmp / 'message'
        message.write_bytes(b'actual-python-to-java-card-apdu')
        before = len(self.apdus)
        code, out, err = self.cli('hmac', 'SIGN', '--data-file', str(message))
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), hmac.new(key, message.read_bytes(), hashlib.sha256).hexdigest())
        self.assertNotIn(0x41, [a[1] for a in self.apdus[before:]])
        with patch.object(cs.subprocess, 'run') as run:
            code, out, err = self.cli('run', 'SIGN', '--', 'never-executed-child')
            self.assertEqual(code, 1)
            run.assert_not_called()
        with patch.object(cs.subprocess, 'run') as run:
            run.return_value.returncode = 0
            code, out, err = self.cli('run', 'TOKEN', '--', 'trusted-fixture-child')
            self.assertEqual(code, 0, err)
            self.assertEqual(run.call_args.kwargs['env']['NURI_SECRET_TOKEN'], 'bridge-bearer-sentinel')
        with patch.object(cs, 'proxy') as proxy:
            code, out, err = self.cli('proxy', 'TOKEN', '--upstream', 'https://api.example.com/v1')
            self.assertEqual(code, 0, err)
            self.assertEqual(proxy.call_args.args[1], b'bridge-bearer-sentinel')
        self.assertEqual(self.cli('list', pins=('999999',))[0], 1)
        self.assertEqual(self.cli('list')[0], 0)
        self.assertEqual(self.cli('rm', 'SIGN')[0], 0)
        code, out, err = self.cli('list')
        self.assertEqual(json.loads(out), [{'kind': 'bearer', 'name': 'TOKEN'}])
        self.assertEqual(self.cli('hmac', 'SIGN', '--data-file', str(message))[0], 1)

if __name__ == '__main__':
    unittest.main()
