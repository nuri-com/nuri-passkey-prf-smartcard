"""Synthetic installer fixture: GP_BIN always a fake; no reader/card imported."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FAKE_GP = '''#!/usr/bin/env python3
import json, os, pathlib, sys
args=sys.argv[1:]
root=pathlib.Path(os.environ['FIXTURE'])
with (root/'log').open('a') as out: out.write(json.dumps(args)+'\\n')
if any(a in ('--delete','--uninstall','--force','-f') for a in args): raise SystemExit(99)
if '-l' in args:
    after=(root/'installed').exists()
    registry=['APP: A0000006472F0001 (FIDO2)', 'APP: 4E55524945544801 (ETH)', 'PKG: AABBCCDDEE']
    if os.environ.get('PRE_PACKAGE'): registry.append('PKG: 4E555249564C54')
    if after or os.environ.get('PRE_INSTALLED'): registry.append('APP: 4E555249564C5401 (vault)')
    if os.environ.get('NO_FIDO') or (after and os.environ.get('LOSE_FIDO')): registry=[r for r in registry if 'A0000006472F0001' not in r]
    if after and os.environ.get('LOSE_ETH'): registry=[r for r in registry if '4E55524945544801' not in r]
    if after and os.environ.get('NO_VAULT'): registry=[r for r in registry if '4E555249564C5401' not in r]
    if os.environ.get('PREFIX_FIDO'): registry=[r.replace('A0000006472F0001', 'A0000006472F000100') for r in registry]
    print('\\n'.join(registry))
elif '--install' in args or '--create' in args:
    if os.environ.get('FAIL_INSTALL'): raise SystemExit(7)
    (root/'installed').touch()
else: raise SystemExit(98)
'''

class InstallerTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'scripts').mkdir()
        (self.root / 'dist').mkdir()
        shutil.copy2(ROOT / 'scripts/install-vault-card.sh', self.root / 'scripts/install-vault-card.sh')
        (self.root / 'dist/nuri-vault.cap').write_bytes(b'UNMISTAKABLE_SYNTHETIC_CAP_NOT_A_REAL_PACKAGE')
        digest = hashlib.sha256((self.root / 'dist/nuri-vault.cap').read_bytes()).hexdigest()
        (self.root / 'dist/SHA256SUMS').write_text(digest + '  nuri-vault.cap\n')
        self.gp = self.root / 'fake-gp'
        self.gp.write_text(FAKE_GP)
        self.gp.chmod(0o700)

    def run_fixture(self, *argv, **overrides):
        env = {k: v for k, v in os.environ.items() if not k.startswith(('GP_', 'VAULT_'))}
        env.update(GP_BIN=str(self.gp), FIXTURE=str(self.root), **overrides)
        result = subprocess.run(['bash', str(self.root / 'scripts/install-vault-card.sh'), *argv], env=env, capture_output=True, text=True)
        log = self.root / 'log'
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        for call in calls:
            self.assertTrue(not set(call) & {'--delete', '--uninstall', '-f', '--force'}, call)
        return result, calls

    def test_happy_install_reads_back(self):
        result, calls = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [['-l'], ['--install', str(self.root / 'dist/nuri-vault.cap')], ['-l']])
        self.assertIn('VAULT_INSTALLED_ALONGSIDE_FIDO2', result.stdout)

    def test_already_installed_never_replaces(self):
        result, calls = self.run_fixture(PRE_INSTALLED='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [['-l']])

    def test_existing_package_only_creates(self):
        result, calls = self.run_fixture(PRE_PACKAGE='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[1], ['--package', '4E555249564C54', '--applet', '4E555249564C5401', '--create', '4E555249564C5401'])
        self.assertEqual(calls[-1], ['-l'])

    def test_fido_required_exact_aid(self):
        for mode in ('NO_FIDO', 'PREFIX_FIDO'):
            with self.subTest(mode=mode):
                (self.root / 'log').unlink(missing_ok=True)
                result, calls = self.run_fixture(**{mode: '1'})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [['-l']])

    def test_readback_asserts_fido_and_all_old_applets(self):
        for mode in ('LOSE_FIDO', 'LOSE_ETH', 'NO_VAULT'):
            with self.subTest(mode=mode):
                (self.root / 'log').unlink(missing_ok=True)
                (self.root / 'installed').unlink(missing_ok=True)
                result, calls = self.run_fixture(**{mode: '1'})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls[-1], ['-l'])
                self.assertIn('ASSERT FAILED', result.stderr)

    def test_rejects_every_extra_flag_before_gp(self):
        for variable in ('GP_EXTRA_ARGS', 'GP_ARGS_EXTRA'):
            for flag in ('--delete A0000006472F0001', '--uninstall X', '--force', '-f', '--debug'):
                with self.subTest(variable=variable, flag=flag):
                    result, calls = self.run_fixture(**{variable: flag})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(calls, [])

    def test_script_arguments_refused(self):
        result, calls = self.run_fixture('--delete', 'A0000006472F0001')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_bad_hash_fails_before_gp(self):
        (self.root / 'dist/nuri-vault.cap').write_bytes(b'tampered')
        result, calls = self.run_fixture()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_missing_or_duplicate_hash_fails_before_gp(self):
        manifest = self.root / 'dist/SHA256SUMS'
        original = manifest.read_text()
        for data in ('', original + original):
            manifest.write_text(data)
            result, calls = self.run_fixture()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])

    def test_dry_run_does_not_install(self):
        result, calls = self.run_fixture(VAULT_DRY_RUN='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [['-l']])

    def test_install_failure_propagated(self):
        result, calls = self.run_fixture(FAIL_INSTALL='1')
        self.assertEqual(result.returncode, 7)
        self.assertEqual(len(calls), 2)

    def test_reader_is_single_argument(self):
        result, calls = self.run_fixture(GP_READER='FAKE reader --delete A0000006472F0001')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(c[:2] == ['-r', 'FAKE reader --delete A0000006472F0001'] for c in calls))

if __name__ == '__main__':
    unittest.main()
