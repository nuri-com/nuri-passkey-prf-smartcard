"""Fake-gp-only key sealing regressions; no reader/card calls."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("card_lock_tests_subject", ROOT / "scripts/card_lock.py")
assert spec is not None and spec.loader is not None
lock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lock)
PASSWORD = b"owner-only-test-passphrase-2026"


class CardLockTest(unittest.TestCase):
    def setUp(self):
        build = ROOT / ".build"
        build.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="lock-test-", dir=build)
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.private = self.home / ".nuri-card"
        self.private.mkdir(mode=0o700)
        self.deny = self.private / "no-lock-cplc.txt"
        self.deny.write_text("# Owner's blocked card serials or complete CPLC values\n")
        self.deny.chmod(0o600)
        self.escrow = self.private / "keys.json"
        self.log = self.home / "calls.jsonl"
        self.state = self.home / "state.json"
        self.initial = dict.fromkeys(("enc", "mac", "dek"), lock.DEFAULT_KEY)
        self.state.write_text(json.dumps({"keys": self.initial}))
        self.bin = self.home / "bin"
        self.bin.mkdir()
        gp = self.bin / "gp"
        gp.write_text(f'#!{sys.executable}\nimport runpy\nrunpy.run_path({str(ROOT / "test/fake_gp_lock.py")!r}, run_name="__main__")\n')
        gp.chmod(0o700)
        self.env = {**os.environ, "HOME": str(self.home), "GP_BIN": "gp",
                    "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "PYTHON_BIN": sys.executable, "FAKE_GP_STATE": str(self.state),
                    "FAKE_GP_ESCROW": str(self.escrow), "FAKE_GP_LOG": str(self.log)}

    def change(self, **fields):
        state = json.loads(self.state.read_text())
        state.update(fields)
        self.state.write_text(json.dumps(state))

    def run_script(self, action="lock", execute=True, password=PASSWORD, serial="12345678",
                   reader="Fake reader", extra=()):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, password + b"\n")
        os.close(write_fd)
        try:
            return subprocess.run(["bash", str(ROOT / f"scripts/{action}-card.sh"),
                                   *(["--execute"] if execute else []),
                                   "--reader", reader, "--escrow", str(self.escrow),
                                   "--passphrase-fd", str(read_fd), *extra],
                                  input=serial + "\n", capture_output=True, text=True,
                                  env=self.env, pass_fds=(read_fd,), timeout=40)
        finally:
            os.close(read_fd)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def rotations(self):
        return [c for c in self.calls() if "--lock-enc" in c["args"]]

    def assert_refused_without_rotation(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.rotations(), [])
        self.assertEqual(json.loads(self.state.read_text())["keys"], self.initial)
        self.assertNotIn("CARD_LOCK_VERIFIED", result.stdout)

    def test_dry_run_no_process_no_files(self):
        for action in ("lock", "unlock"):
            result = self.run_script(action=action, execute=False)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.log.exists())
        self.assertFalse(self.escrow.exists())

    def test_denylisted_serial_refuses_before_auth(self):
        self.deny.write_text("12345678 # demo card\n")
        self.assert_refused_without_rotation(self.run_script())
        self.assertFalse(any("-l" in c["args"] for c in self.calls()))

    def test_full_cplc_denylist(self):
        cplc = "".join("12345678" if f == "ICSerialNumber" else "01" * n for f, n in lock.CPLC_FIELDS)
        self.deny.write_text(cplc + "\n")
        self.assert_refused_without_rotation(self.run_script())

    def test_missing_denylist_fails_closed(self):
        self.deny.unlink()
        self.assert_refused_without_rotation(self.run_script())

    def test_malformed_denylist_fails_closed(self):
        self.deny.write_text("not-a-card\n")
        self.assert_refused_without_rotation(self.run_script())

    def test_missing_each_required_applet(self):
        for aid in lock.REQUIRED_APPS:
            with self.subTest(aid=aid):
                self.change(missing_apps=[aid])
                self.assert_refused_without_rotation(self.run_script())
        self.assertFalse(self.escrow.exists())

    def test_wrong_serial_refuses(self):
        self.assert_refused_without_rotation(self.run_script(serial="00000000"))
        self.assertFalse(self.escrow.exists())

    def test_exact_gp_version_required(self):
        for version in ("v25.01.01", "v24.10.15-1-gdeadbeef", "v24.10.15-dirty"):
            with self.subTest(version=version):
                self.change(version=version)
                self.assert_refused_without_rotation(self.run_script())

    def test_factory_extra_and_unknown_keysets_refused(self):
        for fields in ({"key_versions": [0]}, {"key_versions": [255]},
                       {"key_versions": [1, 2]}, {"key_versions": [1], "key_type": "RSA"}):
            with self.subTest(fields=fields):
                self.change(**fields)
                self.assert_refused_without_rotation(self.run_script())

    def test_mixed_aes_des3_keyset_refused(self):
        self.change(key_types={"1": "AES", "2": "DES3", "3": "AES"})
        self.assert_refused_without_rotation(self.run_script())
        self.assertFalse(self.escrow.exists())

    def test_scp01_scp02_version_ranges_refused_before_rotation(self):
        for version in (0x10, 0x1F, 0x20, 0x2F):
            with self.subTest(version=version):
                self.change(key_versions=[version])
                self.assert_refused_without_rotation(self.run_script())
        self.assertFalse(self.escrow.exists())

    def test_scp03_version_30_lock_unlock(self):
        self.change(key_versions=[0x30])
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.run_script(action="unlock").returncode, 0)
        self.assertEqual(json.loads(self.state.read_text())["keys"], self.initial)

    def test_new_directory_publication_fsynced(self):
        events = []
        real_mkdir, real_fsync = os.mkdir, os.fsync

        def mkdir(path, mode=0o777, *, dir_fd=None):
            result = real_mkdir(path, mode, dir_fd=dir_fd)
            events.append(("mkdir", os.fstat(dir_fd).st_ino))
            return result

        def fsync(fd):
            events.append(("fsync", os.fstat(fd).st_ino))
            return real_fsync(fd)

        target = self.private / "new-a/new-b/keys.json"
        with mock.patch.object(lock.os, "mkdir", side_effect=mkdir), mock.patch.object(lock.os, "fsync", side_effect=fsync):
            lock.atomic_escrow(target, b"ciphertext")
        published = [i for i, event in enumerate(events) if event[0] == "mkdir"]
        self.assertEqual(len(published), 2)
        for index in published:
            self.assertEqual(events[index + 1], ("fsync", events[index][1]))
        self.assertEqual(target.read_bytes(), b"ciphertext")

    def test_malformed_cplc_refuses(self):
        self.change(malformed_cplc=True)
        self.assert_refused_without_rotation(self.run_script())

    def test_encrypted_escrow_before_rotation_and_verify_required(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CARD_LOCK_VERIFIED", result.stdout)
        self.assertEqual(len(self.rotations()), 1)
        rotation = self.rotations()[0]
        self.assertTrue(rotation["escrow_exists"])
        self.assertEqual(rotation["mode"], 0o600)
        payload = lock.decrypt(self.escrow.read_bytes(), PASSWORD)
        self.assertEqual(payload["old_keys"], self.initial)
        self.assertEqual(len(set(payload["new_keys"].values())), 3)
        self.assertEqual(payload["new_keys"], json.loads(self.state.read_text())["keys"])
        for key in payload["new_keys"].values():
            self.assertNotIn(key, self.escrow.read_text())
            self.assertNotIn(key, result.stdout + result.stderr)
        commands = [c["args"] for c in self.calls()]
        position = next(i for i, a in enumerate(commands) if "--lock-enc" in a)
        self.assertIn("-l", commands[position + 1])
        self.assertEqual(commands[position + 1][commands[position + 1].index("--key-enc") + 1], payload["new_keys"]["enc"])
        self.assertEqual(rotation["args"][rotation["args"].index("--new-keyver") + 1], "0x01")
        self.assertEqual(stat.S_IMODE(self.escrow.stat().st_mode), 0o600)

    def test_verify_failure_never_reports_success_or_deletes_escrow(self):
        self.change(fail_verify=True)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UNVERIFIED", result.stderr)
        self.assertNotIn("CARD_LOCK_VERIFIED", result.stdout)
        payload = lock.decrypt(self.escrow.read_bytes(), PASSWORD)
        self.assertEqual(payload["old_keys"], self.initial)
        self.assertEqual(payload["new_keys"], json.loads(self.state.read_text())["keys"])
        for key in payload["new_keys"].values():
            self.assertNotIn(key, result.stdout + result.stderr)
        self.assertEqual(len(self.rotations()), 1)  # never silently roll back

    def test_partial_failure_preserves_old_keys_and_escrow(self):
        self.change(rotate_fail=True)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.state.read_text())["keys"], self.initial)
        self.assertEqual(lock.decrypt(self.escrow.read_bytes(), PASSWORD)["old_keys"], self.initial)
        self.assertIn("UNVERIFIED", result.stderr)

    def test_response_loss_keeps_both_keysets_no_rollback(self):
        self.change(fail_after_commit=True)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        payload = lock.decrypt(self.escrow.read_bytes(), PASSWORD)
        self.assertEqual(json.loads(self.state.read_text())["keys"], payload["new_keys"])
        self.assertEqual(payload["old_keys"], self.initial)
        self.assertEqual(len(self.rotations()), 1)

    def test_unlock_restores_defaults_and_retains_escrow(self):
        self.assertEqual(self.run_script().returncode, 0)
        before = self.escrow.read_bytes()
        result = self.run_script(action="unlock")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CARD_DEFAULT_KEYS_RESTORED_VERIFIED", result.stdout)
        self.assertEqual(json.loads(self.state.read_text())["keys"], self.initial)
        self.assertEqual(self.escrow.read_bytes(), before)

    def test_wrong_passphrase_unlock_no_gp_call(self):
        self.assertEqual(self.run_script().returncode, 0)
        self.log.unlink()
        result = self.run_script(action="unlock", password=b"wrong-passphrase-123456")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertTrue(self.escrow.exists())

    def test_ciphertext_tamper_fails_authentication(self):
        self.assertEqual(self.run_script().returncode, 0)
        data = json.loads(self.escrow.read_text())
        data["ciphertext"] = ("01" if data["ciphertext"][:2] != "01" else "02") + data["ciphertext"][2:]
        self.escrow.write_text(json.dumps(data))
        self.log.unlink()
        self.assertNotEqual(self.run_script(action="unlock").returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_existing_escrow_never_overwritten(self):
        self.escrow.write_text("keep-me")
        self.escrow.chmod(0o600)
        self.assert_refused_without_rotation(self.run_script())
        self.assertEqual(self.escrow.read_text(), "keep-me")

    def test_symlink_escrow_refuses_no_target_write(self):
        target = self.private / "owner-file"
        target.write_text("keep-me")
        self.escrow.symlink_to(target)
        self.assert_refused_without_rotation(self.run_script())
        self.assertEqual(target.read_text(), "keep-me")

    def test_parent_symlink_refuses(self):
        real = self.home / "real"
        real.mkdir(mode=0o700)
        linked = self.home / "linked"
        linked.symlink_to(real, target_is_directory=True)
        self.escrow = linked / "keys.json"
        self.assert_refused_without_rotation(self.run_script(extra=("--escrow", str(self.escrow))))
        self.assertFalse((real / "keys.json").exists())

    def test_insecure_denylist_permissions_refuse(self):
        self.deny.chmod(0o644)
        self.assert_refused_without_rotation(self.run_script())

    def test_weak_passphrase_refuses_without_escrow(self):
        self.assert_refused_without_rotation(self.run_script(password=b"short"))
        self.assertFalse(self.escrow.exists())

    def test_wrong_card_escrow_refuses(self):
        self.assertEqual(self.run_script().returncode, 0)
        self.change(other_card=True)
        before = len(self.rotations())
        self.assertNotEqual(self.run_script(action="unlock").returncode, 0)
        self.assertEqual(len(self.rotations()), before)

    def test_des3_lock_unlock_odd_parity_and_escrow_type(self):
        self.change(key_type="DES3")
        locked = self.run_script()
        self.assertEqual(locked.returncode, 0, locked.stderr)
        self.assertIn("key type: DES3", locked.stdout)
        payload = lock.decrypt(self.escrow.read_bytes(), PASSWORD)
        self.assertEqual(payload["key_type"], "DES3")
        for key in payload["new_keys"].values():
            self.assertTrue(all(bin(byte).count("1") % 2 == 1 for byte in bytes.fromhex(key)))
        self.assertTrue(self.rotations()[0]["new_keys_odd_parity"])
        unlocked = self.run_script(action="unlock")
        self.assertEqual(unlocked.returncode, 0, unlocked.stderr)
        self.assertEqual(len(self.rotations()), 2)
        self.assertEqual(json.loads(self.state.read_text())["keys"], self.initial)

    def test_unlock_key_type_mismatch_refused_before_rotation(self):
        self.change(key_type="DES3")
        self.assertEqual(self.run_script().returncode, 0)
        before = len(self.rotations())
        locked_keys = json.loads(self.state.read_text())["keys"]
        self.change(key_type="AES")
        result = self.run_script(action="unlock")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("key type", result.stderr)
        self.assertEqual(len(self.rotations()), before)
        self.assertEqual(json.loads(self.state.read_text())["keys"], locked_keys)

    def test_legacy_escrow_without_key_type_unlocks_aes(self):
        self.assertEqual(self.run_script().returncode, 0)
        payload = lock.decrypt(self.escrow.read_bytes(), PASSWORD)
        payload.pop("key_type")
        self.escrow.write_bytes(lock.encrypt(payload, PASSWORD))
        result = self.run_script(action="unlock")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.state.read_text())["keys"], self.initial)

    def test_dual_slot_exact_reader_sets_ignore_for_every_card_call(self):
        contact = "HID Global OMNIKEY 5422 Smartcard Reader"
        other = contact + " 01"
        self.change(readers=[other, contact], card_readers=[other, contact], target_reader=contact)
        result = self.run_script(reader=contact)
        self.assertEqual(result.returncode, 0, result.stderr)
        card_calls = [call for call in self.calls()
                      if call["args"] not in (["--version"], ["--reader"])]
        self.assertTrue(card_calls)
        for call in card_calls:
            self.assertEqual(call["GP_READER_IGNORE"], other)

    def test_dual_slot_reader_01_is_refused_as_ambiguous(self):
        contact = "HID Global OMNIKEY 5422 Smartcard Reader"
        other = contact + " 01"
        self.change(readers=[contact, other], card_readers=[contact, other], target_reader=other)
        result = self.run_script(reader=other)
        self.assert_refused_without_rotation(result)
        self.assertIn("gp could not select exactly this reader; leave only the target card inserted",
                      result.stderr)
        self.assertFalse(self.escrow.exists())

    def test_reader_substring_is_not_exact_match(self):
        contact = "HID Global OMNIKEY 5422 Smartcard Reader"
        other = contact + " 01"
        self.change(readers=[other, contact], card_readers=[other, contact], target_reader=contact)
        result = self.run_script(reader="OMNIKEY")
        self.assert_refused_without_rotation(result)
        self.assertEqual([call["args"] for call in self.calls()], [["--version"], ["--reader"]])
        self.assertFalse(self.escrow.exists())

    def test_semicolon_in_reader_name_refused(self):
        self.change(readers=["Fake;reader"])
        result = self.run_script(reader="Fake;reader")
        self.assert_refused_without_rotation(result)
        self.assertFalse(self.escrow.exists())

    def test_inherited_gp_environment_is_not_forwarded(self):
        self.env["GP_READER_IGNORE"] = "x"
        self.env["GP_TRACE"] = "1"
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        for call in self.calls():
            self.assertIsNone(call["GP_READER_IGNORE"])
            self.assertIsNone(call["GP_TRACE"])


if __name__ == "__main__":
    unittest.main()
