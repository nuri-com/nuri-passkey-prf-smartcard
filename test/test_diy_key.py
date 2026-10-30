"""DIY wizard regressions: fake gp, no reader/card and no network."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/diy-key.sh"
spec = importlib.util.spec_from_file_location("diy_key_tests_subject", ROOT / "scripts/card_lock.py")
assert spec is not None and spec.loader is not None
lock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lock)
PASSWORD = b"owner-only-test-passphrase-2026"
SERIAL = "12345678"
DEFAULT = lock.DEFAULT_KEY
CPLC = "".join(SERIAL if field == "ICSerialNumber" else "01" * size
               for field, size in lock.CPLC_FIELDS)


class DiyKeyTest(unittest.TestCase):
    def setUp(self):
        build = ROOT / ".build"
        build.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="diy-test-", dir=build)
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.private = self.home / ".nuri-card"
        self.private.mkdir(mode=0o700)
        self.deny = self.private / "no-lock-cplc.txt"
        self.deny.write_text("# Owner's blocked card serials\n")
        self.deny.chmod(0o600)
        self.escrow = self.private / "escrow" / (CPLC + ".json")
        self.log = self.home / "calls.jsonl"
        self.state = self.home / "state.json"
        self.state.write_text(json.dumps({"keys": dict.fromkeys(("enc", "mac", "dek"), DEFAULT)}))
        self.bin = self.home / "bin"
        self.bin.mkdir()
        gp = self.bin / "gp"
        gp.write_text(f'#!{sys.executable}\nimport runpy\n'
                      f'runpy.run_path({str(ROOT / "test/fake_gp_lock.py")!r}, run_name="__main__")\n')
        gp.chmod(0o700)
        self.gp = gp
        self.env = {**os.environ, "HOME": str(self.home), "GP_BIN": str(gp),
                    "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "PYTHON_BIN": sys.executable, "FAKE_GP_STATE": str(self.state),
                    "FAKE_GP_ESCROW": str(self.escrow), "FAKE_GP_LOG": str(self.log)}

    # ------------------------------------------------------------- helpers
    def change(self, **fields):
        state = json.loads(self.state.read_text())
        state.update(fields)
        self.state.write_text(json.dumps(state))

    def run_wizard(self, args=(), stdin="", password=PASSWORD, env=None):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, password + b"\n")
        os.close(write_fd)
        try:
            return subprocess.run(["bash", str(SCRIPT), *args, "--passphrase-fd", "3"],
                                  input=stdin, capture_output=True, text=True,
                                  env=self.env if env is None else env,
                                  pass_fds=(read_fd,),
                                  preexec_fn=lambda: os.dup2(read_fd, 3),
                                  timeout=90, cwd=str(ROOT))
        finally:
            os.close(read_fd)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def lock(self, **kwargs):
        return self.run_wizard(["--reader", "Fake reader", "--yes"], stdin=SERIAL + "\n", **kwargs)

    # --------------------------------------------------------------- cases
    def test_lock_end_to_end(self):
        result = self.lock()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CARD_LOCK_VERIFIED", result.stdout)
        self.assertTrue(self.escrow.is_file())
        self.assertEqual(stat.S_IMODE(self.escrow.stat().st_mode), 0o600)
        self.assertIn(str(self.escrow), result.stdout)

    def test_unlock_end_to_end_via_picker(self):
        self.assertEqual(self.lock().returncode, 0)
        result = self.run_wizard(["unlock", "--reader", "Fake reader", "--yes"],
                                 stdin="1\n" + SERIAL + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CARD_DEFAULT_KEYS_RESTORED_VERIFIED", result.stdout)
        state = json.loads(self.state.read_text())
        self.assertEqual(set(state["keys"].values()), {DEFAULT})

    def test_missing_denylist_created_with_header(self):
        self.deny.unlink()
        result = self.run_wizard(["--reader", "Fake reader", "--yes"], stdin="\n" + SERIAL + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.deny.is_file())
        self.assertEqual(stat.S_IMODE(self.deny.stat().st_mode), 0o600)
        self.assertTrue(self.deny.read_text().splitlines()[0].startswith("#"))

    def test_missing_denylist_invalid_thrice(self):
        self.deny.unlink()
        result = self.run_wizard(["--reader", "Fake reader", "--yes"], stdin="XYZ\n" * 3)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(self.deny.exists())

    def test_reader_picker_passes_exact_second_name(self):
        # Distinct names: "Fake reader 01" style suffixes are ambiguous for the fake.
        first, second = "Alpha reader", "Bravo reader"
        self.change(readers=[first, second], card_readers=[first, second], target_reader=second)
        result = self.run_wizard(["--yes"], stdin="2\n" + SERIAL + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        chosen = [call["args"][1] for call in self.calls()
                  if call["args"][:1] == ["--reader"] and len(call["args"]) > 1]
        self.assertTrue(chosen)
        self.assertEqual(set(chosen), {second})

    def test_jar_install_and_no_reader_hint(self):
        jar = self.home / "gp.jar"
        blob = b"not really a jar\n" * 8
        jar.write_bytes(blob)
        env = dict(self.env)
        env.pop("GP_BIN")
        env["NURI_GP_URL"] = "file://" + str(jar)
        env["NURI_GP_SIZE"] = str(len(blob))
        env["NURI_GP_SHA256"] = hashlib.sha256(blob).hexdigest()
        stub = self.bin / "java"
        stub.write_text('#!/bin/sh\ncase "$*" in\n'
                        '  *-version*) echo \'openjdk version "21.0.1" 2023-10-17\' >&2; exit 0 ;;\n'
                        'esac\necho "Available readers:"\n')
        stub.chmod(0o700)
        result = self.run_wizard(["--yes"], stdin="\n", env=env)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("No card reader", result.stdout)
        installed = self.private / "tools/gp-24.10.15.jar"
        wrapper = self.private / "tools/gp-24.10.15"
        self.assertEqual(installed.read_bytes(), blob)
        self.assertEqual(stat.S_IMODE(wrapper.stat().st_mode), 0o700)
        self.assertIn("exec java -jar", wrapper.read_text())

    def test_jar_wrong_sha_leaves_nothing(self):
        jar = self.home / "gp.jar"
        blob = b"tampered\n"
        jar.write_bytes(blob)
        env = dict(self.env)
        env.pop("GP_BIN")
        env["NURI_GP_URL"] = "file://" + str(jar)
        env["NURI_GP_SIZE"] = str(len(blob))
        env["NURI_GP_SHA256"] = "0" * 64
        result = self.run_wizard(["--yes"], stdin="\n", env=env)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        tools = self.private / "tools"
        self.assertFalse((tools / "gp-24.10.15.jar").exists())
        self.assertFalse((tools / "gp-24.10.15").exists())
        self.assertEqual(list(tools.iterdir()), [])

    def test_help_creates_nothing(self):
        empty = self.home / "empty-home"
        empty.mkdir()
        result = self.run_wizard(["--help"], env={**self.env, "HOME": str(empty)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Usage:", result.stdout)
        self.assertEqual(list(empty.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
