"""card-setup regressions: fake gp and fake pyscard, no reader and no network."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/card-setup.sh"
SERIAL = "12345678"
DEFAULT_KEY = "404142434445464748494A4B4C4D4E4F"
ALL_AIDS = [
    "A0000006472F0001", "4E5552494D554701", "4E555249544F5450",
    "4E5552494554483201", "4E5552494D55473201", "4E5552494D55473301", "4E555249564C5401",
]
LEGACY_ETH1_AID = "4E55524945544801"
EXPECTED_CAPS = [
    "FIDO2-up.cap", "nuri-musig2-v20-keygen.cap", "nuri-oath-totp.cap",
    "nuri-eth2-signer.cap", "nuri-musig2-v20-keygen-aid2.cap", "nuri-musig2-v20-keygen-aid3.cap",
    "nuri-vault.cap",
]


class CardSetupTest(unittest.TestCase):
    def setUp(self):
        build = ROOT / ".build"
        build.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="setup-test-", dir=build)
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        private = self.home / ".nuri-card"
        private.mkdir(mode=0o700)
        self.deny = private / "no-lock-cplc.txt"
        self.deny.write_text("# Owner's blocked card serials\n")
        self.deny.chmod(0o600)
        self.state = self.home / "card.json"
        self.write_state()
        self.log = self.home / "calls.jsonl"
        self.bin = self.home / "bin"
        self.bin.mkdir()
        gp = self.bin / "gp"
        gp.write_text(f'#!{sys.executable}\nimport runpy\n'
                      f'runpy.run_path({str(ROOT / "test/fake_gp_setup.py")!r}, run_name="__main__")\n')
        gp.chmod(0o700)
        self.env = {
            **os.environ,
            "HOME": str(self.home),
            "GP_BIN": str(gp),
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "PYTHON_BIN": sys.executable,
            "PYTHONPATH": os.pathsep.join(
                [str(ROOT / "test/fake_pyscard"), *filter(None, [os.environ.get("PYTHONPATH")])]),
            "FAKE_GP_STATE": str(self.state),
            "FAKE_GP_LOG": str(self.log),
            "FAKE_CARD_STATE": str(self.state),
        }
        stub = self.bin / "java"
        stub.write_text('#!/bin/sh\ncase "$*" in\n'
                        '  *-version*) echo \'openjdk version "21.0.1" 2023-10-17\' >&2; exit 0 ;;\n'
                        'esac\nexit 0\n')
        stub.chmod(0o700)

    # ------------------------------------------------------------- helpers
    def write_state(self, **fields):
        state = {"key": DEFAULT_KEY, "aids": [], "serial": SERIAL,
                 "readers": ["Fake reader"], "target": "Fake reader"}
        state.update(fields)
        self.state.write_text(json.dumps(state))

    def card(self):
        return json.loads(self.state.read_text())

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def installs(self):
        caps = []
        for call in self.calls():
            for flag in ("--install", "--load"):
                if flag in call["args"]:
                    caps.append(Path(call["args"][call["args"].index(flag) + 1]).name)
        return caps

    def auth_calls(self):
        return [call for call in self.calls() if call.get("auth")]

    def run_setup(self, args=(), stdin="", env=None):
        return subprocess.run(["bash", str(SCRIPT), "--reader", "Fake reader", *args],
                              input=stdin, capture_output=True, text=True,
                              env=self.env if env is None else env,
                              timeout=180, cwd=str(ROOT))

    # --------------------------------------------------------------- cases
    def test_blank_card_installs_all_seven_in_order(self):
        result = self.run_setup(stdin=SERIAL + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"CARD_SETUP_VERIFIED {SERIAL}", result.stdout)
        self.assertEqual(self.installs(), EXPECTED_CAPS)
        self.assertEqual(sorted(self.card()["aids"]), sorted(ALL_AIDS))
        # The legacy PIN-less ETH1 applet is not installed any more.
        self.assertNotIn(LEGACY_ETH1_AID, self.card()["aids"])
        self.assertNotIn("nuri-eth-signer.cap", self.installs())
        self.assertIn("seven applets", result.stdout)
        shim = self.home / ".nuri-card/tools/bin/gp"
        self.assertEqual(stat.S_IMODE(shim.stat().st_mode), 0o700)
        self.assertIn(str(self.bin / "gp"), shim.read_text())
        log = next((self.home / ".nuri-card/logs").iterdir())
        self.assertTrue(log.name.startswith(f"setup-{SERIAL}-"))
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)

    def test_non_blank_card_writes_nothing(self):
        self.write_state(aids=["A0000006472F0001"])
        result = self.run_setup(stdin=SERIAL + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("not blank", result.stdout)
        self.assertIn("A0000006472F0001", result.stdout)
        self.assertEqual(self.installs(), [])

    def test_wrong_default_key_stops_after_one_auth(self):
        self.write_state(key="00112233445566778899AABBCCDDEEFF")
        result = self.run_setup(stdin=SERIAL + "\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("does not use the public default admin key", result.stdout)
        self.assertIn("Do not retry", result.stdout)
        self.assertEqual(len(self.auth_calls()), 1)
        self.assertEqual(self.installs(), [])

    def test_denylisted_serial_is_refused_before_auth(self):
        self.deny.write_text("12345678\n")
        result = self.run_setup(stdin=SERIAL + "\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("deny-list", result.stdout)
        self.assertEqual(self.auth_calls(), [])

    def test_wrong_typed_serial_is_refused(self):
        result = self.run_setup(stdin="99999999\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("serials differ", result.stdout)
        self.assertEqual(self.installs(), [])

    def test_exact_serial_flag_skips_the_prompt(self):
        result = self.run_setup(["--serial", SERIAL, "--yes"], stdin="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Serial confirmed with --serial.", result.stdout)
        self.assertEqual(self.installs(), EXPECTED_CAPS)

    def test_mismatched_serial_flag_writes_nothing(self):
        result = self.run_setup(["--serial", "99999999"], stdin="")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.installs(), [])

    def test_dry_run_makes_no_write_call(self):
        result = self.run_setup(["--dry-run"], stdin=SERIAL + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DRY RUN", result.stdout)
        self.assertIn("provision-card-v1.sh", result.stdout)
        self.assertEqual(self.installs(), [])
        self.assertEqual([call for call in self.calls() if "--create" in call["args"]], [])

    def test_resume_installs_only_missing_applets(self):
        self.write_state(aids=["A0000006472F0001", "4E5552494554483201"])
        result = self.run_setup(["--resume", "--serial", SERIAL], stdin="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.installs(), ["nuri-musig2-v20-keygen.cap", "nuri-oath-totp.cap",
                                           "nuri-musig2-v20-keygen-aid2.cap",
                                           "nuri-musig2-v20-keygen-aid3.cap", "nuri-vault.cap"])

    def test_resume_keeps_an_existing_eth1_and_never_reinstalls_it(self):
        self.write_state(aids=["A0000006472F0001", LEGACY_ETH1_AID])
        result = self.run_setup(["--resume", "--serial", SERIAL], stdin="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("nuri-eth-signer.cap", self.installs())
        self.assertIn(LEGACY_ETH1_AID, self.card()["aids"])

    def test_provision_bundle_is_told_to_skip_eth1(self):
        result = self.run_setup(stdin=SERIAL + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Legacy PIN-less ETH1 is not installed", result.stdout)
        self.assertEqual(self.installs().count("nuri-eth-signer.cap"), 0)

    def test_resume_on_complete_card_does_nothing(self):
        self.write_state(aids=ALL_AIDS)
        result = self.run_setup(["--resume"], stdin=SERIAL + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Nothing to do", result.stdout)
        self.assertEqual(self.installs(), [])

    def test_musig2_reinstall_never_reaches_the_installs(self):
        env = {**self.env, "MUSIG2_REINSTALL": "YES"}
        result = self.run_setup(stdin=SERIAL + "\n", env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.calls())
        self.assertEqual({call["musig2_reinstall"] for call in self.calls()}, {None})

    def test_twin_reader_slot_is_ignored(self):
        self.write_state(readers=["Fake reader", "Fake reader 01"], card_readers=["Fake reader"])
        result = self.run_setup(stdin=SERIAL + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Fake reader 01", self.auth_calls()[0]["gp_reader_ignore"])

    def test_help_creates_nothing(self):
        empty = self.home / "empty-home"
        empty.mkdir()
        result = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True,
                                env={**self.env, "HOME": str(empty)}, cwd=str(ROOT), timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Usage:", result.stdout)
        self.assertEqual(list(empty.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
