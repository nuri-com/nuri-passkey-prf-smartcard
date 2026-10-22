"""Host-only tests for card-secrets.py --backend card.

No reader, no pyscard, no real card: the real scripts/nuri_pcsc.py is imported
and only nuri_pcsc.open_applet is patched to return an in-memory fake that
implements the vault applet APDU contract (AID 4E555249564C5401, CLA 80).
getpass.getpass is patched to supply PINs. There is no test mode in the script
itself; nothing here can select real hardware.
"""
import contextlib
import getpass
import hashlib
import hmac
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/card-secrets.py"
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import nuri_pcsc  # noqa: E402  (real module; only open_applet is patched)

spec = importlib.util.spec_from_file_location("card_secrets_under_test", SCRIPT)
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)

PIN = "2468"
BEARER = b"synthetic-bearer-token-test-only"
HMAC_KEY = b"synthetic-hmac-key-test-only-0123456789"


class FakeVault:
    """Card-side state shared by every connection (models the applet contract)."""

    def __init__(self, max_slots=16):
        self.pin = None
        self.tries = 5
        self.entries = {}          # raw name -> (class, secret), insertion ordered
        self.max_slots = max_slots
        self.log = []              # every APDU, every connection
        self.connections = []

    def open(self, aid_hex, reader=None):
        assert aid_hex == "4E555249564C5401", aid_hex
        conn = FakeConnection(self)
        self.connections.append(conn)
        return conn

    def ins_seen(self):
        return [apdu[1] for apdu in self.log]


class FakeConnection:
    def __init__(self, card):
        self.card = card
        self.verified = False
        self.closed = False

    def close(self):
        self.closed = True

    def transmit(self, apdu):
        assert not self.closed, "transmit after close"
        apdu = bytes(apdu)
        self.card.log.append(apdu)
        return self._handle(apdu)

    def _handle(self, apdu):
        c = self.card
        if apdu == bytes.fromhex("00A40400084E555249564C5401"):
            self.verified = False
            return b"", 0x9000
        if len(apdu) < 4:
            return b"", 0x6700
        cla, ins, p1, p2 = apdu[:4]
        rest = apdu[4:]
        if len(rest) <= 1:
            data = b""
        else:
            lc = rest[0]
            if len(rest) not in (1 + lc, 2 + lc) or lc == 0:
                return b"", 0x6700
            data = rest[1:1 + lc]
        if cla != 0x80:
            return b"", 0x6E00
        if ins not in (0x01, 0x10, 0x20, 0x30, 0x31, 0x40, 0x41, 0x50):
            return b"", 0x6D00
        if p2 != 0 or (ins != 0x31 and p1 != 0) or (ins == 0x31 and p1 not in (0, 1)):
            return b"", 0x6A86
        if ins == 0x01:
            if data:
                return b"", 0x6700
            return bytes([1, int(c.pin is not None), c.tries, c.max_slots]), 0x9000
        if ins == 0x10:
            if not 4 <= len(data) <= 16:
                return b"", 0x6700
            if c.pin is not None:
                return b"", 0x6985
            c.pin = data
            return b"", 0x9000          # NOT authenticated
        if c.pin is None:
            return b"", 0x6985
        if c.tries == 0:
            return b"", 0x6983
        if ins == 0x20:
            if not 4 <= len(data) <= 16:
                return b"", 0x6700
            if hmac.compare_digest(data, c.pin):
                c.tries = 5
                self.verified = True
                return b"", 0x9000
            c.tries -= 1
            self.verified = False
            return b"", (0x6983 if c.tries == 0 else 0x63C0 | c.tries)
        if not self.verified:
            return b"", 0x6982
        if ins == 0x30:
            if len(data) < 3 or not 1 <= data[1] <= 16 or len(data) < 2 + data[1] + 1:
                return b"", 0x6700
            kind, nlen = data[0], data[1]
            name, secret = data[2:2 + nlen], data[2 + nlen:]
            if kind not in (1, 2):
                return b"", 0x6A80
            if not 1 <= len(secret) <= 64:
                return b"", 0x6700
            if name in c.entries:
                return b"", 0x6985
            if len(c.entries) >= c.max_slots:
                return b"", 0x6A84
            c.entries[name] = (kind, secret)
            return b"", 0x9000
        if ins == 0x31:
            if data:
                return b"", 0x6700
            page = list(c.entries.items())[p1 * 8:p1 * 8 + 8]
            return b"".join(bytes([k, len(n)]) + n for n, (k, _) in page), 0x9000
        if not data or not 1 <= data[0] <= 16 or len(data) < 1 + data[0]:
            return b"", 0x6700
        name, tail = data[1:1 + data[0]], data[1 + data[0]:]
        if name not in c.entries:
            return b"", 0x6A88
        kind, secret = c.entries[name]
        if ins == 0x40:
            if kind != 1:
                return b"", 0x6985
            return hmac.new(secret, tail, hashlib.sha256).digest(), 0x9000
        if tail:
            return b"", 0x6700
        if ins == 0x41:
            return (b"", 0x6985) if kind != 2 else (secret, 0x9000)
        del c.entries[name]                # 0x50 DELETE
        return b"", 0x9000


class Stdin(io.TextIOWrapper):
    def __init__(self, data=b"", tty=False):
        super().__init__(io.BytesIO(data))
        self._tty = tty

    def isatty(self):
        return self._tty


class CardBackendTest(unittest.TestCase):
    def setUp(self):
        self.card = FakeVault()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.vault_file = self.tmp / "vault.json"
        patcher = patch.object(nuri_pcsc, "open_applet", side_effect=self.card.open)
        self.open_applet = patcher.start()
        self.addCleanup(patcher.stop)

    def cli(self, *argv, stdin=b"", pins=(), tty=False, env=None):
        out, err = io.StringIO(), io.StringIO()
        pin_iter = iter(pins)

        def fake_getpass(prompt="Password: ", stream=None):
            try:
                return next(pin_iter)
            except StopIteration:
                raise AssertionError(f"unexpected PIN prompt {prompt!r}") from None

        argv = ["card-secrets.py", "--vault", str(self.vault_file), *argv]
        with patch.object(sys, "argv", argv), patch.object(sys, "stdin", Stdin(stdin, tty)), \
                patch.object(getpass, "getpass", side_effect=fake_getpass) as prompt, \
                patch.dict(os.environ, env or {}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cs.main()
            except SystemExit as exit_:
                code = exit_.code
        self.prompts = prompt.call_count
        return code, out.getvalue(), err.getvalue()

    def card_cli(self, *argv, **kw):
        return self.cli("--backend", "card", *argv, **kw)

    def init(self):
        code, out, err = self.card_cli("init", pins=(PIN, PIN))
        self.assertEqual(code, 0, err)
        return out

    def put(self, name, value, kind=None):
        args = ["put", name] + (["--kind", kind] if kind else [])
        return self.card_cli(*args, stdin=value, pins=(PIN,))

    def assert_every_connection_closed(self):
        self.assertTrue(self.card.connections)
        self.assertTrue(all(conn.closed for conn in self.card.connections))
        self.assertTrue(all(not conn.verified for conn in self.card.connections))

    # --- contract / init -------------------------------------------------
    def test_init_sets_pin_explicitly_and_does_not_authenticate(self):
        out = self.init()
        self.assertEqual(json.loads(out), {"initialized": True, "tries": 5, "max_slots": 16})
        self.assertEqual(self.card.pin, PIN.encode())
        self.assertEqual(self.card.log, [bytes.fromhex("8001000000"),
                                         bytes.fromhex("801000000432343638"),
                                         bytes.fromhex("8001000000")])
        self.assertEqual(self.prompts, 2)
        code, _, err = self.card_cli("init", pins=(PIN, PIN))
        self.assertEqual(code, 1)
        self.assertIn("already set", err)
        self.assertNotIn(0x20, self.card.ins_seen())
        self.assertFalse(self.vault_file.exists())
        self.assert_every_connection_closed()

    def test_init_mismatch_writes_nothing(self):
        code, _, err = self.card_cli("init", pins=(PIN, "9999"))
        self.assertEqual(code, 1)
        self.assertIn("do not match", err)
        self.assertIsNone(self.card.pin)
        self.assertNotIn(0x10, self.card.ins_seen())

    def test_put_does_not_silently_initialize(self):
        code, _, err = self.put("API", BEARER)
        self.assertEqual(code, 1)
        self.assertIn("not initialized", err)
        self.assertIsNone(self.card.pin)
        self.assertEqual(self.card.ins_seen(), [0x01])
        self.assertEqual(self.prompts, 0)

    def test_put_list_rm_exact_apdus_and_read_back(self):
        self.init()
        self.card.log.clear()
        code, _, err = self.put("API", BEARER)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.card.log, [
            bytes.fromhex("8001000000"),
            bytes.fromhex("802000000432343638"),
            bytes([0x80, 0x30, 0, 0, 2 + 3 + len(BEARER), 2, 3]) + b"API" + BEARER,
            bytes.fromhex("8031000000"),
            bytes.fromhex("8031010000"),
            bytes.fromhex("00A40400084E555249564C5401"),
        ])
        code, _, err = self.put("SIGNER", HMAC_KEY, kind="hmac")
        self.assertEqual(code, 0, err)
        code, out, _ = self.card_cli("list", pins=(PIN,))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), [{"kind": "bearer", "name": "API"}, {"kind": "hmac", "name": "SIGNER"}])
        self.assertNotIn(BEARER.decode(), out)
        self.card.log.clear()
        code, _, err = self.card_cli("rm", "API", pins=(PIN,))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.card.log[2], bytes.fromhex("8050000004") + b"\x03API")
        self.assertEqual(self.card.log[3:], [bytes.fromhex("8031000000"), bytes.fromhex("8031010000"), bytes.fromhex("00A40400084E555249564C5401")])
        self.assertEqual(list(self.card.entries), [b"SIGNER"])
        self.assertFalse(self.vault_file.exists())
        self.assert_every_connection_closed()
        # Each CLI call is one connection: init, put, put, list, rm.
        self.assertEqual(len(self.card.connections), 5)

    def test_list_requires_pin_pages_and_foreign_names(self):
        self.init()
        for i in range(10):
            self.card.entries[f"K{i}".encode()] = (2, b"x")
        self.card.entries[b"\xff-raw"] = (1, b"y")
        code, out, _ = self.card_cli("list", pins=(PIN,))
        self.assertEqual(code, 0)
        names = json.loads(out)
        self.assertEqual(len(names), 11)
        self.assertEqual(names[-1], {"kind": "hmac", "name_hex": "ff2d726177"})
        self.assertEqual(self.prompts, 1)
        self.card.entries.clear()
        code, out, _ = self.card_cli("list", pins=(PIN,))
        self.assertEqual((code, json.loads(out)), (0, []))

    def test_put_refusals_before_card_and_on_card(self):
        self.init()
        opened = self.open_applet.call_count
        for args, stdin, message in ((["put", "API", "--tag", "x"], BEARER, "tags"),
                                     (["put", "A" * 17], BEARER, "at most 16"),
                                     (["put", "API"], b"", "1..64"),
                                     (["put", "API"], b"z" * 65, "1..64")):
            code, _, err = self.card_cli(*args, stdin=stdin)
            self.assertEqual(code, 1, args)
            self.assertIn(message, err)
        code, _, err = self.card_cli("put", "API", stdin=BEARER, tty=True)
        self.assertEqual(code, 1)
        self.assertIn("piped stdin", err)
        self.assertEqual(self.open_applet.call_count, opened)   # no card, no PIN prompt
        self.assertEqual(self.put("API", BEARER)[0], 0)
        code, _, err = self.put("API", b"other")
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)
        self.assertEqual(self.card.entries[b"API"], (2, BEARER))
        self.card.max_slots = 1
        code, _, err = self.put("MORE", b"v")
        self.assertEqual(code, 1)
        self.assertIn("full", err)
        code, _, err = self.card_cli("rm", "MISSING", pins=(PIN,))
        self.assertEqual(code, 1)
        self.assertIn("no such entry", err)

    def test_read_back_mismatch_is_not_claimed_as_success(self):
        self.init()
        original = FakeConnection._handle

        def lying_list(conn, apdu):
            data, sw = original(conn, apdu)
            return (b"", sw) if apdu[1] == 0x31 else (data, sw)

        with patch.object(FakeConnection, "_handle", lying_list):
            code, _, err = self.put("API", BEARER)
        self.assertEqual(code, 1)
        self.assertIn("not confirmed", err)

    # --- PIN handling ----------------------------------------------------
    def test_wrong_pin_is_sent_once_and_never_retried(self):
        self.init()
        self.put("API", BEARER)
        self.card.log.clear()
        code, out, err = self.card_cli("run", "API", "--", sys.executable, "-c", "raise SystemExit(7)",
                                       pins=("0000",))
        self.assertEqual(code, 1)
        self.assertIn("4 tries left", err)
        self.assertIn("not retried", err)
        self.assertEqual(self.card.ins_seen(), [0x01, 0x20, 0xA4])
        self.assertEqual(self.prompts, 1)
        self.assertNotIn(BEARER.decode(), out + err)
        self.card.tries = 0
        self.card.log.clear()
        code, _, err = self.card_cli("list", pins=())
        self.assertEqual(code, 1)
        self.assertIn("blocked", err)
        self.assertEqual(self.card.ins_seen(), [0x01])

    def test_pin_never_from_argv_env_or_piped_stdin(self):
        self.init()
        code, _, _ = self.card_cli("--pin", PIN, "list")
        self.assertEqual(code, 2)
        self.card.log.clear()

        def no_tty(prompt="", stream=None):
            warnings.warn("Can not control echo on the terminal.", getpass.GetPassWarning)
            return PIN

        out, err = io.StringIO(), io.StringIO()
        argv = ["card-secrets.py", "--backend", "card", "list"]
        with patch.object(sys, "argv", argv), patch.object(getpass, "getpass", no_tty), \
                patch.dict(os.environ, {"NURI_CARD_PIN": PIN, "CARD_PIN": PIN}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(cs.main(), 1)
        self.assertIn("needs a terminal", err.getvalue())
        self.assertEqual(self.card.ins_seen(), [0x01])   # no VERIFY sent

    # --- HMAC ------------------------------------------------------------
    def test_hmac_computes_on_card_without_reveal(self):
        self.init()
        self.put("SIGNER", HMAC_KEY, kind="hmac")
        message = bytes(range(256))[:200]
        data_file = self.tmp / "msg.bin"
        data_file.write_bytes(message)
        self.card.log.clear()
        code, out, err = self.card_cli("hmac", "SIGNER", "--data-file", str(data_file), pins=(PIN,))
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), hmac.new(HMAC_KEY, message, hashlib.sha256).hexdigest())
        self.assertEqual(self.card.log[2], bytes([0x80, 0x40, 0, 0, 1 + 6 + 200, 6]) + b"SIGNER" + message + b"\x00")
        self.assertNotIn(0x41, self.card.ins_seen())
        self.assertNotIn(HMAC_KEY.hex(), out + err)
        # exact single-APDU bound: 254 - nameLen bytes, no prehash
        data_file.write_bytes(b"m" * (254 - 6 + 1))
        code, _, err = self.card_cli("hmac", "SIGNER", "--data-file", str(data_file))
        self.assertEqual(code, 1)
        self.assertIn("at most 248", err)
        data_file.write_bytes(b"m" * 248)
        self.assertEqual(self.card_cli("hmac", "SIGNER", "--data-file", str(data_file), pins=(PIN,))[0], 0)
        self.put("API", BEARER)
        code, _, err = self.card_cli("hmac", "API", "--data-file", str(data_file), pins=(PIN,))
        self.assertEqual(code, 1)
        self.assertIn("not an HMAC-kind", err)

    def test_run_and_proxy_refuse_hmac_kind(self):
        self.init()
        self.put("SIGNER", HMAC_KEY, kind="hmac")
        marker = self.tmp / "child-ran"
        code, out, err = self.card_cli("run", "SIGNER", "--", sys.executable, "-c",
                                       f"open({str(marker)!r}, 'w').close()", pins=(PIN,))
        self.assertEqual(code, 1)
        self.assertIn("never leave the card", err)
        self.assertFalse(marker.exists())
        with patch.object(cs, "proxy") as proxy:
            code, _, err = self.card_cli("proxy", "SIGNER", "--upstream", "https://api.example.invalid/v1", pins=(PIN,))
        self.assertEqual(code, 1)
        proxy.assert_not_called()
        self.assertNotIn(HMAC_KEY.decode(), out + err)

    def test_no_reveal_cli(self):
        for command in ("reveal", "get", "show"):
            self.assertEqual(self.card_cli(command, "API")[0], 2)

    # --- broker ----------------------------------------------------------
    def test_run_injects_bearer_and_scrubs_pin_names(self):
        self.init()
        self.put("API", BEARER)
        target = self.tmp / "child"
        program = ("import os,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(os.environ['NURI_SECRET_API']); "
                   "bad=[k for k in os.environ if 'PIN' in k.upper().split('_') or k.startswith(('NURI_SECRET_OLD','FIDO2_'))]; "
                   "assert not bad, bad; assert os.environ['KEEP_ME']=='1'")
        env = {"NURI_CARD_PIN": PIN, "CARD_PIN": PIN, "NURI_TOTP_PIN": PIN, "pin": PIN, "FIDO2_BACKUP_PIN": PIN,
               "NURI_SECRET_OLD": "x", "KEEP_ME": "1"}
        code, out, err = self.card_cli("run", "API", "--", sys.executable, "-c", program, str(target),
                                       pins=(PIN,), env=env)
        self.assertEqual(code, 0, err)
        self.assertEqual(target.read_bytes(), BEARER)
        self.assertNotIn(BEARER.decode(), out + err)
        self.assert_every_connection_closed()   # card closed before the child runs
        code, _, _ = self.card_cli("run", "API", "--", sys.executable, "-c", "raise SystemExit(5)", pins=(PIN,))
        self.assertEqual(code, 5)

    def test_proxy_receives_bearer_after_card_closed(self):
        self.init()
        self.put("API", BEARER)
        seen = []

        def fake_proxy(args, secret):
            seen.append((args.upstream, args.header, secret, all(c.closed for c in self.card.connections)))

        with patch.object(cs, "proxy", side_effect=fake_proxy):
            code, _, err = self.card_cli("proxy", "API", "--upstream", "https://api.example.invalid/v1",
                                         "--header", "X-API-Key", pins=(PIN,))
        self.assertEqual(code, 0, err)
        self.assertEqual(seen, [("https://api.example.invalid/v1", "X-API-Key", BEARER, True)])
        opened = self.open_applet.call_count
        code, _, err = self.card_cli("proxy", "API", "--upstream", "http://example.invalid/v1")
        self.assertEqual(code, 1)
        self.assertEqual(self.open_applet.call_count, opened)

    def test_logout_failure_prevents_child_and_still_closes(self):
        self.init()
        self.put("API", BEARER)
        original = FakeConnection._handle

        def fail_logout(conn, apdu):
            if apdu[1] == 0xA4:
                return b"", 0x6F00
            return original(conn, apdu)

        with patch.object(FakeConnection, "_handle", fail_logout), patch.object(cs.subprocess, "run") as child:
            code, out, err = self.card_cli("run", "API", "--", "not-executed", pins=(PIN,))
        self.assertEqual(code, 1)
        self.assertIn("could not confirm vault logout", err)
        self.assertNotIn(BEARER.decode(), out + err)
        child.assert_not_called()
        self.assertTrue(all(conn.closed for conn in self.card.connections))

    def test_reader_errors_are_reported_without_traceback(self):
        self.open_applet.side_effect = nuri_pcsc.CardError("NO_APPLET", "SELECT failed")
        code, _, err = self.card_cli("list")
        self.assertEqual(code, 1)
        self.assertIn("vault applet unavailable (NO_APPLET)", err)
        self.assertNotIn("Traceback", err)


class DiskDefaultRegressionTest(unittest.TestCase):
    """The default backend must not touch PC/SC and must keep the v1 vault format."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.vault = self.tmp / "vault.json"
        patcher = patch.object(nuri_pcsc, "open_applet", side_effect=AssertionError("disk backend opened PC/SC"))
        self.open_applet = patcher.start()
        self.addCleanup(patcher.stop)

    def cli(self, *argv, stdin=b""):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["card-secrets.py", "--vault", str(self.vault), *argv]), \
                patch.object(sys, "stdin", Stdin(stdin)), \
                patch.object(getpass, "getpass", side_effect=AssertionError("disk backend prompted for a PIN")), \
                patch.dict(os.environ, {"NURI_CARD_SECRETS_FAKE_PRF": "11" * 32}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cs.main()
            except SystemExit as exit_:
                code = exit_.code
        return code, out.getvalue(), err.getvalue()

    def test_default_is_disk_with_unchanged_format(self):
        self.assertEqual(self.cli("put", "API", "--tag", "t", stdin=b"disk-secret")[0], 0)
        self.assertEqual(self.cli("--backend", "disk", "put", "B", stdin=b"x")[0], 0)
        vault = json.loads(self.vault.read_text())
        self.assertEqual(set(vault), {"version", "mode", "salt", "secrets"})
        self.assertEqual((vault["version"], vault["mode"]), (1, "fake"))
        self.assertEqual(set(vault["secrets"]["API"]), {"name", "created", "tags", "wrapped_key", "data"})
        code, out, _ = self.cli("list")
        self.assertEqual(code, 0)
        self.assertEqual([(e["name"], e["tags"]) for e in json.loads(out)], [("API", ["t"]), ("B", [])])
        self.assertEqual(set(json.loads(out)[0]), {"name", "created", "tags"})
        self.assertEqual(self.cli("rm", "B")[0], 0)
        self.open_applet.assert_not_called()

    def test_card_only_commands_rejected_on_disk(self):
        for argv in (["init"], ["hmac", "API", "--data-file", "/dev/null"], ["put", "API", "--kind", "hmac"]):
            self.assertEqual(self.cli(*argv, stdin=b"x")[0], 2, argv)
        self.assertFalse(self.vault.exists())
        self.open_applet.assert_not_called()

    def test_disk_error_message_unchanged(self):
        code, _, err = self.cli("rm", "MISSING")
        self.assertEqual(code, 1)
        self.assertEqual(err, "card-secrets: operation failed (check name, card/profile, vault permissions and input)\n")


if __name__ == "__main__":
    unittest.main()
