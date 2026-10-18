#!/usr/bin/env python3
"""Guard, token-file, pairing and framing tests for scripts/card-dashboard-server.py +
scripts/nuri_helper_auth.py.

Fake card only: nuri_pcsc.open_applet is replaced by a fake applet that answers
SELECT/VERSION with 9000 and raises for anything that would sign or generate a key.
The server runs in-process on a random loopback port. No reader is ever opened.

Run:  python3 -m unittest test/test_helper_auth.py
      (needs ecdsa + pycryptodome + base58, same as the dashboard itself:
       scripts/run-card-python.sh -m unittest test/test_helper_auth.py; missing ones are stubbed)
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import nuri_helper_auth  # noqa: E402
import nuri_pcsc  # noqa: E402

TOKEN = "0123456789abcdef" * 4  # 64 lowercase hex, 16 distinct chars
AUTH_LINE = f"Authorization: Bearer {TOKEN}\r\n"
PAIR_JS = "/* test fixture for web/helper-pair.js */ window.__pairFixture = 1;\n"
TOKEN_ENV = ("NURI_DASHBOARD_TOKEN", "NURI_DASHBOARD_TOKEN_FILE", "NURI_CARD_TOKEN", "NURI_CARD_TOKEN_FILE",
             "NURI_ALLOW_REMOTE")


ETH1_AID = bytes.fromhex("4E55524945544801")
ETH2_AID = bytes.fromhex("4E5552494554483201")


class FakeApplet:
    """Answers SELECT (INS A4) and VERSION (INS 01) only. Everything else = test failure.

    SELECT: 9000 for an AID in `present`, 6A82 otherwise; `eth2_sw` overrides the ETH2
    answer (int) or makes it raise ("transport"). Default card: ETH1 demo only, no ETH2.
    """
    version = (1, 3)
    calls: list[bytes] = []
    present = {ETH1_AID}
    eth2_sw = None

    def transmit(self, apdu):
        apdu = bytes(apdu)
        FakeApplet.calls.append(apdu)
        ins = apdu[1]
        if ins == 0xA4:
            aid = apdu[5:5 + apdu[4]]
            if aid == ETH2_AID and FakeApplet.eth2_sw is not None:
                if FakeApplet.eth2_sw == "transport":
                    raise OSError("reader went away")
                return b"", FakeApplet.eth2_sw
            if aid in FakeApplet.present or aid not in (ETH1_AID, ETH2_AID):
                return b"", 0x9000
            return b"", 0x6A82
        if ins == 0x01:
            return bytes(FakeApplet.version) + b"\x00test", 0x9000
        raise AssertionError(f"card must not be touched: INS {ins:02X}")

    def close(self):
        pass


def _stub_missing_crypto_deps():
    """The guard tests never sign/verify; stub ecdsa/pycryptodome/base58 if not installed."""
    import types
    try:
        import ecdsa  # noqa: F401
    except ImportError:
        m = types.ModuleType("ecdsa"); m.VerifyingKey = object; m.SECP256k1 = object
        u = types.ModuleType("ecdsa.util"); u.sigdecode_string = None
        sys.modules["ecdsa"] = m; sys.modules["ecdsa.util"] = u
    try:
        from Crypto.Hash import keccak  # noqa: F401
    except ImportError:
        c = types.ModuleType("Crypto"); h = types.ModuleType("Crypto.Hash"); k = types.ModuleType("Crypto.Hash.keccak")
        h.keccak = k
        sys.modules["Crypto"] = c; sys.modules["Crypto.Hash"] = h; sys.modules["Crypto.Hash.keccak"] = k
    try:
        import base58  # noqa: F401
    except ImportError:
        sys.modules["base58"] = types.ModuleType("base58")


def load_dashboard():
    _stub_missing_crypto_deps()
    spec = importlib.util.spec_from_file_location("card_dashboard_server", SCRIPTS / "card-dashboard-server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CleanEnv(unittest.TestCase):
    """Saves/restores os.environ and starts with no token variables set."""

    def setUp(self):
        self._env = dict(os.environ)
        for k in TOKEN_ENV:
            os.environ.pop(k, None)
        self.tmp = tempfile.mkdtemp(prefix="nuri-helper-test-")
        os.chmod(self.tmp, 0o700)

    def tearDown(self):
        os.environ.clear(); os.environ.update(self._env)
        shutil.rmtree(self.tmp, ignore_errors=True)


# --- guard ---------------------------------------------------------------------

class GuardUnit(unittest.TestCase):
    def g(self, method="POST", path="/api/eth/sign", pairing=None, **headers):
        h = {k.replace("_", "-"): v for k, v in headers.items()}
        return nuri_helper_auth.guard_request(method, path, h, port=8788, token=TOKEN, pairing=pairing)

    def test_rules(self):
        good = dict(host="127.0.0.1:8788", content_type="application/json", authorization=f"Bearer {TOKEN}")
        self.assertIsNone(self.g(**good))
        self.assertIsNone(self.g(**{**good, "host": "localhost:8788", "origin": "http://localhost:8788"}))
        self.assertIsNone(self.g(**{**good, "origin": "http://127.0.0.1:8788"}))
        self.assertEqual(self.g(**{**good, "host": "evil.example:8788"})[0], 403)
        self.assertEqual(self.g(**{**good, "host": "127.0.0.1:1"})[0], 403)
        self.assertEqual(self.g(**{**good, "origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.g(**{**good, "origin": "null"})[0], 403)
        self.assertEqual(self.g(**{**good, "content_type": "text/plain"})[0], 415)
        self.assertEqual(self.g(**{**good, "authorization": "Bearer nope"})[0], 401)
        self.assertEqual(self.g("OPTIONS", **good)[0], 403)
        self.assertIsNone(self.g("GET", "/", host="127.0.0.1:8788"))
        self.assertEqual(self.g("GET", "/", host="evil:1")[0], 403)
        self.assertEqual(self.g("GET", "/api/eth/pubkey", host="127.0.0.1:8788")[0], 401)
        self.assertEqual(nuri_helper_auth.guard_request("GET", "/api/x", {"host": "127.0.0.1:8788", "authorization": "Bearer "}, port=8788, token="")[0], 401)

    def test_origin_must_equal_this_exact_origin(self):
        good = dict(host="127.0.0.1:8788", content_type="application/json", authorization=f"Bearer {TOKEN}")
        for bad in ("http://127.0.0.1:8787",        # another helper's port
                    "http://localhost:8788",        # other allowed host name, not this Host
                    "https://127.0.0.1:8788",       # scheme
                    "http://127.0.0.1:8788/x",      # not an origin
                    "http://127.0.0.1:8788@evil",   # userinfo trick
                    "http://[::1]:8788"):
            self.assertEqual(self.g(**{**good, "origin": bad})[0], 403, bad)
        self.assertEqual(self.g(**{**good, "sec_fetch_site": "cross-site"})[0], 403)
        self.assertEqual(self.g(**{**good, "sec_fetch_site": "same-site"})[0], 403)
        self.assertIsNone(self.g(**{**good, "sec_fetch_site": "same-origin"}))

    def test_pair_route_rules(self):
        h = dict(host="127.0.0.1:8788", content_type="application/json")
        self.assertIsNone(self.g("POST", "/pair", **h))  # no credential needed; handler checks code
        self.assertEqual(self.g("GET", "/pair", **h)[0], 405)
        self.assertEqual(self.g("POST", "/pair", host="127.0.0.1:8788", content_type="text/plain")[0], 415)
        self.assertEqual(self.g("POST", "/pair", **h, origin="http://127.0.0.1:9999")[0], 403)
        self.assertEqual(self.g("POST", "/pair", **h, sec_fetch_site="cross-site")[0], 403)
        self.assertEqual(self.g("POST", "/pair", host="evil:8788", content_type="application/json")[0], 403)

    def test_cookie_session_needs_exact_same_origin(self):
        p = nuri_helper_auth.Pairing(log=lambda m: None)
        sid = p.pair(p._code)
        ck = f"{nuri_helper_auth.SESSION_COOKIE}={sid}"
        host = "127.0.0.1:8788"
        self.assertIsNone(self.g("GET", "/api/eth/pubkey", p, host=host, cookie=ck, sec_fetch_site="same-origin"))
        self.assertIsNone(self.g("POST", "/api/eth/sign", p, host=host, cookie=ck, content_type="application/json",
                                 origin="http://127.0.0.1:8788"))
        # no Origin and no Sec-Fetch-Site: not provably a same-origin browser request
        self.assertEqual(self.g("GET", "/api/eth/pubkey", p, host=host, cookie=ck)[0], 403)
        self.assertEqual(self.g("POST", "/api/eth/sign", p, host=host, cookie=ck, content_type="application/json")[0], 403)
        self.assertEqual(self.g("GET", "/api/eth/pubkey", p, host=host, cookie=ck, origin="http://localhost:8788")[0], 403)
        self.assertEqual(self.g("GET", "/api/eth/pubkey", p, host=host, cookie=f"{nuri_helper_auth.SESSION_COOKIE}=forged",
                                sec_fetch_site="same-origin")[0], 401)
        self.assertEqual(self.g("GET", "/api/eth/pubkey", p, host=host, cookie=f"other={sid}", sec_fetch_site="same-origin")[0], 401)

    def test_error_texts_do_not_echo_request_values(self):
        marker = "ZZmarkerZZ"
        for hdr in (dict(host=f"{marker}:1"), dict(host="127.0.0.1:8788", origin=f"http://{marker}")):
            err = self.g("GET", "/api/x", **hdr)
            self.assertNotIn(marker.lower(), err[1].lower())

    def test_check_bind_is_loopback_only_without_override(self):
        nuri_helper_auth.check_bind("127.0.0.1")
        nuri_helper_auth.check_bind("localhost")
        nuri_helper_auth.check_bind("::1")
        with mock.patch.dict(os.environ, {"NURI_ALLOW_REMOTE": "1", "NURI_DASHBOARD_TOKEN": TOKEN}):
            for host in ("0.0.0.0", "::", "192.168.1.5", "example.com"):
                with self.assertRaisesRegex(RuntimeError, "loopback-only"):
                    nuri_helper_auth.check_bind(host, "env")

    def test_framing(self):
        f = lambda **h: nuri_helper_auth.check_framing({k.replace("_", "-"): v for k, v in h.items()}, 1 << 20)
        self.assertEqual(f(), (None, 0))
        self.assertEqual(f(content_length="0"), (None, 0))
        self.assertEqual(f(content_length="12"), (None, 12))
        self.assertEqual(f(content_length=str(1 << 20)), (None, 1 << 20))
        self.assertEqual(f(content_length=str((1 << 20) + 1))[0][0], 413)
        for bad in ("-1", "+5", "1e3", "0x10", " ", "", "12 13", "99999999999"):
            self.assertEqual(f(content_length=bad)[0][0], 400, bad)
        self.assertEqual(f(transfer_encoding="chunked")[0][0], 501)
        self.assertEqual(f(transfer_encoding="identity", content_length="1")[0][0], 501)


# --- service token file ------------------------------------------------------------

class TokenFile(CleanEnv):
    def path(self, *parts):
        return os.path.join(self.tmp, *parts)

    def test_created_0600_in_0700_dir_value_never_logged(self):
        os.environ["HOME"] = self.tmp
        logs = []
        token, source = nuri_helper_auth.load_or_create_token("dashboard", log=logs.append)
        self.assertEqual(source, self.path(".nuri-card", "dashboard.token"))
        self.assertRegex(token, r"^[0-9a-f]{64}$")
        self.assertEqual(stat.S_IMODE(os.stat(source).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.path(".nuri-card")).st_mode), 0o700)
        self.assertFalse(any(token in m for m in logs), "token must never be printed")
        token2, _ = nuri_helper_auth.load_or_create_token("dashboard", log=logs.append)
        self.assertEqual(token, token2)
        self.assertFalse(any(token in m for m in logs))
        self.assertEqual(sorted(os.listdir(self.path(".nuri-card"))), ["dashboard.token"], "no temp files left")

    def test_path_precedence_and_legacy_suffix(self):
        os.environ["HOME"] = self.tmp
        self.assertEqual(nuri_helper_auth.token_path(), Path(self.tmp) / ".nuri-card" / "dashboard.token")
        os.environ["NURI_CARD_TOKEN_FILE"] = self.path("legacy", "token")
        self.assertEqual(nuri_helper_auth.token_path(), Path(self.path("legacy", "token.dashboard")))
        os.environ["NURI_DASHBOARD_TOKEN_FILE"] = self.path("own", "dash.tok")
        self.assertEqual(nuri_helper_auth.token_path(), Path(self.path("own", "dash.tok")))
        os.mkdir(self.path("own"), 0o700)
        _, src = nuri_helper_auth.load_or_create_token(log=lambda m: None)
        self.assertEqual(src, self.path("own", "dash.tok"))
        self.assertFalse(os.path.exists(self.path("legacy")), "legacy path not touched when override set")

    def test_env_token_strict(self):
        os.environ["NURI_DASHBOARD_TOKEN"] = TOKEN
        self.assertEqual(nuri_helper_auth.load_or_create_token(log=lambda m: None), (TOKEN, "env"))
        for bad in ("short", "a" * 64, "ab" * 32, "abcd" * 16, TOKEN.upper(), TOKEN + "0", TOKEN[:-1] + "g",
                    "test-token-0123456789abcdef0123456789abcdef"):
            os.environ["NURI_DASHBOARD_TOKEN"] = bad
            with self.assertRaises(nuri_helper_auth.TokenError, msg=bad) as cm:
                nuri_helper_auth.load_or_create_token(log=lambda m: None)
            self.assertNotIn(bad, str(cm.exception), "error must not echo the token")

    def test_generic_card_token_refused_with_migration_message(self):
        os.environ["HOME"] = self.tmp
        os.environ["NURI_CARD_TOKEN"] = TOKEN
        with self.assertRaisesRegex(nuri_helper_auth.TokenError, "NURI_DASHBOARD_TOKEN"):
            nuri_helper_auth.load_or_create_token(log=lambda m: None)
        self.assertFalse(os.path.exists(self.path(".nuri-card")), "nothing created on refusal")
        other = "fedcba9876543210" * 4
        os.environ["NURI_DASHBOARD_TOKEN"] = other  # service token wins; generic one never used
        self.assertEqual(nuri_helper_auth.load_or_create_token(log=lambda m: None), (other, "env"))

    def _existing(self, content=TOKEN + "\n", fmode=0o600, dmode=0o700):
        d = self.path("tok"); os.mkdir(d, 0o700)
        f = os.path.join(d, "dashboard.token")
        with open(f, "w") as fh:
            fh.write(content)
        os.chmod(f, fmode)
        os.chmod(d, dmode)
        os.environ["NURI_DASHBOARD_TOKEN_FILE"] = f
        return d, f

    def test_existing_private_file_loads(self):
        self._existing()
        self.assertEqual(nuri_helper_auth.load_or_create_token(log=lambda m: None)[0], TOKEN)

    def test_existing_file_with_loose_mode_rejected_not_repaired(self):
        for mode in (0o644, 0o640, 0o604, 0o660):
            with self.subTest(mode=oct(mode)):
                _, f = self._existing(fmode=mode)
                with self.assertRaisesRegex(nuri_helper_auth.TokenError, "private"):
                    nuri_helper_auth.load_or_create_token(log=lambda m: None)
                self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), mode, "mode left for the owner to fix")
                shutil.rmtree(self.path("tok"))

    def test_loose_directory_rejected(self):
        for mode in (0o755, 0o750, 0o701, 0o500):
            with self.subTest(mode=oct(mode)):
                d, _ = self._existing(dmode=mode)
                with self.assertRaises(nuri_helper_auth.TokenError):
                    nuri_helper_auth.load_or_create_token(log=lambda m: None)
                os.chmod(d, 0o700); shutil.rmtree(d)

    def test_malformed_or_weak_existing_token_rejected(self):
        for content in ("", "short\n", "a" * 64 + "\n", "\xff" * 10, TOKEN.upper()):
            with self.subTest(content=content[:8]):
                self._existing(content=content)
                with self.assertRaises(nuri_helper_auth.TokenError):
                    nuri_helper_auth.load_or_create_token(log=lambda m: None)
                shutil.rmtree(self.path("tok"))

    def test_symlinked_file_and_directory_rejected(self):
        real_d, real_f = self._existing()
        link_f = self.path("tok", "link.token")
        os.symlink(real_f, link_f)
        os.environ["NURI_DASHBOARD_TOKEN_FILE"] = link_f
        with self.assertRaisesRegex(nuri_helper_auth.TokenError, "symlink"):
            nuri_helper_auth.load_or_create_token(log=lambda m: None)
        link_d = self.path("dirlink")
        os.symlink(real_d, link_d)
        os.environ["NURI_DASHBOARD_TOKEN_FILE"] = os.path.join(link_d, "dashboard.token")
        with self.assertRaisesRegex(nuri_helper_auth.TokenError, "symlink"):
            nuri_helper_auth.load_or_create_token(log=lambda m: None)
        dangling = self.path("tok", "dangling.token")
        os.symlink(self.path("nowhere"), dangling)
        os.environ["NURI_DASHBOARD_TOKEN_FILE"] = dangling
        with self.assertRaises(nuri_helper_auth.TokenError):
            nuri_helper_auth.load_or_create_token(log=lambda m: None)
        self.assertFalse(os.path.exists(self.path("nowhere")), "never created through a dangling symlink")

    def test_non_regular_file_rejected_without_blocking(self):
        d = self.path("tok"); os.mkdir(d, 0o700)
        fifo = os.path.join(d, "dashboard.token")
        os.mkfifo(fifo, 0o600)
        os.environ["NURI_DASHBOARD_TOKEN_FILE"] = fifo
        t0 = time.monotonic()
        with self.assertRaisesRegex(nuri_helper_auth.TokenError, "regular"):
            nuri_helper_auth.load_or_create_token(log=lambda m: None)
        self.assertLess(time.monotonic() - t0, 2)

    def test_foreign_owner_rejected(self):
        self._existing()
        with mock.patch.object(nuri_helper_auth.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(nuri_helper_auth.TokenError, "owned by uid"):
                nuri_helper_auth.load_or_create_token(log=lambda m: None)

    def test_failed_creation_leaves_no_partial_file(self):
        d = self.path("tok"); os.mkdir(d, 0o700)
        os.environ["NURI_DASHBOARD_TOKEN_FILE"] = os.path.join(d, "dashboard.token")
        with mock.patch.object(nuri_helper_auth.os, "link", side_effect=OSError(28, "No space left")):
            with self.assertRaises(OSError):
                nuri_helper_auth.load_or_create_token(log=lambda m: None)
        self.assertEqual(os.listdir(d), [], "neither target nor temp file left behind")

    def test_concurrent_first_start_agrees_on_one_token(self):
        d = self.path("race")
        target = os.path.join(d, "dashboard.token")
        code = ("import os,sys,time; sys.path.insert(0, sys.argv[1]); import nuri_helper_auth as a\n"
                "while time.time() < float(sys.argv[2]): pass\n"
                "print(a.load_or_create_token(log=lambda m: None)[0])")
        env = {**os.environ, "NURI_DASHBOARD_TOKEN_FILE": target, "PYTHONDONTWRITEBYTECODE": "1"}
        start = str(time.time() + 1.0)
        procs = [subprocess.Popen([sys.executable, "-c", code, str(SCRIPTS), start], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(12)]
        outs = [p.communicate(timeout=30) for p in procs]
        for p, (out, err) in zip(procs, outs):
            self.assertEqual(p.returncode, 0, err)
        tokens = {out.strip() for out, _ in outs}
        self.assertEqual(len(tokens), 1, "every starter must end up with the same token")
        with open(target) as fh:
            self.assertEqual(fh.read().strip(), tokens.pop())
        self.assertEqual(os.listdir(d), ["dashboard.token"])
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)


# --- pairing ---------------------------------------------------------------------

class PairingUnit(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.logs = []
        self.p = nuri_helper_auth.Pairing(log=self.logs.append, clock=lambda: self.now)

    def code(self):
        return re.findall(r"([A-Z0-9]{4}-[A-Z0-9]{4})", self.logs[-1])[-1]

    def test_code_is_single_use_and_rotates(self):
        c = self.code()
        self.assertEqual(c.replace("-", ""), self.p._code)
        sid = self.p.pair(c.lower())  # case/dash tolerant
        self.assertIsNotNone(sid)
        self.assertIsNone(self.p.pair(c), "a used code never works again")
        self.assertNotEqual(self.code(), c)
        self.assertIsNotNone(self.p.pair(self.code()))

    def test_code_expires_without_creating_a_session(self):
        old = self.code()
        self.now += nuri_helper_auth.PAIR_CODE_TTL_S
        self.assertIsNone(self.p.pair(old))
        self.assertEqual(len(self.p._sessions), 0)
        self.assertIsNotNone(self.p.pair(self.code()))

    def test_code_concurrent_exchange_has_one_winner(self):
        import concurrent.futures
        old = self.code()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.p.pair(old), range(8)))
        self.assertEqual(sum(s is not None for s in results), 1)

    def test_wrong_codes_burn_the_code(self):
        c = self.code()
        for bad in (None, 123, "", "x" * 1000, {"code": c}, ["a"]):
            self.assertIsNone(self.p.pair(bad))
        for _ in range(nuri_helper_auth.PAIR_MAX_FAILURES - 6):
            self.assertIsNone(self.p.pair("AAAA-AAAA"))
        self.assertIsNone(self.p.pair(c), "after too many failures the old code is burned")
        self.assertIsNotNone(self.p.pair(self.code()))

    def test_session_absolute_expiry_not_renewed_by_use(self):
        sid = self.p.pair(self.code())
        ck = f"{nuri_helper_auth.SESSION_COOKIE}={sid}"
        self.assertTrue(self.p.valid(ck))
        for _ in range(11):
            self.now += 3600
            self.assertTrue(self.p.valid(ck))
        self.now += 3600  # 12 h after pairing, despite continuous use
        self.assertFalse(self.p.valid(ck))
        self.assertEqual(self.p.remaining(ck), 0)

    def test_cookie_attributes(self):
        sid = self.p.pair(self.code())
        c = self.p.set_cookie(sid)
        self.assertTrue(c.startswith(f"nuri_dashboard_session={sid};"))
        for attr in ("Path=/api/", "HttpOnly", "SameSite=Strict", "Max-Age=43200"):
            self.assertIn(attr, c)
        self.assertNotIn("Domain", c)
        self.assertGreaterEqual(len(sid), 40)

    def test_sessions_stored_hashed_and_bounded(self):
        sids = [self.p.pair(self.code()) for _ in range(nuri_helper_auth.MAX_SESSIONS + 5)]
        self.assertEqual(len(self.p._sessions), nuri_helper_auth.MAX_SESSIONS)
        self.assertFalse(any(s in self.p._sessions for s in sids), "raw session ids are not stored")
        self.assertTrue(self.p.valid(f"{nuri_helper_auth.SESSION_COOKIE}={sids[-1]}"))
        self.assertFalse(self.p.valid(f"{nuri_helper_auth.SESSION_COOKIE}={sids[0]}"), "oldest evicted")


# --- live server -------------------------------------------------------------------

class DashboardServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_dashboard()
        cls.mod.nuri_pcsc = nuri_pcsc
        cls._orig_open_applet = nuri_pcsc.open_applet
        nuri_pcsc.open_applet = lambda aid: FakeApplet()
        cls.mod._applet = None
        # Existing ETH tests run against the ETH1 demo applet: opt in explicitly (W28).
        cls._saved_demo = os.environ.get("NURI_ALLOW_ETH1_DEMO")
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        cls.web = tempfile.mkdtemp(prefix="nuri-web-")
        shutil.copy(ROOT / "web" / "dashboard.html", cls.web)
        with open(os.path.join(cls.web, "helper-pair.js"), "w") as fh:
            fh.write(PAIR_JS)  # untracked fixture; the real file is web/helper-pair.js
        cls.mod.WEB_DIR = cls.web
        cls.mod.REQUEST_DEADLINE_S = 1.5
        cls.logs = []
        cls.pairing = nuri_helper_auth.Pairing(log=cls.logs.append)
        cls.srv = cls.mod.DashboardServer(("127.0.0.1", 0), cls.mod.Handler)
        cls.port = cls.srv.server_address[1]
        cls.mod.AUTH.update(token=TOKEN, port=cls.port, pairing=cls.pairing)
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        nuri_pcsc.open_applet = cls._orig_open_applet
        os.environ.pop("NURI_ALLOW_ETH1_DEMO", None)
        if cls._saved_demo is not None:
            os.environ["NURI_ALLOW_ETH1_DEMO"] = cls._saved_demo
        shutil.rmtree(cls.web, ignore_errors=True)

    @property
    def origin(self):
        return f"http://127.0.0.1:{self.port}"

    def req(self, method, path, body=None, headers=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = dict(headers or {})
        h["Host"] = host or f"127.0.0.1:{self.port}"
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data

    def raw(self, data, wait=5.0):
        """Send raw bytes, return (elapsed, full response bytes until the server closes)."""
        s = socket.create_connection(("127.0.0.1", self.port), timeout=wait)
        t0 = time.monotonic()
        try:
            s.sendall(data)
            out = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                out += chunk
        finally:
            s.close()
        return time.monotonic() - t0, out

    def head(self, extra=""):
        return f"Host: 127.0.0.1:{self.port}\r\nContent-Type: application/json\r\n{extra}"

    def good(self):
        return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

    def pair_session(self):
        code = self.pairing._code
        status, headers, body = self.req("POST", "/pair", body=json.dumps({"code": code}),
                                         headers={"Content-Type": "application/json", "Origin": self.origin})
        self.assertEqual(status, 200, body)
        m = re.match(r"nuri_dashboard_session=([^;]+);", headers["set-cookie"])
        return code, m.group(1), headers["set-cookie"]

    # --- page ---

    def test_page_has_no_credential_and_security_headers(self):
        status, headers, body = self.req("GET", "/")
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn('<script src="/helper-pair.js"></script>', text)
        for secret in (TOKEN, self.pairing._code):
            self.assertNotIn(secret, text)
        self.assertNotIn("NURI_CARD_TOKEN", text)
        self.assertNotIn("authorization", text.lower())
        self.assertNotIn("set-cookie", headers)
        csp = headers["content-security-policy"]
        for part in ("default-src 'self'", "frame-ancestors 'none'", "script-src 'self' 'unsafe-inline'", "object-src 'none'"):
            self.assertIn(part, csp)
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(headers["referrer-policy"], "no-referrer")
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertNotIn("access-control-allow-origin", headers)

    def test_pair_script_served_from_web(self):
        status, headers, body = self.req("GET", "/helper-pair.js")
        self.assertEqual(status, 200)
        self.assertEqual(body.decode(), PAIR_JS)
        self.assertTrue(headers["content-type"].startswith("text/javascript"))
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])

    # --- pairing over HTTP ---

    def test_pairing_flow_single_use_and_session_scope(self):
        status, _, body = self.req("POST", "/pair", body=json.dumps({"code": "WRNG-CODE"}),
                                   headers={"Content-Type": "application/json"})
        self.assertEqual(status, 401)
        code, sid, cookie = self.pair_session()
        for attr in ("HttpOnly", "SameSite=Strict", "Path=/api/", "Max-Age=43200"):
            self.assertIn(attr, cookie)
        # the code is now burned
        status, _, _ = self.req("POST", "/pair", body=json.dumps({"code": code}),
                                headers={"Content-Type": "application/json"})
        self.assertEqual(status, 401)
        ck = {"Cookie": f"nuri_dashboard_session={sid}"}
        status, _, body = self.req("GET", "/api/eth/version", headers={**ck, "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200, body)
        status, _, body = self.req("GET", "/api/session", headers={**ck, "Origin": self.origin})
        self.assertEqual(status, 200)
        info = json.loads(body)
        self.assertEqual((info["paired"], info["auth"]), (True, "session"))
        self.assertGreater(info["expires_in"], 43000)
        self.assertNotIn(sid, body.decode())
        # session alone, without a same-origin signal, is refused
        self.assertEqual(self.req("GET", "/api/eth/version", headers=ck)[0], 403)
        # cross-port / cross-host origin with a valid cookie
        self.assertEqual(self.req("GET", "/api/eth/version", headers={**ck, "Origin": "http://127.0.0.1:1"})[0], 403)
        self.assertEqual(self.req("GET", "/api/eth/version", headers={**ck, "Origin": f"http://localhost:{self.port}"})[0], 403)
        self.assertEqual(self.req("GET", "/api/eth/version", headers={**ck, "Sec-Fetch-Site": "cross-site"})[0], 403)
        # forged cookie
        self.assertEqual(self.req("GET", "/api/eth/version", headers={"Cookie": "nuri_dashboard_session=x",
                                                                       "Sec-Fetch-Site": "same-origin"})[0], 401)
        # POST with session needs Origin; keygen stays disabled
        os.environ.pop("NURI_ALLOW_KEYGEN", None)
        status, _, body = self.req("POST", "/api/eth/keygen", body="{}",
                                   headers={**ck, "Content-Type": "application/json", "Origin": self.origin})
        self.assertEqual(status, 403)
        self.assertIn("NURI_ALLOW_KEYGEN", json.loads(body)["error"])

    def test_pair_endpoint_guards(self):
        self.assertEqual(self.req("GET", "/pair")[0], 405)
        self.assertEqual(self.req("POST", "/pair", body='{"code":"x"}', headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.req("POST", "/pair", body='{"code":"x"}', headers={"Content-Type": "application/json",
                                                                                 "Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/pair", body='{"code":"x"}', headers={"Content-Type": "application/json"},
                                  host="evil.example")[0], 403)
        self.assertEqual(self.req("POST", "/pair", body='["x"]', headers={"Content-Type": "application/json"})[0], 400)
        self.assertEqual(self.req("POST", "/pair", body="x" * 2000, headers={"Content-Type": "application/json"})[0], 413)

    def test_pairing_code_and_token_never_in_responses(self):
        code = self.pairing._code
        bodies = []
        for method, path, h in (("GET", "/", {}), ("GET", "/helper-pair.js", {}), ("GET", "/api/session", {}),
                                ("GET", "/api/eth/version", {}), ("POST", "/pair", {"Content-Type": "application/json"}),
                                ("GET", "/nope", {}), ("OPTIONS", "/api/x", {})):
            status, headers, body = self.req(method, path, body="{}" if method == "POST" else None, headers=h)
            bodies.append(body.decode("utf-8", "replace") + json.dumps(headers))
        for b in bodies:
            self.assertNotIn(code, b)
            self.assertNotIn(TOKEN, b)

    # --- existing guards ---

    def test_401_without_auth(self):
        for path, method in (("/api/eth/sign", "POST"), ("/api/btc/sign", "POST"), ("/api/eth/pubkey", "GET"),
                             ("/api/eth/keygen", "POST"), ("/api/session", "GET")):
            status, _, body = self.req(method, path, body="{}" if method == "POST" else None,
                                       headers={"Content-Type": "application/json"})
            self.assertEqual(status, 401, (path, body))

    def test_403_bad_host_or_origin(self):
        status, _, _ = self.req("POST", "/api/eth/sign", body="{}", headers=self.good(), host="evil.example")
        self.assertEqual(status, 403)
        status, _, _ = self.req("POST", "/api/eth/sign", body="{}", headers={**self.good(), "Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        status, _, _ = self.req("POST", "/api/eth/sign", body="{}", headers={**self.good(), "Origin": "http://127.0.0.1:8787"})
        self.assertEqual(status, 403)
        status, headers, _ = self.req("OPTIONS", "/api/eth/sign", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        self.assertEqual(status, 403)
        self.assertNotIn("access-control-allow-origin", headers)

    def test_415_without_json_content_type(self):
        status, _, _ = self.req("POST", "/api/eth/sign", body="{}", headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_200_with_bearer(self):
        status, headers, body = self.req("GET", "/api/eth/version", headers={"Authorization": f"Bearer {TOKEN}", "Origin": self.origin})
        self.assertEqual(status, 200, body)
        d = json.loads(body)
        self.assertEqual((d["major"], d["minor"]), (1, 3))
        self.assertEqual(headers["cache-control"], "no-store")

    def test_bad_sign_input_rejected_before_card(self):
        before = len(FakeApplet.calls)
        for body in ('{"hash": "00 " }', '{"hash": "' + "00 " * 21 + '"}', '{"hash": 5}', "[]", "{bad",
                     '{"hash": "' + "0" * 62 + '"}'):
            status, _, _ = self.req("POST", "/api/eth/sign", body=body, headers=self.good())
            self.assertEqual(status, 400, body)
        self.assertEqual(self.req("POST", "/api/btc/sign", body='{"message": 1}', headers=self.good())[0], 400)
        self.assertEqual(len(FakeApplet.calls), before, "card not touched for malformed input")

    def test_keygen_disabled_by_default_and_on_old_applet(self):
        before = len(FakeApplet.calls)
        os.environ.pop("NURI_ALLOW_KEYGEN", None)
        status, _, body = self.req("POST", "/api/eth/keygen", body="{}", headers=self.good())
        self.assertEqual(status, 403)
        self.assertIn("NURI_ALLOW_KEYGEN", json.loads(body)["error"])
        self.assertEqual(len(FakeApplet.calls), before, "card not touched when keygen is disabled")
        os.environ["NURI_ALLOW_KEYGEN"] = "1"
        try:
            FakeApplet.version = (1, 3)
            status, _, body = self.req("POST", "/api/eth/keygen", body="{}", headers=self.good())
            self.assertEqual(status, 403)
            self.assertIn("< 1.4", json.loads(body)["error"])
            self.assertFalse(any(a[1] == 0x03 for a in FakeApplet.calls), "KEYGEN INS never sent")
        finally:
            os.environ.pop("NURI_ALLOW_KEYGEN", None)

    # --- W28 ETH policy ---

    def _eth_case(self, demo="1", present=None, eth2_sw=None):
        os.environ.pop("NURI_ALLOW_ETH1_DEMO", None)
        if demo is not None:
            os.environ["NURI_ALLOW_ETH1_DEMO"] = demo
        FakeApplet.present = {ETH1_AID} if present is None else present
        FakeApplet.eth2_sw = eth2_sw
        self.addCleanup(self._eth_reset)
        before = len(FakeApplet.calls)
        status, _, body = self.req("GET", "/api/eth/version", headers=self.good())
        sent = FakeApplet.calls[before:]
        eth1_selects = [a for a in sent if a[1] == 0xA4 and a[5:5 + a[4]] == ETH1_AID]
        return status, json.loads(body), eth1_selects, sent

    def _eth_reset(self):
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        FakeApplet.present = {ETH1_AID}
        FakeApplet.eth2_sw = None

    def test_eth1_refused_unless_demo_env_exactly_1(self):
        for demo in (None, "", "0", "true", "yes", "1 ", "01"):
            with self.subTest(demo=demo):
                status, d, eth1, _ = self._eth_case(demo=demo)
                self.assertEqual(status, 403)
                self.assertEqual(d["code"], "ETH1_DEMO_DISABLED")
                self.assertEqual(eth1, [], "ETH1 never selected")

    def test_eth1_demo_allowed_carries_warning(self):
        status, d, eth1, _ = self._eth_case(demo="1")
        self.assertEqual(status, 200, d)
        self.assertEqual(d["eth_applet"], "eth1-demo")
        self.assertIn("NO PIN", d["warning"])
        self.assertTrue(eth1)

    def test_eth2_installed_fails_closed_pin_unsupported(self):
        status, d, eth1, sent = self._eth_case(demo="1", present={ETH1_AID, ETH2_AID})
        self.assertEqual(status, 409)
        self.assertEqual(d["code"], "ETH2_PIN_UNSUPPORTED")
        self.assertEqual(eth1, [], "never bypass ETH2 via ETH1")
        self.assertFalse(any(a[1] in (0x01, 0x02, 0x04) for a in sent), "no ETH2 command without PIN flow")

    def test_eth2_ambiguous_status_or_transport_never_downgrades(self):
        status, d, eth1, _ = self._eth_case(demo="1", eth2_sw=0x6999)
        self.assertEqual((status, d["code"]), (503, "DOWNGRADE_REFUSED"))
        self.assertEqual(eth1, [])
        status, d, eth1, _ = self._eth_case(demo="1", eth2_sw="transport")
        self.assertEqual(status, 500)
        self.assertEqual(eth1, [])

    def test_sign_endpoints_follow_policy(self):
        os.environ.pop("NURI_ALLOW_ETH1_DEMO", None)
        self.addCleanup(self._eth_reset)
        before = len(FakeApplet.calls)
        for path, body in (("/api/eth/sign", json.dumps({"hash": "11" * 32})), ("/api/btc/sign", '{"message": "x"}'),
                           ("/api/eth/keygen", "{}")):
            os.environ["NURI_ALLOW_KEYGEN"] = "1"
            try:
                status, _, raw = self.req("POST", path, body=body, headers=self.good())
            finally:
                os.environ.pop("NURI_ALLOW_KEYGEN", None)
            self.assertEqual((status, json.loads(raw)["code"]), (403, "ETH1_DEMO_DISABLED"), path)
        self.assertFalse(any(a[1] in (0x02, 0x03, 0x04) for a in FakeApplet.calls[before:]))

    def test_card_status_skips_eth1_without_demo_env(self):
        os.environ.pop("NURI_ALLOW_ETH1_DEMO", None)
        self.addCleanup(self._eth_reset)
        before = len(FakeApplet.calls)
        status, _, body = self.req("GET", "/api/card/status", headers=self.good())
        self.assertEqual(status, 200, body)
        d = json.loads(body)
        self.assertIn("skipped", d["applets"]["eth"])
        self.assertEqual(d["applets"]["eth2"]["present"], False)
        self.assertFalse(any(a[1] == 0xA4 and a[5:5 + a[4]] == ETH1_AID for a in FakeApplet.calls[before:]))

    # --- framing / DoS ---

    def status_of(self, resp):
        return int(resp.split(b" ", 2)[1]) if resp else None

    def test_negative_and_malformed_length_rejected_before_auth(self):
        for cl in ("-1", "abc", "1, 1", "+3"):
            elapsed, resp = self.raw(f"POST /api/eth/sign HTTP/1.1\r\n{self.head()}Content-Length: {cl}\r\n\r\n".encode())
            self.assertEqual(self.status_of(resp), 400, (cl, resp[:80]))
            self.assertIn(b"Connection: close", resp)
            self.assertLess(elapsed, 1.0)
        elapsed, resp = self.raw(f"POST /api/eth/sign HTTP/1.1\r\n{self.head()}Content-Length: 2\r\nContent-Length: 2\r\n\r\n{{}}".encode())
        self.assertEqual(self.status_of(resp), 400)

    def test_oversized_body_413_without_reading_it(self):
        big = (1 << 20) + 1
        elapsed, resp = self.raw(f"POST /api/eth/sign HTTP/1.1\r\n{self.head()}Content-Length: {big}\r\n\r\n".encode())
        self.assertEqual(self.status_of(resp), 413, resp[:120])
        self.assertLess(elapsed, 1.0, "answered at once, did not wait for/drain the body")
        # also with valid auth, and on /pair
        elapsed, resp = self.raw(f"POST /pair HTTP/1.1\r\n{self.head()}Content-Length: {big}\r\n\r\n".encode())
        self.assertEqual(self.status_of(resp), 413)

    def test_transfer_encoding_refused_and_closed(self):
        elapsed, resp = self.raw(f"POST /api/eth/sign HTTP/1.1\r\n{self.head(AUTH_LINE)}"
                                 "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".encode())
        self.assertEqual(self.status_of(resp), 501)
        self.assertIn(b"Connection: close", resp)
        self.assertEqual(resp.count(b"HTTP/1."), 1, "no second (smuggled) request is processed")

    def test_unsupported_method_errors_also_have_page_guards(self):
        status, headers, body = self.req("PUT", "/", body="{}")
        self.assertEqual(status, 501)
        h = {k.lower(): v for k, v in headers.items()}
        self.assertEqual(h["x-frame-options"], "DENY")
        self.assertIn("default-src 'self'", h["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", h["content-security-policy"])
        self.assertNotIn(TOKEN.encode(), body)

    def test_get_with_body_refused(self):
        _, resp = self.raw(f"GET /api/eth/version HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nContent-Length: 3\r\n\r\nabc".encode())
        self.assertEqual(self.status_of(resp), 400)

    def test_slow_body_hits_absolute_deadline(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        t0 = time.monotonic()
        s.sendall(f"POST /api/eth/sign HTTP/1.1\r\n{self.head(AUTH_LINE)}"
                  "Content-Length: 200\r\n\r\n".encode())
        resp = b""
        try:
            for _ in range(40):  # trickle one byte every 0.2 s: a per-recv timeout would never fire
                s.sendall(b" ")
                time.sleep(0.2)
                s.setblocking(False)
                try:
                    chunk = s.recv(65536)
                    resp += chunk
                    if not chunk or b"\r\n\r\n" in resp:
                        break
                except BlockingIOError:
                    pass
                finally:
                    s.setblocking(True)
        except (BrokenPipeError, ConnectionResetError):
            pass
        s.close()
        elapsed = time.monotonic() - t0
        self.assertEqual(self.status_of(resp), 408, resp[:120])
        self.assertLess(elapsed, self.mod.REQUEST_DEADLINE_S + 1.0, "deadline is absolute, not renewed per byte")

    def test_slow_headers_hit_deadline_and_do_not_block_others(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        s.sendall(b"GET /api/eth/version HTTP/1.1\r\nHost: 127.0.0.1")  # never finishes the headers
        t0 = time.monotonic()
        status, _, _ = self.req("GET", "/api/eth/version", headers={"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(status, 200)
        self.assertLess(time.monotonic() - t0, 1.0, "a stalled client does not block other clients")
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        s.close()
        self.assertLess(time.monotonic() - t0, self.mod.REQUEST_DEADLINE_S + 1.0)
        self.assertEqual(self.status_of(resp), 408)

    def test_rejection_closes_connection(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(f"GET /api/eth/version HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n\r\n"
                  f"GET /api/eth/version HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nAuthorization: Bearer {TOKEN}\r\n\r\n".encode())
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        s.close()
        self.assertEqual(self.status_of(resp), 401)
        self.assertEqual(resp.count(b"HTTP/1."), 1, "pipelined request after a rejection is not served")


class MainStartup(CleanEnv):
    def test_main_refuses_remote_bind_and_generic_token(self):
        mod = load_dashboard()
        os.environ["HOME"] = self.tmp
        os.environ["NURI_CARD_HOST"] = "0.0.0.0"
        os.environ["NURI_ALLOW_REMOTE"] = "1"
        os.environ["NURI_DASHBOARD_TOKEN"] = TOKEN
        with self.assertRaisesRegex(RuntimeError, "loopback-only"):
            mod.main()
        os.environ["NURI_CARD_HOST"] = "127.0.0.1"
        del os.environ["NURI_DASHBOARD_TOKEN"]
        os.environ["NURI_CARD_TOKEN"] = TOKEN
        with self.assertRaises(SystemExit) as cm:
            mod.main()
        self.assertIn("NURI_DASHBOARD_TOKEN", str(cm.exception.code))


if __name__ == "__main__":
    unittest.main()
