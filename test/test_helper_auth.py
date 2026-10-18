#!/usr/bin/env python3
"""Guard tests for scripts/card-dashboard-server.py + scripts/nuri_helper_auth.py.

No reader, no card: nuri_pcsc.open_applet is replaced by a fake applet that
answers SELECT/VERSION with 9000 and raises for anything that would sign or
generate a key. The server is started in-process on a random loopback port.

Run:  python3 -m unittest test/test_helper_auth.py
      (needs ecdsa + pycryptodome + base58, same as the dashboard itself:
       scripts/run-card-python.sh -m unittest test/test_helper_auth.py)
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import nuri_helper_auth  # noqa: E402
import nuri_pcsc  # noqa: E402

TOKEN = "test-token-0123456789abcdef0123456789abcdef"


class FakeApplet:
    """Answers SELECT (INS A4) and VERSION (INS 01) only. Everything else = test failure."""
    version = (1, 3)
    calls: list[bytes] = []

    def transmit(self, apdu):
        apdu = bytes(apdu)
        FakeApplet.calls.append(apdu)
        ins = apdu[1]
        if ins == 0xA4:
            return b"", 0x9000
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


class GuardUnit(unittest.TestCase):
    def g(self, method="POST", path="/api/eth/sign", **headers):
        h = {k.replace("_", "-"): v for k, v in headers.items()}
        return nuri_helper_auth.guard_request(method, path, h, port=8788, token=TOKEN)

    def test_rules(self):
        good = dict(host="127.0.0.1:8788", content_type="application/json", authorization=f"Bearer {TOKEN}")
        self.assertIsNone(self.g(**good))
        self.assertIsNone(self.g(**{**good, "host": "localhost:8788", "origin": "http://localhost:8788"}))
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

    def test_check_bind(self):
        nuri_helper_auth.check_bind("127.0.0.1", "env")
        env = dict(os.environ)
        os.environ.pop("NURI_ALLOW_REMOTE", None)
        try:
            with self.assertRaisesRegex(RuntimeError, "refusing to bind 0.0.0.0"):
                nuri_helper_auth.check_bind("0.0.0.0", "env")
            os.environ["NURI_ALLOW_REMOTE"] = "1"
            with self.assertRaisesRegex(RuntimeError, "NURI_CARD_TOKEN"):
                nuri_helper_auth.check_bind("0.0.0.0", "/some/file")
            nuri_helper_auth.check_bind("0.0.0.0", "env")
        finally:
            os.environ.clear(); os.environ.update(env)

    def test_token_file_created_0600(self):
        env = dict(os.environ)
        with tempfile.TemporaryDirectory() as d:
            os.environ.pop("NURI_CARD_TOKEN", None)
            os.environ["NURI_CARD_TOKEN_FILE"] = os.path.join(d, "sub", "token")
            try:
                logs = []
                token, source = nuri_helper_auth.load_or_create_token(log=logs.append)
                self.assertEqual(len(token), 64)
                self.assertEqual(source, os.environ["NURI_CARD_TOKEN_FILE"])
                self.assertEqual(stat.S_IMODE(os.stat(source).st_mode), 0o600)
                self.assertTrue(any(token in m for m in logs), "printed once")
                token2, _ = nuri_helper_auth.load_or_create_token(log=logs.append)
                self.assertEqual(token, token2)
            finally:
                os.environ.clear(); os.environ.update(env)

    def test_inject_token(self):
        out = nuri_helper_auth.inject_token("<html><head><title>x</title></head></html>", "abc")
        self.assertIn('<head><script>(function(){var t="abc"', out)


class DashboardServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_dashboard()
        cls.mod.nuri_pcsc = nuri_pcsc
        cls._orig_open_applet = nuri_pcsc.open_applet
        nuri_pcsc.open_applet = lambda aid: FakeApplet()
        cls.mod._applet = None
        cls.srv = HTTPServer(("127.0.0.1", 0), cls.mod.Handler)
        cls.port = cls.srv.server_address[1]
        cls.mod.AUTH.update(token=TOKEN, port=cls.port, remote=False, bind_host="127.0.0.1")
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        nuri_pcsc.open_applet = cls._orig_open_applet

    def req(self, method, path, body=None, headers=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = dict(headers or {})
        h["Host"] = host or f"127.0.0.1:{self.port}"
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict(r.getheaders()), data

    def good(self):
        return {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

    def test_page_opens_with_token_shim_and_no_cors(self):
        status, headers, body = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"window.NURI_CARD_TOKEN=t", body)
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in headers})

    def test_401_without_token(self):
        for path, method in (("/api/eth/sign", "POST"), ("/api/btc/sign", "POST"), ("/api/eth/pubkey", "GET"), ("/api/eth/keygen", "POST")):
            status, _, body = self.req(method, path, body="{}", headers={"Content-Type": "application/json"})
            self.assertEqual(status, 401, (path, body))

    def test_403_bad_host_or_origin(self):
        status, _, _ = self.req("POST", "/api/eth/sign", body="{}", headers=self.good(), host="evil.example")
        self.assertEqual(status, 403)
        status, _, _ = self.req("POST", "/api/eth/sign", body="{}", headers={**self.good(), "Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        status, headers, _ = self.req("OPTIONS", "/api/eth/sign", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
        self.assertEqual(status, 403)
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in headers})

    def test_415_without_json_content_type(self):
        status, _, _ = self.req("POST", "/api/eth/sign", body="{}", headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_200_with_token(self):
        status, _, body = self.req("GET", "/api/eth/version", headers={"Authorization": f"Bearer {TOKEN}", "Origin": f"http://localhost:{self.port}"})
        self.assertEqual(status, 200, body)
        d = json.loads(body)
        self.assertEqual((d["major"], d["minor"]), (1, 3))

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


if __name__ == "__main__":
    unittest.main()
