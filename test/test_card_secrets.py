"""Synthetic PRF only: no fido2 import, enrollment, reader or real credential."""
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import tempfile
import threading
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/card-secrets.py"
SECRET = "synthetic-card-secrets-test-only"


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.vault = self.home / ".nuri-card/vault.json"
        self.env = {**os.environ, "HOME": str(self.home), "NURI_CARD_SECRETS_FAKE_PRF": "11" * 32}
        self.base = [sys.executable, str(SCRIPT)]

    def cli(self, *args, value=None, env=None):
        return subprocess.run(self.base + list(args), input=value, env=env or self.env,
                              capture_output=True, timeout=10)

    def put(self):
        result = self.cli("put", "API", "--tag", "test", value=SECRET.encode())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_round_trip_permissions_and_wrong_prf(self):
        self.put()
        result = self.cli("list")
        self.assertEqual(result.returncode, 0)
        entry, = json.loads(result.stdout)
        self.assertEqual((entry["name"], entry["tags"]), ("API", ["test"]))
        self.assertTrue(entry["created"])
        self.assertNotIn(SECRET, self.vault.read_text())
        self.assertEqual(stat.S_IMODE(self.vault.stat().st_mode), 0o600)
        bad = self.cli("run", "API", "--", sys.executable, "-c", "raise SystemExit(99)",
                       env={**self.env, "NURI_CARD_SECRETS_FAKE_PRF": "22" * 32})
        self.assertEqual(bad.returncode, 1)
        self.assertNotIn(SECRET.encode(), bad.stdout + bad.stderr)
        self.assertEqual(self.cli("rm", "API").returncode, 0)
        self.assertEqual(json.loads(self.cli("list").stdout), [])

    def test_run_injects_only_child_and_preserves_stdin_bytes(self):
        self.put()
        target = self.home / "child-result"
        program = ("import os,pathlib,sys; pathlib.Path(sys.argv[1]).write_text(os.environ['NURI_SECRET_API']); "
                   "assert 'NURI_CARD_SECRETS_FAKE_PRF' not in os.environ; "
                   "assert 'NURI_SECRET_OLD' not in os.environ")
        result = self.cli("run", "API", "--", sys.executable, "-c", program, str(target),
                          env={**self.env, "NURI_SECRET_OLD": "unrelated"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_text(), SECRET)
        self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)
        self.assertNotEqual(self.cli("put", "API", value=b"overwrite").returncode, 0)
        self.assertNotEqual(self.cli("put", "bad-name", value=b"invalid").returncode, 0)

    def test_metadata_tampering_and_permissive_vault_fail_closed(self):
        self.put()
        vault = json.loads(self.vault.read_text())
        vault["secrets"]["API"]["tags"] = ["tampered"]
        self.vault.write_text(json.dumps(vault))
        self.assertEqual(self.cli("run", "API", "--", "false").returncode, 1)
        self.vault.chmod(0o644)
        self.assertEqual(self.cli("list").returncode, 1)
        self.assertEqual(self.cli("run", "API", "--", "false",
                                  env={k: v for k, v in self.env.items() if k != "NURI_CARD_SECRETS_FAKE_PRF"}).returncode, 1)

    def test_proxy_injects_headers_fixed_upstream_no_leaky_logs(self):
        self.put()
        seen = []

        class Upstream(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization"), self.headers.get("X-API-Key")))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_):
                pass

        with HTTPServer(("127.0.0.1", 0), Upstream) as upstream:
            thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(upstream.shutdown)
            for header in ("Authorization", "X-API-Key"):
                proc = subprocess.Popen(self.base + ["proxy", "API", "--upstream",
                    f"http://127.0.0.1:{upstream.server_port}/v1", "--header", header],
                    env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    with selectors.DefaultSelector() as sel:
                        sel.register(proc.stdout, selectors.EVENT_READ)
                        self.assertTrue(sel.select(10), "proxy startup timed out")
                    url = proc.stdout.readline().decode().strip()
                    self.assertTrue(url.startswith("http://127.0.0.1:"), url)
                    client = http.client.HTTPConnection(url.removeprefix("http://"), timeout=5)
                    for path, headers, status in (("/test?do_not_log=sentinel", {}, 200),
                            ("/blocked", {"Origin": "https://example.invalid"}, 403),
                            ("http://example.invalid/escape", {}, 403),
                            ("/blocked", {"Host": "example.invalid"}, 403)):
                        client.request("GET", path, headers=headers)
                        response = client.getresponse()
                        self.assertEqual(response.status, status)
                        self.assertNotIn(SECRET.encode(), response.read())
                    client.close()
                    expected = ("/v1/test?do_not_log=sentinel", "Bearer " + SECRET, None) if header == "Authorization" else ("/v1/test?do_not_log=sentinel", None, SECRET)
                    self.assertEqual(seen[-1], expected)
                finally:
                    proc.terminate()
                    out, err = proc.communicate(timeout=5)
                self.assertNotIn(SECRET.encode(), out + err)
                self.assertNotIn(b"do_not_log", err)
                self.assertIn(b'GET "/test" 200', err)
            self.assertEqual(len(seen), 2)


if __name__ == "__main__":
    unittest.main()
