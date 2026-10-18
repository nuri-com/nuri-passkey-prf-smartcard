"""Synthetic PRF only: no fido2 import, enrollment, reader or real credential."""
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch
import runpy
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
        signal = self.cli("run", "API", "--", sys.executable, "-c", "import os,signal; os.kill(os.getpid(), signal.SIGTERM)")
        self.assertEqual(signal.returncode, 143)

    def test_metadata_tampering_and_permissive_vault_fail_closed(self):
        self.put()
        self.assertEqual(self.cli("run", "API", "--", "false",
                                  env={k: v for k, v in self.env.items() if k != "NURI_CARD_SECRETS_FAKE_PRF"}).returncode, 1)
        vault = json.loads(self.vault.read_text())
        vault["secrets"]["OTHER"] = vault["secrets"].pop("API")
        self.vault.write_text(json.dumps(vault))
        self.assertEqual(self.cli("run", "OTHER", "--", sys.executable, "-c", "pass").returncode, 1)
        vault["secrets"]["API"] = vault["secrets"].pop("OTHER")
        vault["secrets"]["API"]["tags"] = ["tampered"]
        self.vault.write_text(json.dumps(vault))
        self.assertEqual(self.cli("run", "API", "--", "false").returncode, 1)
        self.vault.chmod(0o644)
        self.assertEqual(self.cli("list").returncode, 1)

    def test_existing_derive_path_with_stub_no_hardware(self):
        module = runpy.run_path(str(SCRIPT))
        backup = Mock()
        backup.derive_once.return_value = (b"p" * 32, None)
        args = Mock(profile_path="existing-profile.json", transport="pcsc", device_index=None)
        with patch.dict(os.environ, {}, clear=True), patch("importlib.util.spec_from_file_location"), patch("importlib.util.module_from_spec", return_value=backup):
            self.assertEqual(module["prf"](args), b"p" * 32)
        backup.read_profile.assert_called_once_with(Path("existing-profile.json"))
        call = backup.derive_once.call_args.args
        self.assertEqual((call[0].user_verification, call[2:]), ("required", (b"nuri-card-secrets-v1", None)))
        self.assertTrue(call[0].pin_prompt)
        backup.command_enroll.assert_not_called()

    def test_proxy_injects_headers_fixed_upstream_no_leaky_logs(self):
        self.put()
        seen = []

        class Upstream(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization"), self.headers.get("X-API-Key")))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
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
                    assert proc.stdout is not None
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
