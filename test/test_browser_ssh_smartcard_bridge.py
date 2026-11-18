import importlib.util
import json
import os
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BRIDGE_PATH = ROOT / "scripts" / "browser-ssh-smartcard-bridge.py"


def load_bridge():
    os.environ["SWARM_ORIGIN"] = "https://code.emin.de"
    spec = importlib.util.spec_from_file_location("browser_ssh_smartcard_bridge", BRIDGE_PATH)
    mod = importlib.util.module_from_spec(spec)
    # Stub fido2 imports if running in bare system python without python-fido2
    fake_fido2 = mock.MagicMock()
    fake_fido2.cose.ES256.ALGORITHM = -7
    fake_fido2.pcsc.CtapPcscDevice.list_devices.return_value = []
    with mock.patch.dict(
        "sys.modules",
        {
            "fido2": fake_fido2,
            "fido2.cose": fake_fido2.cose,
            "fido2.ctap2": fake_fido2.ctap2,
            "fido2.pcsc": fake_fido2.pcsc,
        },
    ), mock.patch("nuri_pcsc.patch_fido2"):
        spec.loader.exec_module(mod)
    return mod


class BrowserSshSmartcardBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_bridge()
        cls.srv = cls.mod.ThreadingHTTPServer(("127.0.0.1", 0), cls.mod.BridgeHandler)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _req(self, method: str, path: str, body: dict | None = None, origin: str | None = None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        raw = None
        if origin is not None:
            headers["Origin"] = origin
        if body is not None:
            raw = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=raw, headers=headers)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return res.status, json.loads(data.decode("utf-8")) if data else {}

    def test_forbids_foreign_origin(self):
        code, body = self._req("POST", "/ssh-sign", {"application": "ssh:"}, origin="https://evil.example")
        self.assertEqual(code, 403)
        self.assertEqual(body.get("error"), "Origin forbidden")

    def test_refuses_non_ssh_application_on_ssh_sign(self):
        code, body = self._req(
            "POST",
            "/ssh-sign",
            {"application": "code.emin.de", "dataHex": "00", "keyHandleHex": "00"},
            origin="https://code.emin.de",
        )
        self.assertEqual(code, 500)
        self.assertIn("Refusing non-SSH application", body.get("error", ""))

    def test_refuses_mismatched_rp_id_on_webauthn_get(self):
        code, body = self._req(
            "POST",
            "/webauthn-get",
            {"options": {"rpId": "other.example", "challenge": "AAAA", "allowCredentials": []}},
            origin="https://code.emin.de",
        )
        self.assertEqual(code, 500)
        self.assertIn("Refusing unexpected rpId", body.get("error", ""))

    def test_der_ecdsa_rs_parses_leading_zero_padded_integers(self):
        # DER SEQUENCE { INTEGER 0x0081, INTEGER 0x01 }
        der = bytes.fromhex("300702020081020101")
        r, s = self.mod.der_ecdsa_rs(der)
        self.assertEqual(r.hex(), "81")
        self.assertEqual(s.hex(), "01")


if __name__ == "__main__":
    unittest.main()
