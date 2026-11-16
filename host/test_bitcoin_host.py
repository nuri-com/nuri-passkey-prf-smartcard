#!/usr/bin/env python3
"""Bitcoin host commands against a fake bridge and fake PC/SC. No reader, no card.

The bridge is a stand-in for scripts/ext-card-wallet.mjs: it speaks the same
JSON-lines preview/decision protocol, so the host's spawn, digest binding, PIN
forwarding, cancellation, timeout and error mapping are all exercised for real.
"""

import io
import json
import os
import shutil
import sys
import tempfile
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import nuri_card_host as host  # noqa: E402
import bitcoin_commands as bc  # noqa: E402

from contextlib import redirect_stderr  # noqa: E402

BRIDGE = r'''
import json, os, sys, time

cfg = json.loads(sys.stdin.readline())
mode = cfg.get("mode")
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "log.jsonl"), "a") as log:
    log.write(json.dumps({"mode": mode, "argv": sys.argv[1:], "pin_env": os.environ.get("NURI_CARD_PIN"), "params": cfg}) + "\n")
if mode == "info":
    print(json.dumps({"phase": "result", "status": "NURI_CARD_BITCOIN_INFO_OK", "ark_address": "ark1info", "onchain_address": "bc1pinfo", "boarding_address": "bc1pboard", "aggregate_pubkey33": "02aa", "server_pubkey33": "02bb", "pin_set": True, "pin_tries_left": 5}), flush=True)
    sys.exit(0)
if mode in ("balance", "invoice"):
    print(json.dumps({"phase": "result", "status": "OK", "vtxo_sats": 4926, "boarding_sats": 0}), flush=True)
    sys.exit(0)
# send: preview, wait for the decision, then answer it
if cfg.get("kind") == "ark" and cfg.get("target") == "ark1slow":
    time.sleep(3)
print(json.dumps({"phase": "preview", "digest": "0x" + "ab" * 32, "summary": {"kind": cfg["kind"], "amount_sats": cfg.get("amount_sats")}}), flush=True)
decision = json.loads(sys.stdin.readline())
if not decision.get("approved"):
    print(json.dumps({"phase": "cancelled", "digest": decision.get("digest")}), flush=True)
    sys.exit(0)
print(json.dumps({"phase": "result", "status": "NURI_CARD_BITCOIN_SEND_OK", "ark_txid": "cd" * 32, "approved_digest": decision.get("digest"), "pin_seen": bool(decision.get("pin"))}), flush=True)
'''


def fake_pcsc():
    """Minimum C1 surface for a successful ETH2 `info` (no MuSig2 involvement)."""
    from ecdsa import SigningKey, SECP256k1
    from ecdsa.util import sigencode_der, sigencode_string

    key = SigningKey.from_secret_exponent(0x51, curve=SECP256k1)

    class CardError(Exception):
        def __init__(self, code, msg=""):
            super().__init__(msg or code)
            self.code = code

    class Applet:
        reader_name = "Fake Reader 00 00"
        protocol = "T0"

        def transmit(self, apdu):
            ins = bytes(apdu)[1]
            if ins == 0x01:
                return b"\x02\x00\x00ETH2" + bytes([0x01, 0x00, 5]), 0x9000
            if ins == 0x02:
                return key.get_verifying_key().to_string("uncompressed"), 0x9000
            return b"", 0x6D00

        def close(self):
            pass

    mod = types.ModuleType("nuri_pcsc")
    mod.CardError = CardError
    mod.Applet = Applet
    mod.open_applet = lambda aid, reader=None: Applet()
    mod._list_readers = lambda: []
    mod._select_readers = lambda readers, hint: list(readers)
    mod.select_apdu = lambda aid: b"\x00\xa4\x04\x00\x00"
    sys.modules["nuri_pcsc"] = mod


class BitcoinHostTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.bridge = os.path.join(self.dir, "bridge.py")
        with open(self.bridge, "w") as stream:
            stream.write(BRIDGE)
        self.saved = {key: os.environ.get(key) for key in
                      ("NURI_CARD_SIM", "NURI_BITCOIN_BRIDGE", "NURI_NODE", "NURI_CARD_PIN")}
        os.environ.pop("NURI_CARD_SIM", None)
        os.environ["NURI_BITCOIN_BRIDGE"] = self.bridge
        os.environ["NURI_NODE"] = sys.executable
        fake_pcsc()
        host._reset_session()
        host._INFO = None
        bc._JOBS.clear()
        self._stderr = io.StringIO()
        self._redirect = redirect_stderr(self._stderr)
        self._redirect.__enter__()

    def tearDown(self):
        for job in list(bc._JOBS.values()):
            bc._kill(job["proc"])
            try:
                job["proc"].wait(timeout=2)
            except Exception:
                pass
        bc._JOBS.clear()
        self._redirect.__exit__(None, None, None)
        sys.modules.pop("nuri_pcsc", None)
        for key, value in self.saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value
        host._reset_session()

    def call(self, method, params=None, ident=1):
        request = {"id": ident, "method": method}
        if params is not None:
            request["params"] = params
        return host.handle(request)

    def seen(self):
        try:
            with open(os.path.join(self.dir, "log.jsonl")) as stream:
                return [json.loads(line) for line in stream if line.strip()]
        except FileNotFoundError:
            return []

    def ready(self):
        info = self.call("info")
        self.assertTrue(info["ok"], info)
        return info

    # -- gating -----------------------------------------------------------
    def test_info_first_is_required(self):
        self.assertEqual(self.call("bitcoin_info")["error"]["code"], "INFO_REQUIRED")
        self.assertEqual(self.call("bitcoin_balance")["error"]["code"], "INFO_REQUIRED")
        self.assertEqual(self.seen(), [])

    def test_simulator_fails_closed(self):
        os.environ["NURI_CARD_SIM"] = "1"
        self.ready()
        result = self.call("bitcoin_info")
        self.assertEqual(result["error"]["code"], "BITCOIN_UNAVAILABLE")
        self.assertIn("card", result["error"]["message"])

    def test_missing_node_is_reported(self):
        self.ready()
        os.environ["NURI_NODE"] = os.path.join(self.dir, "nope")
        self.assertEqual(self.call("bitcoin_info")["error"]["code"], "BITCOIN_UNAVAILABLE")

    # -- read paths -------------------------------------------------------
    def test_info_and_balance_pass_through(self):
        self.ready()
        info = self.call("bitcoin_info")["result"]
        self.assertEqual(info["ark_address"], "ark1info")
        balance = self.call("bitcoin_balance")["result"]
        self.assertEqual(balance["vtxo_sats"], 4926)
        self.assertEqual([entry["mode"] for entry in self.seen()], ["info", "balance"])

    def test_invoice_validates_amount_and_memo(self):
        self.ready()
        for amount, memo, code in ((0, "x", "BAD_REQUEST"), (2500, "", "BAD_REQUEST"),
                                   ("2500", "x", "BAD_REQUEST"), (10 ** 9, "x", "BAD_REQUEST")):
            result = self.call("bitcoin_invoice", {"amount_sats": amount, "memo": memo})
            self.assertEqual(result["error"]["code"], code, (amount, memo))
        ok = self.call("bitcoin_invoice", {"amount_sats": 2500, "memo": "coffee"})
        self.assertTrue(ok["ok"], ok)

    def test_preview_validates_kind_target_and_amount(self):
        self.ready()
        cases = (
            ({"kind": "card", "target": "x"}, "BAD_REQUEST"),
            ({"kind": "ark", "target": "ark1a", "amount_sats": 0}, "BAD_REQUEST"),
            ({"kind": "ark", "target": "bc1px", "amount_sats": 5}, "BAD_REQUEST"),
            ({"kind": "lightning", "target": "lntb1xyz"}, "BAD_REQUEST"),
            ({"kind": "lightning", "target": "bc1px"}, "BAD_REQUEST"),
        )
        for params, code in cases:
            self.assertEqual(self.call("bitcoin_preview", params)["error"]["code"], code, params)
        # A bare amount prefix is accepted here; the extension checks the full shape.
        self.assertTrue(self.call("bitcoin_preview", {"kind": "lightning", "target": "lnbc2500u1pvjluezpp5"})["ok"])

    # -- spend ------------------------------------------------------------
    def test_preview_returns_a_digest_and_sign_returns_the_result(self):
        self.ready()
        preview = self.call("bitcoin_preview", {"kind": "lightning", "target": "lnbc2500u1pvjluezpp5"})["result"]
        self.assertRegex(preview["digest"], r"^0x[0-9a-f]{64}$")
        self.assertEqual(preview["summary"]["kind"], "lightning")
        signed = self.call("bitcoin_sign_partial",
                           {"job_id": preview["job_id"], "digest": preview["digest"], "pin": "2468"})
        self.assertTrue(signed["ok"], signed)
        self.assertEqual(signed["result"]["approved_digest"], preview["digest"])
        self.assertTrue(signed["result"]["pin_seen"])
        self.assertEqual(bc._JOBS, {})

    def test_digest_mismatch_never_signs_and_keeps_the_job(self):
        self.ready()
        preview = self.call("bitcoin_preview", {"kind": "lightning", "target": "lnbc2500u1pvjluezpp5"})["result"]
        wrong = self.call("bitcoin_sign_partial", {"job_id": preview["job_id"], "digest": "0x" + "00" * 32})
        self.assertEqual(wrong["error"]["code"], "DIGEST_MISMATCH")
        self.assertIn(preview["job_id"], bc._JOBS, "a mismatched digest must not burn the preview")
        again = self.call("bitcoin_sign_partial", {"job_id": preview["job_id"], "digest": preview["digest"]})
        self.assertTrue(again["ok"], again)

    def test_pin_travels_in_the_decision_line_not_argv_and_is_never_echoed(self):
        self.ready()
        preview = self.call("bitcoin_preview", {"kind": "ark", "target": "ark1qqy", "amount_sats": 900})["result"]
        # The bridge logs the env it saw at start (before the PIN existed) and then
        # echoes whether it received one on the decision line.
        self.assertIsNone(self.seen()[-1]["pin_env"], "the PIN must not be in the child env at spawn time")
        signed = self.call("bitcoin_sign_partial",
                           {"job_id": preview["job_id"], "digest": preview["digest"], "pin": "2468"})
        self.assertTrue(signed["result"]["pin_seen"])
        self.assertNotIn("2468", " ".join(self.seen()[-1]["argv"]))
        self.assertNotIn("2468", json.dumps(signed["result"]))

    def test_cancel_kills_the_job_and_the_old_digest_cannot_sign(self):
        self.ready()
        preview = self.call("bitcoin_preview", {"kind": "lightning", "target": "lnbc2500u1pvjluezpp5"})["result"]
        self.assertEqual(self.call("bitcoin_cancel", {"job_id": preview["job_id"]})["result"], {"cancelled": True})
        self.assertEqual(bc._JOBS, {})
        late = self.call("bitcoin_sign_partial", {"job_id": preview["job_id"], "digest": preview["digest"]})
        self.assertEqual(late["error"]["code"], "UNKNOWN_JOB")
        self.assertEqual(self.call("bitcoin_cancel", {"job_id": "nope"})["result"], {"cancelled": False})

    def test_preview_timeout_is_typed_and_reaped(self):
        self.ready()
        saved = bc.PREVIEW_TIMEOUT
        bc.PREVIEW_TIMEOUT = 0.2
        try:
            result = self.call("bitcoin_preview", {"kind": "ark", "target": "ark1slow", "amount_sats": 5})
        finally:
            bc.PREVIEW_TIMEOUT = saved
        self.assertEqual(result["error"]["code"], "BITCOIN_TIMEOUT")
        self.assertEqual(bc._JOBS, {})

    def test_bridge_error_phase_maps_to_a_typed_error(self):
        self.ready()
        with open(self.bridge, "w") as stream:
            stream.write("import json,sys\ncfg=json.loads(sys.stdin.readline())\nprint(json.dumps({'phase':'error','error':'send/prepare failed: 409'}),flush=True)\n")
        result = self.call("bitcoin_preview", {"kind": "lightning", "target": "lnbc2500u1pvjluezpp5"})
        self.assertEqual(result["error"]["code"], "BITCOIN_ERROR")
        self.assertIn("409", result["error"]["message"])

    def test_sign_without_params_and_unknown_job(self):
        self.ready()
        self.assertEqual(self.call("bitcoin_sign_partial")["error"]["code"], "BAD_REQUEST")
        self.assertEqual(self.call("bitcoin_sign_partial", {"job_id": "x", "digest": "0x" + "ab" * 32})["error"]["code"], "UNKNOWN_JOB")


if __name__ == "__main__":
    unittest.main(verbosity=2)
