"""Offline W28 integration regressions; no PC/SC reader is opened."""
import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PolicyIntegrationTests(unittest.TestCase):
    def test_dashboard_keeps_selection_between_policy_and_operation(self):
        dash = load('w28_dashboard', ROOT / 'scripts/card-dashboard-server.py')
        selected = None
        calls = []

        def transmit(apdu):
            nonlocal selected
            calls.append(bytes(apdu))
            if apdu[1] == 0xA4:
                aid = bytes(apdu[5:])
                selected = aid
                return b'', 0x6A82 if aid == dash.AID_ETH2 else 0x9000
            self.assertEqual(selected, dash.AID_ETH, 'liveness must not SELECT ETH2 between policy and SIGN')
            return b'synthetic-response', 0x9000

        setattr(dash, '_applet', types.SimpleNamespace(transmit=transmit, close=Mock()))
        with patch.dict(os.environ, {'NURI_ALLOW_ETH1_DEMO': '1'}):
            with patch.object(dash.nuri_pcsc, 'open_applet', side_effect=AssertionError('unexpected reconnect')):
                self.assertEqual(dash.select_eth()['eth_applet'], 'eth1-demo')
                data, sw = dash.transmit(bytes.fromhex('8004000020') + bytes(32))
        self.assertEqual(data, b'synthetic-response')
        self.assertEqual(sw, 0x9000)
        self.assertEqual([p[1] for p in calls], [0xA4, 0xA4, 0x04])

    def test_dashboard_failed_sign_is_never_retried(self):
        dash = load('w28_dashboard_error', ROOT / 'scripts/card-dashboard-server.py')
        transport = Mock(side_effect=OSError('removed during sign'))
        close = Mock()
        setattr(dash, '_applet', types.SimpleNamespace(transmit=transport, close=close))
        with self.assertRaisesRegex(OSError, 'removed during sign'):
            dash.transmit(bytes.fromhex('8004000020') + bytes(32))
        self.assertEqual(transport.call_count, 1)
        close.assert_called_once()
        self.assertIsNone(dash._applet)

    def test_dashboard_direct_eth1_selection_cannot_bypass_env(self):
        dash = load('w28_dashboard_direct', ROOT / 'scripts/card-dashboard-server.py')
        with patch.dict(os.environ, {}, clear=True), patch.object(dash, 'transmit') as transmit:
            with self.assertRaisesRegex(RuntimeError, 'ETH1_DEMO_DISABLED'):
                dash.select_aid(dash.AID_ETH)
            transmit.assert_not_called()

    def test_host_eth2_aid_cannot_alias_eth1(self):
        host = load('w28_native_host', ROOT / 'host/nuri_card_host.py')
        signer = host.CardSigner.__new__(host.CardSigner)
        pcsc = types.SimpleNamespace(CardError=RuntimeError, open_applet=Mock())
        signer._pcsc = pcsc
        signer._reader_hint = None
        with patch.object(host, 'AID_ETH_V2', host.AID_ETH_V1):
            with self.assertRaises(host.HostError) as error:
                signer._open()
        self.assertEqual(error.exception.code, 'CONFIG_ERROR')
        pcsc.open_applet.assert_not_called()


if __name__ == '__main__':
    unittest.main()
