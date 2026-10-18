#!/usr/bin/env python3
"""Fake-reader tests for scripts/nuri_pcsc.py (no pyscard, no hardware).

Run from any cwd:  python3 -m unittest test/test_nuri_pcsc.py
Fakes model the two readers the parent measured on the real card:
  * OMNIKEY 5422: default connect works, T=1 transport, plain 9000 answers
  * Realtek 0bda:0165: default connect -> "unresponsive" (0x80100066),
    T=1 -> "protocol mismatch" (0x8010000F), T=0 works and answers
    61XX (GET RESPONSE) and 6CXX (resend with Le=XX)
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import nuri_pcsc  # noqa: E402

ETH_AID = "4E55524945544801"
FIDO_AID = "A0000006472F0001"
T0 = 0x00000001
T1 = 0x00000002

SELECT_ETH = list(bytes.fromhex("00A4040008" + ETH_AID))
VERSION = [0x80, 0x01, 0x00, 0x00, 0x00]
PUBKEY = [0x80, 0x02, 0x00, 0x00, 0x00]
SIGN = [0x80, 0x04, 0x00, 0x00, 0x20] + [0x11] * 32
VERSION_RESP = [0x01, 0x03, 0x01] + list(b"ETH1")
PUBKEY_RESP = list(bytes.fromhex("031f0f76cf2da4d2c679130f1accfb1e3b149c20ea15291a49b643e350cc63c4b1"))
SIG_RESP = list(range(64)) + [1]  # r||s||v, v in {0,1} (pkcs11-helper rejects anything else)


class ConnectError(Exception):
    def __init__(self, message, hresult):
        super().__init__(message)
        self.hresult = hresult


class NoCardException(Exception):  # same class name pyscard uses
    def __init__(self, message, hresult=0x8010000C):
        super().__init__(message)
        self.hresult = hresult


class FakeCard:
    """A card image: AIDs present, behaviour on T=0 vs T=1."""

    def __init__(self, aids=(ETH_AID, FIDO_AID)):
        self.aids = {a.upper() for a in aids}

    def answer(self, apdu, protocol):
        """Return (data, sw1, sw2) for one raw APDU the way the real card does."""
        if apdu[:4] == [0x00, 0xA4, 0x04, 0x00]:
            aid = bytes(apdu[5:5 + apdu[4]]).hex().upper()
            return ([], 0x90, 0x00) if aid in self.aids else ([], 0x6A, 0x82)
        # The ETH applet ignores CLA (scripts send 00, the dashboard/brief send 80).
        if apdu[1:4] == [0x01, 0x00, 0x00]:
            return self._case2(apdu, VERSION_RESP, protocol)
        if apdu[1:4] == [0x02, 0x00, 0x00]:
            return self._case2(apdu, PUBKEY_RESP, protocol)
        if apdu[1:5] == [0x04, 0x00, 0x00, 0x20]:
            if protocol == T0:
                return [], 0x61, 0x41
            return SIG_RESP, 0x90, 0x00
        return [], 0x6D, 0x00

    @staticmethod
    def _case2(apdu, resp, protocol):
        le = apdu[4]
        if protocol == T0 and le != len(resp):
            return [], 0x6C, len(resp)
        return list(resp), 0x90, 0x00


class FakeConnection:
    def __init__(self, reader):
        self.reader = reader
        self.protocol = None
        self.connected = False
        self.log = []
        self.pending = None  # response waiting for GET RESPONSE on T=0

    def connect(self, protocol=None):
        self.reader.connect_calls.append(protocol)
        if self.reader.card is None:
            raise NoCardException("Unable to connect")
        error = self.reader.connect_errors.get(protocol)
        if error is not None:
            raise ConnectError(*error)
        self.protocol = protocol if protocol is not None else self.reader.default_protocol
        self.connected = True

    def disconnect(self):
        self.connected = False
        self.reader.disconnects += 1

    def getATR(self):
        return list(self.reader.atr)

    def transmit(self, apdu, protocol=None):
        if not self.connected:
            raise ConnectError("not connected", 0x80100067)
        apdu = list(apdu)
        self.log.append(apdu)
        if apdu[:4] == [0x00, 0xC0, 0x00, 0x00]:
            if self.pending is None:
                return [], 0x6F, 0x00
            data, self.pending = self.pending, None
            return data, 0x90, 0x00
        data, sw1, sw2 = self.reader.card.answer(apdu, self.protocol)
        if sw1 == 0x61:
            self.pending = SIG_RESP
        return data, sw1, sw2


class FakeReader:
    def __init__(self, name, card, connect_errors=None, default_protocol=T1, atr=b"\x3b\x11\x95\x80"):
        self.name = name
        self.card = card
        self.connect_errors = connect_errors or {}
        self.default_protocol = default_protocol
        self.atr = atr
        self.connect_calls = []
        self.disconnects = 0
        self.connections = []

    def createConnection(self):
        conn = FakeConnection(self)
        self.connections.append(conn)
        return conn

    def __str__(self):
        return self.name


_DEFAULT_CARD = object()  # sentinel: card=None means "reader slot is empty"


def omnikey(card=_DEFAULT_CARD, name="HID Global OMNIKEY 5422CL Smartcard Reader"):
    return FakeReader(name, FakeCard() if card is _DEFAULT_CARD else card, default_protocol=T1)


def realtek(card=_DEFAULT_CARD, name="Generic Smart Card Reader Interface"):
    """Measured: default -> 0x80100066 unresponsive, T=1 -> 0x8010000F protocol mismatch, T=0 works."""
    return FakeReader(
        name,
        FakeCard() if card is _DEFAULT_CARD else card,
        connect_errors={
            None: ("Unable to connect with protocol: T0 or T1. Card is unresponsive", 0x80100066),
            T1: ("Unable to connect with protocol: T1. Card protocol mismatch", 0x8010000F),
        },
        default_protocol=T0,
    )


class PcscTestCase(unittest.TestCase):
    def setUp(self):
        self._orig_list = nuri_pcsc._list_readers
        self._env = {k: os.environ.pop(k) for k in ("NURI_READER", "NURI_PCSC_PROTOCOL") if k in os.environ}

    def tearDown(self):
        nuri_pcsc._list_readers = self._orig_list
        for key in ("NURI_READER", "NURI_PCSC_PROTOCOL"):
            os.environ.pop(key, None)
        os.environ.update(self._env)

    def use(self, *readers):
        nuri_pcsc._list_readers = lambda: list(readers)
        return readers


class OpenAppletTests(PcscTestCase):
    def test_omnikey_default_connect_works_first_try(self):
        (rdr,) = self.use(omnikey())
        applet = nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(applet.protocol, "default")
        self.assertEqual(applet.reader_name, str(rdr))
        self.assertEqual(rdr.connect_calls, [None])
        self.assertEqual(applet.conn.log, [SELECT_ETH])
        data, sw = applet.transmit(bytes(VERSION))
        self.assertEqual((data, sw), (bytes(VERSION_RESP), 0x9000))
        applet.close()
        self.assertEqual(rdr.disconnects, 1)

    def test_realtek_falls_back_to_t0(self):
        (rdr,) = self.use(realtek())
        applet = nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(applet.protocol, "T0")
        self.assertEqual(rdr.connect_calls, [None, T0])  # T1 never tried once T0 worked
        self.assertEqual(rdr.disconnects, 0)

    def test_realtek_t0_6cxx_resend_and_61xx_get_response(self):
        self.use(realtek())
        applet = nuri_pcsc.open_applet(ETH_AID)
        data, sw = applet.transmit(bytes(VERSION))
        self.assertEqual((data, sw), (bytes(VERSION_RESP), 0x9000))
        self.assertEqual(applet.conn.log[-2:], [VERSION, [0x80, 0x01, 0x00, 0x00, 0x07]])
        data, sw = applet.transmit(bytes(PUBKEY))
        self.assertEqual((data, sw), (bytes(PUBKEY_RESP), 0x9000))
        self.assertEqual(applet.conn.log[-1], [0x80, 0x02, 0x00, 0x00, 0x21])
        data, sw = applet.transmit(bytes(SIGN))
        self.assertEqual((data, sw), (bytes(SIG_RESP), 0x9000))
        self.assertEqual(applet.conn.log[-2:], [SIGN, [0x00, 0xC0, 0x00, 0x00, 0x41]])

    def test_non_9000_never_raises(self):
        self.use(omnikey())
        applet = nuri_pcsc.open_applet(ETH_AID)
        data, sw = applet.transmit(bytes([0x80, 0x7F, 0x00, 0x00, 0x00]))
        self.assertEqual((data, sw), (b"", 0x6D00))

    def test_ladder_tries_t1_after_t0_fails(self):
        card = FakeCard()
        rdr = FakeReader(
            "weird",
            card,
            connect_errors={None: ("unresponsive", 0x80100066), T0: ("mismatch", 0x8010000F)},
            default_protocol=T1,
        )
        self.use(rdr)
        applet = nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(applet.protocol, "T1")
        self.assertEqual(rdr.connect_calls, [None, T0, T1])

    def test_select_61xx_counts_as_present(self):
        class Card61(FakeCard):
            """SELECT answers 61 00 with the FCI pending (seen on some T=0 stacks)."""

            def answer(self, apdu, protocol):
                if apdu[:4] == [0x00, 0xA4, 0x04, 0x00]:
                    return [], 0x61, 0x00
                return super().answer(apdu, protocol)

        self.use(FakeReader("x", Card61()))
        applet = nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(applet.protocol, "default")

    def test_no_reader(self):
        self.use()
        with self.assertRaises(nuri_pcsc.CardError) as ctx:
            nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(ctx.exception.code, "NO_READER")

    def test_no_card_in_any_reader(self):
        self.use(omnikey(card=None), realtek(card=None))
        with self.assertRaises(nuri_pcsc.CardError) as ctx:
            nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(ctx.exception.code, "NO_CARD")

    def test_card_without_applet(self):
        self.use(realtek(card=FakeCard(aids=(FIDO_AID,))))
        with self.assertRaises(nuri_pcsc.CardError) as ctx:
            nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(ctx.exception.code, "NO_APPLET")

    def test_no_applet_outranks_no_card_across_readers(self):
        self.use(omnikey(card=None), realtek(card=FakeCard(aids=(FIDO_AID,))))
        with self.assertRaises(nuri_pcsc.CardError) as ctx:
            nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(ctx.exception.code, "NO_APPLET")

    def test_transport_when_every_protocol_fails(self):
        rdr = FakeReader(
            "dead",
            FakeCard(),
            connect_errors={None: ("x", 0x80100066), T0: ("x", 0x8010000F), T1: ("x", 0x8010000F)},
        )
        self.use(rdr)
        with self.assertRaises(nuri_pcsc.CardError) as ctx:
            nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(ctx.exception.code, "TRANSPORT")

    def test_skips_empty_reader_and_uses_next(self):
        empty, real = self.use(omnikey(card=None, name="HID OMNIKEY 5422CL"), realtek())
        applet = nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(applet.reader_name, str(real))
        self.assertEqual(applet.protocol, "T0")

    def test_reader_argument_and_env_filter(self):
        omni, rt = self.use(omnikey(), realtek())
        self.assertEqual(nuri_pcsc.open_applet(ETH_AID, reader="Generic").reader_name, str(rt))
        os.environ["NURI_READER"] = "OMNIKEY"
        self.assertEqual(nuri_pcsc.open_applet(ETH_AID).reader_name, str(omni))
        self.assertEqual(nuri_pcsc.reader_names(), [str(omni)])
        os.environ["NURI_READER"] = "nonexistent"
        with self.assertRaises(nuri_pcsc.CardError) as ctx:
            nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(ctx.exception.code, "NO_READER")

    def test_env_pins_protocol(self):
        (rdr,) = self.use(omnikey())
        os.environ["NURI_PCSC_PROTOCOL"] = "T0"
        applet = nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(applet.protocol, "T0")
        self.assertEqual(rdr.connect_calls, [T0])
        os.environ["NURI_PCSC_PROTOCOL"] = "T1"
        (rt,) = self.use(realtek())
        with self.assertRaises(nuri_pcsc.CardError) as ctx:
            nuri_pcsc.open_applet(ETH_AID)
        self.assertEqual(ctx.exception.code, "TRANSPORT")
        self.assertEqual(rt.connect_calls, [T1])
        os.environ["NURI_PCSC_PROTOCOL"] = "bogus"
        with self.assertRaises(ValueError):
            nuri_pcsc.open_applet(ETH_AID)

    def test_context_manager_closes(self):
        (rdr,) = self.use(omnikey())
        with nuri_pcsc.open_applet(ETH_AID) as applet:
            self.assertEqual(applet.atr(), b"\x3b\x11\x95\x80")
        self.assertEqual(rdr.disconnects, 1)

    def test_bad_aid_rejected(self):
        with self.assertRaises(ValueError):
            nuri_pcsc.select_apdu("00")


class TransmitRawTests(unittest.TestCase):
    def test_6cxx_on_case4_keeps_data(self):
        class Conn:
            def __init__(self):
                self.log = []

            def transmit(self, apdu, protocol=None):
                self.log.append(list(apdu))
                if len(self.log) == 1:
                    return [], 0x6C, 0x05
                return [1, 2, 3, 4, 5], 0x90, 0x00

        conn = Conn()
        apdu = bytes([0x80, 0x10, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x00])
        data, sw = nuri_pcsc.transmit_raw(conn, apdu)
        self.assertEqual((data, sw), (bytes([1, 2, 3, 4, 5]), 0x9000))
        self.assertEqual(conn.log[1], [0x80, 0x10, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x05])

    def test_61xx_chain_concatenates(self):
        class Conn:
            def __init__(self):
                self.calls = 0

            def transmit(self, apdu, protocol=None):
                self.calls += 1
                if self.calls == 1:
                    return [], 0x61, 0x02
                if self.calls == 2:
                    return [0xA, 0xB], 0x61, 0x01
                return [0xC], 0x90, 0x00

        data, sw = nuri_pcsc.transmit_raw(Conn(), bytes([0x80, 0x04, 0x00, 0x00, 0x00]))
        self.assertEqual((data, sw), (bytes([0xA, 0xB, 0xC]), 0x9000))


class PatchFido2Tests(PcscTestCase):
    """Inject a fake fido2.pcsc module shaped like python-fido2 2.x and check the patch."""

    def setUp(self):
        super().setUp()
        self._saved = {k: sys.modules.get(k) for k in ("fido2", "fido2.pcsc")}
        fido2 = types.ModuleType("fido2")
        pcsc = types.ModuleType("fido2.pcsc")

        class CtapPcscDevice:
            selected = []

            def __init__(self, connection, name):
                self._conn = connection
                self._name = name
                self.connect()

            def connect(self):
                self._conn.connect()
                self._select()

            def _select(self):
                _, sw1, sw2 = self._conn.transmit(list(bytes.fromhex("00A4040008" + FIDO_AID)))
                if (sw1, sw2) != (0x90, 0x00):
                    raise ValueError("FIDO applet selection failure.")
                CtapPcscDevice.selected.append(self._name)

            @classmethod
            def list_devices(cls, name=""):
                for reader in nuri_pcsc._list_readers():
                    if name in str(reader):
                        try:
                            yield cls(reader.createConnection(), str(reader))
                        except Exception:
                            pass

        pcsc.CtapPcscDevice = CtapPcscDevice
        fido2.pcsc = pcsc
        sys.modules["fido2"] = fido2
        sys.modules["fido2.pcsc"] = pcsc
        self.cls = CtapPcscDevice

    def tearDown(self):
        for key, mod in self._saved.items():
            if mod is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = mod
        super().tearDown()

    def test_unpatched_list_devices_misses_realtek(self):
        self.use(realtek())
        self.assertEqual(list(self.cls.list_devices()), [])

    def test_patched_list_devices_finds_realtek_on_t0(self):
        (rdr,) = self.use(realtek())
        nuri_pcsc.patch_fido2()
        devices = list(self.cls.list_devices())
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].nuri_protocol, "T0")
        self.assertEqual(rdr.connect_calls, [None, T0])
        self.assertIn(str(rdr), self.cls.selected)

    def test_patched_still_works_on_omnikey_and_is_idempotent(self):
        (rdr,) = self.use(omnikey())
        nuri_pcsc.patch_fido2()
        first = self.cls.connect
        nuri_pcsc.patch_fido2()
        self.assertIs(self.cls.connect, first)
        devices = list(self.cls.list_devices())
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].nuri_protocol, "default")
        self.assertEqual(rdr.connect_calls, [None])

    def test_patched_skips_card_without_fido_applet(self):
        self.use(realtek(card=FakeCard(aids=(ETH_AID,))))
        nuri_pcsc.patch_fido2()
        self.assertEqual(list(self.cls.list_devices()), [])


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MUSIG2_AID = "4E5552494D554701"
TOTP_AID = "4E555249544F5450"


class MuSig2Card(FakeCard):
    """MuSig2 applet: 00 01 version, 00 03 pubkey (T=0: 6CXX first)."""

    def answer(self, apdu, protocol):
        if apdu[:4] == [0x00, 0x01, 0x00, 0x00]:
            return self._case2(apdu, [1, 11, 0] + list(b"MUS1"), protocol)
        if apdu[:4] == [0x00, 0x03, 0x00, 0x00]:
            return self._case2(apdu, PUBKEY_RESP, protocol)
        return super().answer(apdu, protocol)


class CallSiteTests(PcscTestCase):
    """The switched scripts work end-to-end against the fake T=0-only reader."""

    def test_card_cosign_tweaked_card_class_on_realtek(self):
        (rdr,) = self.use(realtek(card=MuSig2Card(aids=(MUSIG2_AID,))))
        core = load_script("card-cosign-tweaked")
        card = core.Card()
        card.connect()
        self.assertEqual(card.applet.protocol, "T0")
        self.assertIn("[T0]", card.reader)
        self.assertEqual(card.version(), "1.11")
        self.assertEqual(card.pubkey(), bytes(PUBKEY_RESP))
        self.assertEqual(card.applet.conn.log[-1], [0x00, 0x03, 0x00, 0x00, 0x21])  # 6C21 resend
        card.close()
        self.assertEqual(rdr.disconnects, 1)

    def test_card_cosign_tweaked_reports_missing_card(self):
        self.use(omnikey(card=None))
        core = load_script("card-cosign-tweaked")
        with self.assertRaises(RuntimeError) as ctx:
            core.Card().connect()
        self.assertIn("NO_CARD", str(ctx.exception))

    def test_real_card_cosign_proof_card_on_realtek(self):
        self.use(realtek(card=MuSig2Card(aids=(MUSIG2_AID,))))
        proof = load_script("real-card-cosign-proof")
        card = proof.NuriMuSig2Card()
        card.connect()
        self.assertEqual(card.version(), {"version": "1.11", "build": "MUS1"})
        self.assertEqual(card.pubkey(), bytes(PUBKEY_RESP))
        card.disconnect()

    def test_pkcs11_helper_card_init_on_realtek(self):
        self.use(realtek())
        # W28: this card image has only the PIN-less ETH1 demo applet; opt in explicitly.
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        self.addCleanup(os.environ.pop, "NURI_ALLOW_ETH1_DEMO", None)
        helper = load_script("pkcs11-helper")
        conn = helper.card_init()
        self.assertEqual(conn.protocol, "T0")
        self.assertEqual(helper.card_pubkey(conn), bytes(PUBKEY_RESP).hex())
        sig_hex, v = helper.card_sign(conn, "11" * 32)
        self.assertEqual(sig_hex, bytes(SIG_RESP[:64]).hex())
        self.assertEqual(v, SIG_RESP[64])
        self.assertEqual(conn.conn.log[-1], [0x00, 0xC0, 0x00, 0x00, 0x41])  # 61 41 GET RESPONSE
        conn.close()

    def test_card_totp_connect_on_realtek_and_errors(self):
        self.use(realtek(card=FakeCard(aids=(TOTP_AID,))))
        totp = load_script("card-totp")
        conn = totp.connect()
        self.assertEqual(conn.protocol, "T0")
        data, sw1, sw2 = totp.transmit(conn, [0x00, 0xA4, 0x04, 0x00, len(totp.AID), *totp.AID])
        self.assertEqual((data, sw1, sw2), ([], 0x90, 0x00))
        self.use(realtek(card=FakeCard(aids=(ETH_AID,))))
        with self.assertRaises(SystemExit) as ctx:
            totp.connect()
        self.assertIn("NO_APPLET", str(ctx.exception))
        self.use()
        with self.assertRaises(SystemExit) as ctx:
            totp.connect()
        self.assertIn("no PC/SC reader", str(ctx.exception))

    def test_card_eth_test_helpers_on_realtek(self):
        self.use(realtek())
        eth = load_script("card-eth-test")
        applet = nuri_pcsc.open_applet(eth.APPLET_AID.hex())
        self.assertEqual(eth.get_version(applet), bytes(VERSION_RESP))
        self.assertEqual(eth.get_pubkey(applet), bytes(PUBKEY_RESP))
        self.assertEqual(eth.sign(applet, bytes([0x11] * 32)), bytes(SIG_RESP))
        self.assertEqual(eth.raw_sw(applet, bytes([0x80, 0x7F, 0x00, 0x00, 0x00])), (b"", 0x6D00))
        with self.assertRaises(RuntimeError):
            eth.transmit(applet, bytes([0x80, 0x7F, 0x00, 0x00, 0x00]))


ETH2_AID = "4E5552494554483201"


class Eth2TransportFailCard(FakeCard):
    """SELECT ETH2 raises (reader hiccup): nuri_pcsc reports that as NO_APPLET too."""

    def answer(self, apdu, protocol):
        if apdu[:4] == [0x00, 0xA4, 0x04, 0x00] and bytes(apdu[5:5 + apdu[4]]).hex().upper() == ETH2_AID:
            raise ConnectError("transmit failed", 0x80100016)
        return super().answer(apdu, protocol)


class EthPolicyTests(PcscTestCase):
    """W28 scripts/nuri_eth_policy.py + card-eth-test.py gate on fake readers (no card)."""

    def setUp(self):
        super().setUp()
        self._demo = os.environ.pop("NURI_ALLOW_ETH1_DEMO", None)
        import nuri_eth_policy
        self.policy = nuri_eth_policy
        self.warned = []

    def tearDown(self):
        os.environ.pop("NURI_ALLOW_ETH1_DEMO", None)
        if self._demo is not None:
            os.environ["NURI_ALLOW_ETH1_DEMO"] = self._demo
        super().tearDown()

    @staticmethod
    def eth1_selects(*readers):
        return [a for r in readers for c in r.connections for a in c.log if a == SELECT_ETH]

    def warn(self):
        self.warned.append(1)

    def test_eth2_preferred_even_with_demo_env(self):
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        (rdr,) = self.use(realtek(card=FakeCard(aids=(ETH_AID, ETH2_AID))))
        applet, which = self.policy.open_eth(nuri_pcsc, warn=self.warn)
        self.assertEqual((which, applet.aid_hex), ("eth2", ETH2_AID))
        self.assertEqual(self.eth1_selects(rdr), [])
        self.assertEqual(self.warned, [])

    def test_eth1_refused_without_exact_env(self):
        for value in (None, "", "0", "true", "yes", "1 ", "01"):
            with self.subTest(value=value):
                os.environ.pop("NURI_ALLOW_ETH1_DEMO", None)
                if value is not None:
                    os.environ["NURI_ALLOW_ETH1_DEMO"] = value
                (rdr,) = self.use(realtek())
                with self.assertRaises(self.policy.EthPolicyError) as ctx:
                    self.policy.open_eth(nuri_pcsc, warn=self.warn)
                self.assertEqual(ctx.exception.code, "ETH1_DEMO_DISABLED")
                with self.assertRaises(self.policy.EthPolicyError) as ctx:
                    self.policy.open_eth1_demo(nuri_pcsc, warn=self.warn)
                self.assertEqual(ctx.exception.code, "ETH1_DEMO_DISABLED")
                self.assertEqual(self.eth1_selects(rdr), [])
                self.assertEqual(self.warned, [])

    def test_confirmed_6a82_allows_eth1_with_warning(self):
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        (rdr,) = self.use(realtek())
        applet, which = self.policy.open_eth(nuri_pcsc, warn=self.warn)
        self.assertEqual((which, applet.aid_hex, applet.protocol), ("eth1", ETH_AID, "T0"))
        self.assertEqual(self.warned, [1])

    def test_ambiguous_no_applet_from_transport_refuses_downgrade(self):
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        (rdr,) = self.use(realtek(card=Eth2TransportFailCard()))
        with self.assertRaises(nuri_pcsc.CardError) as ctx:
            nuri_pcsc.open_applet(ETH2_AID)
        self.assertEqual(ctx.exception.code, "NO_APPLET")  # the conflation the policy guards against
        for opener in (self.policy.open_eth, self.policy.open_eth1_demo):
            with self.subTest(opener=opener.__name__):
                with self.assertRaises(self.policy.EthPolicyError) as ctx:
                    opener(nuri_pcsc, warn=self.warn)
                self.assertEqual(ctx.exception.code, "DOWNGRADE_REFUSED")
        self.assertEqual(self.eth1_selects(rdr), [])
        self.assertEqual(self.warned, [])

    def test_absence_needed_on_every_reader(self):
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        good, bad = self.use(realtek(), omnikey(card=Eth2TransportFailCard(), name="Second Reader"))
        with self.assertRaises(self.policy.EthPolicyError) as ctx:
            self.policy.open_eth(nuri_pcsc, warn=self.warn)
        self.assertEqual(ctx.exception.code, "DOWNGRADE_REFUSED")
        self.assertIn("Second Reader", ctx.exception.message)
        self.assertEqual(self.eth1_selects(good, bad), [])

    def test_no_reader_never_downgrades(self):
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        self.use()
        with self.assertRaises(nuri_pcsc.CardError) as ctx:
            self.policy.open_eth(nuri_pcsc, warn=self.warn)
        self.assertEqual(ctx.exception.code, "NO_READER")
        with self.assertRaises(self.policy.EthPolicyError) as ctx:
            self.policy.open_eth1_demo(nuri_pcsc, warn=self.warn)
        self.assertEqual(ctx.exception.code, "DOWNGRADE_REFUSED")

    def test_eth1_only_tool_refuses_when_eth2_installed(self):
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        (rdr,) = self.use(realtek(card=FakeCard(aids=(ETH_AID, ETH2_AID))))
        with self.assertRaises(self.policy.EthPolicyError) as ctx:
            self.policy.open_eth1_demo(nuri_pcsc, warn=self.warn)
        self.assertEqual(ctx.exception.code, "ETH2_PRESENT")
        self.assertEqual(self.eth1_selects(rdr), [])

    def test_card_eth_test_main_gated(self):
        eth = load_script("card-eth-test")
        (rdr,) = self.use(realtek())
        with mock.patch.object(sys, "argv", ["card-eth-test.py"]):
            with self.assertRaises(SystemExit) as ctx:
                eth.main()
        self.assertIn("ETH1_DEMO_DISABLED", str(ctx.exception.code))
        self.assertEqual(rdr.connections, [], "env gate before any card I/O")
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        (rdr,) = self.use(realtek(card=FakeCard(aids=(ETH_AID, ETH2_AID))))
        with mock.patch.object(sys, "argv", ["card-eth-test.py", "--regenerate"]):
            with self.assertRaises(SystemExit) as ctx:
                eth.main()
        self.assertIn("ETH2_PRESENT", str(ctx.exception.code))
        self.assertEqual(self.eth1_selects(rdr), [])
        self.assertFalse(any(a[1] == 0x03 for c in rdr.connections for a in c.log), "KEYGEN never sent")


class CardEthFailClosedTests(PcscTestCase):
    """W30: card-eth-test.py fails closed on invalid/mismatched ETH1 ECDSA signatures.

    A valid signature prints REAL_CARD_ETH_SIGN_FLOW_OK and exits 0; a mismatched,
    malformed or unrecoverable signature closes the connection and exits non-zero
    (SystemExit with a non-empty message), so scripts/accept-card-v1.sh:22 can no
    longer print REAL_CARD_V1_ACCEPTANCE_OK after a bad signature.
    """

    # Same hash the script signs: scripts/card-eth-test.py:166.
    _Z = int.from_bytes(hashlib.sha256(b"nuri-card-eth-test").digest(), "big")
    _K = 0x16A9F5D2C39B8E71A4D0F6C5E2B8973AD1F6042C7B9E5D3A8F1C64B0E7D2A9533

    def setUp(self):
        super().setUp()
        os.environ["NURI_ALLOW_ETH1_DEMO"] = "1"
        self.addCleanup(os.environ.pop, "NURI_ALLOW_ETH1_DEMO", None)
        self.eth = load_script("card-eth-test")

    @staticmethod
    def _keygen_sig(z, d, k):
        R = _point_mul(k, _G)
        r = R[0] % _N
        s = (pow(k, -1, _N) * (z + r * d)) % _N
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([R[1] & 1])

    def _card(self, pubkey33, sig65):
        class Eth1SignCard(FakeCard):
            """ETH1 image whose GET_PUBKEY/SIGN answers are set by the test."""

            def answer(self, apdu, protocol):
                if apdu[1:4] == [0x02, 0x00, 0x00]:
                    return self._case2(apdu, list(pubkey33), protocol)
                if apdu[1:5] == [0x04, 0x00, 0x00, 0x20]:
                    return list(sig65), 0x90, 0x00
                return super().answer(apdu, protocol)

        return Eth1SignCard(aids=(ETH_AID,))

    def _run_main(self, card):
        (rdr,) = self.use(omnikey(card=card))
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", ["card-eth-test.py"]):
            with contextlib.redirect_stdout(buf):
                self.eth.main()
        return rdr, buf.getvalue()

    def _run_main_expecting_exit(self, card):
        (rdr,) = self.use(omnikey(card=card))
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", ["card-eth-test.py"]):
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as ctx:
                    self.eth.main()
        return rdr, buf.getvalue(), ctx.exception

    @staticmethod
    def _assert_all_disconnected(test, rdr):
        test.assertTrue(
            rdr.connections and all(not c.connected for c in rdr.connections),
            "connection must be closed before exiting",
        )

    def test_valid_signature_passes_and_exits_clean(self):
        d = 2
        rdr, out = self._run_main(self._card(_eth1_pubkey(d), self._keygen_sig(self._Z, d, self._K)))
        self.assertIn("REAL_CARD_ETH_SIGN_FLOW_OK", out)
        self.assertIn("=== DONE ===", out)
        self._assert_all_disconnected(self, rdr)
        # No KEYGEN (INS 0x03) was ever sent: the existing key is used.
        self.assertFalse(any(a[1] == 0x03 for c in rdr.connections for a in c.log))

    def test_mismatched_signature_fails_closed(self):
        sig = self._keygen_sig(self._Z, 2, self._K)  # signs with key d=2 ...
        card_pubkey = _eth1_pubkey(3)  # ... but the card reports key d=3
        rdr, out, exc = self._run_main_expecting_exit(self._card(card_pubkey, sig))
        self.assertIn("MISMATCH", out)
        self.assertNotIn("REAL_CARD_ETH_SIGN_FLOW_OK", out)
        self.assertNotIn("=== DONE ===", out)
        self.assertNotIn(exc.code, (None, 0))
        self.assertIn("MISMATCH", str(exc.code))
        self._assert_all_disconnected(self, rdr)

    def test_malformed_signature_wrong_length_fails_closed(self):
        sig64 = self._keygen_sig(self._Z, 2, self._K)[:64]  # v byte missing
        rdr, out, exc = self._run_main_expecting_exit(self._card(_eth1_pubkey(2), sig64))
        self.assertIn("Malformed ETH1 signature", str(exc.code))
        self.assertNotIn(exc.code, (None, 0))
        self.assertNotIn("REAL_CARD_ETH_SIGN_FLOW_OK", out)
        self._assert_all_disconnected(self, rdr)

    def test_malformed_signature_bad_v_fails_closed(self):
        sig = self._keygen_sig(self._Z, 2, self._K)
        sig = sig[:64] + bytes([7])  # v must be 0 or 1
        rdr, out, exc = self._run_main_expecting_exit(self._card(_eth1_pubkey(2), sig))
        self.assertIn("Malformed ETH1 signature", str(exc.code))
        self.assertNotIn(exc.code, (None, 0))
        self._assert_all_disconnected(self, rdr)

    def test_malformed_signature_zero_r_fails_closed(self):
        sig = bytes(32) + (1).to_bytes(32, "big") + bytes([0])  # r=0: recovery raises
        rdr, out, exc = self._run_main_expecting_exit(self._card(_eth1_pubkey(2), sig))
        self.assertIn("malformed (recovery raised ValueError", str(exc.code))
        self.assertNotIn(exc.code, (None, 0))
        self._assert_all_disconnected(self, rdr)

    def test_out_of_range_scalars_fail_closed(self):
        # For s=0, recovery used to accept Q=(-z/r)G as the reported card key.
        point = _point_mul(self._K, _G)
        assert point is not None
        r = point[0] % _N
        d = (-self._Z * pow(r, -1, _N)) % _N
        for r_value, s_value in ((r, 0), (0, 1), (_N, 1), (r, _N), (r, _N + 1)):
            with self.subTest(r=r_value, s=s_value):
                sig = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big") + bytes([0])
                rdr, out, exc = self._run_main_expecting_exit(self._card(_eth1_pubkey(d), sig))
                self.assertNotIn(exc.code, (None, 0))
                self.assertIn("r and s must satisfy", str(exc.code))
                self.assertNotIn("REAL_CARD_ETH_SIGN_FLOW_OK", out)
                self._assert_all_disconnected(self, rdr)

    def test_invalid_recovery_point_fails_closed(self):
        r = next(r for r in range(1, 100)
                 if pow((pow(r, 3, _P) + 7) % _P, (_P - 1) // 2, _P) == _P - 1)
        sig = r.to_bytes(32, "big") + (1).to_bytes(32, "big") + bytes([0])
        rdr, out, exc = self._run_main_expecting_exit(self._card(_eth1_pubkey(2), sig))
        self.assertIn("r does not identify a secp256k1 point", str(exc.code))
        self.assertNotIn(exc.code, (None, 0))
        self.assertNotIn("REAL_CARD_ETH_SIGN_FLOW_OK", out)
        self._assert_all_disconnected(self, rdr)

    def test_recovery_point_at_infinity_fails_closed(self):
        point = _point_mul(self._Z, _G)
        assert point is not None
        sig = point[0].to_bytes(32, "big") + (1).to_bytes(32, "big") + bytes([point[1] & 1])
        rdr, out, exc = self._run_main_expecting_exit(self._card(_eth1_pubkey(2), sig))
        self.assertIn("point at infinity", str(exc.code))
        self.assertNotIn(exc.code, (None, 0))
        self.assertNotIn("REAL_CARD_ETH_SIGN_FLOW_OK", out)
        self._assert_all_disconnected(self, rdr)

    def test_real_script_process_exit_status(self):
        """Run the real __main__ with fake readers, not a standalone SystemExit."""
        import subprocess

        code = """
import runpy, sys
fakes = runpy.run_path('test/test_nuri_pcsc.py', run_name='fake_helpers')
fixture = fakes['CardEthFailClosedTests']()
fixture.setUp()
case = sys.argv[1]
sig = fixture._keygen_sig(fixture._Z, 2, fixture._K)
if case == 'malformed':
    sig = sig[:64]
pubkey = fakes['_eth1_pubkey'](3 if case == 'mismatch' else 2)
(reader,) = fixture.use(fakes['omnikey'](card=fixture._card(pubkey, sig)))
sys.argv = ['scripts/card-eth-test.py']
try:
    runpy.run_path('scripts/card-eth-test.py', run_name='__main__')
finally:
    closed = bool(reader.connections) and all(not c.connected for c in reader.connections)
    print('FAKE_CONNECTION_CLOSED=' + str(closed), file=sys.stderr)
    fixture.tearDown()
    fixture.doCleanups()
"""
        for case, expected in (("valid", 0), ("mismatch", 1), ("malformed", 1)):
            with self.subTest(case=case):
                proc = subprocess.run(
                    [sys.executable, "-c", code, case], cwd=ROOT,
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(proc.returncode, expected, proc.stdout + proc.stderr)
                self.assertEqual("REAL_CARD_ETH_SIGN_FLOW_OK" in proc.stdout, expected == 0)
                self.assertIn("FAKE_CONNECTION_CLOSED=True", proc.stderr)


# secp256k1 helpers (pure stdlib) for the W30 fail-closed ETH1 fakes above.
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    if a == b:
        lam = (3 * a[0] * a[0] * pow(2 * a[1], -1, _P)) % _P
    else:
        lam = ((b[1] - a[1]) * pow(b[0] - a[0], -1, _P)) % _P
    x3 = (lam * lam - a[0] - b[0]) % _P
    return (x3, (lam * (a[0] - x3) - a[1]) % _P)


def _point_mul(k, pt):
    k %= _N
    result, addend = None, pt
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _eth1_pubkey(d):
    q = _point_mul(d, _G)
    return bytes([0x02 if q[1] % 2 == 0 else 0x03]) + q[0].to_bytes(32, "big")


class ScriptImportTests(unittest.TestCase):
    """Every script touched by the reader-compat change still compiles."""

    def test_py_compile_all_scripts(self):
        import py_compile

        for path in sorted(SCRIPTS.glob("*.py")):
            py_compile.compile(str(path), doraise=True)

    def test_module_imports_without_pyscard(self):
        spec = importlib.util.spec_from_file_location("nuri_pcsc_fresh", SCRIPTS / "nuri_pcsc.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(callable(module.open_applet))


if __name__ == "__main__":
    unittest.main()
