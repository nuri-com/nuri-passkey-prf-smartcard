#!/usr/bin/env python3
"""Shared PC/SC access for every Nuri card script (contract C1).

Why this exists: cheap readers (Realtek "Generic Smart Card Reader Interface",
USB 0bda:0165) leave the card "unresponsive" (0x80100066) under pyscard's
default connect (T0|T1) and reject T=1 (0x8010000F); forcing T=0 works. On T=0
the card answers 61XX (fetch with GET RESPONSE) and 6CXX (resend with Le=XX).
The OMNIKEY 5422 works with the default connect. Every script used to carry
its own copy of this logic; this module is the one place for it.

    applet = open_applet("4E55524945544801")      # ETH applet
    data, sw = applet.transmit(bytes.fromhex("8001000000"))
    applet.close()

    patch_fido2()   # then fido2.pcsc.CtapPcscDevice.list_devices() finds the
                    # card on T=0-only readers too

Environment:
    NURI_READER         substring; only readers whose name contains it are tried
    NURI_PCSC_PROTOCOL  auto (default -> T0 -> T1), T0, T1 or default: pin one

pyscard is imported lazily inside functions, so the module imports without
pyscard installed and tests can inject fake readers/connections.
"""
from __future__ import annotations

import os
from typing import Callable, Optional

# Same values as smartcard.CardConnection.T0_protocol / T1_protocol, so we do
# not need pyscard at import time.
_PROTOCOL_FLAGS = {"default": None, "T0": 0x00000001, "T1": 0x00000002}
_LADDER = ("default", "T0", "T1")

# pcsc-lite / winscard: SCARD_E_NO_SMARTCARD, SCARD_W_REMOVED_CARD
_NO_CARD_HRESULTS = {0x8010000C, 0x80100069}

_MAX_CHAIN = 64  # upper bound for 61XX / 6CXX loops; a sane card never needs this

ERROR_CODES = ("NO_READER", "NO_CARD", "NO_APPLET", "TRANSPORT")


class CardError(Exception):
    """code is one of NO_READER | NO_CARD | NO_APPLET | TRANSPORT."""

    def __init__(self, code: str, message: str = ""):
        if code not in ERROR_CODES:
            raise ValueError(f"unknown CardError code {code!r}")
        self.code = code
        super().__init__(f"{code}: {message}" if message else code)


def _list_readers():
    """Lazy pyscard import; tests patch this function."""
    from smartcard.System import readers  # noqa: WPS433 (lazy on purpose)

    return list(readers())


def reader_names(reader: Optional[str] = None) -> list[str]:
    """Names of the readers open_applet would try (after NURI_READER filtering)."""
    return [str(r) for r in _select_readers(_list_readers(), reader)]


def _select_readers(all_readers, reader: Optional[str]):
    wanted = reader if reader is not None else os.environ.get("NURI_READER", "")
    if not wanted:
        return list(all_readers)
    return [r for r in all_readers if wanted in str(r)]


def protocol_ladder(pin: Optional[str] = None) -> tuple[str, ...]:
    """Protocols to try, in order. pin overrides env NURI_PCSC_PROTOCOL."""
    value = (pin if pin is not None else os.environ.get("NURI_PCSC_PROTOCOL", "auto")).strip()
    if value == "" or value.lower() == "auto":
        return _LADDER
    normalized = value.upper() if value.upper() in ("T0", "T1") else value.lower()
    if normalized not in _PROTOCOL_FLAGS:
        raise ValueError(f"NURI_PCSC_PROTOCOL must be auto, T0, T1 or default, not {value!r}")
    return (normalized,)


def _connect(conn, protocol: str) -> None:
    flag = _PROTOCOL_FLAGS[protocol]
    if flag is None:
        conn.connect()
    else:
        conn.connect(flag)


def _disconnect(conn) -> None:
    try:
        conn.disconnect()
    except Exception:
        pass


def _is_no_card(error: Exception) -> bool:
    if type(error).__name__ == "NoCardException":
        return True
    return getattr(error, "hresult", None) in _NO_CARD_HRESULTS


def transmit_raw(conn, apdu: bytes) -> tuple[bytes, int]:
    """Send one APDU on a connected pyscard connection; returns (data, sw).

    Handles T=0 procedure bytes: 6CXX (wrong Le: resend with Le=XX) and 61XX
    (response pending: GET RESPONSE 00 C0 00 00 XX, looped and concatenated).
    Never raises on a non-9000 status word.
    """
    cmd = list(apdu)
    data, sw1, sw2 = conn.transmit(cmd)
    data = list(data)

    retries = 0
    while sw1 == 0x6C and retries < _MAX_CHAIN:
        retries += 1
        if len(cmd) <= 5:                              # case 1 / case 2: header + Le
            cmd = cmd[:4] + [sw2]
        elif len(cmd) == 5 + cmd[4]:                   # case 3: no Le yet, add the one asked for
            cmd = cmd + [sw2]
        else:                                          # case 4: replace Le
            cmd = cmd[:-1] + [sw2]
        data, sw1, sw2 = conn.transmit(cmd)
        data = list(data)

    fetches = 0
    while sw1 == 0x61 and fetches < _MAX_CHAIN:
        fetches += 1
        more, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
        data += list(more)

    return bytes(data), (sw1 << 8) | sw2


def select_apdu(aid_hex: str) -> bytes:
    aid = bytes.fromhex(aid_hex)
    if not 5 <= len(aid) <= 16:
        raise ValueError(f"AID must be 5..16 bytes, got {len(aid)}")
    return bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid


def _select_ok(sw: int) -> bool:
    return sw == 0x9000 or (sw >> 8) == 0x61


class Applet:
    """A connected card with one applet selected."""

    def __init__(self, conn, reader_name: str, protocol: str, aid_hex: str):
        self.conn = conn
        self.reader_name = reader_name
        self.protocol = protocol
        self.aid_hex = aid_hex.upper()

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        return transmit_raw(self.conn, apdu)

    def atr(self) -> bytes:
        return bytes(self.conn.getATR() or b"")

    def close(self) -> None:
        _disconnect(self.conn)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __repr__(self):
        return f"Applet(aid={self.aid_hex}, reader={self.reader_name!r}, protocol={self.protocol})"


def connect_ladder(conn, probe: Callable[[object], bool], protocols=None) -> str:
    """Connect `conn` trying each protocol in order until `probe(conn)` is True.

    probe runs on a connected connection and returns True when the card
    answered as expected (e.g. SELECT ok); a False/raising probe disconnects
    and moves to the next protocol. Returns the protocol name that worked.
    Raises CardError(NO_CARD) if every connect said "no card", else
    CardError(NO_APPLET) if a connect worked but every probe failed, else
    CardError(TRANSPORT).
    """
    saw_card = False
    probe_failed = False
    last_error: Optional[Exception] = None
    for protocol in protocols or protocol_ladder():
        try:
            _connect(conn, protocol)
        except Exception as error:  # pyscard CardConnectionException / NoCardException
            last_error = error
            if not _is_no_card(error):
                saw_card = True
            continue
        try:
            ok = probe(conn)
        except Exception as error:
            last_error = error
            ok = False
        if ok:
            return protocol
        saw_card = True
        probe_failed = True
        _disconnect(conn)
    if probe_failed:
        raise CardError("NO_APPLET", f"card answered but probe failed ({last_error})")
    if saw_card:
        raise CardError("TRANSPORT", f"no protocol worked ({last_error})")
    raise CardError("NO_CARD", f"no card ({last_error})")


def open_applet(aid_hex: str, reader: Optional[str] = None) -> Applet:
    """Find a reader+protocol on which SELECT aid_hex succeeds (see module doc)."""
    select = select_apdu(aid_hex)
    all_readers = _list_readers()
    if not all_readers:
        raise CardError("NO_READER", "no PC/SC reader found")
    candidates = _select_readers(all_readers, reader)
    if not candidates:
        names = ", ".join(str(r) for r in all_readers)
        raise CardError("NO_READER", f"no reader matches {reader or os.environ.get('NURI_READER')!r} (have: {names})")

    def probe(conn) -> bool:
        _, sw = transmit_raw(conn, select)
        return _select_ok(sw)

    worst: Optional[CardError] = None
    rank = {"NO_CARD": 0, "TRANSPORT": 1, "NO_APPLET": 2}
    for rdr in candidates:
        conn = rdr.createConnection()
        try:
            protocol = connect_ladder(conn, probe)
        except CardError as error:
            if worst is None or rank[error.code] > rank[worst.code]:
                worst = error
            continue
        return Applet(conn, str(rdr), protocol, aid_hex)
    assert worst is not None
    raise CardError(worst.code, f"{worst} on readers: {', '.join(str(r) for r in candidates)}")


_FIDO_AID_HEX = "A0000006472F0001"


def patch_fido2() -> None:
    """Make fido2.pcsc.CtapPcscDevice.connect use the protocol ladder. Idempotent.

    python-fido2's CtapPcscDevice.connect() (fido2/pcsc.py) does a plain
    self._conn.connect() and then self._select(); on T=0-only readers that
    connect fails, so list_devices() silently yields nothing. We replace it
    with the ladder, then call the original self._select() so capability
    detection (U2F_V2 / CBOR) is unchanged.
    """
    from fido2 import pcsc as fido2_pcsc  # lazy: only FIDO2 scripts need python-fido2

    cls = fido2_pcsc.CtapPcscDevice
    if getattr(cls.connect, "_nuri_pcsc_patched", False):
        return
    select = select_apdu(_FIDO_AID_HEX)

    def connect(self):
        def probe(conn) -> bool:
            _, sw = transmit_raw(conn, select)
            return _select_ok(sw)

        self.nuri_protocol = connect_ladder(self._conn, probe)
        self._select()

    connect._nuri_pcsc_patched = True  # type: ignore[attr-defined]
    cls.connect = connect


__all__ = [
    "Applet",
    "CardError",
    "connect_ladder",
    "open_applet",
    "patch_fido2",
    "protocol_ladder",
    "reader_names",
    "select_apdu",
    "transmit_raw",
]
