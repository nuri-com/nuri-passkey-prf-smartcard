#!/usr/bin/env python3
"""ETH applet selection policy shared by the Python card entrypoints (W28).

ETH2 (AID 4E5552494554483201, PIN-gated) is always preferred. The legacy ETH1
demo applet (AID 4E55524945544801) has NO PIN: any local process that can reach
the reader can make it sign. Every path that would talk to ETH1 therefore:

  1. refuses unless env NURI_ALLOW_ETH1_DEMO is exactly "1" (checked before any
     ETH1 APDU is sent),
  2. never downgrades on an ambiguous ETH2 failure. nuri_pcsc reports NO_APPLET
     both for a genuine 6A82 and for a SELECT whose transmit raised, so a
     NO_APPLET from open_applet(ETH2) is only a hint: every candidate reader is
     re-probed and only a confirmed 6A82 on all of them allows ETH1. Transport,
     reader, protocol and any other status word refuse the downgrade. PIN
     failures happen after ETH2 was selected and never reach this module.
  3. prints a warning to stderr whenever ETH1 is actually selected.

Used by scripts/card-dashboard-server.py and scripts/card-eth-test.py. The
native host (host/nuri_card_host.py) carries an equivalent inline copy because
it is installed as a fixed file snapshot. scripts/pkcs11-helper.py has its own
copy (require_eth2_absent / card_init).

Takes the nuri_pcsc module as a parameter so tests can inject fake readers
(nuri_pcsc._list_readers) without a card.
"""
from __future__ import annotations

import os
import sys

ETH2_AID = "4E5552494554483201"
ETH1_AID = "4E55524945544801"
ETH1_DEMO_ENV = "NURI_ALLOW_ETH1_DEMO"
SW_FILE_NOT_FOUND = 0x6A82

ETH1_WARNING = ("WARNING: ETH1 DEMO (NURI_ALLOW_ETH1_DEMO=1): the legacy ETH1 applet has NO PIN; "
                "any local process can sign with it. Demo only, never fund its address.")


class EthPolicyError(RuntimeError):
    """A refused ETH1 path. code: ETH1_DEMO_DISABLED | ETH2_PRESENT | DOWNGRADE_REFUSED."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def eth1_demo_allowed(env=None) -> bool:
    env = os.environ if env is None else env
    return env.get(ETH1_DEMO_ENV) == "1"


def require_eth1_demo(what: str = "ETH1 access") -> None:
    if not eth1_demo_allowed():
        raise EthPolicyError(
            "ETH1_DEMO_DISABLED",
            f"{what} refused: the ETH1 demo applet has no PIN and requires {ETH1_DEMO_ENV}=1 exactly; "
            "use the PIN-gated ETH2 signer")


def warn_eth1(stream=None) -> None:
    print(ETH1_WARNING, file=stream or sys.stderr, flush=True)


def confirm_eth2_absent(pcsc, reader=None) -> None:
    """Raise EthPolicyError(DOWNGRADE_REFUSED) unless every candidate reader answers
    SELECT ETH2 with 6A82. Faults on any reader/protocol are retained, not skipped."""
    try:
        candidates = pcsc._select_readers(pcsc._list_readers(), reader)
        select = pcsc.select_apdu(ETH2_AID)
    except Exception as error:
        raise EthPolicyError("DOWNGRADE_REFUSED", f"cannot confirm ETH2 absence ({type(error).__name__})") from error
    if not candidates:
        raise EthPolicyError("DOWNGRADE_REFUSED", "cannot confirm ETH2 absence: no reader")
    faults = []
    confirmed = 0
    for rdr in candidates:
        conn = rdr.createConnection()
        absent = False
        empty = False

        def probe(raw):
            nonlocal absent
            try:
                _, sw = pcsc.transmit_raw(raw, select)
            except Exception:
                faults.append(f"{rdr}: ETH2 SELECT transport failure")
                raise
            if sw == SW_FILE_NOT_FOUND:
                absent = True
                return True  # absence positively known; stop the protocol ladder
            faults.append(f"{rdr}: ETH2 absence not confirmed (SW={sw:04X})")
            return False

        before = len(faults)
        try:
            pcsc.connect_ladder(conn, probe)
        except Exception as error:
            # Empty slot (no card on every protocol, no probe ran): holds no applet.
            if getattr(error, "code", None) == "NO_CARD" and len(faults) == before:
                empty = True
            else:
                faults.append(f"{rdr}: reader/protocol failure")
        finally:
            pcsc._disconnect(conn)
        if absent:
            confirmed += 1
        elif not empty:
            faults.append(f"{rdr}: ETH2 absence not confirmed")
    if not faults and confirmed == 0:
        faults.append("no card answered SELECT ETH2")
    if faults:
        raise EthPolicyError("DOWNGRADE_REFUSED", "refusing ETH1 downgrade: " + "; ".join(faults))


def _open_eth1(pcsc, reader, warn):
    confirm_eth2_absent(pcsc, reader)
    applet = pcsc.open_applet(ETH1_AID, reader=reader)
    (warn or warn_eth1)()
    return applet


def open_eth(pcsc, reader=None, warn=None):
    """-> (applet, "eth2" | "eth1"). ETH2 first; ETH1 only with the demo env and a
    confirmed 6A82 ETH2 absence. Non-NO_APPLET ETH2 errors propagate (no downgrade)."""
    try:
        return pcsc.open_applet(ETH2_AID, reader=reader), "eth2"
    except pcsc.CardError as error:
        if getattr(error, "code", "") != "NO_APPLET":
            raise
        try:
            require_eth1_demo("ETH2 applet not found; ETH1 fallback")
        except EthPolicyError as refused:
            raise refused from error
    return _open_eth1(pcsc, reader, warn), "eth1"


def open_eth1_demo(pcsc, reader=None, warn=None):
    """For ETH1-only tools: env gate before any card I/O, refuse when ETH2 is installed
    (or its absence cannot be confirmed), then warn and open ETH1."""
    require_eth1_demo()
    try:
        applet = pcsc.open_applet(ETH2_AID, reader=reader)
    except pcsc.CardError as error:
        if getattr(error, "code", "") != "NO_APPLET":
            raise EthPolicyError("DOWNGRADE_REFUSED", f"ETH2 probe failed ({error}); refusing ETH1") from error
    else:
        applet.close()
        raise EthPolicyError("ETH2_PRESENT", "the PIN-gated ETH2 applet is installed; refusing the ETH1 demo path")
    return _open_eth1(pcsc, reader, warn)
