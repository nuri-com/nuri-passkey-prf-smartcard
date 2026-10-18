#!/usr/bin/env python3
"""PKCS#11 helper: key=value replies, or one JSON object per command with --json.

Default is real PC/SC. Simulation requires exact NURI_PKCS11_MODE=sim, even
with --sim. ETH2 is preferred; this process-per-operation bridge cannot yet
carry a PIN-authenticated ETH2 session, so ETH2 signing fails closed.
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ETH2_AID = '4E5552494554483201'
ETH1_AID = '4E55524945544801'
SIM_KEY = None
SIM_PUBKEY = None


def selected_mode():
    mode = os.environ.get('NURI_PKCS11_MODE', 'card')
    if mode not in ('card', 'sim'):
        raise ValueError('NURI_PKCS11_MODE must be exactly card or sim (unset means card)')
    return mode


def sim_init():
    global SIM_KEY, SIM_PUBKEY
    from ecdsa import SigningKey, SECP256k1
    secexp = int.from_bytes(hashlib.sha256(b'nuri-card-sim-v1').digest(), 'big') % SECP256k1.order
    SIM_KEY = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    SIM_PUBKEY = SIM_KEY.get_verifying_key()


def sim_sign(hash_hex):
    digest = bytes.fromhex(hash_hex)
    if len(digest) != 32:
        raise ValueError('SIGN requires exactly 32 bytes')
    assert SIM_KEY is not None
    return SIM_KEY.sign_digest(digest).hex(), 0


def sim_pubkey():
    assert SIM_PUBKEY is not None
    return SIM_PUBKEY.to_string('compressed').hex()


def card_tx(conn, apdu):
    data, sw = conn.transmit(bytes(apdu))
    return list(data), sw >> 8, sw & 0xFF


def card_sign(conn, hash_hex):
    # Never try legacy signing against ETH2 or pretend a host-side login is PIN
    # verification. In particular, never fall back to ETH1 after this failure.
    if conn.aid_hex.upper() == ETH2_AID:
        raise RuntimeError('ETH2 PIN required: authenticated PIN sessions are not implemented by this PKCS#11 bridge')
    if conn.aid_hex.upper() != ETH1_AID or os.environ.get('NURI_ALLOW_ETH1_DEMO') != '1':
        raise RuntimeError('ETH1 demo signing requires NURI_ALLOW_ETH1_DEMO=1')
    h = bytes.fromhex(hash_hex)
    if len(h) != 32:
        raise ValueError('SIGN requires exactly 32 bytes')
    data, sw1, sw2 = card_tx(conn, [0x00, 0x04, 0x00, 0x00, 0x20] + list(h))
    sw = (sw1 << 8) | sw2
    if sw != 0x9000:
        raise RuntimeError(f'SIGN failed: SW={sw:04X}')
    if len(data) != 65 or data[64] not in (0, 1):
        raise RuntimeError('Malformed ETH1 signature response')
    return bytes(data[:64]).hex(), data[64]


def card_pubkey(conn):
    # ETH2 supports P1=01 for a compressed point; ETH1 returns compressed by default.
    p1 = 1 if conn.aid_hex.upper() == ETH2_AID else 0
    data, sw1, sw2 = card_tx(conn, [0x00, 0x02, p1, 0x00, 0x00])
    sw = (sw1 << 8) | sw2
    if sw != 0x9000:
        raise RuntimeError(f'GET_PUBKEY failed: SW={sw:04X}')
    if len(data) != 33 or data[0] not in (2, 3):
        raise RuntimeError('Malformed compressed public key')
    return bytes(data).hex()


def require_eth2_absent():
    """Confirm genuine 6A82 absence before demo downgrade.

    Shared open_applet's NO_APPLET also covers SELECT transport exceptions.
    Re-probe every selected reader and retain faults across readers/protocols;
    only confirmed 6A82 responses allow ETH1, never an ambiguous NO_APPLET.
    """
    import nuri_pcsc
    candidates = nuri_pcsc._select_readers(nuri_pcsc._list_readers(), None)
    if not candidates:
        raise RuntimeError('Cannot confirm ETH2 absence: no reader')
    select = nuri_pcsc.select_apdu(ETH2_AID)
    faults = []
    for reader in candidates:
        conn = reader.createConnection()
        absent = False
        def probe(raw):
            nonlocal absent
            try:
                _, sw = nuri_pcsc.transmit_raw(raw, select)
            except Exception:
                faults.append('ETH2 SELECT transport failure')
                raise
            if sw == 0x6A82:
                absent = True
                return True  # stop the ladder once absence is positively known
            faults.append(f'ETH2 absence not confirmed: SW={sw:04X}')
            return False
        try:
            nuri_pcsc.connect_ladder(conn, probe)
        except nuri_pcsc.CardError:
            faults.append('ETH2 reader/protocol failure')
        finally:
            nuri_pcsc._disconnect(conn)
        if not absent:
            faults.append('ETH2 absence not confirmed for reader')
    if faults:
        raise RuntimeError('Refusing ETH1 downgrade: ' + '; '.join(faults))


def card_init():
    import nuri_pcsc
    try:
        return nuri_pcsc.open_applet(ETH2_AID)
    except nuri_pcsc.CardError as error:
        if error.code != 'NO_APPLET':
            raise
        if os.environ.get('NURI_ALLOW_ETH1_DEMO') != '1':
            raise RuntimeError('ETH2 unavailable; ETH1 demo selection requires NURI_ALLOW_ETH1_DEMO=1') from error
    require_eth2_absent()
    print('WARNING: ETH1 DEMO: no PIN protection; local processes can sign.', file=sys.stderr)
    return nuri_pcsc.open_applet(ETH1_AID)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--card', action='store_true')
    group.add_argument('--sim', action='store_true')
    parser.add_argument('--json', action='store_true', help='JSON replies (always include mode)')
    args = parser.parse_args()
    conn = None
    mode = os.environ.get('NURI_PKCS11_MODE', 'card')

    def emit(values):
        values = {'mode': mode, **values}
        if args.json:
            print(json.dumps(values), flush=True)
        else:
            for key, value in values.items():
                print(f'{key}={value}', flush=True)

    try:
        mode = selected_mode()
        if (args.sim and mode != 'sim') or (args.card and mode != 'card'):
            raise ValueError('CLI mode conflicts with NURI_PKCS11_MODE; --sim requires NURI_PKCS11_MODE=sim')
        if mode == 'sim':
            print('WARNING: SIMULATOR: deterministic software key; NOT a hardware card.', file=sys.stderr)
            sim_init()
        else:
            conn = card_init()
        applet = 'SIMULATOR' if conn is None else ('ETH2' if conn.aid_hex.upper() == ETH2_AID else 'ETH1')
        metadata = {'applet': applet, 'pin_required': int(applet == 'ETH2')}
        for line in sys.stdin:
            parts = line.strip().split(' ', 1)
            cmd = parts[0]
            arg = parts[1] if len(parts) > 1 else ''
            if not cmd:
                continue
            if cmd in ('INIT', 'CLOSE_SESSION', 'FINALIZE'):
                values = {'status': 'OK', **metadata}
            elif cmd == 'SLOTS':
                values = {'slots': 1, 'slot_0_label': 'Nuri SIMULATOR' if mode == 'sim' else f'Nuri Smartcard ({applet})', 'slot_0_flags': 1}
            elif cmd == 'OPEN_SESSION':
                values = {'session': 1}
            elif cmd == 'FIND_KEY':
                values = {'key_handle': 1, 'key_type': 'EC', 'key_pubkey': sim_pubkey() if mode == 'sim' else card_pubkey(conn)}
            elif cmd == 'SIGN':
                sig, recovery = sim_sign(arg) if mode == 'sim' else card_sign(conn, arg)
                values = {'signature': sig, 'recovery_id': recovery}
            else:
                raise ValueError(f'UNKNOWN_COMMAND: {cmd}')
            emit(values)
            if cmd == 'FINALIZE':
                break
    except Exception as error:
        if mode not in ('card', 'sim'):
            mode = 'invalid'
        emit({'error': str(error).replace('\n', ' ')})
        print(f'PKCS11 {mode}: {error}', file=sys.stderr)
        return 1
    finally:
        if conn is not None:
            conn.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
