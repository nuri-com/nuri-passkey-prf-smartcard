#!/usr/bin/env python3
"""Live physical-card acceptance proof for NURI-SC v1 (`4E55524953433031`).

Executes against a real Java Card over PC/SC (`nuri_pcsc`), verifying:
1. Plaintext command rejection (`SC_REQUIRED`: `0x6985` on SET_PIN, VERIFY_PIN, PUT, HMAC, PING).
2. `INS_GET_PUBKEY` (65-byte P-256 identity key) and `INS_OPEN` ECDH+ECDSA-SHA256 handshake.
3. Encrypted `PING` across AES block boundaries (`0`, `1`, `15`, `16`, `32`, `180` bytes).
4. Encrypted `SET_PIN` (if not yet set) and proof that PIN bytes never appear on the PC/SC wire.
5. Encrypted wrong-PIN (`0x63Cx` inside encrypted D2C payload while outer wire SW stays `0x9000`)
   followed by encrypted right-PIN (`0x9000`, tries restored to `5`).
6. Encrypted `PUT_SECRET` + RFC 4231 Case 2 (`"Jefe"`) HMAC-SHA256 vector verification.
7. Replay attack on `INS_WRAP` (`0x6988` + immediate session & `OwnerPIN` validation wipe).
8. Ciphertext/tag bit-flip attack (`0x6988` + immediate session & `OwnerPIN` validation wipe).
9. Re-open + clean `INS_CLOSE` (`open=0`).

Writes a sanitized JSON receipt (no PINs, no secrets) to `--out`.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import nuri_pcsc
import nuri_sc as sc

DEMO_TEST_PIN = b"739184"  # Dedicated test-only PIN for standalone NuriSecureChannelApplet


def read_cplc(conn) -> tuple[str, str]:
    # Select default ISD first so 80 CA 9F 7F routes to Card Manager, not the active applet.
    nuri_pcsc.transmit_raw(conn, bytes.fromhex("00A4040000"))
    raw, sw = nuri_pcsc.transmit_raw(conn, bytes.fromhex("80CA9F7F00"))
    if sw == 0x9000 and len(raw) >= 42:
        cplc = raw[-42:]
        return cplc[12:16].hex().upper(), cplc.hex().upper()
    return "UNKNOWN", ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reader", default="ACR39U", help="PC/SC reader substring")
    ap.add_argument("--protocol", default="auto", help="PC/SC protocol (auto, T0, T1, default)")
    ap.add_argument("--out", type=Path, required=True, help="Output JSON receipt path")
    args = ap.parse_args()

    import os
    os.environ["NURI_PCSC_PROTOCOL"] = args.protocol
    applet = nuri_pcsc.open_applet(sc.DEFAULT_AID.hex().upper(), reader=args.reader)
    try:
        serial, cplc_hex = read_cplc(applet.conn)
        # Re-select SC applet after CPLC query
        _, sel_sw = applet.transmit(sc.select_apdu(sc.DEFAULT_AID))
        assert sel_sw == 0x9000, f"re-select failed: {sel_sw:04X}"

        wire_log: list[tuple[bytes, bytes, int]] = []

        def tx(cmd: bytes) -> tuple[bytes, int]:
            data, sw = applet.transmit(cmd)
            wire_log.append((bytes(cmd), bytes(data), sw))
            return data, sw

        sess = sc.ScCardSession(tx, sc.DEFAULT_AID)
        t0 = time.monotonic()

        st0 = sess.status()
        ver, ecdh_mode, is_open0, pin_set0, tries0 = list(st0)
        assert ver == 1 and is_open0 == 0, f"unexpected initial status: {st0.hex()}"

        pub = sess.get_pubkey()
        assert len(pub) == 65 and pub[0] == 0x04

        # 1. Plaintext rejection check
        plaintext_sws: dict[str, str] = {}
        for name, ins in [
            ("SET_PIN", sc.INS_SET_PIN),
            ("VERIFY_PIN", sc.INS_VERIFY_PIN),
            ("PUT_SECRET", sc.INS_PUT_SECRET),
            ("HMAC", sc.INS_HMAC),
            ("PING", sc.INS_PING),
        ]:
            _, sw = tx(sc.outer_apdu(0x80, ins, 0, 0, b"123456"))
            assert sw == 0x6985, f"{name} allowed in plaintext: {sw:04X}"
            plaintext_sws[name] = f"0x{sw:04X}"

        # 2. Handshake timing & verification
        t_hs0 = time.monotonic()
        opened = sess.open(pub)
        hs_ms = round((time.monotonic() - t_hs0) * 1000, 1)
        assert sess.status()[2] == 1

        # 3. Encrypted PING across block boundaries
        ping_lengths = [0, 1, 15, 16, 32, 180]
        for n in ping_lengths:
            payload = bytes(((i * 13 + 5) & 0xFF) for i in range(n))
            echo, inner_sw = sess.transceive(0x80, sc.INS_PING, data=payload)
            assert inner_sw == 0x9000 and echo == payload, f"PING {n} failed: {inner_sw:04X}"

        # 4. Encrypted SET_PIN (first run) or idempotent 0x6985 (re-run)
        wire_before_pin = len(wire_log)
        if pin_set0 == 0:
            _, set_sw = sess.transceive(0x80, sc.INS_SET_PIN, data=DEMO_TEST_PIN)
            assert set_sw == 0x9000, f"SET_PIN failed: {set_sw:04X}"
            set_pin_result = "0x9000 (initialized)"
        else:
            _, set_sw = sess.transceive(0x80, sc.INS_SET_PIN, data=DEMO_TEST_PIN)
            assert set_sw == 0x6985, f"expected 0x6985 on already-set PIN, got {set_sw:04X}"
            set_pin_result = "0x6985 (already initialized; replace refused)"

        # 5. Encrypted wrong-PIN -> outer wire SW 0x9000, inner SW 0x63C4; then right-PIN -> 0x9000
        _, wrong_sw = sess.transceive(0x80, sc.INS_VERIFY_PIN, data=b"000000")
        outer_wrong_wire_sw = wire_log[-1][2]
        assert outer_wrong_wire_sw == 0x9000, f"outer SW leaked error: {outer_wrong_wire_sw:04X}"
        assert (wrong_sw & 0xFFF0) == 0x63C0, f"unexpected wrong PIN inner SW: {wrong_sw:04X}"

        _, right_sw = sess.transceive(0x80, sc.INS_VERIFY_PIN, data=DEMO_TEST_PIN)
        assert right_sw == 0x9000, f"VERIFY_PIN failed: {right_sw:04X}"
        assert sess.status()[4] == 5, "PIN tries did not reset to 5 after valid VERIFY_PIN"

        # Verify PIN never appeared in plaintext on any wire APDU
        pin_leaked = any(DEMO_TEST_PIN in cmd or DEMO_TEST_PIN in rsp for cmd, rsp, _ in wire_log[wire_before_pin:])
        assert not pin_leaked, "PIN bytes appeared in wire APDU!"

        # 6. Encrypted PUT_SECRET + RFC 4231 Case 2 HMAC-SHA256
        rfc_key = b"Jefe"
        rfc_msg = b"what do ya want for nothing?"
        _, put_sw = sess.transceive(0x80, sc.INS_PUT_SECRET, data=rfc_key)
        assert put_sw == 0x9000
        mac_bytes, hmac_sw = sess.transceive(0x80, sc.INS_HMAC, data=rfc_msg)
        assert hmac_sw == 0x9000
        expected_mac = hmac.new(rfc_key, rfc_msg, hashlib.sha256).hexdigest()
        assert mac_bytes.hex() == expected_mac
        key_leaked = any(rfc_key in cmd or rfc_msg in cmd for cmd, _, _ in wire_log[-2:])
        assert not key_leaked, "HMAC key/message appeared in plaintext on wire!"

        # 7. Replay attack -> 0x6988 + session/PIN wipe
        frame = sess.channel.wrap(sc.inner_apdu(0x80, sc.INS_PING, data=b"live-replay-check"))
        rsp1, sw1 = tx(sc.wrap_apdu(frame))
        assert sw1 == 0x9000 and sess.channel.unwrap(rsp1) == (b"live-replay-check", 0x9000)
        _, replay_sw = tx(sc.wrap_apdu(frame))
        assert replay_sw == 0x6988
        sess.channel.close()
        assert sess.status()[2] == 0

        # Prove PIN validation was wiped when replay tore down session
        sess.open(pub)
        _, unauth_hmac_sw = sess.transceive(0x80, sc.INS_HMAC, data=rfc_msg)
        assert unauth_hmac_sw == 0x6982

        # 8. Ciphertext bit-flip attack -> 0x6988 + session/PIN wipe
        assert sess.transceive(0x80, sc.INS_VERIFY_PIN, data=DEMO_TEST_PIN)[1] == 0x9000
        tampered = bytearray(sess.channel.wrap(sc.inner_apdu(0x80, sc.INS_HMAC, data=rfc_msg)))
        tampered[24] ^= 0x01
        _, tamper_sw = tx(sc.wrap_apdu(bytes(tampered)))
        assert tamper_sw == 0x6988
        sess.channel.close()
        assert sess.status()[2] == 0

        # 9. Clean re-open + CLOSE
        t_w0 = time.monotonic()
        sess.open(pub)
        _, ping_sw = sess.transceive(0x80, sc.INS_PING, data=b"done")
        wrap_ms = round((time.monotonic() - t_w0) * 1000, 1)
        assert ping_sw == 0x9000
        sess.close()
        st_final = sess.status()
        assert st_final[2] == 0 and st_final[4] == 5

        total_ms = round((time.monotonic() - t0) * 1000, 1)
        cap_sha256 = hashlib.sha256((ROOT / "dist" / "nuri-sc.cap").read_bytes()).hexdigest()

        receipt = {
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "protocol": "NURI-SC-V1",
            "applet_aid": sc.DEFAULT_AID.hex().upper(),
            "package_aid": "4E555249534330",
            "cap_sha256": cap_sha256,
            "card": {
                "serial": serial,
                "ic_fabricator": cplc_hex[:4] if cplc_hex else "UNKNOWN",
                "os_id": cplc_hex[8:12] if cplc_hex else "UNKNOWN",
                "ecdh_mode": f"0x{ecdh_mode:02X}" + (" (ALG_EC_SVDP_DH_PLAIN)" if ecdh_mode == 0x03 else " (ALG_EC_SVDP_DH_PLAIN_XY)"),
                "identity_pubkey_uncompressed": pub.hex(),
            },
            "transport": {
                "reader": applet.reader_name,
                "pcsc_protocol": applet.protocol,
                "atr": applet.atr().hex().upper(),
            },
            "timings_ms": {
                "open_handshake": hs_ms,
                "reopen_plus_wrapped_ping": wrap_ms,
                "full_suite_total": total_ms,
            },
            "checks": {
                "plaintext_commands_rejected": plaintext_sws,
                "handshake_ecdsa_verified": True,
                "session_id_len_bytes": len(opened.session_id),
                "encrypted_ping_lengths_verified": ping_lengths,
                "encrypted_set_pin": set_pin_result,
                "wrong_pin_outer_wire_sw": f"0x{outer_wrong_wire_sw:04X}",
                "wrong_pin_inner_decrypted_sw": f"0x{wrong_sw:04X}",
                "right_pin_inner_decrypted_sw": f"0x{right_sw:04X}",
                "pin_tries_restored": int(st_final[4]),
                "pin_bytes_absent_from_wire": not pin_leaked,
                "rfc4231_case2_hmac_sha256": mac_bytes.hex(),
                "secret_bytes_absent_from_wire": not key_leaked,
                "replay_attack_outer_sw": f"0x{replay_sw:04X}",
                "pin_wiped_after_replay_inner_sw": f"0x{unauth_hmac_sw:04X}",
                "ciphertext_bitflip_outer_sw": f"0x{tamper_sw:04X}",
                "clean_close_session_open_flag": int(st_final[2]),
            },
            "result": "REAL_CARD_NURI_SC_V1_VERIFIED",
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, indent=2))
        return 0
    finally:
        applet.close()


if __name__ == "__main__":
    raise SystemExit(main())
