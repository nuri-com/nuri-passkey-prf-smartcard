#!/usr/bin/env python3
"""Verify ETH2 simulator signatures written by test/eth2/Eth2SimTest.java.

For every entry: r,s in range, s <= n/2 (EIP-2 low-S), signature verifies with
python-ecdsa against the pubkey the card returned in the same response, and
public-key recovery yields that pubkey for exactly one yParity in {0,1}.
Also round-trips each entry through host/nuri_card_host.py verify_and_recover
(the native-messaging host) so the host-side parser is exercised on real
applet output. No reader, no card.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO_ROOT, "host"))


def main() -> int:
    path = sys.argv[1]
    min_count = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    from ecdsa import SECP256k1, VerifyingKey, BadSignatureError
    from ecdsa.util import sigdecode_string

    import nuri_card_host as host

    n = SECP256k1.order
    entries = json.load(open(path))
    if len(entries) < min_count:
        print(f"FAIL only {len(entries)} signatures, need >= {min_count}")
        return 1
    pubs = set()
    parity = {0: 0, 1: 0}
    for i, e in enumerate(entries):
        h = bytes.fromhex(e["hash"])
        r = int(e["r"], 16)
        s = int(e["s"], 16)
        pub = bytes.fromhex(e["pub"])
        pubs.add(pub)
        assert len(h) == 32, f"#{i} hash length"
        assert len(pub) == 65 and pub[0] == 4, f"#{i} pubkey not uncompressed"
        assert 1 <= r < n and 1 <= s < n, f"#{i} r/s out of range"
        assert s <= n // 2, f"#{i} HIGH-S: s={e['s']}"
        vk = VerifyingKey.from_string(pub, curve=SECP256k1)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        try:
            vk.verify_digest(sig, h, sigdecode=sigdecode_string)
        except BadSignatureError:
            print(f"FAIL #{i} signature does not verify: {e}")
            return 1
        cands = VerifyingKey.from_public_key_recovery_with_digest(sig, h, SECP256k1, sigdecode=sigdecode_string)
        matches = [idx for idx, c in enumerate(cands) if c.to_string("uncompressed") == pub]
        assert len(matches) == 1, f"#{i} recovery matched {matches}"
        parity[matches[0]] += 1
        # host parser on the raw 129-byte applet response
        raw = sig + pub
        hr, hs = host.parse_eth2_signature(raw)
        assert (hr, hs) == (r, s), f"#{i} host parse mismatch"
        res = host.verify_and_recover(host.compress_pubkey(pub), h, hr, hs)
        assert res["yParity"] == matches[0], f"#{i} host yParity {res['yParity']} != {matches[0]}"
        assert res["signature"] == "0x" + sig.hex() + bytes([27 + matches[0]]).hex()
    assert len(pubs) == 1, f"expected one card pubkey, saw {len(pubs)}"
    addr = host.pubkey_to_address(next(iter(pubs)))
    print(f"ETH2_SIM_VERIFY_OK signatures={len(entries)} all_low_s=True yParity0={parity[0]} yParity1={parity[1]} address={addr}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
