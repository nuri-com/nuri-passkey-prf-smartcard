#!/usr/bin/env python3
"""Opt-in persistent card bridge. No KEYGEN, provisioning or PIN mutation.
Not executed as part of the zero-funds/software proof.
"""
import json
import os
import sys


def main():
    if not os.environ.get('NURI_CARD_PIN') or not os.environ.get('NURI_MUSIG2_AID'):
        raise RuntimeError('NURI_CARD_PIN and NURI_MUSIG2_AID environment required')
    # Importing/connecting is deferred until explicit bridge execution.
    from nuri_musig2_card import MuSig2Card
    card = MuSig2Card()
    card.connect()
    try:
        if not card.pin_protocol:
            raise RuntimeError('231-byte FINALIZE requires PIN applet >=1.14')
        for line in sys.stdin:
            try:
                req = json.loads(line)
                if req['op'] == 'pubkey':
                    response = {'pubkey': card.pubkey().hex()}
                elif req['op'] == 'nonces':
                    k1, k2 = card.nonces()
                    if card._token is None:
                        raise RuntimeError('PIN nonce token missing')
                    response = {'publicNonce': (k1 + k2).hex(), 'token': card._token.hex()}
                elif req['op'] == 'finalize':
                    p = bytes.fromhex(req['payload'])
                    if len(p) != 231 or card._token != p[97:101]:
                        raise ValueError('invalid FINALIZE length or token')
                    partial = card.finalize(p[:32], p[32:64], p[64], p[65:97], r_agg=p[101:166], p_agg=p[166:231])
                    response = {'partial': partial.hex()}
                else:
                    raise ValueError('unsupported card operation')
                print(json.dumps(response), flush=True)
            except Exception:
                # Never echo transport/PIN/secret-bearing exception contents.
                print(json.dumps({'error': 'card bridge operation failed; session closed'}), flush=True)
                return 1
    finally:
        card.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
