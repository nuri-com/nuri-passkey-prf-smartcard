#!/usr/bin/env python3
"""Generate package-local clean-room helper sources; --check verifies exact copies."""
from pathlib import Path
import argparse

ROOT = Path(__file__).resolve().parents[1]
# SEC2 / FIPS P-256: p, a, b, n, uncompressed G. No external dependency.
P256 = bytes.fromhex(
    'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'
    'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc'
    '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'
    'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'
    '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
    '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'
)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    assert len(P256) == 193
    template = (ROOT / 'card/attestation/NuriAttestation.java.in').read_text()
    curve = ','.join('(byte)0x%02x' % b for b in P256)
    for directory, package in [('eth2', 'com.nuri.eth2'), ('musig2', 'nuri.musig2'), ('vault', 'com.nuri.vault')]:
        path = ROOT / 'card' / directory / 'NuriAttestation.java'
        content = template.replace('@PACKAGE@', package).replace('@P256@', curve)
        if args.check:
            if not path.exists() or path.read_text() != content:
                raise SystemExit('stale generated attestation source: ' + str(path))
        else:
            path.write_text(content)
    print('ATTESTATION_SOURCES_OK')

if __name__ == '__main__':
    main()
