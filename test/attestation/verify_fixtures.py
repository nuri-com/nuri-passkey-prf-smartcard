#!/usr/bin/env python3
"""Verify exported Java simulator evidence, never generate replacement evidence.

Usage: python test/attestation/verify_fixtures.py FIXTURE_DIRECTORY
The directory must contain fixtures.json with ca_pub and exactly one fixture for
eth2, musig2 and vault. Required fixture fields: applet, aid, challenge,
signing_pub, certificate, info_page, tail_page, response and binding. All fields
except applet are hex strings; pages contain response data only, without SW9000.
This checks supplied bytes, not the provenance of whoever produced the JSON.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from typing import Any

# Import the production implementation without creating files outside this test.
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import nuri_attest as att  # pyright: ignore[reportMissingImports]


AIDS = {"eth2": att.ETH2_AID, "musig2": att.MUSIG2_AID, "vault": att.VAULT_AID}
HEX_FIELDS = ("aid", "challenge", "signing_pub", "certificate", "info_page",
              "tail_page", "response", "binding")


def require(condition, message):
    # Do not use assert: this acceptance gate must also work under python -O.
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def hex_bytes(value, label):
    require(isinstance(value, str) and bool(value) and len(value) % 2 == 0,
            f"{label}: expected nonempty even-length hex string")
    require(all(c in "0123456789abcdefABCDEF" for c in value),
            f"{label}: invalid hex (whitespace is not allowed)")
    return bytes.fromhex(value)


def load_fixtures(directory):
    path = directory / "fixtures.json"
    document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    require(isinstance(document, dict), "fixtures.json: expected object")
    require(set(document) == {"ca_pub", "fixtures"},
            "fixtures.json: only public CA key and fixtures may be exported")
    ca_pub = hex_bytes(document.get("ca_pub"), "ca_pub")
    require(len(ca_pub) == 65 and ca_pub[0] == 4,
            "ca_pub: expected uncompressed SEC1 P256 public key")
    att.load_ca_pubkey(ca_pub)
    fixtures = document.get("fixtures")
    require(isinstance(fixtures, list) and len(fixtures) == 3,
            "fixtures: expected exactly 3 fixtures")
    require(all(isinstance(f, dict) for f in fixtures), "fixtures: expected objects")
    names = [f.get("applet") for f in fixtures]
    require(all(isinstance(name, str) for name in names), "fixtures: applet names required")
    require(Counter(names) == Counter(AIDS.keys()),
            "fixtures: names must be exactly eth2, musig2, vault, each unique")
    decoded = []
    for fixture in fixtures:
        name = fixture["applet"]
        require(set(fixture) == {"applet", *HEX_FIELDS},
                f"{name}: only the public evidence schema may be exported")
        fields = {field: hex_bytes(fixture.get(field), f"{name}.{field}")
                  for field in HEX_FIELDS}
        require(fields["aid"] == AIDS[name], f"{name}: unexpected AID")
        require(len(fields["challenge"]) == 32, f"{name}: challenge must be 32 bytes")
        decoded.append(dict(fields, applet=name))
    return ca_pub, decoded


class FixtureTransport:
    """Replay only the two exact exported Java pages; no signing or synthesis."""

    def __init__(self, fixture):
        self.fixture = fixture
        self.cla = 0 if fixture["applet"] == "musig2" else 0x80
        self.calls = []

    def transmit(self, apdu):
        raw = bytes(apdu)
        page = len(self.calls)
        require(page < 2, "transport: unexpected third APDU (retry/SELECT/reconnect)")
        require(len(raw) == 38, "transport: expected 38-byte SHORT case-4 APDU")
        require(raw[:5] == bytes([self.cla, 0x72, page, 0, 32]),
                f"transport: incorrect CLA/INS/page/P2/short Lc for page {page}")
        require(raw[5:37] == self.fixture["challenge"],
                f"transport: page {page} changed caller challenge")
        require(raw[-1] == 0, "transport: SHORT Le must be 00 (256)")
        response = self.fixture["info_page" if page == 0 else "tail_page"]
        require(0 < len(response) <= 256, f"transport: page {page} exceeds SHORT response")
        self.calls.append(raw)
        return response, 0x9000


def flip(raw, offset):
    require(0 <= offset < len(raw), "mutation offset outside evidence")
    return raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:]


def other_public_key(pub, applet):
    # Negate the exported point: a distinct valid point, not a generated key.
    if applet != "vault":
        require(len(pub) == 33 and pub[0] in (2, 3), "expected compressed money key")
        return bytes([pub[0] ^ 1]) + pub[1:]
    require(len(pub) == 65 and pub[0] == 4, "expected uncompressed vault key")
    y = int.from_bytes(pub[33:], "big")
    negated_y = (-y) % att.NIST256p.curve.p()
    alternate = pub[:33] + negated_y.to_bytes(32, "big")
    require(alternate != pub, "negated public key must differ")
    return alternate


def verify_fixture(fixture, ca_pub) -> dict[str, Any]:
    name = fixture["applet"]
    response, info = fixture["response"], fixture["info_page"]
    tail, certificate, binding = (fixture[field] for field in
                                  ("tail_page", "certificate", "binding"))
    require(response == info + tail, f"{name}: response is not exact page concatenation")
    parsed_info = att.parse_info(info)
    parsed = att.parse_response(response)
    require(parsed_info["version"] == 1 and parsed_info["sealed"] is True,
            f"{name}: expected sealed INFO v1")
    require(parsed_info["aid"] == fixture["aid"], f"{name}: parsed AID mismatch")
    require(len(parsed_info["card_id"]) == 16, f"{name}: card ID length mismatch")
    require(parsed_info["cert"] == certificate, f"{name}: certificate differs from Java export")
    require(parsed["binding_sig"] == binding, f"{name}: binding differs from Java export")
    require(parsed["signing_pub"] == fixture["signing_pub"], f"{name}: money key mismatch")
    require(all(parsed[field] == value for field, value in parsed_info.items()),
            f"{name}: parsed INFO/response fields disagree")

    # Locate fields by the wire lengths, never by searching for byte substrings.
    cert_offset = 1 + 16 + 1 + len(fixture["aid"]) + 65 + 1 + 1
    require(info[cert_offset - 1] == len(certificate) and
            info[cert_offset:] == certificate, f"{name}: certificate boundary mismatch")
    pub_offset = len(info) + 1
    pub_length = len(fixture["signing_pub"])
    pin_offset = pub_offset + pub_length
    require(response[len(info)] == pub_length, f"{name}: money key length mismatch")
    require(response[pin_offset] == parsed["pin_state"], f"{name}: PIN state boundary mismatch")
    sig_offset = pin_offset + 2
    require(response[pin_offset + 1] == len(parsed["response_sig"]),
            f"{name}: response DER length mismatch")
    binding_offset = sig_offset + len(parsed["response_sig"]) + 1
    require(response[binding_offset - 1] == len(binding) and
            response[binding_offset:] == binding, f"{name}: binding boundary mismatch")

    args = dict(ca_pubkey=ca_pub, challenge=fixture["challenge"],
                expected_aid=fixture["aid"], expected_signing_pub=fixture["signing_pub"])
    require(att.verify_response(response, **args) == parsed,
            f"{name}: direct verification returned different fields")
    transport = FixtureTransport(fixture)
    collected = att.read_attestation(transport, transport.cla, fixture["challenge"])
    require(len(transport.calls) == 2, f"{name}: transport must issue exactly two APDUs")
    require(collected == response, f"{name}: read_attestation changed Java evidence")
    require(att.verify_response(collected, **args) == parsed,
            f"{name}: collected verification returned different fields")

    controls = []

    def reject(label, mutated, expected_error, **overrides):
        # Requiring a successful parse AND an exact error rules out a vacuous
        # negative control caught by malformed DER or an earlier unrelated guard.
        att.parse_response(mutated)
        try:
            att.verify_response(mutated, **dict(args, **overrides))
        except att.VerificationError as error:
            require(str(error) == expected_error,
                    f"{name}/{label}: expected {expected_error!r}, got {str(error)!r}")
        else:
            raise ValueError(f"{name}/{label}: invalid evidence was accepted")
        controls.append(label)

    reject("certificate-last-byte-xor1", flip(response, cert_offset + len(certificate) - 1),
           "CA certificate signature invalid")
    reject("wrong-challenge", response, "response signature invalid",
           challenge=flip(fixture["challenge"], 0))
    alternate_pub = other_public_key(fixture["signing_pub"], name)
    reject("wrong-expected-money-pub", response, "signing public key mismatch",
           expected_signing_pub=alternate_pub)
    reject("NHWV1-last-byte-xor1", flip(response, binding_offset + len(binding) - 1),
           "NHWV1 binding signature invalid")
    mutated_pub = response[:pub_offset] + alternate_pub + response[pin_offset:]
    reject("signed-money-pub", mutated_pub, "response signature invalid",
           expected_signing_pub=alternate_pub)
    reject("signed-pinState", flip(response, pin_offset), "response signature invalid")
    reject("signed-cardID", flip(response, 1), "CA certificate signature invalid")
    reject("wrong-expected-AID", response, "AID mismatch",
           expected_aid=flip(fixture["aid"], len(fixture["aid"]) - 1))
    return dict(applet=name, positive_verifications=2, transport_apdus=len(transport.calls),
                negative_controls=controls)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_directory", type=Path,
                        help="directory containing Java-exported fixtures.json")
    options = parser.parse_args(argv)
    try:
        ca_pub, fixtures = load_fixtures(options.fixture_directory)
        results = [verify_fixture(fixture, ca_pub) for fixture in fixtures]
        require(Counter(result["applet"] for result in results) == Counter(AIDS.keys()),
                "verified fixture names/count mismatch")
        report = dict(fixtures=len(results),
                      positive_verifications=sum(r["positive_verifications"] for r in results),
                      transport_apdus=sum(r["transport_apdus"] for r in results),
                      negative_controls=sum(len(r["negative_controls"]) for r in results),
                      results=results)
    except Exception as error:
        print(f"ATTESTATION_PYTHON_FIXTURES_FAILED: {error}", file=sys.stderr)
        return 1
    print("ATTESTATION_PYTHON_FIXTURES_OK " + json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
