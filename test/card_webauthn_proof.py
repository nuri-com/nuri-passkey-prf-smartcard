#!/usr/bin/env python3
"""Hardware proof: Connect-style WebAuthn create + PRF get on the real Nuri card,
through the native host's stdio framing exactly as Chrome sends it.

  <venv>/bin/python test/card_webauthn_proof.py [out.json]

Prompts for the card FIDO2 PIN (getpass; never stored, logged or written).
Creates ONE throwaway discoverable credential (user "nuri-card-proof") on the
card. Writes the WebAuthn JSON to out.json for verification with Connect's own
server verifiers (test/card_webauthn_verify.ts in nuri-connect).
"""

import getpass
import hashlib
import json
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = os.path.join(os.path.dirname(HERE), "host", "nuri_card_host.py")
ORIGIN, RP = "https://connect.nuri.com", "nuri.com"
SALT = "nuri-card-proof-salt-v1"


def b64u(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def call(proc, msg):
    body = json.dumps(msg).encode()
    proc.stdin.write(struct.pack("<I", len(body)) + body)
    proc.stdin.flush()
    n = struct.unpack("<I", proc.stdout.read(4))[0]
    return json.loads(proc.stdout.read(n))


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "card-webauthn-proof.json"
    env = {k: v for k, v in os.environ.items() if k != "NURI_CARD_SIM"}
    env["NURI_CARD_HOST_LOG"] = ""
    proc = subprocess.Popen([sys.executable, HOST, "chrome-extension://hlljlndpkgephgelnfgcpnneecmklnmf/"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
    try:
        reg_challenge, prf_challenge, get_challenge = (os.urandom(32) for _ in range(3))
        pin = getpass.getpass("Card FIDO2 PIN: ")
        create = {
            "rp": {"id": RP, "name": "Nuri Wallet"},
            "user": {"id": b64u(os.urandom(16)), "name": "nuri-card-proof", "displayName": "nuri-card-proof"},
            "challenge": b64u(reg_challenge),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"},
            "attestation": "none", "timeout": 60000, "extensions": {"prf": {}},
        }
        reg = call(proc, {"id": 1, "method": "webauthn_create", "params": {"origin": ORIGIN, "publicKey": create, "pin": pin}})
        if not reg.get("ok"):
            pin = None
            sys.exit(f"create failed: {reg.get('error')}")
        cred_id = reg["result"]["id"]
        print("created credential", cred_id)
        salt = b64u(SALT.encode())
        gets = []
        for i, ch in enumerate((prf_challenge, get_challenge)):
            req = {"challenge": b64u(ch), "rpId": RP, "userVerification": "required", "timeout": 60000,
                   "allowCredentials": [{"type": "public-key", "id": cred_id}],
                   "extensions": {"prf": {"eval": {"first": salt}}}}
            r = call(proc, {"id": 2 + i, "method": "webauthn_get", "params": {"origin": ORIGIN, "publicKey": req, "pin": pin}})
            if not r.get("ok"):
                pin = None
                sys.exit(f"get #{i + 1} failed: {r.get('error')}")
            gets.append({"challenge": b64u(ch), "result": r["result"]})
        pin = None
        prf = [g["result"]["clientExtensionResults"]["prf"]["results"]["first"] for g in gets]
        print("prf #1", prf[0])
        print("prf #2", prf[1])
        print("PRF deterministic:", prf[0] == prf[1], "| len", len(prf[0]))
        proof = {"origin": ORIGIN, "rp_id": RP, "prf_salt": SALT,
                 "registration": {"challenge": b64u(reg_challenge), "result": reg["result"]}, "assertions": gets,
                 "prf_sha256": hashlib.sha256(prf[0].encode()).hexdigest()}
        with open(out_path, "w") as f:
            json.dump(proof, f, indent=2)
        print("wrote", out_path)
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)


if __name__ == "__main__":
    main()
