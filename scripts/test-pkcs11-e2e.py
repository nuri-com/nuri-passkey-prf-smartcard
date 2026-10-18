#!/usr/bin/env python3
"""End-to-end PKCS#11 test for the Nuri smartcard module (dist/pkcs11-nuri.so).

The previous version of this file only exercised python-ecdsa against itself.
This one drives the real module through a real PKCS#11 consumer (OpenSC
`pkcs11-tool`):

  1. C_GetTokenInfo / C_GetMechanismList (pkcs11-tool -L, -M)
  2. C_FindObjects + C_GetAttributeValue: CKA_EC_PARAMS = secp256k1 OID,
     CKA_EC_POINT = DER OCTET STRING of the uncompressed point (-O, --read-object)
  3. C_SignInit/C_Sign with CKM_ECDSA on a 32-byte digest (--sign -m ECDSA)
  4. The signature is verified with python-ecdsa against the public key the
     module itself reported (SubjectPublicKeyInfo from --read-object)
  5. Inputs that are not 32 bytes are rejected (the applet signs one digest)
  6. Several signatures over different digests all verify

Default: NURI_PKCS11_MODE unset -> the helper runs --sim (no card, no PC/SC).
Real card: NURI_PKCS11_MODE=card python3 scripts/test-pkcs11-e2e.py  (needs the
ETH applet, pyscard, and a reader; see docs/hsm.md).

Env: NURI_PKCS11_PYTHON (python with `ecdsa`, plus `pyscard` for card mode;
     defaults to the interpreter running this test),
     NURI_PKCS11_MODULE (default dist/pkcs11-nuri.so), PKCS11_TOOL (default pkcs11-tool).
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE = os.environ.get("NURI_PKCS11_MODULE", os.path.join(ROOT, "dist", "pkcs11-nuri.so"))
TOOL = os.environ.get("PKCS11_TOOL", "pkcs11-tool")
SECP256K1_OID_DER = "06052b8104000a"  # OBJECT IDENTIFIER 1.3.132.0.10


def tool(*args, check=True):
    cmd = [TOOL, "--module", MODULE, *args]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed rc={p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


def main():
    from ecdsa import VerifyingKey, SECP256k1
    from ecdsa.util import sigdecode_string

    if not shutil.which(TOOL):
        print(f"SKIP: {TOOL} not found (brew install opensc / apt install opensc)")
        return 0
    if not os.path.exists(MODULE):
        print(f"FAIL: {MODULE} missing (run scripts/build-pkcs11.sh)")
        return 1
    os.environ.setdefault("NURI_PKCS11_PYTHON", sys.executable)
    mode = os.environ.get("NURI_PKCS11_MODE", "sim")
    results = []

    def rec(name, ok, detail=""):
        results.append((name, bool(ok), detail))

    # 1. token + mechanisms
    out = tool("-L").stdout
    rec("C_GetTokenInfo (-L)", "token initialized" in out and "Nuri Smartcard" in out, out.strip().splitlines()[1])
    out = tool("-M").stdout
    rec("C_GetMechanismList (-M) = ECDSA only", "ECDSA, keySize={256,256}" in out and out.count("keySize") == 1,
        out.strip().splitlines()[-1])

    # 2. objects + EC attributes
    out = tool("-O").stdout
    ec_point = [l.split()[1] for l in out.splitlines() if "EC_POINT:" in l]
    ec_params = [l.split()[1] for l in out.splitlines() if "EC_PARAMS:" in l]
    rec("Private + public key objects listed (-O)", "Private Key Object; EC" in out and "Public Key Object; EC" in out)
    rec("CKA_EC_PARAMS = secp256k1 OID 1.3.132.0.10", ec_params == [SECP256K1_OID_DER], ec_params[0] if ec_params else "missing")
    rec("CKA_EC_POINT = DER OCTET STRING(04||X||Y), 67 bytes",
        len(ec_point) == 1 and ec_point[0].startswith("044104") and len(ec_point[0]) == 134, ec_point[0] if ec_point else "missing")

    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as td:
        pub = os.path.join(td, "pub.der")
        tool("--read-object", "--type", "pubkey", "--id", "01", "-o", pub)
        vk = VerifyingKey.from_der(open(pub, "rb").read())
        rec("--read-object pubkey parses as SubjectPublicKeyInfo on SECP256k1", vk.curve == SECP256k1,
            "pubkey_uncompressed=" + vk.to_string("uncompressed").hex())
        rec("EC_POINT equals read-object pubkey", ec_point and ec_point[0][6:] == vk.to_string("uncompressed").hex()[2:])

        # 3+4. sign 32-byte digests, verify against the module's own pubkey
        sigs = []
        n_sigs = 3 if mode == "card" else 5
        for i in range(n_sigs):
            digest = hashlib.sha256(f"Nuri PKCS#11 e2e {i}".encode()).digest()
            din, sout = os.path.join(td, f"h{i}.bin"), os.path.join(td, f"s{i}.bin")
            open(din, "wb").write(digest)
            tool("--sign", "-m", "ECDSA", "-i", din, "-o", sout)
            sig = open(sout, "rb").read()
            ok = len(sig) == 64 and vk.verify_digest(sig, digest, sigdecode=sigdecode_string)
            rec(f"C_Sign(CKM_ECDSA) #{i} verifies with python-ecdsa", ok, f"digest={digest.hex()} sig={sig.hex()}")
            sigs.append(sig)
        rec("Signatures are distinct (fresh nonces)", len(set(sigs)) == len(sigs))
        low_s = all(int.from_bytes(s[32:], "big") <= SECP256k1.order // 2 for s in sigs)
        rec("low-s (EIP-2)" + ("" if mode == "card" else " [informational in sim]"),
            low_s if mode == "card" else True, f"all_low_s={low_s}")

        # 5. wrong length rejected
        bad = os.path.join(td, "h31.bin")
        open(bad, "wb").write(b"\x00" * 31)
        p = tool("--sign", "-m", "ECDSA", "-i", bad, "-o", os.path.join(td, "x.bin"), check=False)
        err = (p.stderr or p.stdout).strip()
        rec("31-byte input rejected (no partial sign)", p.returncode != 0 and not os.path.exists(os.path.join(td, "x.bin")),
            err.splitlines()[-1] if err else "")

    print("=" * 64)
    print(f"Nuri Smartcard PKCS#11 end-to-end  mode={mode}  module={MODULE}")
    print("=" * 64)
    all_ok = True
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        if detail:
            print(f"       {detail}")
        all_ok &= ok
    print("=" * 64)
    print("ALL TESTS PASSED" if all_ok else "SOME TESTS FAILED")
    if mode != "card":
        print("Mode: --sim (software key, deterministic). Nothing here was run on a card.")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
