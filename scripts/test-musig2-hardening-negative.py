#!/usr/bin/env python3
"""Simulator-only negative controls on isolated copies; never edits the candidate.
Run after scripts/test-musig2-jcardsim.sh. Uses its pinned cached jCardSim jar.
"""
from pathlib import Path
import os
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BUILD = Path(os.environ.get("CARD_BUILD_ROOT", ROOT / ".build/card-v1"))
JAR = Path(os.environ.get("JCARDSIM_JAR", Path.home() / ".gradle/caches/modules-2/files-2.1/com.klinec/jcardsim/3.0.5.11/87d0049bd958e674d7aa92ddacd3662d1133074e/jcardsim-3.0.5.11.jar"))
JAVA = Path(os.environ.get("JAVA17_HOME", "/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home")) / "bin"
APPLET = ROOT / "card/musig2/NuriMuSig2v019.java"
ORIGINAL = APPLET.read_text()
TEST = ROOT / "test/musig2-jcardsim/PinHardeningTest.java"
MUTATIONS = [
    ("PIN gate", "if ((pinRequired || pinSet) && (!pinSet || !pin.isValidated()))", "if (false)", "expected 6982 got"),
    ("session token", "if (!equalCT(buffer, (short)(off + 97), nonceSession, (short)0, (short)4)\n            || !equalCT(nonceSession, (short)0, sessionCounter, (short)0, (short)4))", "if (false)", "expected 6984 got"),
    ("double-computation compare", "if (!equalCT(result, (short)0, checkResult, (short)0, (short)32))", "if (false)", "expected 6988 got"),
    ("curve equation", "if (!equalCT(scratch32_4, (short)0, scratch32_5, (short)0, (short)32))", "if (false)", "expected 6a80 got"),
    ("keygen atomicity", "JCSystem.beginTransaction();\n        masterKey.setS(scratch32_1, (short)0, (short)32);\n        Util.arrayCopy(apdu.getBuffer(), (short)0, masterPublicKey, (short)0, (short)33);\n        attestation.commitBinding();\n        keyGenerated = true;\n        JCSystem.commitTransaction();", "masterKey.setS(scratch32_1, (short)0, (short)32);\n        Util.arrayCopy(apdu.getBuffer(), (short)0, masterPublicKey, (short)0, (short)33);\n        keyGenerated = true;", "persistent key set runs inside transaction"),
]


def exercise(name, source):
    work = BUILD / "hardening-negative" / name.replace(" ", "-")
    work.mkdir(parents=True, exist_ok=True)
    (work / APPLET.name).write_text(source)
    shutil.copy2(ROOT / "card/musig2/Scalar256.java", work / "Scalar256.java")
    shutil.copy2(ROOT / "card/musig2/NuriAttestation.java", work / "NuriAttestation.java")
    classes = work / "classes"
    classes.mkdir(exist_ok=True)
    compile_run = subprocess.run([str(JAVA / "javac"), "-nowarn", "-source", "8", "-target", "8", "-cp", str(JAR), "-d", str(classes), str(work / APPLET.name), str(work / "Scalar256.java"), str(work / "NuriAttestation.java"), str(TEST)], capture_output=True, text=True)
    (work / "compile.log").write_text(compile_run.stdout + compile_run.stderr)
    if compile_run.returncode:
        raise RuntimeError(f"{name}: compile failure is not a valid negative control: {compile_run.stderr}")
    run = subprocess.run([str(JAVA / "java"), "-cp", f"{classes}{os.pathsep}{JAR}", "PinHardeningTest"], capture_output=True, text=True)
    (work / "run.log").write_text(run.stdout + run.stderr)
    return run


def main():
    import hashlib
    expected = "f6c3b6b8140401a47cf39d7b9dbfc052e381474c6c3b22018051024be1fca97c"
    assert hashlib.sha256(JAR.read_bytes()).hexdigest() == expected, "unexpected jCardSim artifact"
    for name, old, new, assertion in MUTATIONS:
        assert ORIGINAL.count(old) == 1, f"mutation anchor is not unique: {name}"
        run = exercise(name, ORIGINAL.replace(old, new, 1))
        text = run.stdout + run.stderr
        assert run.returncode != 0 and "AssertionError" in text and assertion in text, f"mutation did not trip its intended assertion: {name}: {text}"
        detail = next(line for line in text.splitlines() if "AssertionError" in line)
        print(f"NEGATIVE_CONTROL_RED {name}: {detail}")
    run = exercise("candidate", ORIGINAL)
    assert run.returncode == 0 and "MUSIG2_JCARDSIM_PIN_HARDENING_OK" in run.stdout, run.stdout + run.stderr
    print(run.stdout.strip())
    assert APPLET.read_text() == ORIGINAL, "candidate bytes changed"
    print(f"MUSIG2_HARDENING_NEGATIVE_CONTROLS_OK red={len(MUTATIONS)} candidate=green")


if __name__ == "__main__":
    main()
