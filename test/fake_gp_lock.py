"""Standalone GP 24.10.15 fake. Never imports smartcard or invokes hardware."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import card_lock as lock

args = sys.argv[1:]
state_path = Path(os.environ["FAKE_GP_STATE"])
state = json.loads(state_path.read_text())
escrow = Path(os.environ["FAKE_GP_ESCROW"])
record = {"args": args, "escrow_exists": escrow.is_file(),
          "mode": (escrow.stat().st_mode & 0o777) if escrow.is_file() else None}
with Path(os.environ["FAKE_GP_LOG"]).open("a") as stream:
    stream.write(json.dumps(record) + "\n")


def value(flag):
    return args[args.index(flag) + 1]


if args == ["--version"]:
    print("# GlobalPlatformPro " + state.get("version", "f2af9ef"))
    sys.exit(0)
if value("--reader") != "Fake reader":
    sys.exit(10)
if "-i" in args:
    for field, size in lock.CPLC_FIELDS:
        val = "12345678" if field == "ICSerialNumber" else "01" * size
        if state.get("other_card") and field == "ICType":
            val = "FFFF"
        print(("CPLC: " if field == "ICFabricator" else "      ") + field + "=" + val)
    if state.get("malformed_cplc"):
        print("ICSerialNumber=BAD")
    for version in state.get("key_versions", [1]):
        for key_id in (1, 2, 3):
            print(f"Version: {version:3d} (0x{version:02X}) ID: {key_id:3d} (0x{key_id:02X}) "
                  f"type: {state.get('key_type', 'AES'):<12s} length: 16")
    sys.exit(0)
keys = {kind: value("--key-" + kind) for kind in ("enc", "mac", "dek")}
if keys != state["keys"] or int(value("--key-ver"), 16) != state.get("key_versions", [1])[0]:
    print("Wrong authentication " + str(keys), file=sys.stderr)
    sys.exit(11)
if "-l" in args:
    state["listings"] = state.get("listings", 0) + 1
    state_path.write_text(json.dumps(state))
    if state.get("fail_verify") and state["listings"] > 1:
        print("key=" + keys["enc"], file=sys.stderr)
        sys.exit(12)
    for aid in sorted(lock.REQUIRED_APPS - set(state.get("missing_apps", []))):
        print("APP: " + aid + " (SELECTABLE)")
    sys.exit(0)
if "--lock-enc" in args:
    if not record["escrow_exists"] or record["mode"] != 0o600:
        sys.exit(13)
    if int(value("--new-keyver"), 16) != state.get("key_versions", [1])[0]:
        sys.exit(14)
    if state.get("rotate_fail"):
        sys.exit(15)  # PUT KEY rejected atomically: old keys stay on fake.
    state["keys"] = {kind: value("--lock-" + kind) for kind in ("enc", "mac", "dek")}
    state_path.write_text(json.dumps(state))
    if state.get("fail_after_commit"):
        sys.exit(16)  # Simulate response loss AFTER the new keys took effect.
    sys.exit(0)
sys.exit(99)
