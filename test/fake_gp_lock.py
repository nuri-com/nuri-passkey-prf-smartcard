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
readers = state.get("readers", ["Fake reader"])
card_readers = state.get("card_readers", readers)
target_reader = state.get("target_reader", "Fake reader")
escrow = Path(os.environ["FAKE_GP_ESCROW"])
record = {"args": args, "escrow_exists": escrow.is_file(),
          "mode": (escrow.stat().st_mode & 0o777) if escrow.is_file() else None,
          "GP_READER_IGNORE": os.environ.get("GP_READER_IGNORE"),
          "GP_TRACE": os.environ.get("GP_TRACE")}


def value(flag):
    return args[args.index(flag) + 1]


if state.get("key_type", "AES") == "DES3" and "--lock" in args:
    record["new_keys_odd_parity"] = all(
        bin(byte).count("1") % 2 == 1 for byte in bytes.fromhex(value("--lock")))
with Path(os.environ["FAKE_GP_LOG"]).open("a") as stream:
    stream.write(json.dumps(record) + "\n")


if args == ["--version"]:
    print("# GlobalPlatformPro " + state.get("version", "f2af9ef"))
    sys.exit(0)
if args == ["--reader"]:
    print("Available readers:")
    for reader in readers:
        print("- " + reader)
    sys.exit(1 if len(card_readers) > 1 else 0)

hint = value("--reader") if "--reader" in args else os.environ.get("GP_READER")
matches = [reader for reader in readers
           if hint and hint.lower() in reader.lower()]
pref = matches[0] if len(matches) == 1 else None
ignore_env = os.environ.get("GP_READER_IGNORE")
ignored = [entry.lower() for entry in ignore_env.split(";")] if ignore_env is not None else []
preferred = []
available = []
for reader in readers:
    if pref is not None and reader.lower() in pref.lower():
        preferred.append(reader)
    elif any(entry in reader.lower() for entry in ignored):
        continue
    elif reader in card_readers:
        available.append(reader)
if preferred:
    chosen = preferred[0] if len(preferred) == 1 else None
else:
    chosen = available[0] if len(available) == 1 else None
if chosen is None:
    print("Specify reader with -r/$GP_READER; available readers:", file=sys.stderr)
    sys.exit(1)
if chosen != target_reader:
    sys.exit(10)
if "-i" in args:
    for field, size in lock.CPLC_FIELDS:
        val = "12345678" if field == "ICSerialNumber" else "01" * size
        if state.get("other_card") and field == "ICType":
            val = "FFFF"
        print(("CPLC: " if field == "ICFabricator" else "      ") + field + "=" + val)
    if state.get("malformed_cplc"):
        print("ICSerialNumber=BAD")
    key_types = state.get("key_types", {})
    for version in state.get("key_versions", [1]):
        for key_id in (1, 2, 3):
            key_type = key_types.get(str(key_id), state.get("key_type", "AES"))
            print(f"Version: {version:3d} (0x{version:02X}) ID: {key_id:3d} (0x{key_id:02X}) "
                  f"type: {key_type:<12s} length: 16")
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
if any(kind in args for kind in ("--lock-enc", "--lock-mac", "--lock-dek")) and "--lock" not in args:
    # Real 24.10.15 NPEs in HexBytes.v(args.valueOf(OPT_LOCK)) -> keyFromPlugin returned empty.
    print("java.lang.NullPointerException", file=sys.stderr)
    sys.exit(17)  # Nothing sent: fake keys unchanged.
if "--lock" in args:
    if not record["escrow_exists"] or record["mode"] != 0o600:
        sys.exit(13)
    if int(value("--new-keyver"), 16) != state.get("key_versions", [1])[0]:
        sys.exit(14)
    if state.get("rotate_fail"):
        sys.exit(15)  # PUT KEY rejected atomically: old keys stay on fake.
    # PlaintextKeys.fromMasterKey: one key becomes ENC = MAC = DEK, replacing the keyset.
    state["keys"] = dict.fromkeys(("enc", "mac", "dek"), value("--lock"))
    state_path.write_text(json.dumps(state))
    print("A000000151000000 locked with: " + value("--lock"))
    print("Write this down, DO NOT FORGET/LOSE IT!")
    if state.get("fail_after_commit"):
        sys.exit(16)  # Simulate response loss AFTER the new keys took effect.
    sys.exit(0)
sys.exit(99)
