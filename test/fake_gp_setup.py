"""Standalone, hardware-free GlobalPlatformPro fake for scripts/card-setup.sh.

Models a blank or partly provisioned card: one admin key, a registry of applet
instances, and installs. Never imports pyscard and never touches a reader.

State file (FAKE_GP_STATE, JSON):
  key          the only accepted admin key (default: the public GP default)
  aids         installed applet AIDs
  readers      readers reported by `--reader` (default: one fake reader)
  card_readers readers that hold a card (default: all of them)
  target       the reader the card is really on
Every call is appended to FAKE_GP_LOG as one JSON line.
"""
import json
import os
from pathlib import Path
import sys

DEFAULT_KEY = "404142434445464748494A4B4C4D4E4F"

CAP_AIDS = {
    "FIDO2-up.cap": "A0000006472F0001",
    "nuri-musig2-v20-keygen.cap": "4E5552494D554701",
    "nuri-oath-totp.cap": "4E555249544F5450",
    "nuri-eth-signer.cap": "4E55524945544801",
    "nuri-eth2-signer.cap": "4E5552494554483201",
    "nuri-musig2-v20-keygen-aid2.cap": "4E5552494D55473201",
    "nuri-musig2-v20-keygen-aid3.cap": "4E5552494D55473301",
    "nuri-vault.cap": "4E555249564C5401",
}

args = sys.argv[1:]
state_path = Path(os.environ["FAKE_GP_STATE"])
state = json.loads(state_path.read_text())
log_path = Path(os.environ["FAKE_GP_LOG"])


def value(flag):
    return args[args.index(flag) + 1]


def keys_from_args():
    if "-k" in args:
        key = value("-k").upper()
        return {"enc": key, "mac": key, "dek": key}
    return {kind: value("--key-" + kind).upper() for kind in ("enc", "mac", "dek")
            if "--key-" + kind in args}


def save():
    state_path.write_text(json.dumps(state))


record = {"args": args, "musig2_reinstall": os.environ.get("MUSIG2_REINSTALL"),
          "gp_reader_ignore": os.environ.get("GP_READER_IGNORE")}


def write_record():
    with log_path.open("a") as stream:
        stream.write(json.dumps(record) + "\n")


readers = state.get("readers", ["Fake reader"])
card_readers = state.get("card_readers", readers)
target = state.get("target", readers[0])

if args == ["--version"]:
    print("# GlobalPlatformPro f2af9ef")
    sys.exit(0)
if args == ["--reader"]:
    write_record()
    print("Available readers:")
    for reader in readers:
        print("- " + reader)
    sys.exit(1 if len(card_readers) > 1 else 0)

hint = value("-r") if "-r" in args else value("--reader") if "--reader" in args else None
matches = [reader for reader in readers if hint and hint.lower() in reader.lower()]
ignored = [entry.lower() for entry in (record["gp_reader_ignore"] or "").split(";") if entry]
available = [reader for reader in readers
             if reader in matches and not any(entry in reader.lower() for entry in ignored)
             and reader in card_readers]
chosen = available[0] if len(available) == 1 else None
if chosen is None:
    print("Specify reader with -r/$GP_READER; available readers:", file=sys.stderr)
    write_record()
    sys.exit(1)
if chosen != target:
    write_record()
    sys.exit(10)

keys = keys_from_args()
if keys:
    state["auth_calls"] = state.get("auth_calls", 0) + 1
    record["auth"] = "ok" if all(v == state.get("key", DEFAULT_KEY) for v in keys.values()) else "wrong"
else:
    record["auth"] = None
write_record()
if keys and record["auth"] != "ok":
    print("Wrong authentication", file=sys.stderr)
    save()
    sys.exit(11)

if "-l" in args or "--list" in args:
    for aid in sorted(state.get("aids", [])):
        print(f"APP: {aid} (SELECTABLE)")
    save()
    sys.exit(0)

if "-i" in args:
    for field, size in (("ICFabricator", 2), ("ICType", 2), ("OperatingSystemID", 2)):
        val = state.get("fabricator", "4790") if field == "ICFabricator" else "01" * size
        print(f"{field}={val}")
    print(f"ICSerialNumber={state.get('serial', '12345678')}")
    sys.exit(0)

if "--install" in args or "--load" in args:
    flag = "--install" if "--install" in args else "--load"
    cap = Path(value(flag)).name
    aid = CAP_AIDS.get(cap)
    if aid is None:
        print("unknown CAP " + cap, file=sys.stderr)
        sys.exit(20)
    if aid not in state.setdefault("aids", []):
        state["aids"].append(aid)
    save()
    print(f"{cap} loaded: {aid}")
    sys.exit(0)

if "--create" in args:
    aid = value("--create").upper()
    if aid not in state.setdefault("aids", []):
        state["aids"].append(aid)
    save()
    print(f"created {aid}")
    sys.exit(0)

print("unsupported fake gp call " + " ".join(args), file=sys.stderr)
sys.exit(99)
