#!/usr/bin/env python3
"""Reversible GP key sealing, not a card lifecycle transition. No PC/SC imports."""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

from Crypto.Cipher import AES, DES3
from Crypto.Protocol.KDF import scrypt

GP_VERSION = "24.10.15"
DEFAULT_KEY = "404142434445464748494A4B4C4D4E4F"
REQUIRED_APPS = {"A0000006472F0001", "4E5552494554483201", "4E555249564C5401"}
CPLC_FIELDS = (
    ("ICFabricator", 2), ("ICType", 2), ("OperatingSystemID", 2),
    ("OperatingSystemReleaseDate", 2), ("OperatingSystemReleaseLevel", 2),
    ("ICFabricationDate", 2), ("ICSerialNumber", 4), ("ICBatchIdentifier", 2),
    ("ICModuleFabricator", 2), ("ICModulePackagingDate", 2),
    ("ICCManufacturer", 2), ("ICEmbeddingDate", 2), ("ICPrePersonalizer", 2),
    ("ICPrePersonalizationEquipmentDate", 2), ("ICPrePersonalizationEquipmentID", 4),
    ("ICPersonalizer", 2), ("ICPersonalizationDate", 2),
    ("ICPersonalizationEquipmentID", 4),
)
FORMAT = "nuri-gp-escrow-v1"
AAD = FORMAT.encode("ascii")
SCRYPT = {"N": 131072, "r": 8, "p": 1}


class Refusal(Exception):
    pass


def private_stat(st, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(st.st_mode) or st.st_uid != os.getuid():
        raise Refusal("Private path must have the current owner and expected file type")
    if stat.S_IMODE(st.st_mode) != (0o700 if directory else 0o600):
        raise Refusal("Private directory must be 0700; private file must be 0600")


def parent_fd(path, create=False):
    """Walk via directory FDs; no symlink in any component is followed."""
    path = Path(os.path.abspath(os.path.expanduser(str(path))))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parent.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)  # persist the newly published directory entry
                except FileExistsError:
                    pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            st = os.fstat(fd)
            if st.st_mode & 0o022:
                raise Refusal("Refusing group/world-writable parent directory")
        private_stat(os.fstat(fd), directory=True)
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def read_private(path):
    parent, name = parent_fd(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            private_stat(os.fstat(stream.fileno()))
            data = stream.read(65537)
            if len(data) > 65536:
                raise Refusal("Private file too large")
            return data
    finally:
        os.close(parent)


def atomic_escrow(path, data):
    """Publish complete fsynced ciphertext atomically, never overwrite a target."""
    parent, name = parent_fd(path, create=True)
    temp = ".escrow-" + secrets.token_hex(16)
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # link is atomic and fails if name already exists (including a symlink).
        os.link(temp, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.unlink(temp, dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temp, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def encrypt(payload, password):
    salt, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    key = scrypt(password, salt, 32, **SCRYPT)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(AAD)
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(payload, sort_keys=True).encode())
    return json.dumps({"format": FORMAT, "kdf": {"name": "scrypt", **SCRYPT},
                       "salt": salt.hex(), "nonce": nonce.hex(), "tag": tag.hex(),
                       "ciphertext": ciphertext.hex()}, sort_keys=True).encode() + b"\n"


def decrypt(data, password):
    try:
        envelope = json.loads(data)
        if envelope["format"] != FORMAT or envelope["kdf"] != {"name": "scrypt", **SCRYPT}:
            raise ValueError("Unsupported format")
        salt = bytes.fromhex(envelope["salt"])
        nonce = bytes.fromhex(envelope["nonce"])
        tag = bytes.fromhex(envelope["tag"])
        if (len(salt), len(nonce), len(tag)) != (32, 12, 16):
            raise ValueError("Invalid lengths")
        key = scrypt(password, salt, 32, **SCRYPT)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        cipher.update(AAD)
        payload = json.loads(cipher.decrypt_and_verify(bytes.fromhex(envelope["ciphertext"]), tag))
        validate_payload(payload)
        return payload
    except (KeyError, TypeError, ValueError, OverflowError):
        raise Refusal("Escrow authentication failed (wrong passphrase, damaged or unsupported file)") from None


def validate_payload(payload):
    if payload["gp_version"] != GP_VERSION:
        raise ValueError("Wrong GP version")
    if not re.fullmatch(r"[0-9A-F]{84}", payload["cplc"]):
        raise ValueError("Bad CPLC")
    if not re.fullmatch(r"[0-9A-F]{8}", payload["serial"]):
        raise ValueError("Bad serial")
    if payload["serial"] != payload["cplc"][24:32]:
        raise ValueError("Serial mismatch")
    if (type(payload["key_version"]) is not int or not 1 <= payload["key_version"] <= 127
            or 0x10 <= payload["key_version"] <= 0x2F):
        raise ValueError("Bad key version")
    key_type = payload.get("key_type", "AES")
    if key_type not in ("AES", "DES3"):
        raise ValueError("Bad key type")
    for field in ("old_keys", "new_keys"):
        if set(payload[field]) != {"enc", "mac", "dek"}:
            raise ValueError("Bad keyset")
        for value in payload[field].values():
            if not re.fullmatch(r"[0-9A-F]{32}", value):
                raise ValueError("Bad key")
    if key_type == "DES3":
        for value in payload["new_keys"].values():
            if any(bin(byte).count("1") % 2 != 1 for byte in bytes.fromhex(value)):
                raise ValueError("DES3 keys must have odd parity")
    if set(payload["old_keys"].values()) != {DEFAULT_KEY}:
        raise ValueError("Not a default-key migration")


def password_from(args, confirm=False):
    if args.passphrase_fd is not None:
        # A pipe/descriptor, never argv or environment. Bound the input.
        with os.fdopen(os.dup(args.passphrase_fd), "rb") as stream:
            value = stream.readline(4098)
        if len(value) > 4097:
            raise Refusal("Passphrase too long")
        password = value.rstrip(b"\r\n")
    else:
        if not sys.stdin.isatty():
            raise Refusal("Use a terminal for the passphrase, or --passphrase-fd with a private pipe")
        password = getpass.getpass("Escrow passphrase: ").encode()
        if confirm and password != getpass.getpass("Repeat escrow passphrase: ").encode():
            raise Refusal("Passphrases differ")
    if len(password) < 16:
        raise Refusal("Use an escrow passphrase of at least 16 bytes")
    return password


class GP:
    def __init__(self, args):
        self.binary = os.environ.get("GP_BIN", "gp")
        reader = args.reader or os.environ.get("GP_READER")
        if not reader or reader.startswith("-"):
            raise Refusal("Specify one explicit --reader (or GP_READER); indexes are not accepted")
        self.reader = reader
        # Prevent inherited GP_* values/KDFs/tracing from changing the operation.
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("GP_", "SCP01", "SCP02", "SCP03"))}
        version = self.run(["--version"], reader=False)
        # The official 24.10.15 jar embeds the abbreviated release commit, not its tag.
        if not re.search(r"(?m)^# GlobalPlatformPro (?:v?24\.10\.15|f2af9ef)\r?$", version):
            raise Refusal("Only GlobalPlatformPro 24.10.15 is supported")
        try:
            result = subprocess.run([self.binary, "--reader"], capture_output=True, text=True,
                                    env=self.env, timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Refusal("GP launch/transport failed; captured diagnostics suppressed to protect keys") from None
        if result.returncode not in (0, 1):
            raise Refusal("Could not list GP readers")
        lines = result.stdout.splitlines()
        if not lines or lines[0] != "Available readers:":
            raise Refusal("Could not parse GP reader list")
        readers = [line[2:] for line in lines[1:] if line.startswith("- ")]
        if not readers:
            raise Refusal("No GP readers found")
        if any(not name or ";" in name for name in readers):
            raise Refusal("GP reader names must be non-empty and must not contain ';'")
        if self.reader not in readers:
            raise Refusal("Reader must exactly match one of: " + " | ".join(readers))
        other_readers = [name for name in readers if name != self.reader]
        if other_readers:
            self.env["GP_READER_IGNORE"] = ";".join(other_readers)

    def run(self, args, reader=True):
        command = [self.binary] + (["--reader", self.reader] if reader else []) + args
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    env=self.env, timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Refusal("GP launch/transport failed; captured diagnostics suppressed to protect keys") from None
        if result.returncode != 0:
            if "Specify reader with -r" in result.stderr:
                raise Refusal("gp could not select exactly this reader; leave only the target card inserted")
            raise Refusal("GP operation failed; captured diagnostics suppressed to protect keys")
        return result.stdout + "\n" + result.stderr

    @staticmethod
    def auth(keys, version):
        return ["--key-ver", f"0x{version:02X}"] + [x for kind in ("enc", "mac", "dek")
                                                        for x in ("--key-" + kind, keys[kind])]

    def listing(self, keys, version):
        output = self.run(self.auth(keys, version) + ["-l"])
        apps = set(re.findall(r"(?m)^\s*APP:\s*([0-9A-Fa-f]+)\b", output))
        if not REQUIRED_APPS <= {aid.upper() for aid in apps}:
            raise Refusal("Authenticated registry must include FIDO2, ETH2 and vault applet instances")

    def rotate(self, old, new, version):
        # SAME version is crucial: GP otherwise adds a keyset and leaves defaults usable.
        self.run(self.auth(old, version) + ["--new-keyver", f"0x{version:02X}"] +
                 [x for kind in ("enc", "mac", "dek") for x in ("--lock-" + kind, new[kind])])


def identity(info):
    values = {}
    for field, size in CPLC_FIELDS:
        matches = re.findall(r"\b" + field + r"=([0-9A-Fa-f]+)\b", info)
        if len(matches) != 1 or not re.fullmatch(r"[0-9A-Fa-f]{%d}" % (size * 2), matches[0]):
            raise Refusal("Cannot parse complete unambiguous CPLC")
        values[field] = matches[0].upper()
    return "".join(values.values()), values["ICSerialNumber"]


def check_denylist(cplc, serial):
    # Mandatory file, no CLI override: absence is not permission to seal the demo card.
    path = Path.home() / ".nuri-card/no-lock-cplc.txt"
    try:
        data = read_private(path).decode("ascii")
    except (OSError, UnicodeError):
        raise Refusal("Owner must create ~/.nuri-card/no-lock-cplc.txt (0600 in 0700 directory) first") from None
    for line in data.splitlines():
        value = line.partition("#")[0].strip().upper()
        if not value:
            continue
        if not re.fullmatch(r"(?:[0-9A-F]{8}|[0-9A-F]{84})", value):
            raise Refusal("Malformed deny-list entry: expected serial8 or full CPLC84")
        if value in (serial, cplc):
            raise Refusal("CPLC is on the no-lock deny-list; no key rotation permitted")


def key_version(info):
    rows = re.findall(r"Version:\s*\d+\s*\(0x([0-9A-Fa-f]{2})\)\s*ID:\s*(\d+)\s*\(0x[0-9A-Fa-f]{2}\)\s*type:\s*(\S+)\s*length:\s*(\d+)", info)
    versions = {int(row[0], 16) for row in rows}
    if len(versions) != 1 or len(rows) != 3:
        raise Refusal("Require exactly one existing three-key ISD keyset; refuse extra/factory/unknown keys")
    version = versions.pop()
    key_types = {row[2] for row in rows}
    if (not 1 <= version <= 127 or 0x10 <= version <= 0x2F
            or {int(row[1]) for row in rows} != {1, 2, 3}
            or {int(row[3]) for row in rows} != {16}
            or len(key_types) != 1 or not key_types <= {"AES", "DES3"}):
        raise Refusal("Require one replaceable AES-128 or DES3 keyset, version 01..0F or 30..7F")
    return version, key_types.pop()


def new_key(key_type):
    if key_type == "AES":
        return secrets.token_hex(16).upper()
    for _ in range(8):
        try:
            return DES3.adjust_key_parity(secrets.token_bytes(16)).hex().upper()
        except ValueError:
            pass
    raise Refusal("Could not generate a valid DES3 key after 8 attempts")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("lock", "unlock"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="perform checks and prompt before any PUT KEY")
    mode.add_argument("--dry-run", action="store_true", help="default: no GP process, prompts or writes")
    parser.add_argument("--reader", help="explicit GP reader name")
    parser.add_argument("--escrow", help="new (lock) or existing (unlock) encrypted escrow path")
    parser.add_argument("--passphrase-fd", type=int, help="read passphrase from a private inherited descriptor")
    args = parser.parse_args(argv)
    if not args.execute:
        print("DRY RUN: no GP calls, no card access, no files written. Execute requires CPLC serial confirmation.")
        return 0
    attempted = False
    escrow_path = None
    try:
        # Unlock decrypts BEFORE any GP call: wrong password cannot touch the card.
        payload = None
        if args.action == "unlock":
            if not args.escrow:
                raise Refusal("Unlock requires --escrow")
            payload = decrypt(read_private(args.escrow), password_from(args))
        gp = GP(args)
        info = gp.run(["-i"])
        cplc, serial = identity(info)
        check_denylist(cplc, serial)
        version, key_type = key_version(info)
        if payload and ((payload["cplc"], payload["key_version"], payload.get("key_type", "AES"))
                        != (cplc, version, key_type)):
            raise Refusal("Escrow belongs to a different CPLC/key version/key type")
        defaults = dict.fromkeys(("enc", "mac", "dek"), DEFAULT_KEY)
        current = payload["new_keys"] if payload else defaults
        gp.listing(current, version)
        print(f"Target CPLC serial: {serial}; key version: 0x{version:02X}; key type: {key_type}")
        if input(f"Type the card CPLC serial {serial} to {args.action}: ").strip() != serial:
            raise Refusal("CPLC serial confirmation mismatch")
        if args.action == "lock":
            password = password_from(args, confirm=True)
            payload = {"gp_version": GP_VERSION, "cplc": cplc, "serial": serial,
                       "key_version": version, "key_type": key_type, "old_keys": defaults,
                       "new_keys": {k: new_key(key_type) for k in defaults}}
            escrow_path = Path(args.escrow).expanduser() if args.escrow else (
                Path.home() / ".nuri-card/escrow" / (cplc + ".json"))
            atomic_escrow(escrow_path, encrypt(payload, password))
            # Read back/authenticate the exact published file before changing a card.
            if decrypt(read_private(escrow_path), password) != payload:
                raise Refusal("Escrow readback mismatch")
            print(f"Encrypted escrow durably published: {escrow_path}", flush=True)
        else:
            escrow_path = Path(args.escrow).expanduser()
        # Re-read identity immediately before PUT KEY to catch normal card swaps.
        if identity(gp.run(["-i"])) != (cplc, serial):
            raise Refusal("Card identity changed; no rotation sent")
        check_denylist(cplc, serial)
        assert payload is not None
        target = payload["new_keys"] if args.action == "lock" else payload["old_keys"]
        attempted = True
        gp.rotate(current, target, version)
        gp.listing(target, version)  # mandatory fresh secure-channel authentication
        if identity(gp.run(["-i"])) != (cplc, serial):
            raise Refusal("Card identity changed after rotation")
        print("CARD_LOCK_VERIFIED" if args.action == "lock" else "CARD_DEFAULT_KEYS_RESTORED_VERIFIED")
        return 0
    except (Refusal, OSError, EOFError, ValueError, KeyboardInterrupt) as error:
        # Do not echo exception text from OS/subprocess/JSON paths: it may include secrets.
        message = str(error) if isinstance(error, Refusal) else "Input/filesystem operation failed"
        print("REFUSED: " + message, file=sys.stderr)
        if attempted:
            print(f"Rotation attempted; state is UNVERIFIED. Keep escrow {escrow_path}; it contains BOTH keysets. "
                  "Do not retry or delete it. No automatic rollback was attempted.", file=sys.stderr)
        else:
            print("No rotation command sent; existing card keys unchanged.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
