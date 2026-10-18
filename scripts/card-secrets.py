#!/usr/bin/env python3
"""Disk envelope vault (default) or on-card vault applet (--backend card); only the broker and trusted child receive plaintext."""
import argparse
import contextlib
import fcntl
import getpass
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import warnings
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DOMAIN = b"nuri-card-secrets-v1"
LIMIT = 8 * 1024 * 1024
NAME_RE = r"[A-Za-z_][A-Za-z0-9_]*"
# Child processes never inherit secrets, the fake-PRF override or anything PIN-shaped.
SCRUB_PREFIXES = ("NURI_SECRET_", "FIDO2_", "NURI_CARD_SECRETS_FAKE_PRF")
PIN_ENV_RE = re.compile(r"(^|_)PIN($|_)")

# --- On-card vault applet contract (package 4E555249564C54, applet AID below) ---
VAULT_AID = "4E555249564C5401"
CLA = 0x80
INS_STATUS, INS_SET_PIN, INS_VERIFY = 0x01, 0x10, 0x20
INS_PUT, INS_LIST, INS_HMAC, INS_REVEAL, INS_DELETE = 0x30, 0x31, 0x40, 0x41, 0x50
# INS_REVEAL is used only internally by run/proxy; there is deliberately no CLI for it.
KINDS = {"hmac": 1, "bearer": 2}
KIND_NAMES = {v: k for k, v in KINDS.items()}
PIN_MIN, PIN_MAX = 4, 16
CARD_NAME_MAX = 16
CARD_SECRET_MAX = 64
HMAC_MESSAGE_ROOM = 254          # nameLen(1) + name + message fits one short APDU
LIST_PAGES = (0, 1)              # 16 slots, up to 8 records per page
SW_OK = 0x9000
SW_TEXT = {
    0x6700: "card rejected the command shape (6700)",
    0x6982: "PIN not verified on this connection (6982)",
    0x6983: "card vault PIN is blocked (6983); the vault cannot be unlocked",
    0x6985: "card refused: conditions not satisfied (6985)",
    0x6A80: "card rejected the secret kind (6A80)",
    0x6A84: "card vault is full (6A84); remove an entry first",
    0x6A86: "card rejected P1/P2 (6A86)",
    0x6A88: "no such entry on the card (6A88)",
    0x6D00: "vault applet does not support this instruction (6D00)",
    0x6E00: "vault applet rejected the class byte (6E00)",
}


class CardVaultError(Exception):
    """Message is safe to print: it never contains PIN, secret or HMAC input bytes."""


def card_apdu(ins, p1=0, data=b"", response=False):
    """Short APDU, P2=0. Case 2/4 carry Le=00; nuri_pcsc handles 61XX/6CXX."""
    if len(data) > 255:
        raise CardVaultError("command data too long for one short APDU")
    body = bytes([len(data)]) + bytes(data) if data else b""
    return bytes([CLA, ins, p1, 0x00]) + body + (b"\x00" if response else b"")


def card_fail(sw, context=None):
    if sw == 0x6985 and context:
        raise CardVaultError(context)
    raise CardVaultError(SW_TEXT.get(sw, f"card returned status {sw:04X}"))


def card_tx(applet, ins, p1=0, data=b"", response=False, refused=None):
    out, sw = applet.transmit(card_apdu(ins, p1, data, response))
    if sw != SW_OK:
        card_fail(sw, refused)
    return bytes(out)


@contextlib.contextmanager
def card_session():
    """One applet connection per CLI invocation, always closed."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
    import nuri_pcsc  # lazy: the disk backend never touches PC/SC
    try:
        applet = nuri_pcsc.open_applet(VAULT_AID)
    except nuri_pcsc.CardError as error:
        raise CardVaultError(f"vault applet unavailable ({error.code})") from None
    try:
        yield applet
    finally:
        try:
            if getattr(applet, "_vault_verify_attempted", False):
                # A PC/SC disconnect is not itself applet logout. Re-select our
                # exact AID to reset OwnerPIN before releasing the connection.
                _, sw = applet.transmit(nuri_pcsc.select_apdu(VAULT_AID))
                if sw != SW_OK:
                    raise CardVaultError("could not confirm vault logout; remove the card before further use")
        finally:
            applet.close()


def card_status(applet):
    data = card_tx(applet, INS_STATUS, response=True)
    if len(data) != 4 or data[0] != 1:
        raise CardVaultError("unsupported vault applet version or STATUS shape")
    return {"version": data[0], "pin_set": bool(data[1]), "tries": data[2], "max_slots": data[3]}


def read_pin(prompt):
    """PIN only from the controlling terminal: never argv, environment or piped stdin."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            pin = getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise CardVaultError("PIN entry needs a terminal (refusing to read it from stdin)") from None
    raw = pin.encode("utf-8")
    if not PIN_MIN <= len(raw) <= PIN_MAX:
        raise CardVaultError(f"PIN must be {PIN_MIN}..{PIN_MAX} bytes")
    return raw


def card_authenticate(applet):
    """Exactly one VERIFY per connection; a wrong PIN is reported, never retried."""
    status = card_status(applet)
    if not status["pin_set"]:
        raise CardVaultError("card vault is not initialized; the owner runs: card-secrets.py --backend card init")
    if status["tries"] == 0:
        raise CardVaultError(SW_TEXT[0x6983])
    pin = read_pin("Card vault PIN: ")
    applet._vault_verify_attempted = True  # also logout if a VERIFY response is lost
    _, sw = applet.transmit(card_apdu(INS_VERIFY, data=pin))
    if sw == SW_OK:
        return
    if sw & 0xFFF0 == 0x63C0:
        raise CardVaultError(f"wrong card vault PIN, {sw & 0x0F} tries left (not retried)")
    if sw == 0x6985:
        raise CardVaultError("card vault is not initialized")
    card_fail(sw)


def card_name(name):
    raw = name.encode("ascii")
    if not 1 <= len(raw) <= CARD_NAME_MAX:
        raise CardVaultError(f"card entry names are at most {CARD_NAME_MAX} bytes")
    return raw


def parse_list_page(data):
    records, i = [], 0
    while i < len(data):
        if i + 2 > len(data) or i + 2 + data[i + 1] > len(data) or not 1 <= data[i + 1] <= CARD_NAME_MAX:
            raise CardVaultError("malformed LIST response")
        records.append((data[i], bytes(data[i + 2:i + 2 + data[i + 1]])))
        i += 2 + data[i + 1]
    if len(records) > 8:
        raise CardVaultError("malformed LIST response")
    return records


def card_list(applet):
    return [rec for page in LIST_PAGES for rec in parse_list_page(card_tx(applet, INS_LIST, p1=page, response=True))]


def describe(record):
    kind, raw = record
    item = {"kind": KIND_NAMES.get(kind, f"unknown-{kind}")}
    text = raw.decode("ascii", "replace")
    if raw.isascii() and re.fullmatch(NAME_RE, text):
        item["name"] = text
    else:
        item["name_hex"] = raw.hex()  # foreign or non-CLI name: shown, never guessed
    return item


def card_init():
    with card_session() as applet:
        if card_status(applet)["pin_set"]:
            raise CardVaultError("card vault PIN is already set (init is first-use only)")
        pin = read_pin(f"New card vault PIN ({PIN_MIN}-{PIN_MAX} bytes): ")
        if read_pin("Repeat new card vault PIN: ") != pin:
            raise CardVaultError("PINs do not match; nothing was written")
        card_tx(applet, INS_SET_PIN, data=pin, refused="card vault PIN is already set (init is first-use only)")
        status = card_status(applet)  # read back: SET_PIN does not authenticate
        if not status["pin_set"]:
            raise CardVaultError("SET_PIN not confirmed by STATUS")
    print(json.dumps({"initialized": True, "tries": status["tries"], "max_slots": status["max_slots"]}))


def card_command(args):
    """Dispatch for --backend card. Returns the bearer bytes for run/proxy, else None.

    Every usage/input check happens before the card is opened or a PIN is asked.
    """
    if args.command == "init":
        card_init()
        return None
    raw = b"" if args.command == "list" else card_name(args.name)
    value, kind, message = b"", KINDS["bearer"], b""
    if args.command == "put":
        if args.tag:
            raise CardVaultError("tags are disk-vault metadata; the card stores only kind and name")
        if sys.stdin.isatty():
            raise CardVaultError("put requires piped stdin")
        value = sys.stdin.buffer.read(CARD_SECRET_MAX + 1)
        if not 1 <= len(value) <= CARD_SECRET_MAX:
            raise CardVaultError(f"card secrets must be 1..{CARD_SECRET_MAX} bytes")
        kind = KINDS[args.kind or "bearer"]
    if args.command == "hmac":
        message = read_hmac_file(args.data_file, HMAC_MESSAGE_ROOM - len(raw))
    if args.command == "run" and not run_cmd(args):
        raise CardVaultError("run requires a child command")
    if args.command == "proxy":
        check_upstream(args.upstream)
    with card_session() as applet:
        card_authenticate(applet)
        if args.command == "list":
            print(json.dumps([describe(rec) for rec in card_list(applet)]))
            return None
        if args.command == "put":
            card_tx(applet, INS_PUT, data=bytes([kind, len(raw)]) + raw + value,
                    refused="name already exists on the card; remove it explicitly first")
            if [rec for rec in card_list(applet) if rec[1] == raw] != [(kind, raw)]:
                raise CardVaultError("PUT not confirmed by LIST read-back")
            return None
        if args.command == "rm":
            card_tx(applet, INS_DELETE, data=bytes([len(raw)]) + raw)
            if any(rec[1] == raw for rec in card_list(applet)):
                raise CardVaultError("DELETE not confirmed by LIST read-back")
            return None
        if args.command == "hmac":
            mac = card_tx(applet, INS_HMAC, data=bytes([len(raw)]) + raw + message, response=True,
                          refused="entry is not an HMAC-kind secret")
            if len(mac) != 32:
                raise CardVaultError("malformed HMAC response")
            print(mac.hex())
            return None
        # run / proxy: the broker can only ever read bearer-kind entries.
        secret = card_tx(applet, INS_REVEAL, data=bytes([len(raw)]) + raw, response=True,
                         refused="HMAC-kind secrets never leave the card; use: hmac NAME --data-file F")
        if not 1 <= len(secret) <= CARD_SECRET_MAX:
            raise CardVaultError("malformed REVEAL response")
        return secret


def read_hmac_file(path, room):
    with open(path, "rb") as handle:
        message = handle.read(room + 1)
    if len(message) > room:
        raise CardVaultError(f"HMAC message must be at most {room} bytes for this name (no prehash)")
    return message


def run_cmd(args):
    return args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd


def child_env(name, secret, scrub_pins):
    env = {k: v for k, v in os.environ.items() if not k.startswith(SCRUB_PREFIXES)
           and not (scrub_pins and PIN_ENV_RE.search(k.upper()))}
    env["NURI_SECRET_" + name] = secret.decode("utf-8")
    return env


def check_upstream(value):
    upstream = urlsplit(value)
    if (upstream.scheme not in ("https", "http") or not upstream.hostname or upstream.username
            or upstream.password or upstream.query or upstream.fragment
            or (upstream.scheme == "http" and upstream.hostname not in ("127.0.0.1", "::1", "localhost"))):
        raise ValueError("upstream requires HTTPS (HTTP permitted only for loopback tests)")
    return upstream


def prf(args):
    fake = os.environ.get("NURI_CARD_SECRETS_FAKE_PRF")
    if fake is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", fake):
            raise ValueError("invalid fake PRF")
        return bytes.fromhex(fake)
    # Import the existing implementation, never its CLI (which prints PRF outputs).
    path = Path(__file__).with_name("card-prf-backup.py")
    spec = importlib.util.spec_from_file_location("card_prf_backup", path)
    assert spec is not None and spec.loader is not None
    backup = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()):
        spec.loader.exec_module(backup)
        profile = backup.read_profile(Path(args.profile_path))
        device = argparse.Namespace(transport=args.transport, device_index=args.device_index,
                                   pin=None, pin_prompt=False, user_verification=None)
        first, _ = backup.derive_once(device, profile, DOMAIN, None)
    return first


def metadata(entry):
    return {k: entry[k] for k in ("name", "created", "tags")}


def aad(entry):
    return json.dumps(metadata(entry), sort_keys=True, separators=(",", ":")).encode()


def seal(key, value, associated):
    nonce = os.urandom(12)
    return {"nonce": nonce.hex(), "ciphertext": AESGCM(key).encrypt(nonce, value, associated).hex()}


def unseal(key, value, associated):
    return AESGCM(key).decrypt(bytes.fromhex(value["nonce"]),
                               bytes.fromhex(value["ciphertext"]), associated)


def kek(args, vault):
    mode = "fake" if "NURI_CARD_SECRETS_FAKE_PRF" in os.environ else "card"
    if vault["mode"] != mode:
        raise ValueError("test/real vault mismatch")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(vault["salt"]),
                info=DOMAIN + b"/kek").derive(prf(args))


def unwrap(args, vault):
    entry = vault["secrets"][args.name]
    if entry["name"] != args.name:
        raise ValueError("entry identity mismatch")
    key = unseal(kek(args, vault), entry["wrapped_key"], aad(entry) + b"/key")
    return unseal(key, entry["data"], aad(entry) + b"/data")


def secure_open(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(fd)
        raise ValueError("vault must be an owned regular file with mode 0600")
    return os.fdopen(fd)


@contextlib.contextmanager
def locked_vault(path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with secure_open(path) as handle:
                vault = json.load(handle)
            if vault["version"] != 1:
                raise ValueError("unknown vault version")
        except FileNotFoundError:
            vault = {"version": 1, "mode": "fake" if "NURI_CARD_SECRETS_FAKE_PRF" in os.environ else "card",
                     "salt": os.urandom(32).hex(), "secrets": {}}
        yield vault


def save(path, vault):
    fd, name = tempfile.mkstemp(prefix=".vault-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(vault, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def proxy(args, secret):
    upstream = check_upstream(args.upstream)
    token = secret.decode("ascii")
    if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("invalid header value")
    injected = "Bearer " + token if args.header == "Authorization" else token

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def request(self):
            status, body, content_type = 502, b"upstream unavailable\n", "text/plain"
            connection = None
            try:
                if (self.headers.get_all("Host") != [expected_host]
                        or "Origin" in self.headers or "Sec-Fetch-Site" in self.headers
                        or not self.path.startswith("/") or self.path.startswith("//")
                        or "\\" in self.path or "#" in self.path):
                    status, body = 403, b"forbidden\n"
                elif ("Transfer-Encoding" in self.headers
                      or len(self.headers.get_all("Content-Length", [])) > 1):
                    status, body = 400, b"invalid framing\n"
                else:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 <= size <= LIMIT:
                        raise ValueError("request too large")
                    data = self.rfile.read(size)
                    headers = {k: self.headers[k] for k in ("Content-Type", "Accept") if k in self.headers}
                    headers[args.header] = injected
                    cls = http.client.HTTPSConnection if upstream.scheme == "https" else http.client.HTTPConnection
                    connection = cls(upstream.hostname, upstream.port, timeout=30)
                    connection.request(self.command, upstream.path.rstrip("/") + self.path, data, headers)
                    response = connection.getresponse()  # Never follow redirects to another host.
                    body = response.read(LIMIT + 1)
                    if len(body) > LIMIT:
                        raise ValueError("response too large")
                    status = response.status
                    content_type = response.getheader("Content-Type", "application/octet-stream")
            except Exception:
                status, body, content_type = 502, b"upstream unavailable\n", "text/plain"
            finally:
                if connection:
                    connection.close()
            self.send_response_only(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            print(self.command, json.dumps(urlsplit(self.path).path), status, file=sys.stderr, flush=True)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = request

    class Server(HTTPServer):
        def handle_error(self, request, client_address):
            pass  # No exception tracebacks containing request/credential material.

        def get_request(self):
            client, address = super().get_request()
            client.settimeout(30)
            return client, address

    with Server(("127.0.0.1", 0), Handler) as server:
        expected_host = f"127.0.0.1:{server.server_port}"
        print("http://" + expected_host, flush=True)
        server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("disk", "card"), default="disk",
                        help="disk (default): PRF-wrapped vault file; card: vault applet " + VAULT_AID)
    parser.add_argument("--vault", type=Path, default=Path.home() / ".nuri-card/vault.json")
    parser.add_argument("--profile-path", type=Path, default=Path.home() / ".nuri-card-prf/nuri-offline-backup.json")
    parser.add_argument("--transport", choices=("pcsc", "hid"), default="pcsc")
    parser.add_argument("--device-index", type=int)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    sub.add_parser("init", help="card backend only: owner sets the first vault PIN")
    for command in ("put", "rm", "run", "proxy", "hmac"):
        item = sub.add_parser(command)
        item.add_argument("name", type=lambda s: s if re.fullmatch(NAME_RE, s) else parser.error("NAME must be an environment-safe identifier"))
        if command == "put":
            item.add_argument("--tag", action="append", default=[])
            item.add_argument("--kind", choices=tuple(KINDS), default=None,
                              help="card backend: bearer (default, readable by run/proxy) or hmac (never leaves the card)")
        if command == "run":
            item.add_argument("cmd", nargs=argparse.REMAINDER)
        if command == "proxy":
            item.add_argument("--upstream", required=True)
            item.add_argument("--header", choices=("Authorization", "X-API-Key"), default="Authorization")
        if command == "hmac":
            item.add_argument("--data-file", required=True, type=Path,
                              help="raw message bytes (no prehash); card backend only")
    args = parser.parse_args()
    if args.backend == "card":
        return main_card(args)
    if args.command in ("init", "hmac") or (args.command == "put" and args.kind == "hmac"):
        parser.error(f"{args.command if args.command != 'put' else 'put --kind hmac'} requires --backend card")
    try:
        with locked_vault(args.vault) as vault:
            if args.command == "list":
                print(json.dumps([metadata(vault["secrets"][k]) for k in sorted(vault["secrets"])]))
                return 0
            if args.command == "put":
                if sys.stdin.isatty():
                    raise ValueError("put requires piped stdin")
                if args.name in vault["secrets"]:
                    raise ValueError("name already exists; remove it explicitly first")
                value = sys.stdin.buffer.read(LIMIT + 1)
                if len(value) > LIMIT:
                    raise ValueError("secret too large")
                entry = {"name": args.name, "created": datetime.now(timezone.utc).isoformat(), "tags": args.tag}
                key = os.urandom(32)
                entry["wrapped_key"] = seal(kek(args, vault), key, aad(entry) + b"/key")
                entry["data"] = seal(key, value, aad(entry) + b"/data")
                vault["secrets"][args.name] = entry
                save(args.vault, vault)
                return 0
            if args.command == "rm":
                del vault["secrets"][args.name]
                save(args.vault, vault)
                return 0
            secret = unwrap(args, vault)
        if args.command == "proxy":
            proxy(args, secret)
            return 0
        cmd = run_cmd(args)
        if not cmd:
            raise ValueError("run requires a child command")
        env = child_env(args.name, secret, scrub_pins=False)  # disk env scrubbing unchanged
        code = subprocess.run(cmd, env=env, shell=False).returncode
        return code if code >= 0 else 128 - code
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("card-secrets: operation failed (check name, card/profile, vault permissions and input)", file=sys.stderr)
        return 1


def main_card(args):
    """--backend card: no vault file is opened or created; secrets live in the applet."""
    try:
        secret = card_command(args)
        if args.command == "proxy":
            proxy(args, secret)
            return 0
        if args.command != "run":
            return 0
        env = child_env(args.name, secret, scrub_pins=True)
        code = subprocess.run(run_cmd(args), env=env, shell=False).returncode
        return code if code >= 0 else 128 - code
    except KeyboardInterrupt:
        return 130
    except CardVaultError as error:
        print(f"card-secrets: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("card-secrets: operation failed (check name, card, PIN and input)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
