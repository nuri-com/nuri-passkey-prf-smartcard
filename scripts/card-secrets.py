#!/usr/bin/env python3
"""Disk envelope vault; only the broker and trusted child receive plaintext."""
import argparse
import contextlib
import fcntl
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
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DOMAIN = b"nuri-card-secrets-v1"
LIMIT = 8 * 1024 * 1024


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
    upstream = urlsplit(args.upstream)
    if (upstream.scheme not in ("https", "http") or not upstream.hostname or upstream.username
            or upstream.password or upstream.query or upstream.fragment
            or (upstream.scheme == "http" and upstream.hostname not in ("127.0.0.1", "::1", "localhost"))):
        raise ValueError("upstream requires HTTPS (HTTP permitted only for loopback tests)")
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
    parser.add_argument("--vault", type=Path, default=Path.home() / ".nuri-card/vault.json")
    parser.add_argument("--profile-path", type=Path, default=Path.home() / ".nuri-card-prf/nuri-offline-backup.json")
    parser.add_argument("--transport", choices=("pcsc", "hid"), default="pcsc")
    parser.add_argument("--device-index", type=int)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    for command in ("put", "rm", "run", "proxy"):
        item = sub.add_parser(command)
        item.add_argument("name", type=lambda s: s if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s) else parser.error("NAME must be an environment-safe identifier"))
        if command == "put":
            item.add_argument("--tag", action="append", default=[])
        if command == "run":
            item.add_argument("cmd", nargs=argparse.REMAINDER)
        if command == "proxy":
            item.add_argument("--upstream", required=True)
            item.add_argument("--header", choices=("Authorization", "X-API-Key"), default="Authorization")
    args = parser.parse_args()
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
        cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
        if not cmd:
            raise ValueError("run requires a child command")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("NURI_SECRET_", "FIDO2_", "NURI_CARD_SECRETS_FAKE_PRF"))}
        env["NURI_SECRET_" + args.name] = secret.decode("utf-8")
        code = subprocess.run(cmd, env=env, shell=False).returncode
        return code if code >= 0 else 128 - code
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("card-secrets: operation failed (check name, card/profile, vault permissions and input)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
