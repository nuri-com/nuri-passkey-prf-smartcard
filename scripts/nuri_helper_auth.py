"""Request guard for the Python card helper (scripts/card-dashboard-server.py).

Twin of scripts/helper-auth.mjs — same rules, same env vars, same token file:
  1. bind loopback only (non-loopback needs NURI_ALLOW_REMOTE=1 + NURI_CARD_TOKEN in env)
  2. Host header must be 127.0.0.1/localhost/[::1]:<port>   (DNS rebinding)
  3. Origin, if present, must be one of those hosts            (cross-site browser calls)
  4. POST must carry Content-Type: application/json             (no CORS "simple request")
  5. /api/* needs Authorization: Bearer <token>                 (any other caller)
  6. no CORS headers at all, OPTIONS -> 403
Token: env NURI_CARD_TOKEN, else ~/.nuri-card/token (created 0600, printed once).
No third-party imports.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
MIN_TOKEN_LEN = 16
_BEARER = re.compile(r"^Bearer\s+(\S+)\s*$", re.IGNORECASE)


def is_loopback_host(host: str) -> bool:
    return str(host or "").strip().lower() in LOOPBACK


def token_path() -> Path:
    return Path(os.environ.get("NURI_CARD_TOKEN_FILE") or Path.home() / ".nuri-card" / "token")


def load_or_create_token(log: Callable[[str], None] = lambda m: print(m, file=sys.stderr)) -> tuple[str, str]:
    """Return (token, source) where source is 'env' or the token file path."""
    from_env = os.environ.get("NURI_CARD_TOKEN", "").strip()
    if from_env:
        if len(from_env) < MIN_TOKEN_LEN:
            raise ValueError(f"NURI_CARD_TOKEN must be at least {MIN_TOKEN_LEN} characters")
        return from_env, "env"
    path = token_path()
    if path.exists():
        token = path.read_text().strip()
        if len(token) >= MIN_TOKEN_LEN:
            log(f'helper token: {path} (send it as "Authorization: Bearer <token>")')
            return token, str(path)
    token = secrets.token_hex(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    os.chmod(path, 0o600)
    log(f"helper token generated (printed once): {token}")
    log(f'stored in {path} (chmod 600). Clients send "Authorization: Bearer <token>".')
    return token, str(path)


def check_bind(host: str, token_source: str) -> None:
    if is_loopback_host(host):
        return
    if os.environ.get("NURI_ALLOW_REMOTE") != "1":
        raise RuntimeError(
            f"refusing to bind {host}: helper servers are loopback-only. Set NURI_ALLOW_REMOTE=1 and "
            "NURI_CARD_TOKEN to override (anyone who reaches the port + token can make the card sign)."
        )
    if token_source != "env":
        raise RuntimeError(f"refusing to bind {host}: NURI_ALLOW_REMOTE=1 also needs NURI_CARD_TOKEN set in the environment.")


def allowed_hosts(port: int, remote: bool = False, bind_host: str = "") -> set[str]:
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    if remote:
        if bind_host and not is_loopback_host(bind_host) and bind_host not in ("0.0.0.0", "::"):
            hosts.add(f"{bind_host.lower()}:{port}")
        for h in os.environ.get("NURI_ALLOWED_HOSTS", "").split(","):
            v = h.strip().lower()
            if v:
                hosts.add(v)
    return hosts


def _token_matches(header: Optional[str], token: str) -> bool:
    m = _BEARER.match(header or "")
    if not m or not token:
        return False
    return hmac.compare_digest(m.group(1).encode(), token.encode())


def default_protected(path: str) -> bool:
    return path.startswith("/api/")


def guard_request(method: str, path: str, headers, *, port: int, token: str, remote: bool = False,
                  bind_host: str = "", is_protected: Callable[[str], bool] = default_protected) -> Optional[tuple[int, str]]:
    """Return None if the request may proceed, else (status, error). `headers` is any .get()-able mapping."""
    method = (method or "GET").upper()
    if method == "OPTIONS":
        return 403, "CORS preflight refused: this helper is same-origin / bearer-token only"
    hosts = allowed_hosts(port, remote, bind_host)
    host = str(headers.get("host") or "").strip().lower()
    if host not in hosts:
        return 403, f"Host header not allowed ({host or 'missing'}); expected 127.0.0.1:{port} or localhost:{port}"
    origin = headers.get("origin")
    if origin is not None:
        o = str(origin).strip().lower()
        try:
            u = urlsplit(o)
            ok = u.scheme in ("http", "https") and u.netloc in hosts
        except ValueError:
            ok = False
        if not ok:
            return 403, f"Origin not allowed ({o})"
    bare = path.split("?", 1)[0]
    if not is_protected(bare):
        return None
    if method == "POST":
        ct = str(headers.get("content-type") or "").split(";")[0].strip().lower()
        if ct != "application/json":
            return 415, "Content-Type must be application/json"
    if not _token_matches(headers.get("authorization"), token):
        return 401, "missing or wrong bearer token (Authorization: Bearer <NURI_CARD_TOKEN or ~/.nuri-card/token>)"
    return None


def token_script(token: str) -> str:
    """Inline <script> for the helper's own HTML: same-origin fetch() to /api gets the bearer header."""
    return (
        "<script>(function(){"
        f"var t={json.dumps(token)};window.NURI_CARD_TOKEN=t;"
        "var f=window.fetch.bind(window);"
        "window.fetch=function(input,init){"
        'var u=typeof input==="string"?input:((input&&input.url)||"");'
        r"if(/^\/(api|mcp)(\/|\?|$)/.test(u)){"
        "init=Object.assign({},init||{});"
        'var h=new Headers(init.headers||(typeof input!=="string"&&input.headers)||undefined);'
        'h.set("authorization","Bearer "+t);'
        'if(String(init.method||"GET").toUpperCase()==="POST"&&!h.has("content-type"))h.set("content-type","application/json");'
        "init.headers=h;}"
        "return f(input,init);};"
        "})();</script>"
    )


def inject_token(html: str, token: str) -> str:
    m = re.search(r"<head[^>]*>", html, re.IGNORECASE)
    if not m:
        return token_script(token) + html
    return html[: m.end()] + token_script(token) + html[m.end():]
