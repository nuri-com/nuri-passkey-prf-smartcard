"""Request guard, service token and browser pairing for the Python card helper
(scripts/card-dashboard-server.py). No third-party imports.

Rules (W13 review R1/R10/R11, docs/helper-servers-security.md):
  1. Bind loopback only. There is no remote override.
  2. Host header must be 127.0.0.1/localhost/[::1]:<port>        (DNS rebinding)
  3. Origin, if supplied, must be exactly http://<the Host header> (cross-site, cross-port, cross-host)
  4. POST to /api/* or /pair must carry Content-Type: application/json (no CORS "simple request")
  5. /api/* needs either
       - Authorization: Bearer <dashboard service token>   (CLI / non-browser clients), or
       - the nuri_dashboard_session cookie from POST /pair  (browser). Cookie requests must also
         prove exact same origin: a matching Origin, or Sec-Fetch-Site: same-origin.
     Sec-Fetch-Site, when sent, must be same-origin on /api/* and /pair.
  6. No CORS headers at all, OPTIONS -> 403. Error texts never echo request values.

Browser pairing: the server prints a one-time pairing code in its terminal. The page
(web/helper-pair.js) POSTs {"code": "..."} to /pair and receives a random session cookie
(HttpOnly, SameSite=Strict, Path=/api/, absolute 12 h lifetime, memory only, not renewed).
The HTML never contains a credential. The code lives only in process memory and the terminal;
it is burned on success and after PAIR_MAX_FAILURES wrong guesses.

Service token: NURI_DASHBOARD_TOKEN (exactly 64 lowercase hex, not repetitive), else the
token file NURI_DASHBOARD_TOKEN_FILE, else <NURI_CARD_TOKEN_FILE>.dashboard, else
~/.nuri-card/dashboard.token. The shared NURI_CARD_TOKEN is refused for this service.
Token files must be regular, owned by the current uid and have no group/other bits, inside
a directory owned by the uid with mode 0700; symlinks are refused (O_NOFOLLOW). Creation is
atomic: exclusive 0600 temp file, fsync, then hard link -- the first link wins and every
starter reads the winner, so nobody sees a partial file. The value is never logged.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
MIN_DISTINCT_TOKEN_CHARS = 8  # 64 random hex chars essentially always have >= 14 distinct
_BEARER = re.compile(r"^Bearer\s+(\S+)\s*$", re.IGNORECASE)

SESSION_COOKIE = "nuri_dashboard_session"
SESSION_TTL_S = 12 * 60 * 60
PAIR_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I/L
PAIR_CODE_LEN = 8                                       # 31^8 ~ 2^39.6
PAIR_CODE_TTL_S = 5 * 60
PAIR_MAX_FAILURES = 10
MAX_SESSIONS = 32
MAX_CODE_INPUT = 64

# 'unsafe-inline' only because web/dashboard.html uses an inline <script> and onclick= handlers.
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'")
SECURITY_HEADERS = (
    ("Content-Security-Policy", CSP),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
)
PAIR_SCRIPT_TAG = '<script src="/helper-pair.js"></script>'


class TokenError(ValueError):
    pass


def _stderr(m: str) -> None:
    print(m, file=sys.stderr)


def is_loopback_host(host: str) -> bool:
    return str(host or "").strip().lower() in LOOPBACK


# --- service token -------------------------------------------------------------

def _env_prefix(service: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9]{0,31}", service or ""):
        raise TokenError(f"invalid service name {service!r}")
    return f"NURI_{service.upper()}"


def token_path(service: str = "dashboard") -> Path:
    prefix = _env_prefix(service)
    explicit = os.environ.get(f"{prefix}_TOKEN_FILE")
    if explicit:
        return Path(explicit)
    legacy = os.environ.get("NURI_CARD_TOKEN_FILE")
    if legacy:
        return Path(legacy + f".{service}")
    return Path.home() / ".nuri-card" / f"{service}.token"


def validate_token(token, what: str = "token") -> str:
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise TokenError(f"{what} must be exactly 64 lowercase hex characters (`openssl rand -hex 32`)")
    if len(set(token)) < MIN_DISTINCT_TOKEN_CHARS:
        raise TokenError(f"{what} is too repetitive to be random; generate one with `openssl rand -hex 32`")
    return token


def _new_token() -> str:
    while True:
        t = secrets.token_hex(32)
        if len(set(t)) >= MIN_DISTINCT_TOKEN_CHARS:
            return t


def _check_private(st: os.stat_result, kind: str, shown: str) -> None:
    if kind == "dir" and not stat.S_ISDIR(st.st_mode):
        raise TokenError(f"{shown} is not a directory")
    if kind == "file" and not stat.S_ISREG(st.st_mode):
        raise TokenError(f"{shown} is not a regular file")
    uid = os.getuid()
    if st.st_uid != uid:
        raise TokenError(f"{shown} is owned by uid {st.st_uid}, not by the current user (uid {uid})")
    mode = stat.S_IMODE(st.st_mode)
    want = 0o700 if kind == "dir" else 0o600
    if mode != want:
        raise TokenError(f"{shown} has mode {mode:04o}; it must be private: chmod {want:o} '{shown}'")


def _open_private_dir(d: Path) -> int:
    """Open the token directory (create it 0700 if missing) without following a final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    try:
        os.mkdir(d, 0o700)  # parent must already exist; umask can only clear bits
    except FileExistsError:
        pass                # existing (or created by a concurrent starter): validated below
    except OSError as e:
        raise TokenError(f"cannot create token directory {d}: {e.strerror}") from e
    try:
        fd = os.open(d, flags)
    except OSError as e:
        if os.path.islink(d):
            raise TokenError(f"refusing token directory {d}: it is a symlink") from e
        raise TokenError(f"cannot open token directory {d}: {e.strerror}") from e
    try:
        _check_private(os.fstat(fd), "dir", str(d))
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_token_at(dfd: int, name: str, shown: str) -> str:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except FileNotFoundError:
        raise
    except OSError as e:
        try:
            if stat.S_ISLNK(os.lstat(name, dir_fd=dfd).st_mode):
                raise TokenError(f"refusing token file {shown}: it is a symlink") from e
        except FileNotFoundError:
            pass
        raise TokenError(f"cannot open token file {shown}: {e.strerror}") from e
    try:
        st = os.fstat(fd)
        _check_private(st, "file", shown)
        if st.st_size > 128:
            raise TokenError("malformed token file: too large")
        data = os.read(fd, 128)
    finally:
        os.close(fd)
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        text = ""
    return validate_token(text, f"token file {shown}")


def _create_token_at(dfd: int, name: str) -> None:
    tmp = f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (_new_token() + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        try:  # link(2) never replaces an existing name: exactly one concurrent creator wins
            os.link(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
        except FileExistsError:
            pass
    finally:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except FileNotFoundError:
            pass


def load_or_create_token(service: str = "dashboard", log: Callable[[str], None] = _stderr) -> tuple[str, str]:
    """Return (token, source); source is 'env' or the token file path. Never logs the value."""
    prefix = _env_prefix(service)
    from_env = os.environ.get(f"{prefix}_TOKEN", "").strip()
    if from_env:
        return validate_token(from_env, f"{prefix}_TOKEN"), "env"
    if os.environ.get("NURI_CARD_TOKEN", "").strip():
        raise TokenError(
            f"NURI_CARD_TOKEN is no longer accepted by the {service} helper: one shared token let every "
            f"helper leak every other helper's credential. Migrate: set {prefix}_TOKEN to its own "
            f"`openssl rand -hex 32`, or unset NURI_CARD_TOKEN to use {token_path(service)}.")
    path = token_path(service)
    dfd = _open_private_dir(path.parent)
    try:
        try:
            token = _read_token_at(dfd, path.name, str(path))
            log(f"{service} API token: {path} (CLI clients send \"Authorization: Bearer $(cat '{path}')\")")
            return token, str(path)
        except FileNotFoundError:
            pass
        _create_token_at(dfd, path.name)
        token = _read_token_at(dfd, path.name, str(path))
        log(f"{service} API token created in {path} (mode 0600, value not printed; "
            f"CLI clients send \"Authorization: Bearer $(cat '{path}')\")")
        return token, str(path)
    finally:
        os.close(dfd)


def check_bind(host: str, token_source: str = "") -> None:
    if not is_loopback_host(host):
        raise RuntimeError(
            f"refusing to bind {host}: the card dashboard is loopback-only and has no remote mode "
            "(W13 R1). Use an SSH tunnel to 127.0.0.1 instead.")


def allowed_hosts(port: int) -> set[str]:
    return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}


# --- pairing and sessions ------------------------------------------------------

def _sid_hash(session: str) -> str:
    return hashlib.sha256(session.encode()).hexdigest()


def session_cookie_values(cookie_header) -> list[str]:
    out = []
    for part in str(cookie_header or "").split(";")[:64]:
        name, sep, value = part.strip().partition("=")
        value = value.strip()
        if sep and name.strip() == SESSION_COOKIE and 0 < len(value) <= 128:
            out.append(value)
    return out[:8]


class Pairing:
    """One-time terminal pairing code -> memory-only browser sessions with absolute expiry."""

    def __init__(self, log: Callable[[str], None] = _stderr, ttl: float = SESSION_TTL_S,
                 clock: Callable[[], float] = time.monotonic):
        self._log = log
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions: dict[str, float] = {}  # sha256(session id) -> absolute expiry (never extended)
        self._code = ""
        self._failures = 0
        self._rotate("pairing code")

    def _rotate(self, label: str) -> None:
        self._code = "".join(secrets.choice(PAIR_CODE_ALPHABET) for _ in range(PAIR_CODE_LEN))
        self._failures = 0
        self._code_expires = self._clock() + PAIR_CODE_TTL_S
        self._log(f"{label}: {self._code[:4]}-{self._code[4:]}  (single use, expires in 5 minutes; type it into the dashboard page)")

    def _prune(self, now: float) -> None:
        for k in [k for k, exp in self._sessions.items() if exp <= now]:
            del self._sessions[k]

    def pair(self, code) -> Optional[str]:
        """Exchange the current code for a new session id (code burned), else None."""
        if not isinstance(code, str) or len(code) > MAX_CODE_INPUT:
            code = ""
        given = re.sub(r"[\s-]", "", code).upper().encode()
        with self._lock:
            if self._clock() >= self._code_expires:
                self._rotate("pairing code expired; new pairing code")
                return None
            if not (given and hmac.compare_digest(given, self._code.encode())):
                self._failures += 1
                if self._failures >= PAIR_MAX_FAILURES:
                    self._rotate(f"{PAIR_MAX_FAILURES} wrong pairing attempts, old code burned; new pairing code")
                return None
            session = secrets.token_urlsafe(32)
            now = self._clock()
            self._prune(now)
            while len(self._sessions) >= MAX_SESSIONS:
                self._sessions.pop(min(self._sessions, key=lambda k: self._sessions[k]))
            self._sessions[_sid_hash(session)] = now + self._ttl
            self._rotate("browser paired; next pairing code")
            return session

    def remaining(self, cookie_header) -> int:
        """Seconds left on the best valid session in the Cookie header, 0 if none."""
        values = session_cookie_values(cookie_header)
        if not values:
            return 0
        with self._lock:
            now = self._clock()
            self._prune(now)
            exps = [self._sessions[h] for h in map(_sid_hash, values) if h in self._sessions]
            return max(1, int(max(exps) - now)) if exps else 0

    def valid(self, cookie_header) -> bool:
        return self.remaining(cookie_header) > 0

    def set_cookie(self, session: str) -> str:
        return (f"{SESSION_COOKIE}={session}; Path=/api/; Max-Age={int(self._ttl)}; "
                "HttpOnly; SameSite=Strict")


# --- request guard ---------------------------------------------------------------

def _token_matches(header: Optional[str], token: str) -> bool:
    m = _BEARER.match(header or "")
    if not m or not token:
        return False
    return hmac.compare_digest(m.group(1).encode(), token.encode())


def default_protected(path: str) -> bool:
    return path.startswith("/api/")


def guard_request(method: str, path: str, headers, *, port: int, token: str,
                  pairing: Optional[Pairing] = None,
                  is_protected: Callable[[str], bool] = default_protected) -> Optional[tuple[int, str]]:
    """Return None if the request may proceed, else (status, error). `headers` is any .get()-able mapping."""
    method = (method or "GET").upper()
    if method == "OPTIONS":
        return 403, "CORS preflight refused: this helper is same-origin only"
    host = str(headers.get("host") or "").strip().lower()
    if host not in allowed_hosts(port):
        return 403, f"Host header not allowed; expected 127.0.0.1:{port} or localhost:{port}"
    origin = headers.get("origin")
    if origin is not None:
        try:
            u = urlsplit(str(origin).strip().lower())
            ok = u.scheme == "http" and u.netloc == host and u.path in ("", "/") and not u.query and not u.fragment
        except ValueError:
            ok = False
        if not ok:
            return 403, "Origin not allowed: it must be exactly this helper's own origin"
    bare = path.split("?", 1)[0]
    is_pair = bare == "/pair"
    if not (is_pair or is_protected(bare)):
        return None
    sfs = headers.get("sec-fetch-site")
    if sfs is not None and str(sfs).strip().lower() != "same-origin":
        return 403, "cross-site request refused (Sec-Fetch-Site)"
    if is_pair and method != "POST":
        return 405, 'use POST /pair with {"code": "..."}'
    if method == "POST":
        ct = str(headers.get("content-type") or "").split(";")[0].strip().lower()
        if ct != "application/json":
            return 415, "Content-Type must be application/json"
    if is_pair:
        return None  # the handler checks the one-time code
    if _token_matches(headers.get("authorization"), token):
        return None
    if pairing is not None and pairing.valid(headers.get("cookie")):
        if origin is None and str(sfs or "").strip().lower() != "same-origin":
            return 403, "browser session needs a same-origin request (Origin or Sec-Fetch-Site)"
        return None
    return 401, "not paired: enter the pairing code shown in the dashboard terminal"


def check_framing(headers, max_body: int) -> tuple[Optional[tuple[int, str]], int]:
    """Validate request framing before auth. Returns (error or None, content_length)."""
    if headers.get("transfer-encoding") is not None:
        return (501, "Transfer-Encoding is not supported; send Content-Length"), 0
    if hasattr(headers, "get_all"):
        values = headers.get_all("content-length") or []
    else:
        v = headers.get("content-length")
        values = [] if v is None else [v]
    if not values:
        return None, 0
    if len(values) != 1 or not re.fullmatch(r"[0-9]{1,10}", str(values[0]).strip()):
        return (400, "invalid Content-Length"), 0
    n = int(str(values[0]).strip())
    if n > max_body:
        return (413, f"body too large (max {max_body} bytes)"), 0
    return None, n


def inject_pair_script(html: str) -> str:
    """Add the shared pairing overlay script to a helper page. It carries no credential."""
    if "/helper-pair.js" in html:
        return html
    m = re.search(r"<head[^>]*>", html, re.IGNORECASE)
    if not m:
        return PAIR_SCRIPT_TAG + html
    return html[: m.end()] + PAIR_SCRIPT_TAG + html[m.end():]
