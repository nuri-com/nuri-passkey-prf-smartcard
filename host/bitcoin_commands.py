"""Bitcoin (Arkade + Lightning) commands for the Chrome native host.

The card's Bitcoin key lives in the NuriMuSig2 applet; the Arkade SDK is Node-only,
so the host spawns scripts/ext-card-wallet.mjs and keeps only the child handle.

Safety rules, same family as the ETH2 path:
  * a successful `info` in this process must precede any Bitcoin command
    (INFO_REQUIRED), so a fresh host can never sign unseen;
  * a `send` is two-phase: `bitcoin_preview` builds the PSBT and its sighashes
    WITHOUT touching the card, `bitcoin_sign_partial` releases the card after the
    human approved the same digest. The child re-checks the digest;
  * the PIN goes popup -> host -> child stdin -> child env (never argv, never
    cached, never logged, never echoed back);
  * cancelling, closing the popup, a digest mismatch or a timeout kills the child;
    nothing was signed before the approval, and a late result cannot revive it;
  * responses carry typed fields only; APDU/exception text is collapsed.
"""

from __future__ import annotations

import json
import os
import re
import select
import subprocess
import time
import uuid
from typing import Any

PREVIEW_TIMEOUT = 120.0   # bridge start, /arkade/info, swap creation, PSBT build
SIGN_TIMEOUT = 240.0      # card nonce + server cosign per input
JOB_TTL = 180.0           # a preview nobody decides on is reaped

_JOBS: dict[str, dict[str, Any]] = {}


def bridge_path() -> str:
    """Env override first (read per call, so a test can swap the bridge), else the repo script."""
    import nuri_card_host as host  # same module instance in tests and in serve()

    return os.environ.get("NURI_BITCOIN_BRIDGE") or os.path.join(host.SCRIPTS_DIR, "ext-card-wallet.mjs")


def node_bin() -> str:
    return os.environ.get("NURI_NODE") or "node"


def _spawn(cfg: dict[str, Any]) -> subprocess.Popen:
    path = bridge_path()
    if not os.path.isfile(path):
        import nuri_card_host as host

        raise host.HostError("BITCOIN_UNAVAILABLE", "Bitcoin bridge script is missing from this install")
    try:
        return subprocess.Popen(
            [node_bin(), path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(os.environ),
        )
    except OSError as exc:
        import nuri_card_host as host

        raise host.HostError("BITCOIN_UNAVAILABLE", f"cannot start {node_bin()} ({type(exc).__name__})")


def _read_line(proc: subprocess.Popen, timeout: float) -> dict[str, Any]:
    """Read one JSON line from the child. Framing errors and exits are typed."""
    import nuri_card_host as host

    deadline = time.monotonic() + timeout
    buf = bytearray()
    fd = proc.stdout.fileno()
    while b"\n" not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill(proc)
            raise host.HostError("BITCOIN_TIMEOUT", "Bitcoin operation timed out")
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        buf += chunk
    line = bytes(buf).split(b"\n", 1)[0].strip()
    if not line:
        code = proc.poll()
        detail = ""
        try:
            detail = (proc.stderr.read(4096) or b"").decode("utf-8", "replace").strip()
        except Exception:
            pass
        _kill(proc)
        raise host.HostError("BITCOIN_UNAVAILABLE", f"Bitcoin bridge produced no answer (exit {code}) {detail[:300]}".strip())
    try:
        return json.loads(line)
    except ValueError:
        _kill(proc)
        raise host.HostError("BITCOIN_UNAVAILABLE", "Bitcoin bridge returned invalid JSON")


def _kill(proc: subprocess.Popen) -> None:
    try:
        if proc.poll() is None:
            proc.kill()
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass


def _run(cfg: dict[str, Any], timeout: float) -> dict[str, Any]:
    """One-shot bridge call: config on stdin, one JSON answer on stdout."""
    import nuri_card_host as host

    proc = _spawn(cfg)
    try:
        proc.stdin.write((json.dumps(cfg) + "\n").encode("utf-8"))
        proc.stdin.flush()
        first = _read_line(proc, timeout)
        if first.get("phase") == "error":
            raise host.HostError("BITCOIN_ERROR", str(first.get("error") or "Bitcoin operation failed")[:300])
        return first
    finally:
        _kill(proc)


def _require_card_seen() -> None:
    """Bitcoin needs the same `info`-first discipline as the ETH path."""
    import nuri_card_host as host

    if host._INFO is None:
        raise host.HostError("INFO_REQUIRED", "call info on this connection before using the Bitcoin wallet")
    if host.resolve_mode() != "card":
        raise host.HostError("BITCOIN_UNAVAILABLE", "the Bitcoin wallet needs the card, not the simulator")


def _config(mode: str, **extra: Any) -> dict[str, Any]:
    cfg = {"mode": mode, "network": os.environ.get("NURI_BITCOIN_NETWORK") or "mainnet"}
    cfg.update(extra)
    return cfg


def _reap() -> None:
    now = time.monotonic()
    for job_id, job in list(_JOBS.items()):
        if job["busy"] or now - job["created"] < JOB_TTL:
            continue
        _JOBS.pop(job_id, None)
        _kill(job["proc"])


def handle_info(params: Any) -> dict[str, Any]:
    _require_card_seen()
    return _run(_config("info"), PREVIEW_TIMEOUT)


def handle_balance(params: Any) -> dict[str, Any]:
    _require_card_seen()
    return _run(_config("balance"), PREVIEW_TIMEOUT)


def handle_invoice(params: Any) -> dict[str, Any]:
    import nuri_card_host as host

    _require_card_seen()
    params = params or {}
    amount = params.get("amount_sats")
    if not isinstance(amount, int) or isinstance(amount, bool) or not 1 <= amount <= 100_000_000:
        raise host.HostError("BAD_REQUEST", "params.amount_sats must be an integer between 1 and 100000000")
    memo = params.get("memo")
    if not isinstance(memo, str) or not 1 <= len(memo) <= 200:
        raise host.HostError("BAD_REQUEST", "params.memo must be 1..200 characters")
    return _run(_config("invoice", amount_sats=amount, memo=memo), PREVIEW_TIMEOUT)


def handle_preview(params: Any) -> dict[str, Any]:
    import nuri_card_host as host

    _require_card_seen()
    _reap()
    params = params or {}
    kind = params.get("kind")
    if kind not in ("lightning", "ark"):
        raise host.HostError("BAD_REQUEST", "params.kind must be lightning or ark")
    target = params.get("target")
    if not isinstance(target, str) or not 1 <= len(target) <= 1200:
        raise host.HostError("BAD_REQUEST", "params.target must be the invoice or address")
    if kind == "ark" and not target.lower().startswith("ark1"):
        raise host.HostError("BAD_REQUEST", "an Arkade address starts with ark1")
    if kind == "lightning" and not target.lower().startswith("lnbc"):
        raise host.HostError("BAD_REQUEST", "a mainnet BOLT11 invoice starts with lnbc")
    extra: dict[str, Any] = {"kind": kind, "target": target}
    if kind == "ark":
        amount = params.get("amount_sats")
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise host.HostError("BAD_REQUEST", "params.amount_sats must be a positive integer")
        extra["amount_sats"] = amount
    for key in ("aggregate_pubkey33", "server_pubkey33"):
        value = params.get(key)
        if value is not None:
            if not isinstance(value, str) or not re.fullmatch(r"0[23][0-9a-fA-F]{64}", value):
                raise host.HostError("BAD_REQUEST", f"params.{key} must be a compressed public key")
            extra[key] = value.lower()

    job_id = uuid.uuid4().hex
    cfg = _config("send", **extra)
    proc = _spawn(cfg)
    try:
        proc.stdin.write((json.dumps(cfg) + "\n").encode("utf-8"))
        proc.stdin.flush()
        preview = _read_line(proc, PREVIEW_TIMEOUT)
    except Exception:
        _kill(proc)
        raise
    if preview.get("phase") == "error":
        _kill(proc)
        raise host.HostError("BITCOIN_ERROR", str(preview.get("error") or "could not build the transaction")[:300])
    if preview.get("phase") != "preview" or not preview.get("digest"):
        _kill(proc)
        raise host.HostError("BITCOIN_ERROR", "Bitcoin bridge returned no preview")
    _JOBS[job_id] = {"proc": proc, "digest": preview["digest"], "busy": False, "created": time.monotonic()}
    return {"job_id": job_id, "digest": preview["digest"], "summary": preview.get("summary") or {}}


def handle_sign_partial(params: Any, pin: Any) -> dict[str, Any]:
    import nuri_card_host as host

    _require_card_seen()
    params = params or {}
    job_id = params.get("job_id")
    job = _JOBS.get(job_id) if isinstance(job_id, str) else None
    if job is None:
        raise host.HostError("UNKNOWN_JOB", "preview expired or unknown; build the transaction again")
    if job["busy"]:
        raise host.HostError("BUSY", "this preview is already signing")
    digest = params.get("digest")
    if not isinstance(digest, str) or digest != job["digest"]:
        raise host.HostError("DIGEST_MISMATCH", "approval digest differs from the previewed transaction")
    decision: dict[str, Any] = {"approved": True, "digest": digest}
    if pin is not None:
        # The caller's buffer is zeroed after the call; the child needs a plain string.
        decision["pin"] = bytes(pin).decode("utf-8", "replace")
    job["busy"] = True
    proc = job["proc"]
    try:
        proc.stdin.write((json.dumps(decision) + "\n").encode("utf-8"))
        proc.stdin.flush()
    except OSError:
        _kill(proc)
        raise host.HostError("BITCOIN_UNAVAILABLE", "Bitcoin bridge went away before signing")
    try:
        result = _read_line(proc, SIGN_TIMEOUT)
    except host.HostError:
        _JOBS.pop(job_id, None)
        raise
    finally:
        job["busy"] = False
    _JOBS.pop(job_id, None)
    _kill(proc)
    if result.get("phase") == "error":
        raise host.HostError("BITCOIN_ERROR", str(result.get("error") or "Bitcoin spend failed")[:300])
    if result.get("phase") != "result":
        raise host.HostError("BITCOIN_ERROR", "Bitcoin bridge returned no result")
    result.pop("phase", None)
    return result


def handle_cancel(params: Any) -> dict[str, Any]:
    params = params or {}
    job_id = params.get("job_id")
    job = _JOBS.pop(job_id, None) if isinstance(job_id, str) else None
    if job is not None:
        _kill(job["proc"])
    return {"cancelled": job is not None}
