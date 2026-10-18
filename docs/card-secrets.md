# Card-backed credential vault

```mermaid
flowchart LR
  D[Encrypted vault on disk] --> B[Trusted local broker]
  C[Existing FIDO2 card credential] -->|PRF output in broker memory| K[HKDF key-encryption key]
  K -->|unwrap random AES data key| B
  A[Agent: names and commands only] --> B
  B -->|environment injection| T[Trusted child program]
  B -->|header injection| U[One fixed HTTPS upstream]
  A -->|HTTP without credential| P[127.0.0.1 ephemeral proxy]
  P --> B
```

## What is stored and where

`scripts/card-secrets.py` stores `~/.nuri-card/vault.json` as an owned regular
0600 file (new parent directory 0700). Every secret has a fresh random 32-byte
AES-256-GCM data key, a random 12-byte data nonce, and a separately random
12-byte wrapping nonce. The data key is wrapped with another AES-256-GCM key:
HKDF-SHA256 of the card's 32-byte PRF output, a random 32-byte vault salt,
and info `nuri-card-secrets-v1/kek`. The PRF input is the UTF-8 bytes
`nuri-card-secrets-v1`, separate from the backup utility's default input.

The JSON contains version, test/card mode, salt, and per-secret name, UTC
creation time, tags, ciphertexts and nonces. Names/times/tags are **public
metadata**, authenticated as GCM associated data when unwrapping. No PRF output,
wrapping key, data key, or plaintext secret is written to the vault. Writes use
an advisory lock and atomic replacement; transient output files are also 0600.
Implementation: `scripts/card-secrets.py:29` (PRF), `:57` (AES-GCM), `:67`
(HKDF), `:75` (authenticated unwrap), `:83` (permissions), `:109` (atomic save).
Deleting an entry is not secure erasure of filesystem snapshots or backups.

The broker calls the existing `card-prf-backup.py` `read_profile` / `derive_once`
functions **in-process**, with user verification required and PIN prompting
available. It does not invoke `derive --raw` or print PRF output. It reuses the
existing `.nuri-card-prf/nuri-offline-backup.json` credential; it never enrolls,
replaces, resets or creates credentials. Run from the repository root, or supply
`--profile-path /path/to/nuri-offline-backup.json` before the subcommand.
`--transport pcsc|hid` and `--device-index N` are optional global selectors.
Only put/run/proxy need the card; list/rm work without it. Missing or wrong
card/profile, modified metadata/ciphertexts and bad file permissions fail closed.
Keep the existing credential profile plus encrypted vault backed up. Losing the
card credential means losing access; neither the JSON nor the profile restores it.

## Commands

Use the existing Python dependency wrapper (cryptography is already pinned in
`requirements-card-v1.txt`; no new dependency):

```sh
# Owner-provisioned secret arrives through stdin, not argv. Newlines are preserved.
trusted-secret-source | scripts/run-card-python.sh scripts/card-secrets.py put API --tag service
scripts/run-card-python.sh scripts/card-secrets.py list

# Exact NAME is appended to NURI_SECRET_; no uppercase/normalization is applied.
scripts/run-card-python.sh scripts/card-secrets.py run API -- trusted-api-client

# First stdout line is the ephemeral local URL. Stop with Ctrl-C.
scripts/run-card-python.sh scripts/card-secrets.py proxy API --upstream https://api.example.com/v1
scripts/run-card-python.sh scripts/card-secrets.py proxy API --upstream https://api.example.com/v1 --header X-API-Key

scripts/run-card-python.sh scripts/card-secrets.py rm API
npm run card:secrets:selftest
```

Names must match `[A-Za-z_][A-Za-z0-9_]*`; duplicates are refused until explicitly
removed. `put` consumes at most 8 MiB, refuses terminal stdin, and never takes a
secret argument. Do not let an agent run a secret-revealing provisioning command.
`--vault PATH` (before the subcommand) selects an alternate vault.

`run` directly spawns the chosen child without a shell and supplies only that
secret as `NURI_SECRET_<NAME>`. Inherited `NURI_SECRET_*`, `FIDO2_*`, and the fake
PRF test override are removed from the child's environment. UTF-8, NUL-free
secrets are required for environment injection. The child exit code is propagated;
signals map to exit status `128 + signal`. Its normal stdout/stderr are not captured or redacted. The trusted child must
not print credentials or persist its environment. Never use `env`, `printenv`,
a shell snippet that echoes the variable, or untrusted agent-generated code.

The proxy listens only on `127.0.0.1:0`, never on a LAN interface. A client sends
requests to its announced local URL; `/models` becomes `/v1/models` for the
example upstream above. It sends `Authorization: Bearer <secret>` by default,
or the raw secret in `X-API-Key` with that header option. Header secrets must be
nonempty visible ASCII without whitespace or control characters. It forwards
GET/HEAD/POST/PUT/PATCH/DELETE, request bodies (8 MiB maximum), Content-Type and
Accept. Incoming authorization and other headers are not forwarded. Responses
forward status/body (8 MiB maximum) and Content-Type only; redirects are **not
followed**, and Location/Set-Cookie/other response headers are not forwarded.
Upstream network operations have a 30-second timeout. HTTPS uses the standard
verified TLS context. HTTP upstreams are allowed only for loopback fixtures.

Absolute-form URLs, alternate Host headers, browser Origin / Sec-Fetch-Site
headers and ambiguous/chunked request framing are rejected. The upstream
scheme/authority cannot be selected by a request. Logs contain only method,
JSON-escaped path (no query string), and status; no headers/bodies or exception
tracebacks. Do not put credentials in request paths. The proxy is single-process,
single-request-at-a-time and intended as a small local broker, not a general HTTP
proxy. Loopback callers are trusted: there is no per-agent authorization layer.

## Agent / MCP boundary and honest limits

An MCP tool should call `run NAME -- <allowlisted trusted client>` or start
`proxy NAME --upstream <allowlisted URL>` and return only its local endpoint to
the agent. The agent calls run/proxy, **never reads** the secret, PRF output,
child environment or card derivation CLI. Provisioning belongs to the owner.
No MCP server or sandbox is installed by this change.

Bearer credentials are kept out of the agent process's normal inputs/outputs by
this workflow, **not protected from root on the machine**. This is not hardware
non-exportability for bearer strings: the broker, trusted child, OS, and upstream
necessarily see plaintext. The PRF output and derived wrapping key also exist in
broker RAM. Same-user process inspection/debugging can expose them on some OSes;
Python cannot promise reliable memory zeroization. An unrestricted agent that
can choose arbitrary children, inspect processes or modify this script can
exfiltrate credentials. Enforce process isolation and tool/child/upstream
allowlists outside this CLI if the agent is adversarial. Upstreams must also be
trusted not to echo credentials in responses. Removing the card does not revoke
an already-running child or proxy; stop the broker/child to end that session.

The test-only `NURI_CARD_SECRETS_FAKE_PRF` accepts exactly 64 hex characters and
bypasses all card imports/access. It is not a recovery key or production feature.
Fake vaults are explicitly marked `mode: fake`; real and fake modes cannot
unwrap each other's vaults. Never set this override for real credentials.
The unittest suite uses only this override, synthetic secrets, temporary HOME,
and loopback HTTP servers. **Real-card behavior is UNVERIFIED by these tests.**

## Parent-only real-card acceptance (not run by builder)

With the existing profile and owner-authorized reader, from the repo root and
with `NURI_CARD_SECRETS_FAKE_PRF` unset, use a disposable vault and non-secret
sentinel. Do not enroll, reset, or force any credential:

```sh
printf %s card-secrets-smoke | scripts/run-card-python.sh scripts/card-secrets.py --vault "$HOME/.nuri-card/smoke-vault.json" put SMOKE
scripts/run-card-python.sh scripts/card-secrets.py --vault "$HOME/.nuri-card/smoke-vault.json" run SMOKE -- python3 -c 'import os; assert os.environ["NURI_SECRET_SMOKE"] == "card-secrets-smoke"; print("CARD_SECRETS_RUN_OK")'
scripts/run-card-python.sh scripts/card-secrets.py --vault "$HOME/.nuri-card/smoke-vault.json" list
# Remove card, repeat run: expect failure and no child execution. Reinsert, retry.
scripts/run-card-python.sh scripts/card-secrets.py --vault "$HOME/.nuri-card/smoke-vault.json" rm SMOKE
```
