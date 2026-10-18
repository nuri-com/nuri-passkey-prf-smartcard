# Helper servers: access control

Three small HTTP servers wrap the physical card on the developer machine. Each
one can make the card **sign** (and the dashboard could make it **generate a
new key**, destroying the old one). Before this change none of them had any
access control: any web page open in the same browser, any process on the
LAN (if bound to `0.0.0.0`), or anyone with an ngrok URL could call them.
Audit items A2, A3, A7 in `_launch/out/W5-audit-and-eth-v2-design.md`.

| Server | Port | Serves | Card operations |
|---|---|---|---|
| `scripts/local-card-cosign-server.mjs` | 8787 | `web/cosign-demo.html`, terminal, profile, checkout pages + `/api/cosign/*`, `/api/wallet/*` | MuSig2 cosign, wallet spend |
| `scripts/card-dashboard-server.py` | 8788 | `web/dashboard.html` + `/api/eth/*`, `/api/btc/*`, … | ETH/BTC sign, (keygen) |
| `scripts/card-mcp-server.mjs` | 8799 | `/mcp` (JSON-RPC), `/healthz` | cosign, wallet spend/broadcast |

Shared guard: `scripts/helper-auth.mjs` (Node) and `scripts/nuri_helper_auth.py`
(Python twin, same rules, same env vars, same token file).

## Threats and the rule that stops each one

```mermaid
flowchart LR
    subgraph attackers
        A1[other web page<br/>in your browser]
        A2[DNS rebinding<br/>evil.example -> 127.0.0.1]
        A3[LAN / tunnel<br/>ngrok, --host=0.0.0.0]
        A4[any local process<br/>curl localhost]
    end
    subgraph guard[helper-auth guard, every request]
        R1[bind 127.0.0.1 only]
        R2[Host must be<br/>127.0.0.1 / localhost / ::1 :port]
        R3[Origin, if present,<br/>must be one of those]
        R4[POST needs<br/>Content-Type: application/json]
        R5[/api/* and /mcp need<br/>Authorization: Bearer token]
        R6[no CORS headers,<br/>OPTIONS -> 403]
    end
    CARD[(card)]
    A3 --> R1
    A2 --> R2
    A1 --> R3
    A1 --> R4
    A1 --> R6
    A4 --> R5
    R1 --> R2 --> R3 --> R4 --> R5 --> R6 --> CARD
```

- **Cross-site browser call** (A1). A page on `evil.example` runs
  `fetch('http://127.0.0.1:8788/api/eth/sign', …)`. Without CORS headers the
  page cannot read the answer, but a "simple request" (`text/plain`,
  no custom headers) is still *sent* — and the card still signs. Three
  independent stops: the `Origin` header the browser attaches is not loopback
  (403); the body is not `application/json` (415); there is no bearer token
  (401). Setting the token header makes it a preflighted request, and the
  preflight is answered 403.
- **DNS rebinding** (A2). `evil.example` resolves to `127.0.0.1` after the
  page loaded, so the browser sends a same-origin request to our port. The
  `Host` header is then `evil.example:8788`, not in the allow-list → 403.
- **Remote / tunnelled access** (A3). Servers refuse to bind anything but
  loopback unless `NURI_ALLOW_REMOTE=1` **and** `NURI_CARD_TOKEN` is set in the
  environment (an auto-generated token file is not accepted for remote mode).
  The ngrok banner and `npm run card:mcp:tunnel` are gone. A tunnel in front
  of a loopback bind still works technically — then only the token stands
  between the internet and the card. Don't.
- **Any other local process** (A4). Needs the token. It lives in
  `~/.nuri-card/token` (chmod 600) or in `NURI_CARD_TOKEN`; a process running
  as you can read it — that is the same trust boundary as the PC/SC reader
  itself.

## Token

```mermaid
sequenceDiagram
    participant S as helper server
    participant F as ~/.nuri-card/token
    participant B as browser page (served by S)
    participant C as MCP / curl client
    S->>S: NURI_CARD_TOKEN set? use it (source=env)
    S->>F: else read; if missing: random 32 bytes, write 0600, print once
    B->>S: GET /  (no token needed for pages)
    S-->>B: HTML with injected shim: window.fetch adds Authorization for /api, /mcp
    B->>S: POST /api/..  Authorization: Bearer t, Content-Type: application/json
    C->>S: POST /mcp  Authorization: Bearer <from env or file>
    S-->>C: 401 if missing/wrong (timing-safe compare)
```

- Minimum length 16; comparison is constant-time.
- The pages the helper serves itself get a tiny `<script>` injected after
  `<head>` that adds the header to same-origin `/api` and `/mcp` fetches, so
  the demo pages keep working unchanged. Any page served from somewhere else
  (file://, another port) does not get the token.
- `NURI_CARD_TOKEN_FILE` overrides the path (tests use a temp dir).

## Env vars

| Var | Default | Effect |
|---|---|---|
| `NURI_CARD_TOKEN` | unset → file | Bearer token. Required for remote mode. |
| `NURI_CARD_TOKEN_FILE` | `~/.nuri-card/token` | Where the generated token is kept. |
| `NURI_ALLOW_REMOTE=1` | off | Allow a non-loopback bind (`HOST`, `--host`, `NURI_CARD_HOST`). Still needs `NURI_CARD_TOKEN`. |
| `NURI_ALLOWED_HOSTS` | — | Extra `host:port` values accepted in `Host`/`Origin` in remote mode. |
| `NURI_ALLOW_MAINNET=1` | off | MCP `nuri_card_wallet_spend` may broadcast on mainnet. Dry-run always works. |
| `NURI_ALLOW_KEYGEN=1` | off | Dashboard `POST /api/eth/keygen` allowed — **and** only on ETH applet >= 1.4. |
| `PORT` / `HOST` | 8799 / 127.0.0.1 | MCP server bind. |
| `NURI_CARD_PORT` / `NURI_CARD_HOST` | 8788 / 127.0.0.1 | Dashboard bind. |

## Keygen

`INS 0x03` on the ETH applet < 1.4 generates a new key **in place of** the old
one with no confirmation; a real card key was rotated that way on 2026-10-18
(see `_launch/BRIEF-COMMON.md`). The dashboard route now refuses unless both
`NURI_ALLOW_KEYGEN=1` is set and the applet reports version >= 1.4; the card is
not touched at all when the env gate is closed. The dashboard button is still
there (labelled "gated") and shows the server's refusal.

## MCP server specifics

- `nuri_card_cosign_tweaked` no longer accepts `client_secret_hex`. A client
  secret must never cross the MCP boundary; the tool uses a random demo client
  key. The stable wallet key path is `nuri_card_wallet_*`.
- `nuri_card_wallet_spend` with `broadcast:true` on `mainnet` is refused with
  an `isError` result unless the server was started with `NURI_ALLOW_MAINNET=1`.
- Request bodies are capped at 1 MiB.

## Tests (no reader, no card)

```bash
npm run test:helper-auth
# = node --test test/helper-auth.test.js
#   starts card-mcp-server.mjs and local-card-cosign-server.mjs --backend=simulated
#   on random ports with a temp token file; asserts 401 / 403 (Host, Origin,
#   OPTIONS) / 415 / 200, token file 0600, 0.0.0.0 refused, mainnet refused,
#   no "ngrok" in the banner
# + python3 -m unittest discover -s test -p test_helper_auth.py
#   same matrix against card-dashboard-server.py with nuri_pcsc.open_applet
#   replaced by a fake applet that raises on any sign/keygen INS
```

## Running the demos after this change

Nothing changes for the normal flow: start the server, open the printed URL,
the page carries the token. For `curl` / MCP clients:

```bash
TOKEN=$(cat ~/.nuri-card/token)
curl -s http://127.0.0.1:8799/mcp \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

An MCP client config needs the same header; there is no query-string or cookie
fallback on purpose.
