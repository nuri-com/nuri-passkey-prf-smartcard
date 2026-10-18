// Shared request guard for the local card helper servers
// (card-mcp-server.mjs, local-card-cosign-server.mjs; Python twin: nuri_helper_auth.py).
//
// Threat: any web page open in a browser on this machine (or anyone who reaches
// the port) could POST to the helper and make the physical card sign. Defence:
//   1. bind loopback only (non-loopback needs NURI_ALLOW_REMOTE=1 + NURI_CARD_TOKEN in env)
//   2. Host header must be 127.0.0.1/localhost/[::1]:<port>   (DNS rebinding)
//   3. Origin, if present, must be one of those hosts            (cross-site browser calls)
//   4. POST must carry Content-Type: application/json             (no CORS "simple request")
//   5. /api/* and /mcp need Authorization: Bearer <token>          (any other caller)
//   6. no CORS headers at all, OPTIONS -> 403
// Token: env NURI_CARD_TOKEN, else ~/.nuri-card/token (created chmod 600, printed once).
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import process from 'node:process';

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
const MIN_TOKEN_LEN = 16;

export function isLoopbackHost(host) {
  return LOOPBACK.has(String(host || '').trim().toLowerCase());
}

export function tokenPath() {
  return process.env.NURI_CARD_TOKEN_FILE || join(homedir(), '.nuri-card', 'token');
}

/** Returns { token, source: 'env' | <path>, created: bool }. */
export function loadOrCreateToken({ log = (m) => console.error(m) } = {}) {
  const fromEnv = String(process.env.NURI_CARD_TOKEN || '').trim();
  if (fromEnv) {
    if (fromEnv.length < MIN_TOKEN_LEN) throw new Error(`NURI_CARD_TOKEN must be at least ${MIN_TOKEN_LEN} characters`);
    return { token: fromEnv, source: 'env', created: false };
  }
  const path = tokenPath();
  if (existsSync(path)) {
    const token = readFileSync(path, 'utf8').trim();
    if (token.length >= MIN_TOKEN_LEN) {
      log(`helper token: ${path} (send it as "Authorization: Bearer <token>")`);
      return { token, source: path, created: false };
    }
  }
  const token = randomBytes(32).toString('hex');
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${token}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  log(`helper token generated (printed once): ${token}`);
  log(`stored in ${path} (chmod 600). Clients send "Authorization: Bearer <token>".`);
  return { token, source: path, created: true };
}

/** Throws unless the bind address is safe: loopback, or explicitly allowed remote with an env token. */
export function checkBind(host, { tokenSource }) {
  if (isLoopbackHost(host)) return;
  if (process.env.NURI_ALLOW_REMOTE !== '1') {
    throw new Error(`refusing to bind ${host}: helper servers are loopback-only. Set NURI_ALLOW_REMOTE=1 and NURI_CARD_TOKEN to override (anyone who reaches the port + token can make the card sign).`);
  }
  if (tokenSource !== 'env') {
    throw new Error(`refusing to bind ${host}: NURI_ALLOW_REMOTE=1 also needs NURI_CARD_TOKEN set in the environment.`);
  }
}

export function allowedHosts(port, { remote = false, bindHost = '' } = {}) {
  const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  if (remote) {
    if (bindHost && !isLoopbackHost(bindHost) && bindHost !== '0.0.0.0' && bindHost !== '::') hosts.add(`${bindHost.toLowerCase()}:${port}`);
    for (const h of String(process.env.NURI_ALLOWED_HOSTS || '').split(',')) {
      const v = h.trim().toLowerCase();
      if (v) hosts.add(v);
    }
  }
  return hosts;
}

function tokenMatches(header, token) {
  const m = /^Bearer\s+(\S+)\s*$/i.exec(String(header || ''));
  if (!m) return false;
  const a = Buffer.from(m[1]);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

export const DEFAULT_PROTECTED = (pathname) => pathname === '/mcp' || pathname.startsWith('/api/');

/**
 * Returns null when the request may proceed, else { status, error }.
 * `port` is the port the server actually listens on; `remote` = NURI_ALLOW_REMOTE mode.
 */
export function guardRequest(req, { port, token, remote = false, bindHost = '', isProtected = DEFAULT_PROTECTED }) {
  const method = String(req.method || 'GET').toUpperCase();
  if (method === 'OPTIONS') return { status: 403, error: 'CORS preflight refused: this helper is same-origin / bearer-token only' };

  // Host allow-list: loopback:<port> always; in remote mode also NURI_ALLOWED_HOSTS (comma list, host:port).
  const hosts = allowedHosts(port, { remote, bindHost });
  const host = String(req.headers?.host || '').trim().toLowerCase();
  if (!hosts.has(host)) return { status: 403, error: `Host header not allowed (${host || 'missing'}); expected 127.0.0.1:${port} or localhost:${port}` };

  // Origin (sent by browsers on cross-site and all POST requests): must be one of the allowed hosts.
  const origin = req.headers?.origin;
  if (origin !== undefined) {
    const o = String(origin).trim().toLowerCase();
    let originOk = false;
    try {
      const u = new URL(o);
      originOk = (u.protocol === 'http:' || u.protocol === 'https:') && hosts.has(u.host);
    } catch { originOk = false; }
    if (!originOk) return { status: 403, error: `Origin not allowed (${o})` };
  }

  const pathname = (() => { try { return new URL(req.url || '/', 'http://127.0.0.1').pathname; } catch { return '/'; } })();
  if (!isProtected(pathname)) return null;

  if (method === 'POST') {
    const ct = String(req.headers?.['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/json') return { status: 415, error: 'Content-Type must be application/json' };
  }
  if (!tokenMatches(req.headers?.authorization, token)) {
    return { status: 401, error: 'missing or wrong bearer token (Authorization: Bearer <NURI_CARD_TOKEN or ~/.nuri-card/token>)' };
  }
  return null;
}

/** Inline script for the helper's own HTML pages: same-origin fetch() to /api|/mcp gets the bearer header. */
export function tokenScript(token) {
  return '<script>(function(){'
    + `var t=${JSON.stringify(token)};window.NURI_CARD_TOKEN=t;`
    + 'var f=window.fetch.bind(window);'
    + 'window.fetch=function(input,init){'
    + 'var u=typeof input==="string"?input:((input&&input.url)||"");'
    + 'if(/^\\/(api|mcp)(\\/|\\?|$)/.test(u)){'
    + 'init=Object.assign({},init||{});'
    + 'var h=new Headers(init.headers||(typeof input!=="string"&&input.headers)||undefined);'
    + 'h.set("authorization","Bearer "+t);'
    + 'if(String(init.method||"GET").toUpperCase()==="POST"&&!h.has("content-type"))h.set("content-type","application/json");'
    + 'init.headers=h;}'
    + 'return f(input,init);};'
    + '})();</script>';
}

export function injectToken(html, token) {
  const s = String(html);
  const i = s.search(/<head[^>]*>/i);
  if (i < 0) return tokenScript(token) + s;
  const end = s.indexOf('>', i) + 1;
  return s.slice(0, end) + tokenScript(token) + s.slice(end);
}
