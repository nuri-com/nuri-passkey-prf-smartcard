// Loopback-only helper boundary. No HTTP response contains a bearer credential.
// Python twin: nuri_helper_auth.py. Pairing codes authorize one browser session.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants as C, closeSync, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir } from 'node:os';
import { basename, dirname, join, parse, resolve } from 'node:path';

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
export const MAX_BODY = 1 << 20;
export const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer', 'cache-control': 'no-store',
  'cross-origin-opener-policy': 'same-origin', 'cross-origin-resource-policy': 'same-origin',
};
export const isLoopbackHost = (host) => LOOPBACK.has(String(host || '').trim().toLowerCase());
function prefix(service) {
  if (!/^[a-z][a-z0-9]{0,31}$/.test(service)) throw new Error('invalid service name');
  return `NURI_${service.toUpperCase()}`;
}
export function tokenPath(service = 'cosign') {
  const p = prefix(service);
  return process.env[`${p}_TOKEN_FILE`] || (process.env.NURI_CARD_TOKEN_FILE
    ? `${process.env.NURI_CARD_TOKEN_FILE}.${service}` : join(homedir(), '.nuri-card', `${service}.token`));
}
export function validateToken(token) {
  if (!/^[0-9a-f]{64}$/.test(token) || new Set(token).size < 8) throw new Error('token must be 64 random lowercase hex characters (openssl rand -hex 32)');
  return token;
}
function checkPrivate(st, dir) {
  if (!(dir ? st.isDirectory() : st.isFile()) || st.uid !== process.getuid() || (st.mode & 0o777) !== (dir ? 0o700 : 0o600)) {
    throw new Error(`token ${dir ? 'directory' : 'file'} must be owner-only ${dir ? '0700' : '0600'} and owned by the current user`);
  }
}
// Node has no openat: reject symlink/writable ancestors before accessing the
// private directory. Other OS users cannot rename any component after validation.
function checkAncestors(path) {
  const root = parse(path).root;
  let current = root;
  for (const part of path.slice(root.length).split('/').filter(Boolean)) {
    current = join(current, part);
    const st = lstatSync(current);
    const writable = (st.mode & 0o022) && !(st.uid === 0 && (st.mode & 0o1000));
    if (!st.isDirectory() || st.isSymbolicLink() || writable) throw new Error('token path has a symlink or writable ancestor');
  }
}
export function loadOrCreateToken({ service = 'cosign', log = console.error } = {}) {
  const p = prefix(service);
  const configured = String(process.env[`${p}_TOKEN`] || '').trim();
  if (configured) return { token: validateToken(configured), source: 'env', created: false };
  if (process.env.NURI_CARD_TOKEN) throw new Error(`NURI_CARD_TOKEN is no longer accepted; use a separate ${p}_TOKEN or unset it for a scoped token file`);
  const requested = resolve(tokenPath(service));
  // Resolve ancestors once (macOS /var is a root-owned alias), but never resolve
  // the token directory or file themselves: O_NOFOLLOW must reject those links.
  const requestedDir = dirname(requested);
  const dir = join(realpathSync(dirname(requestedDir)), basename(requestedDir));
  const path = join(dir, basename(requested));
  checkAncestors(dirname(dir));
  try { mkdirSync(dir, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const dfd = openSync(dir, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
  let created = false;
  function read() {
    const fd = openSync(path, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK);
    try {
      checkPrivate(fstatSync(fd), false);
      if (fstatSync(fd).size > 128) throw new Error('malformed token file');
      return validateToken(readFileSync(fd, 'utf8').trim());
    } finally { closeSync(fd); }
  }
  try {
    checkPrivate(fstatSync(dfd), true);
    let token;
    try { token = read(); } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      const tmp = join(dir, `.${basename(path)}.${randomBytes(16).toString('hex')}.tmp`);
      const fd = openSync(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
      try {
        writeFileSync(fd, `${randomBytes(32).toString('hex')}\n`); fsyncSync(fd);
      } finally { closeSync(fd); }
      try {
        try { linkSync(tmp, path); created = true; } catch (err) { if (err.code !== 'EEXIST') throw err; }
      } finally { unlinkSync(tmp); }
      token = read();
    }
    const now = lstatSync(dir), opened = fstatSync(dfd);
    if (now.dev !== opened.dev || now.ino !== opened.ino || now.isSymbolicLink()) throw new Error('token directory changed');
    log(`${service} API token: ${path} (0600; value not printed)`);
    return { token, source: path, created };
  } finally { closeSync(dfd); }
}
export function checkBind(host) {
  if (!isLoopbackHost(host)) throw new Error(`refusing to bind ${host}: helpers are loopback-only; no remote override`);
}
export function allowedHosts(port) { return new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]); }
function equal(a, b) {
  const aa = Buffer.from(String(a || '')), bb = Buffer.from(String(b || ''));
  return aa.length > 0 && aa.length === bb.length && timingSafeEqual(aa, bb);
}
const hash = (s) => createHash('sha256').update(s).digest('hex');
export class PairingSessions {
  constructor({ service = 'cosign', log = console.error, ttlMs = 43200000, codeTtlMs = 300000 } = {}) {
    prefix(service); this.cookie = `nuri_${service}_session`; this.ttlMs = ttlMs;
    this.codeTtlMs = codeTtlMs; this.log = log; this.sessions = new Map(); this.rotateCode();
  }
  rotateCode() {
    // 64 random bits, five-minute validity, rotated after ten failed guesses.
    this.code = randomBytes(8).toString('hex'); this.codeUntil = Date.now() + this.codeTtlMs;
    this.failures = 0; this.log(`Browser pairing code: ${this.code} (single use, expires in 5 minutes)`);
  }
  exchange(code) {
    if (!this.code || Date.now() >= this.codeUntil || !equal(code, this.code)) {
      if (this.code && (++this.failures >= 10 || Date.now() >= this.codeUntil)) this.rotateCode();
      return null;
    }
    this.code = null; this.failures = 0;
    for (const [key, expiry] of this.sessions) if (expiry <= Date.now()) this.sessions.delete(key);
    while (this.sessions.size >= 32) this.sessions.delete(this.sessions.keys().next().value);
    const sid = randomBytes(32).toString('hex'); this.sessions.set(hash(sid), Date.now() + this.ttlMs);
    this.rotateCode(); // the consumed code never works again; next browser gets a fresh code
    return `${this.cookie}=${sid}; Path=/api/; Max-Age=${Math.floor(this.ttlMs / 1000)}; HttpOnly; SameSite=Strict`;
  }
  accepts(req) {
    if (req.headers.origin === undefined && req.headers['sec-fetch-site'] !== 'same-origin') return false;
    const cookies = String(req.headers.cookie || '').split(';').map((s) => s.trim()).filter((s) => s.startsWith(`${this.cookie}=`));
    if (cookies.length !== 1) return false;
    const sid = cookies[0].slice(this.cookie.length + 1);
    return /^[0-9a-f]{64}$/.test(sid) && (this.sessions.get(hash(sid)) || 0) > Date.now();
  }
}
export const DEFAULT_PROTECTED = (path) => path === '/mcp' || path.startsWith('/api/');
export function guardRequest(req, { port, token, sessions, isProtected = DEFAULT_PROTECTED }) {
  const method = String(req.method || 'GET').toUpperCase();
  if (method === 'OPTIONS') return { status: 403, error: 'CORS preflight refused' };
  const host = String(req.headers?.host || '').toLowerCase();
  if (!allowedHosts(port).has(host)) return { status: 403, error: 'Host header not allowed' };
  const origin = req.headers?.origin;
  if (origin !== undefined && origin !== `http://${host}`) return { status: 403, error: 'Origin not allowed' };
  const path = new URL(req.url || '/', 'http://127.0.0.1').pathname;
  if (!isProtected(path) && path !== '/pair') return null;
  if (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin') return { status: 403, error: 'cross-site request refused' };
  if (method === 'POST' && String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/json') return { status: 415, error: 'Content-Type must be application/json' };
  if (path === '/pair') return null; // only exchange() can authorize this request
  const match = /^Bearer\s+(\S+)\s*$/i.exec(String(req.headers.authorization || ''));
  if (!(match && equal(match[1], token)) && !(path.startsWith('/api/') && sessions?.accepts(req))) return { status: 401, error: 'pair this browser or supply the scoped bearer token' };
  return null;
}
export const pairingPage = (html) => String(html).includes('/helper-pair.js') ? String(html) : String(html).replace(/<head[^>]*>/i, (head) => `${head}<script src="/helper-pair.js"></script>`);
export function bodyError(status, message) { return Object.assign(new Error(message), { status }); }
export function bodyPolicy(req) {
  if (req.headers['transfer-encoding']) return { status: 400, error: 'Transfer-Encoding is not supported' };
  const cl = req.headers['content-length'];
  if (cl !== undefined && !/^\d+$/.test(cl)) return { status: 400, error: 'invalid Content-Length' };
  if (cl !== undefined && (cl.length > 10 || Number(cl) > MAX_BODY)) return { status: 413, error: 'body too large' };
  if (req.method === 'POST' && cl === undefined) return { status: 411, error: 'Content-Length required' };
  return null;
}
export function readJson(req) {
  return new Promise((resolveBody, reject) => {
    const chunks = []; let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) { reject(bodyError(413, 'body too large')); return; }
      chunks.push(chunk);
    });
    req.on('aborted', () => reject(bodyError(408, 'incomplete request body')));
    req.on('error', () => reject(bodyError(400, 'invalid request body')));
    req.on('end', () => {
      try { resolveBody(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch { reject(bodyError(400, 'invalid JSON')); }
    });
  });
}
export function createHelperServer(handler, { timeoutMs = Number(process.env.NURI_HELPER_REQUEST_TIMEOUT_MS || 10000) } = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 10000) throw new Error('request timeout must be 1..10000 ms');
  const server = createServer({ maxHeaderSize: 16384 }, (req, res) => {
    req.socket.helperResponse = res;
    for (const [key, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(key, value);
    res.setHeader('connection', 'close'); // one absolute deadline per connection
    const clear = () => clearTimeout(req.socket.helperTimer);
    req.once('end', clear); req.once('aborted', clear); res.once('finish', clear);
    const denied = bodyPolicy(req);
    if (denied) { res.writeHead(denied.status); res.end(JSON.stringify({ error: denied.error })); return; }
    if (!Number(req.headers['content-length'] || 0)) clear();
    Promise.resolve(handler(req, res)).catch(() => {
      if (!res.writableEnded) res.writeHead(500).end(JSON.stringify({ error: 'request failed' }));
    });
  });
  server.maxConnections = 16;
  server.on('connection', (socket) => {
    socket.helperTimer = setTimeout(() => {
      const res = socket.helperResponse;
      if (res && !res.writableEnded) res.writeHead(408).end(JSON.stringify({ error: 'request read deadline exceeded' }));
      else if (!res) socket.end('HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      setTimeout(() => socket.destroy(), 50).unref();
    }, timeoutMs);
    socket.once('close', () => clearTimeout(socket.helperTimer));
  });
  server.on('clientError', (error, socket) => {
    socket.end(`HTTP/1.1 ${error.code === 'HPE_HEADER_OVERFLOW' ? '431 Request Header Fields Too Large' : '400 Bad Request'}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  });
  return server;
}
