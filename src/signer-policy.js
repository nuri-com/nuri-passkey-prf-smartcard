// Shared Node boundary: card callers never accept an explicit software/sim result.
// Normal callers use MuSig2/FIDO2, not ETH. Guard explicit ETH1 helper/AID
// overrides too; the Python transport owns ETH2-first selection/no fallback.
export function requireCardSubprocess(args, env = process.env) {
  const eth1 = args.some((arg) => /(?:^|[/\\])card-eth-test\.py$/i.test(String(arg)) ||
    /^(?:eth1|--eth1|--applet=eth1|4e55524945544801)$/i.test(String(arg)));
  if (eth1 && env.NURI_ALLOW_ETH1_DEMO !== '1') {
    throw new Error('ETH1 demo access requires NURI_ALLOW_ETH1_DEMO=1; use the PIN-gated ETH2 signer instead');
  }
}

export function requireCardResult(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error('card helper returned no result');
  }
  if ((result.mode !== undefined && result.mode !== 'card') ||
      /sim|software/i.test(String(result.backend || ''))) {
    throw new Error('card helper returned a non-card result; refusing signer downgrade');
  }
  return result;
}

export function installSignerErrorHandler(mode) {
  process.on('uncaughtException', (error) => {
    console.error(JSON.stringify({ mode, error: error.message || String(error) }));
    process.exit(1);
  });
}

export function warnSimulation() {
  console.error('WARNING: SIMULATION ONLY (mode: sim). Keys and signatures are SOFTWARE, NOT a physical card. NEVER FUND simulated addresses.');
}

// Tag at the HTTP boundary, before helper-auth's framing/auth guards run. This
// covers their early failures as well as application responses. Static assets
// carry the header; HTML additionally displays a persistent simulation banner.
export function tagSignerServer(server, mode) {
  if (!['card', 'sim'].includes(mode)) throw new Error('invalid signer mode');
  const envelope = (value) => ({ ...value, mode });
  server.prependListener('request', (_req, res) => {
    res.setHeader('x-nuri-signer-mode', mode);
    const end = res.end;
    res.end = function (chunk, encoding, callback) {
      if (typeof chunk === 'string' || Buffer.isBuffer(chunk)) {
        const text = chunk.toString();
        let body = text;
        try {
          const value = JSON.parse(text);
          if (value && typeof value === 'object' && !Array.isArray(value)) body = JSON.stringify(envelope(value));
        } catch {
          if (mode === 'sim' && String(res.getHeader('content-type') || '').startsWith('text/html')) {
            body = text.replace(/<body[^>]*>/i, (tag) => `${tag}<aside role="alert" data-signer-mode="sim" style="background:#ffec99;color:#111;padding:16px;font-weight:bold">WARNING: SIMULATION ONLY — mode: sim. SOFTWARE keys, NOT a physical card. NEVER FUND these addresses.</aside>`);
          }
        }
        if (body !== text) {
          chunk = Buffer.from(body);
          if (!res.headersSent && res.hasHeader('content-length')) res.setHeader('content-length', chunk.length);
        }
      }
      return end.call(this, chunk, encoding, callback);
    };
  });

  // helper-auth's pre-request parser/deadline failures have no ServerResponse.
  // Preserve its status/deadline/close policy, but send a mode-tagged JSON body.
  const rawError = (socket, status, error) => {
    const body = JSON.stringify(envelope({ error }));
    socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Type: application/json\r\nX-Nuri-Signer-Mode: ${mode}\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
  };
  server.removeAllListeners('clientError');
  server.on('clientError', (error, socket) => rawError(socket,
    error.code === 'HPE_HEADER_OVERFLOW' ? '431 Request Header Fields Too Large' : '400 Bad Request', 'invalid request headers'));
  server.on('connection', (socket) => {
    clearTimeout(socket.helperTimer);
    socket.helperTimer = setTimeout(() => {
      const res = socket.helperResponse;
      if (res && !res.writableEnded) res.writeHead(408).end(JSON.stringify(envelope({ error: 'request read deadline exceeded' })));
      else if (!res) rawError(socket, '408 Request Timeout', 'request read deadline exceeded');
      setTimeout(() => socket.destroy(), 50).unref();
    }, Number(process.env.NURI_HELPER_REQUEST_TIMEOUT_MS || 10000));
  });
  return server;
}
