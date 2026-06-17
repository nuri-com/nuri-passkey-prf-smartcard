#!/usr/bin/env node
// Smartcard-backed MCP cosigning server.
// Mirrors the Nuri MCP shape (initialize / tools/list / tools/call) but the
// signer is the physical card on THIS machine over PC/SC — no browser, no
// sign.nuri.com. Tunnel with ngrok to expose /mcp to a remote agent.
//
// ponytail: uses the card's existing MuSig2 proof flow (plain MuSig2, even-y).
// It is NOT yet byte-compatible with sign.nuri.com's tweaked BIP327 session
// (the applet takes no tweak32). Protocol alignment = a separate applet step.
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import process from 'node:process';
import * as btc from '@scure/btc-signer';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils';

const PY = process.env.REAL_CARD_COSIGN_PYTHON || '/private/tmp/nuri-fido2-real-card-venv/bin/python';
const SCRIPT = process.env.REAL_CARD_COSIGN_SCRIPT || 'scripts/real-card-cosign-proof.py';
const TWEAKED_SCRIPT = process.env.REAL_CARD_TWEAKED_SCRIPT || 'scripts/card-cosign-tweaked.py';
const CSV_BLOCKS = 52500; // matches card-cosign-tweaked.py and nuriBitcoin.ts

// Nuri's exact Taproot derivation: internal = musig2(client,card), one client CSV leaf.
function nuriDerive(clientPk33Hex, cardPk33Hex) {
  const sorted = musig2.sortKeys([hexToBytes(clientPk33Hex), hexToBytes(cardPk33Hex)]);
  const aggComp = musig2.keyAggExport(musig2.keyAggregate(sorted));
  const Px = aggComp.length === 33 ? aggComp.slice(1) : aggComp;
  const userXOnly = hexToBytes(clientPk33Hex).slice(1);
  const leaf = { script: btc.Script.encode([userXOnly, 'CHECKSIGVERIFY', CSV_BLOCKS, 'CHECKSEQUENCEVERIFY']), leafVersion: 0xc0 };
  const p2tr = btc.p2tr(Px, [leaf], btc.NETWORK, true);
  return { outputXOnly: bytesToHex(p2tr.script.slice(2)), address: p2tr.address };
}

// Never run two PC/SC commands at once: serialize all card access.
let cardChain = Promise.resolve();
function runPy(args) {
  const job = cardChain.then(() => new Promise((res, rej) => {
    execFile(PY, args, { cwd: process.cwd(), timeout: 90000, maxBuffer: 1 << 20 }, (err, out, errout) => {
      if (err) return rej(new Error(`${err.message}\n${errout || out}`.trim()));
      try { res(JSON.parse(out)); } catch (e) { rej(new Error(`bad JSON from card script: ${e.message}\n${out}`)); }
    });
  }));
  cardChain = job.catch(() => {}); // keep the chain alive on failure
  return job;
}
function runCard({ msg32, message } = {}) {
  const args = [SCRIPT, '--use-existing-card-key'];
  if (msg32) args.push('--msg32', String(msg32));
  else if (message) args.push('--message', String(message));
  return runPy(args);
}
function runCardTweaked({ msg32, message, clientSecretHex } = {}) {
  const args = [TWEAKED_SCRIPT];
  if (msg32) args.push('--msg32', String(msg32));
  else if (message) args.push('--message', String(message));
  if (clientSecretHex) args.push('--client-secret-hex', String(clientSecretHex));
  return runPy(args);
}

const TOOLS = [
  {
    name: 'nuri_card_info',
    description: 'Public identity of the smartcard cosigner: card pubkey, aggregate key, applet version. No funds move.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'nuri_card_cosign',
    description: 'Sign a 32-byte message with the physical card cosigner (plain 2-of-2 MuSig2, no tweak). Returns a verified BIP340 signature.',
    inputSchema: {
      type: 'object',
      properties: {
        msg32: { type: 'string', description: '32-byte message as 64 hex chars (e.g. a Taproot sighash).' },
        message: { type: 'string', description: 'Plain text hashed to 32 bytes if msg32 is omitted.' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'nuri_card_cosign_tweaked',
    description: 'Sign for the exact Nuri Taproot wallet: musig2(client,card) key-path with the client CSV recovery leaf (BIP327 tweak applied host-side). Returns the Nuri address, output key, and a BIP340 signature verified against it.',
    inputSchema: {
      type: 'object',
      properties: {
        msg32: { type: 'string', description: '32-byte Taproot sighash as 64 hex chars.' },
        message: { type: 'string', description: 'Plain text hashed to 32 bytes if msg32 is omitted.' },
        client_secret_hex: { type: 'string', description: 'Optional 32-byte client secret (hex) for a stable wallet; random demo key if omitted.' },
      },
      additionalProperties: false,
    },
  },
];

async function callTool(name, callArgs) {
  if (name === 'nuri_card_info') {
    const r = await runCard({});
    return {
      status: r.status,
      card_aid: r.card_aid,
      card_version: r.card_version,
      reader: r.reader,
      card_pk33: r.card_pk33,
      aggregate_xonly32: r.aggregate_xonly32,
      key_origin: r.key_origin,
    };
  }
  if (name === 'nuri_card_cosign') {
    const r = await runCard({ msg32: callArgs?.msg32, message: callArgs?.message });
    if (!r.final_signature_verified || !r.card_partial_verified) {
      throw new Error(`card signature not verified: ${JSON.stringify(r)}`);
    }
    return {
      status: r.status,
      msg32: r.msg32,
      card_pk33: r.card_pk33,
      aggregate_xonly32: r.aggregate_xonly32,
      final_signature64: r.final_signature64,
      final_signature_verified: r.final_signature_verified,
      card_partial_verified: r.card_partial_verified,
      broadcast_note: r.broadcast_note,
    };
  }
  if (name === 'nuri_card_cosign_tweaked') {
    const r = await runCardTweaked({ msg32: callArgs?.msg32, message: callArgs?.message, clientSecretHex: callArgs?.client_secret_hex });
    if (r.status !== 'REAL_CARD_TWEAKED_COSIGN_OK') throw new Error(`tweaked cosign failed: ${JSON.stringify(r)}`);
    // Independently confirm the card's output key == Nuri's scure derivation and the sig verifies.
    const nuri = nuriDerive(r.client_pk33, r.card_pk33);
    const matchesNuri = nuri.outputXOnly === r.tweaked_output_xonly32;
    const sigValid = schnorr.verify(hexToBytes(r.final_signature64), hexToBytes(r.msg32), hexToBytes(r.tweaked_output_xonly32));
    if (!matchesNuri || !sigValid) throw new Error(`nuri-compat check failed: matchesNuri=${matchesNuri} sigValid=${sigValid}`);
    return {
      status: 'REAL_CARD_TWEAKED_COSIGN_NURI_COMPATIBLE',
      nuri_address: nuri.address,
      tweaked_output_xonly32: r.tweaked_output_xonly32,
      client_pk33: r.client_pk33,
      card_pk33: r.card_pk33,
      msg32: r.msg32,
      final_signature64: r.final_signature64,
      matches_nuri_scure_derivation: matchesNuri,
      signature_valid_bip340: sigValid,
      csv_blocks: CSV_BLOCKS,
    };
  }
  throw new Error(`unknown tool: ${name}`);
}

const ok = (id, result) => ({ jsonrpc: '2.0', id, result });
const err = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

async function handleRpc(msg) {
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return err(msg?.id ?? null, -32600, 'invalid request');
  }
  switch (msg.method) {
    case 'initialize':
      return ok(msg.id, {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'nuri-smartcard-cosigner', version: '0.1.0' },
      });
    case 'notifications/initialized':
      return null; // notification, no response
    case 'tools/list':
      return ok(msg.id, { tools: TOOLS });
    case 'tools/call': {
      const { name, arguments: callArgs } = msg.params || {};
      try {
        const result = await callTool(name, callArgs);
        return ok(msg.id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
      } catch (e) {
        return ok(msg.id, { content: [{ type: 'text', text: `error: ${e.message}` }], isError: true });
      }
    }
    default:
      return err(msg.id, -32601, `Method not found: ${msg.method}`);
  }
}

async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  return raw ? JSON.parse(raw) : {};
}

function send(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(body);
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method === 'GET' && url.pathname === '/healthz') return send(res, 200, { ok: true });
    if (req.method === 'POST' && url.pathname === '/mcp') {
      const msg = await readJson(req);
      const reply = await handleRpc(msg);
      if (reply === null) { res.writeHead(202).end(); return; }
      return send(res, 200, reply);
    }
    send(res, 404, { error: 'not found' });
  } catch (e) {
    send(res, 500, { error: e?.message || String(e) });
  }
});

// --selftest: exercise the JSON-RPC path + one real card sign (plain + tweaked), then exit.
if (process.argv.includes('--selftest')) {
  const list = await handleRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  if (!list.result.tools.length) throw new Error('no tools listed');
  const call = await handleRpc({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'nuri_card_cosign', arguments: { message: 'mcp selftest' } } });
  const text = call.result.content[0].text;
  if (call.result.isError || !text.includes('"final_signature_verified": true')) {
    throw new Error(`selftest failed: ${text}`);
  }
  const tw = await handleRpc({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'nuri_card_cosign_tweaked', arguments: { message: 'mcp selftest tweaked' } } });
  const twText = tw.result.content[0].text;
  if (tw.result.isError || !twText.includes('NURI_COMPATIBLE')) {
    throw new Error(`tweaked selftest failed: ${twText}`);
  }
  console.log(twText);
  console.log('CARD_MCP_SELFTEST_OK');
  process.exit(0);
}

const port = Number(process.env.PORT || 8799);
const host = process.env.HOST || '127.0.0.1';
server.listen(port, host, () => {
  console.log(`Nuri smartcard MCP cosigner: http://${host}:${port}/mcp  (health: /healthz)`);
  console.log('Expose remotely:  ngrok http ' + port);
});
