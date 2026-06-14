#!/usr/bin/env node
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import process from 'node:process';
import { bytesToHex } from '@noble/curves/abstract/utils';
import { createOnCardGeneratedCard, runCardCosignFlow } from '../src/musig2/cosign-flow.js';

const card = createOnCardGeneratedCard();

function parseArgs(argv) {
  const args = {
    host: '127.0.0.1',
    port: 8787,
    selftest: false,
  };
  for (const arg of argv) {
    if (arg === '--selftest') args.selftest = true;
    else if (arg.startsWith('--host=')) args.host = arg.slice('--host='.length);
    else if (arg.startsWith('--port=')) args.port = Number(arg.slice('--port='.length));
    else if (arg === '--help' || arg === '-h') {
      console.log('Usage: node scripts/local-card-cosign-server.mjs [--host=127.0.0.1] [--port=8787] [--selftest]');
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!Number.isInteger(args.port) || args.port <= 0 || args.port > 65535) {
    throw new Error('port must be 1..65535');
  }
  return args;
}

function json(res, status, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(body);
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  return JSON.parse(raw);
}

async function serveStatic(res, path, contentType) {
  const body = await readFile(path);
  res.writeHead(200, {
    'content-type': contentType,
    'cache-control': 'no-store',
  });
  res.end(body);
}

function handleInfo(res) {
  json(res, 200, {
    status: 'NURI_CARD_COSIGN_SERVER_READY',
    backend: 'simulated-on-card-keygen',
    key_origin: 'card-generated-non-exportable-in-backend',
    card_pk33: bytesToHex(card.getIndividualPubkey()),
    endpoints: {
      sign: 'POST /api/cosign/sign',
    },
    real_card_proof:
      'The installed NuriMuSig2 v1.10/KGEN applet has a real INS_KEYGEN path. Run npm run cosign:real-card to prove on-card keygen, card partial verification, and final aggregate BIP340 verification.',
  });
}

async function handleSign(req, res) {
  const body = await readJson(req);
  const result = runCardCosignFlow({
    card,
    msg32: body.msg32,
    message: body.message,
  });
  json(res, 200, result);
}

async function requestHandler(req, res) {
  try {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/cosign-demo.html')) {
      await serveStatic(res, resolve('web/cosign-demo.html'), 'text/html; charset=utf-8');
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/cosign/info') {
      handleInfo(res);
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/cosign/sign') {
      await handleSign(req, res);
      return;
    }
    json(res, 404, { error: 'not found' });
  } catch (error) {
    json(res, 500, {
      error: error?.message || String(error),
    });
  }
}

const args = parseArgs(process.argv.slice(2));

if (args.selftest) {
  console.log(JSON.stringify(runCardCosignFlow({ card }), null, 2));
  process.exit(0);
}

const server = createServer(requestHandler);
server.listen(args.port, args.host, () => {
  console.log(`Nuri card cosign demo server at http://${args.host}:${args.port}/cosign-demo.html`);
  console.log(`Cosigner card pubkey: ${bytesToHex(card.getIndividualPubkey())}`);
});
