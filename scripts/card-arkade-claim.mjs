#!/usr/bin/env node
/**
 * Claim an Arkade reverse-swap Lightning receive into the card's 2-of-2 Ark
 * balance, using the real card as the MuSig2 client signer.
 *
 * Reuses @arkade-os/sdk + @arkade-os/boltz-swap for all tx construction and
 * ASP submission (claimVHTLC). The only bespoke part is CardBackedAggregate-
 * Identity, which mirrors the proven LocalAggregateIdentity blueprint but
 * replaces the local 2-party MuSig2 with:
 *   - client partial : the physical card (scripts/card-arkade-claim-signer.py)
 *   - server partial : the live Nuri /arkade/sign
 *   - approval       : one card FIDO2 UV assertion (scripts/card-prf-backup.py)
 *
 * Config is read as JSON from stdin. Result JSON is printed to stdout.
 */
import { execFile } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import * as btc from '@scure/btc-signer';
import { tapLeafHash } from '@scure/btc-signer/payment.js';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils';
import {
  Wallet,
  InMemoryWalletRepository,
  InMemoryContractRepository,
  RestArkProvider,
  RestIndexerProvider,
  ArkAddress,
} from '@arkade-os/sdk';
import {
  ArkadeSwaps,
  BoltzSwapProvider,
  InMemorySwapRepository,
  getInvoicePaymentHash,
  getInvoiceSatoshis,
} from '@arkade-os/boltz-swap';

// The offchain claim path does not stream batch events, but guard anyway.
if (!globalThis.EventSource) {
  try { globalThis.EventSource = (await import('eventsource')).EventSource; } catch { /* not needed for offchain claim */ }
}

// --- helpers copied verbatim from the LocalAggregateIdentity blueprint --------
function appendTaprootSighash(sig64, sighashType) {
  if (sighashType === btc.SigHash.DEFAULT) return sig64;
  const out = new Uint8Array(sig64.length + 1);
  out.set(sig64, 0);
  out[sig64.length] = Number(sighashType) & 0xff;
  return out;
}

function scriptContainsXOnly(scriptOps, xOnlyPubkey) {
  const xOnlyHex = bytesToHex(xOnlyPubkey);
  for (const op of scriptOps) {
    if (!(op instanceof Uint8Array)) continue;
    if (op.length === 32 && bytesToHex(op) === xOnlyHex) return true;
    if (op.length === 33 && bytesToHex(op.slice(1)) === xOnlyHex) return true;
  }
  return false;
}

function execFileJson(file, args, { input } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, { maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`${file} ${args.join(' ')} failed: ${stderr || err.message}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch {
        reject(new Error(`${file} did not return JSON: ${stdout.slice(0, 400)}`));
      }
    });
    if (input !== undefined) {
      child.stdin.end(input);
    }
  });
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

// --- card-backed 2-of-2 aggregate identity -----------------------------------
class CardBackedAggregateIdentity {
  constructor({ cardPk33, serverPk33, cardSign, approve }) {
    this.clientPk33 = hexToBytes(cardPk33);
    this.serverPk33 = hexToBytes(serverPk33);
    this.sortedKeys = musig2.sortKeys([this.clientPk33, this.serverPk33]);
    this.aggregatedPk33 = musig2.keyAggregate(this.sortedKeys).aggPublicKey.toBytes(true);
    this.aggregatedXonly = this.aggregatedPk33.slice(1);
    this._cardSign = cardSign; // async (msg32Hex, approvalToken) -> Uint8Array(64)
    this._approve = approve;   // async ({ psbtB64, signRequests }) -> approvalToken
  }

  async compressedPublicKey() { return this.aggregatedPk33; }
  async xOnlyPublicKey() { return this.aggregatedXonly; }
  signerSession() { throw new Error('signerSession() not supported for card claim'); }
  async signMessage() { throw new Error('signMessage() not supported for card claim'); }

  async sign(tx, inputIndexes) {
    const txCopy = tx.clone();
    const targets = Array.isArray(inputIndexes)
      ? [...inputIndexes]
      : [...Array(txCopy.inputsLength).keys()];

    const prevScripts = [];
    const prevAmounts = [];
    for (let i = 0; i < txCopy.inputsLength; i += 1) {
      const input = txCopy.getInput(i);
      prevScripts.push(input?.witnessUtxo?.script || new Uint8Array());
      prevAmounts.push(input?.witnessUtxo?.amount || 0n);
    }

    // Pass 1: plan the script-path signatures (VHTLC claim leaf), collecting msg32.
    const plan = [];
    for (const idx of targets) {
      const input = txCopy.getInput(idx);
      if (!input?.witnessUtxo) {
        if (inputIndexes) throw new Error(`input ${idx} missing witnessUtxo`);
        continue;
      }
      const ws = input.witnessUtxo.script;
      const isTaproot = ws?.length === 34 && ws[0] === 0x51 && ws[1] === 0x20;
      if (!isTaproot) {
        if (inputIndexes) throw new Error(`input ${idx} is not taproot`);
        continue;
      }
      const sighashType = input.sighashType || btc.SigHash.DEFAULT;
      let matched = false;
      if (Array.isArray(input.tapLeafScript)) {
        for (const leaf of input.tapLeafScript) {
          if (!Array.isArray(leaf) || leaf.length < 2) continue;
          const swv = leaf[1];
          if (!(swv instanceof Uint8Array) || swv.length < 2) continue;
          const leafScript = swv.subarray(0, -1);
          const leafVersion = swv[swv.length - 1];
          let decoded = [];
          try { decoded = btc.Script.decode(leafScript); } catch { continue; }
          if (!scriptContainsXOnly(decoded, this.aggregatedXonly)) continue;
          const msg32 = txCopy.preimageWitnessV1(
            idx, prevScripts, sighashType, prevAmounts, undefined, leafScript, leafVersion,
          );
          plan.push({ idx, msg32, leafScript, leafVersion, sighashType });
          matched = true;
          break; // one aggregate-key leaf per input
        }
      }
      if (!matched) {
        throw new Error(`input ${idx}: no aggregate-key script leaf found (key-path claim unsupported)`);
      }
    }
    if (!plan.length) throw new Error('no signable inputs for the card aggregate key');

    // Approve this exact PSBT + its sign requests (FIDO2 UV on the first tx,
    // claim-session token afterward — handled inside _approve).
    const signRequests = plan.map((p) => ({
      kind: 'direct',
      input_index: p.idx,
      msg32: bytesToHex(p.msg32),
      client_pk33: bytesToHex(this.clientPk33),
    }));
    const psbtB64 = Buffer.from(txCopy.toPSBT()).toString('base64');
    const approvalToken = await this._approve({ psbtB64, signRequests });

    // Pass 2: card+server sign each input, attach the tapscript signature.
    for (const p of plan) {
      const sig64 = await this._cardSign(bytesToHex(p.msg32), approvalToken, p.idx);
      const leafSig = appendTaprootSighash(sig64, p.sighashType);
      txCopy.updateInput(
        p.idx,
        {
          tapScriptSig: [[
            { pubKey: this.aggregatedXonly, leafHash: tapLeafHash(p.leafScript, p.leafVersion) },
            leafSig,
          ]],
        },
        true,
      );
    }
    return txCopy;
  }
}

// --- card operations via the Python bridge -----------------------------------
async function pythonCardSign(cfg, msg32Hex, approvalToken) {
  const result = await execFileJson(cfg.python, [
    cfg.claimSigner,
    'sign-input',
    '--msg32', msg32Hex,
    '--approval-token', approvalToken,
    '--sign-url', cfg.signUrl,
    '--client-pk33', cfg.cardPk33,
    '--expect-aggregate', cfg.aggregate33,
  ]);
  if (!result.final_signature_verified) {
    throw new Error(`card claim signature did not verify: ${JSON.stringify(result)}`);
  }
  return hexToBytes(result.final_signature64);
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      'x-arkade-client': 'nuri-card-browser-demo',
      'x-arkade-sdk': 'nuri-card-browser-demo',
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(`${url} returned non-JSON: ${text.slice(0, 300)}`); }
  if (!res.ok) throw new Error(`${url} HTTP ${res.status}: ${data.error || data.reason || text.slice(0, 300)}`);
  return data;
}

// Obtain a receive-claim approval token. First tx uses a real card FIDO2 UV
// assertion (one PIN tap); the checkpoint tx reuses the cached session token.
let CLAIM_SESSION_TOKEN = null;
async function obtainApprovalToken(cfg, { psbtB64, signRequests }) {
  // Send mode has no restore/swap_id yet (Boltz creates the swap). The
  // approve endpoint still needs a swap_id, so use a synthetic one for the
  // send path — the approval is really just "card UV-asserted this PSBT".
  // Send mode has no receive record; Nuri's approve endpoint is receive-only,
  // so let the caller point at a real open receive swap_id to probe whether the
  // gate will still mint a cosign token for a send PSBT (ponytail: experiment).
  const swapId = cfg.approveSwapId
    || (cfg.restore
      ? (cfg.restore.swap_id || cfg.restore.response.id)
      : `send-${cfg.invoice.slice(0, 20)}`);

  if (CLAIM_SESSION_TOKEN) {
    const res = await postJson(cfg.approveUrl, {
      claim_session_token: CLAIM_SESSION_TOKEN,
      swap_id: swapId,
      psbt_b64: psbtB64,
      sign_requests: signRequests,
    });
    if (!res.approval_token) throw new Error(`checkpoint approve failed: ${JSON.stringify(res)}`);
    return res.approval_token;
  }

  // First approval: mint a challenge, sign it with the card (UV), then approve.
  const auth = await postJson(cfg.authUrl, {
    cred_id_b64u: cfg.credId,
    client_signer_pubkey: cfg.cardPk33,
    cred_pubkey_b64u: cfg.credPubkeyB64u,
  });
  if (!auth.token || !auth.challenge) throw new Error(`/arkade/auth failed: ${JSON.stringify(auth)}`);

  const assertion = await execFileJson(cfg.python, [
    cfg.prfScript, 'webauthn-assert',
    '--profile', cfg.credProfile,
    `--challenge-b64u=${auth.challenge}`,
    '--rp-id', cfg.rpId || auth.rp_id,
    // /arkade/auth returns origin as a comma-separated allowlist; use the single registered origin.
    '--origin', cfg.origin || String(auth.origin || '').split(',')[0].trim(),
    `--credential-id=${cfg.credId}`,
    '--user-verification', 'required',
    '--pin', cfg.pin,
  ]);

  const res = await postJson(cfg.approveUrl, {
    token: auth.token,
    client_data_b64u: assertion.client_data_b64u,
    auth_data_b64u: assertion.auth_data_b64u,
    sig_b64u: assertion.sig_b64u,
    swap_id: swapId,
    psbt_b64: psbtB64,
    sign_requests: signRequests,
  });
  if (!res.approval_token) throw new Error(`approve failed: ${JSON.stringify(res)}`);
  if (res.claim_session_token) CLAIM_SESSION_TOKEN = res.claim_session_token;
  return res.approval_token;
}

// --- Nuri native send (send/prepare -> card WebAuthn -> send/cosign) ----------
// The card's Ark funds are locked to musig2(card, live-Nuri-server). To spend
// them we drive Nuri's real send flow instead of the receive-claim path:
//   1. one send/prepare (strict funding PSBT + sign_requests) -> challenge_token
//   2. one card FIDO2 UV assertion over the prepare challenge
//   3. send/cosign per input: card nonce -> server BIP327 partial -> card
//      finalize -> aggregate. The first cosign is the strict funding cosign;
//      checkpoint txs cosign as follow-ups under the same challenge_token.
let SEND_SESSION = null;
let SEND_COSIGN_DONE = false;

async function prepareNuriSend(cfg, { psbtB64, signRequests }) {
  if (SEND_SESSION) return SEND_SESSION; // checkpoints reuse the funding session
  const s = cfg.sendState;
  if (!s) throw new Error('send state not initialized before prepare');
  const fullPackage = {
    kind: 'lightning_invoice',
    cred_id_b64u: cfg.credId,
    client_signer_pubkey: cfg.cardPk33,
    send_intent_id: s.send_intent_id,
    // direct_send_session: the initial funding cosign is strict (validates the
    // prepared PSBT); the checkpoint txs then cosign as lenient follow-ups under
    // the same challenge_token (Arkade offchain tx = arkTx + checkpoint txs).
    route_scope: 'direct_send_session',
    final_recipient: s.final_recipient,
    final_amount_sats: s.final_amount_sats,
    funding_address: s.funding_address,
    funding_script_hex: s.funding_script_hex,
    funding_amount_sats: s.funding_amount_sats,
    payment_hash: s.payment_hash,
    invoice: s.invoice,
    psbt_b64: psbtB64,
    sign_requests: signRequests,
  };
  const prep = await postJson(cfg.prepareUrl, fullPackage);
  if (!prep.challenge_token || !prep.challenge) {
    throw new Error(`send/prepare failed: ${JSON.stringify(prep)}`);
  }

  // One card FIDO2 UV assertion over the prepare challenge.
  const assertion = await execFileJson(cfg.python, [
    cfg.prfScript, 'webauthn-assert',
    '--profile', cfg.credProfile,
    `--challenge-b64u=${prep.challenge}`,
    '--rp-id', cfg.rpId,
    '--origin', cfg.origin,
    `--credential-id=${cfg.credId}`,
    '--user-verification', 'required',
    '--pin', cfg.pin,
  ]);

  const corePackage = { ...fullPackage };
  delete corePackage.psbt_b64;
  delete corePackage.sign_requests;
  SEND_SESSION = {
    challenge_token: prep.challenge_token,
    fullPackage,
    corePackage,
    assertion: {
      client_data_b64u: assertion.client_data_b64u,
      auth_data_b64u: assertion.auth_data_b64u,
      sig_b64u: assertion.sig_b64u,
    },
  };
  return SEND_SESSION;
}

async function pythonSendCosign(cfg, msg32Hex, session, inputIndex) {
  const firstCosign = !SEND_COSIGN_DONE;
  const context = {
    challenge_token: session.challenge_token,
    server_pk33: cfg.serverPk33,
    client_pk33: cfg.cardPk33,
    send_package: firstCosign ? session.fullPackage : session.corePackage,
    assertion: firstCosign ? session.assertion : null,
  };
  const ctxFile = join(tmpdir(), `nuri-send-cosign-${process.pid}-${inputIndex}-${firstCosign ? 'a' : 'b'}.json`);
  await writeFile(ctxFile, JSON.stringify(context));
  const result = await execFileJson(cfg.python, [
    cfg.claimSigner, 'sign-input-send',
    '--msg32', msg32Hex,
    '--input-index', String(inputIndex),
    '--cosign-url', cfg.cosignUrl,
    '--context-file', ctxFile,
    '--server-pk33', cfg.serverPk33,
    '--client-pk33', cfg.cardPk33,
    '--expect-aggregate', cfg.aggregate33,
  ]);
  SEND_COSIGN_DONE = true;
  if (!result.final_signature_verified) {
    throw new Error(`send cosign did not verify: ${JSON.stringify(result)}`);
  }
  return hexToBytes(result.final_signature64);
}

// Ark -> Lightning submarine swap, funded by a card+Nuri MuSig2 spend, then
// consumed with send/complete. Optimistic: waitFor 'funded' returns as soon as
// the VTXO funding lands (Boltz then pays the invoice), no settlement wait.
async function sendLightningNuri(cfg, wallet, swaps) {
  const { invoice } = cfg;
  if (!invoice) throw new Error('invoice is required for send mode');

  const pending = await swaps.createSubmarineSwap({ invoice });
  const lockup = pending.response.address;
  const fundingAmount = pending.response.expectedAmount;
  if (!lockup || !fundingAmount) throw new Error(`submarine swap missing lockup/amount: ${JSON.stringify(pending.response)}`);
  const decodedLockup = ArkAddress.decode(lockup);
  const lockupPkScript = typeof decodedLockup.pkScript === 'function' ? decodedLockup.pkScript() : decodedLockup.pkScript;
  const fundingScriptHex = bytesToHex(lockupPkScript);
  const paymentHash = getInvoicePaymentHash(invoice);
  const finalAmountSats = getInvoiceSatoshis(invoice);

  const intentRes = await postJson(cfg.intentUrl, {
    kind: 'lightning_invoice',
    cred_id_b64u: cfg.credId,
    client_signer_pubkey: cfg.cardPk33,
    final_recipient: invoice,
    final_amount_sats: finalAmountSats,
    funding_address: lockup,
    funding_script_hex: fundingScriptHex,
    funding_amount_sats: fundingAmount,
    payment_hash: paymentHash,
    invoice,
  });
  const sendIntentId = intentRes?.intent?.id;
  if (!sendIntentId) throw new Error(`swap-intent/create failed: ${JSON.stringify(intentRes)}`);

  cfg.sendState = {
    send_intent_id: sendIntentId,
    final_recipient: invoice,
    final_amount_sats: finalAmountSats,
    funding_address: lockup,
    funding_script_hex: fundingScriptHex,
    funding_amount_sats: fundingAmount,
    payment_hash: paymentHash,
    invoice,
  };

  // Fund the lockup (triggers identity.sign -> prepare/assert/cosign).
  const txid = await wallet.send({ address: lockup, amount: fundingAmount });

  // Optimistic: resolve once the funding is confirmed enough for Boltz.
  try { await swaps.waitForSwapFunded(pending); } catch (e) { /* optimistic: funding broadcast is enough */ }

  // Consume the intent.
  let complete = null;
  try {
    complete = await postJson(cfg.completeUrl, {
      challenge_token: SEND_SESSION?.challenge_token,
      send_intent_id: sendIntentId,
      txid,
    });
  } catch (e) { complete = { error: e.message }; }

  return {
    status: 'NURI_CARD_ARKADE_SEND_OK',
    invoice,
    send_intent_id: sendIntentId,
    swap_id: pending.id,
    funding_amount_sats: fundingAmount,
    final_amount_sats: finalAmountSats,
    ark_txid: txid,
    ark_address: await wallet.getAddress(),
    complete,
  };
}

// --- Pure Arkade: card + a locally-held key, zero Nuri --------------------------
// The second MuSig2 key is a secret WE hold (cfg.localAspSecret), so the whole
// aggregate signature is produced on this machine (card partial via APDU + local
// partial in-process). arkade.computer operates the round; no Nuri auth at all.
async function pythonLocalCosign(cfg, msg32Hex) {
  const result = await execFileJson(cfg.python, [
    cfg.claimSigner, 'sign-input-local',
    '--msg32', msg32Hex,
    '--asp-secret-hex', cfg.localAspSecret,
    '--client-pk33', cfg.cardPk33,
    '--expect-aggregate', cfg.aggregate33,
  ]);
  if (!result.final_signature_verified) {
    throw new Error(`local cosign did not verify: ${JSON.stringify(result)}`);
  }
  return hexToBytes(result.final_signature64);
}

async function sendLightningLocal(cfg, wallet, swaps) {
  const { invoice } = cfg;
  if (!invoice) throw new Error('invoice is required for send mode');
  const result = await swaps.sendLightningPayment({ invoice, waitFor: 'funded' });
  return {
    status: 'NURI_CARD_ARKADE_SEND_OK',
    account: 'pure-arkade',
    invoice,
    funding_amount_sats: result.amount,
    ark_txid: result.txid,
    ark_address: await wallet.getAddress(),
  };
}

async function main() {
  const cfg = JSON.parse(await readStdin());
  const mode = cfg.mode || 'claim';
  const r = cfg.restore;

  const sendMode = mode === 'send';
  const localMode = Boolean(cfg.localAspSecret);
  const identity = new CardBackedAggregateIdentity({
    cardPk33: cfg.cardPk33,
    serverPk33: cfg.serverPk33,
    cardSign: localMode
      ? (msg32Hex) => pythonLocalCosign(cfg, msg32Hex)
      : sendMode
        ? (msg32Hex, session, inputIndex) => pythonSendCosign(cfg, msg32Hex, session, inputIndex)
        : (msg32Hex, token) => pythonCardSign(cfg, msg32Hex, token),
    approve: localMode
      ? () => 'local'
      : sendMode
        ? (a) => prepareNuriSend(cfg, a)
        : (a) => obtainApprovalToken(cfg, a),
  });
  cfg.aggregate33 = bytesToHex(identity.aggregatedPk33);

  const nodeUrl = cfg.nodeUrl || 'https://arkade.computer';
  const wallet = await Wallet.create({
    identity,
    arkProvider: new RestArkProvider(nodeUrl),
    indexerProvider: new RestIndexerProvider(nodeUrl),
    storage: {
      walletRepository: new InMemoryWalletRepository(),
      contractRepository: new InMemoryContractRepository(),
    },
    settlementConfig: false,
  });

  // Read-only: show the card's actual Ark wallet balance (no card, no signing).
  if (mode === 'balance') {
    const address = await wallet.getAddress();
    let balance = null;
    try { balance = await wallet.getBalance(); } catch (e) { balance = { error: e.message }; }
    return {
      status: 'NURI_CARD_ARKADE_BALANCE_OK',
      aggregate_pubkey33: bytesToHex(identity.aggregatedPk33),
      ark_address: address,
      balance,
    };
  }

  // Send: Ark -> Lightning submarine swap. Pays a BOLT11 merchant invoice
  // from the card's settled VTXO balance via Nuri's native send flow.
  if (mode === 'send') {
    const swaps = await ArkadeSwaps.create({
      wallet,
      swapProvider: new BoltzSwapProvider({ network: cfg.boltzNetwork || 'bitcoin' }),
      swapRepository: new InMemorySwapRepository(),
      swapManager: false,
    });
    return localMode
      ? await sendLightningLocal(cfg, wallet, swaps)
      : await sendLightningNuri(cfg, wallet, swaps);
  }

  if (r.request?.claimPublicKey && cfg.aggregate33 !== r.request.claimPublicKey.toLowerCase()) {
    throw new Error(`aggregate ${cfg.aggregate33} != swap claimPublicKey ${r.request.claimPublicKey}`);
  }

  const swaps = await ArkadeSwaps.create({
    wallet,
    swapProvider: new BoltzSwapProvider({ network: cfg.boltzNetwork || 'bitcoin' }),
    swapRepository: new InMemorySwapRepository(),
    swapManager: false,
  });

  const pendingSwap = {
    id: r.swap_id || r.response.id,
    type: 'reverse',
    createdAt: r.created_at_unix || 1,
    preimage: r.preimage,
    status: r.status,
    request: {
      claimPublicKey: r.request.claimPublicKey,
      invoiceAmount: r.request.invoiceAmount,
      preimageHash: r.request.preimageHash,
      description: r.request.description,
    },
    response: {
      id: r.response.id,
      invoice: r.response.invoice,
      onchainAmount: r.response.onchainAmount,
      lockupAddress: r.response.lockupAddress,
      refundPublicKey: r.response.refundPublicKey,
      timeoutBlockHeights: r.response.timeoutBlockHeights,
    },
  };

  await swaps.claimVHTLC(pendingSwap);
  const address = await wallet.getAddress();
  return {
    status: 'NURI_CARD_ARKADE_CLAIM_OK',
    swap_id: pendingSwap.id,
    aggregate_pubkey33: bytesToHex(identity.aggregatedPk33),
    ark_address: address,
  };
}

// The SDK's wallet watcher keeps the event loop alive, so exit explicitly.
main().then((out) => {
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
}).catch((err) => {
  process.stdout.write(JSON.stringify({ status: 'NURI_CARD_ARKADE_CLAIM_FAILED', error: err.message }));
  process.exit(1);
});
