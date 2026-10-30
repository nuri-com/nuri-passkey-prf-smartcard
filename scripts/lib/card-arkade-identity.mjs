/**
 * Card-backed 2-of-2 MuSig2 aggregate identity + card/server cosign plumbing.
 *
 * Extracted verbatim from scripts/card-arkade-claim.mjs so the claim CLI and the
 * Chrome-extension bridge (scripts/ext-card-wallet.mjs) share ONE implementation
 * of the money path. The identity is the client signer: the physical card holds
 * the secret nonce and returns a BIP327 partial; the second partial comes from
 * Nuri's server (or a local secret). Nothing here stores a key.
 *
 * New in this module (still one session per input): `onPlan` lets a caller stop
 * AFTER the PSBT and its sighashes are built but BEFORE the card is touched, so a
 * human can approve the exact transaction. `PreviewSignal` carries that preview.
 */
import { execFile } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Buffer } from 'node:buffer';
import * as btc from '@scure/btc-signer';
import { tapLeafHash } from '@scure/btc-signer/payment.js';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { hexToBytes, bytesToHex } from '@noble/curves/utils.js';

export class PreviewSignal extends Error {
  constructor(preview) {
    super('preview');
    this.preview = preview;
  }
}

export function appendTaprootSighash(sig64, sighashType) {
  if (sighashType === btc.SigHash.DEFAULT) return sig64;
  const out = new Uint8Array(sig64.length + 1);
  out.set(sig64, 0);
  out[sig64.length] = Number(sighashType) & 0xff;
  return out;
}

export function scriptContainsXOnly(scriptOps, xOnlyPubkey) {
  const xOnlyHex = bytesToHex(xOnlyPubkey);
  for (const op of scriptOps) {
    if (!(op instanceof Uint8Array)) continue;
    if (op.length === 32 && bytesToHex(op) === xOnlyHex) return true;
    if (op.length === 33 && bytesToHex(op.slice(1)) === xOnlyHex) return true;
  }
  return false;
}

export function execFileJson(file, args, { input, pinEnv } = {}) {
  return new Promise((resolve, reject) => {
    const env = pinEnv ? { ...process.env, ...pinEnv } : process.env;
    const child = execFile(file, args, { env, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
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

export async function postJson(url, body, headers = {}) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      'x-arkade-client': 'nuri-card-browser-demo',
      'x-arkade-sdk': 'nuri-card-browser-demo',
      ...headers,
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { throw new Error(`${url} returned non-JSON: ${text.slice(0, 300)}`); }
  if (!res.ok) throw new Error(`${url} HTTP ${res.status}: ${data.error || data.reason || text.slice(0, 300)}`);
  return data;
}

// --- card-backed 2-of-2 aggregate identity -----------------------------------
export class CardBackedAggregateIdentity {
  constructor({ cardPk33, serverPk33, cardSign, approve, onPlan = null }) {
    this.clientPk33 = hexToBytes(cardPk33);
    this.serverPk33 = hexToBytes(serverPk33);
    this.sortedKeys = musig2.sortKeys([this.clientPk33, this.serverPk33]);
    this.aggregatedPk33 = musig2.keyAggregate(this.sortedKeys).aggPublicKey.toBytes(true);
    this.aggregatedXonly = this.aggregatedPk33.slice(1);
    this._cardSign = cardSign; // async (msg32Hex, approvalToken, inputIndex) -> Uint8Array(64)
    this._approve = approve;   // async ({ psbtB64, signRequests }) -> approvalToken
    this._onPlan = onPlan;     // optional async (preview) -> { proceed: boolean }
  }

  async compressedPublicKey() { return this.aggregatedPk33; }
  async xOnlyPublicKey() { return this.aggregatedXonly; }
  signerSession() { throw new Error('signerSession() not supported for card aggregate identity'); }
  async signMessage() { throw new Error('signMessage() not supported for card aggregate identity'); }

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

    // Pass 1: plan the script-path signatures, collecting msg32.
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

    // Approve this exact PSBT + its sign requests (card UV on the first tx,
    // session token afterward — handled inside _approve).
    const signRequests = plan.map((p) => ({
      kind: 'direct',
      input_index: p.idx,
      msg32: bytesToHex(p.msg32),
      client_pk33: bytesToHex(this.clientPk33),
    }));
    const psbtB64 = Buffer.from(txCopy.toPSBT()).toString('base64');

    // Optional human gate: the card has not been touched yet.
    if (this._onPlan) {
      const decision = await this._onPlan({
        psbtB64,
        signRequests,
        plan: plan.map((p) => ({ input_index: p.idx, msg32: bytesToHex(p.msg32) })),
      });
      if (!decision || decision.proceed !== true) throw new PreviewSignal(decision || {});
    }

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

// --- card operations via the Python bridge (PIN through env only) ------------
export async function pythonCardSign(cfg, msg32Hex, approvalToken) {
  const result = await execFileJson(cfg.python, [
    cfg.claimSigner,
    'sign-input',
    '--msg32', msg32Hex,
    '--approval-token', approvalToken,
    '--sign-url', cfg.signUrl,
    '--client-pk33', cfg.cardPk33,
    '--expect-aggregate', cfg.aggregate33,
  ], pinEnv(cfg));
  if (!result.final_signature_verified) {
    throw new Error(`card claim signature did not verify: ${JSON.stringify(result)}`);
  }
  return hexToBytes(result.final_signature64);
}

export function pinEnv(cfg) {
  return cfg.pin ? { NURI_CARD_PIN: cfg.pin } : undefined;
}

// --- receive-claim approval token (also used for plain Ark spends) -----------
let CLAIM_SESSION_TOKEN = null;
export function resetClaimSession() { CLAIM_SESSION_TOKEN = null; }

export async function obtainApprovalToken(cfg, { psbtB64, signRequests }) {
  // Send mode has no receive record; Nuri's approve endpoint is receive-only, so
  // the caller points at a real open receive swap_id to mint a cosign token.
  const swapId = cfg.approveSwapId
    || (cfg.restore
      ? (cfg.restore.swap_id || cfg.restore.response.id)
      : `send-${String(cfg.invoice || cfg.destination || 'ark').slice(0, 20)}`);

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
  ], pinEnv(cfg));

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

// --- Nuri native send (send/prepare -> card WebAuthn -> send/cosign) ---------
// The card's Ark funds are locked to musig2(card, live-Nuri-server). To spend
// them we drive Nuri's real send flow instead of the receive-claim path:
//   1. one send/prepare (strict funding PSBT + sign_requests) -> challenge_token
//   2. one card FIDO2 UV assertion over the prepare challenge
//   3. send/cosign per input: card nonce -> server BIP327 partial -> card
//      finalize -> aggregate. The first cosign is the strict funding cosign;
//      checkpoint txs cosign as follow-ups under the same challenge_token.
let SEND_SESSION = null;
let SEND_COSIGN_DONE = false;
export function resetSendState() { SEND_SESSION = null; SEND_COSIGN_DONE = false; }

export async function prepareNuriSend(cfg, { psbtB64, signRequests }) {
  if (SEND_SESSION) return SEND_SESSION; // checkpoints reuse the funding session
  const s = cfg.sendState;
  if (!s) throw new Error('send state not initialized before prepare');
  const fullPackage = {
    kind: s.kind || 'lightning_invoice',
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
  ], pinEnv(cfg));

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

export function sendSession() { return SEND_SESSION; }

export async function pythonSendCosign(cfg, msg32Hex, session, inputIndex) {
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
  ], pinEnv(cfg));
  SEND_COSIGN_DONE = true;
  if (!result.final_signature_verified) {
    throw new Error(`send cosign did not verify: ${JSON.stringify(result)}`);
  }
  return hexToBytes(result.final_signature64);
}
