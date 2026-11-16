#!/usr/bin/env node
/**
 * Claim an Arkade reverse-swap Lightning receive into the card's 2-of-2 Ark
 * balance, using the real card as the MuSig2 client signer.
 *
 * Reuses @arkade-os/sdk + @arkade-os/boltz-swap for all tx construction and
 * ASP submission (claimVHTLC). The bespoke part lives in
 * scripts/lib/card-arkade-identity.mjs (also used by the Chrome-extension
 * bridge scripts/ext-card-wallet.mjs):
 *   - client partial : the physical card (scripts/card-arkade-claim-signer.py)
 *   - server partial : the live Nuri /arkade/sign or /arkade/send/cosign
 *   - approval       : one card FIDO2 UV assertion (scripts/card-prf-backup.py)
 *
 * Config is read as JSON from stdin. Result JSON is printed to stdout.
 */
import { Buffer } from 'node:buffer';
import { bytesToHex } from '@noble/curves/utils.js';
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
import {
  CardBackedAggregateIdentity,
  execFileJson,
  obtainApprovalToken,
  postJson,
  prepareNuriSend,
  pythonCardSign,
  pythonSendCosign,
  sendSession,
} from './lib/card-arkade-identity.mjs';

// The offchain claim path does not stream batch events, but guard anyway.
if (!globalThis.EventSource) {
  try { globalThis.EventSource = (await import('eventsource')).EventSource; } catch { /* not needed for offchain claim */ }
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
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
  return requireBytes(result.final_signature64);
}

function requireBytes(hex) {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

// Ark -> Lightning submarine swap, funded by a card+Nuri MuSig2 spend, then
// consumed with send/complete. "Funded" is not merchant settlement; callers
// must label that boundary honestly.
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
    kind: 'lightning_invoice',
    send_intent_id: sendIntentId,
    final_recipient: invoice,
    final_amount_sats: finalAmountSats,
    funding_address: lockup,
    funding_script_hex: fundingScriptHex,
    funding_amount_sats: fundingAmount,
    payment_hash: paymentHash,
    invoice,
  };

  // Subscribe before broadcast so the one mempool/funded event cannot race
  // past a WebSocket that was opened afterward.
  const fundedResult = swaps.waitForSwapFunded(pending).then(
    () => ({ ok: true }),
    (error) => ({ ok: false, error }),
  );

  // Fund the lockup (triggers identity.sign -> prepare/assert/cosign).
  const txid = await wallet.send({ address: lockup, amount: fundingAmount });

  // Consume the verified intent immediately after broadcast. A failed complete
  // request is a failed send flow, not a successful result with an error field.
  const complete = await postJson(cfg.completeUrl, {
    challenge_token: sendSession()?.challenge_token,
    send_intent_id: sendIntentId,
    txid,
  });

  const funded = await fundedResult;
  if (!funded.ok) {
    const message = funded.error instanceof Error ? funded.error.message : String(funded.error);
    throw new Error(`swap funding monitor failed: ${message}`);
  }

  return {
    status: 'NURI_CARD_ARKADE_SEND_OK',
    card_client_pk33: cfg.cardPk33,
    server_pk33: cfg.serverPk33,
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
  const mode = String(cfg.mode || '');
  if (!['balance', 'claim', 'send'].includes(mode)) throw new Error('mode must be balance, claim, or send');
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

  const nodeUrl = String(cfg.nodeUrl || '').trim();
  if (!nodeUrl) throw new Error('nodeUrl is required');
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
    const balance = await wallet.getBalance();
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
    if (cfg.boltzNetwork !== 'bitcoin') throw new Error('boltzNetwork must be bitcoin');
    const swaps = await ArkadeSwaps.create({
      wallet,
      swapProvider: new BoltzSwapProvider({ network: cfg.boltzNetwork }),
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

  if (!r || !r.swap_id || !Number.isFinite(Number(r.created_at_unix))) {
    throw new Error('claim restore requires swap_id and created_at_unix');
  }
  if (cfg.boltzNetwork !== 'bitcoin') throw new Error('boltzNetwork must be bitcoin');
  const swaps = await ArkadeSwaps.create({
    wallet,
    swapProvider: new BoltzSwapProvider({ network: cfg.boltzNetwork }),
    swapRepository: new InMemorySwapRepository(),
    swapManager: false,
  });

  const pendingSwap = {
    id: r.swap_id,
    type: 'reverse',
    createdAt: r.created_at_unix,
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
