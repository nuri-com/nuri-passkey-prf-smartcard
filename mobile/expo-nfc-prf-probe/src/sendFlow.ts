// Nuri native send: Ark -> Lightning submarine swap, signed by the card
// over NFC + the live Nuri ASP over HTTP. Mirrors the server's
// sendLightningNuri in scripts/card-arkade-claim.mjs, but the card partial
// comes from the NFC MuSig2 applet instead of the Python bridge.

import * as btc from '@scure/btc-signer';
import { tapLeafHash } from '@scure/btc-signer/payment.js';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils';
import {
  Wallet,
  InMemoryWalletRepository,
  InMemoryContractRepository,
} from '@arkade-os/sdk';
import { ExpoArkProvider, ExpoIndexerProvider } from '@arkade-os/sdk/adapters/expo';
import {
  ArkadeSwaps,
  BoltzSwapProvider,
  InMemorySwapRepository,
  getInvoicePaymentHash,
  getInvoiceSatoshis,
} from '@arkade-os/boltz-swap';
import { ArkAddress } from '@arkade-os/sdk';
import { musig2SignOverNfc, readCardPubkey, type LogSink } from './musig2Card';
import { webauthnAssert } from './ctapPrf';

// ponytail: the phone holds no key. The card is the MuSig2 client signer
// (NFC), the ASP is the cosigner (HTTP). Ceiling: the applet has no PIN gate
// on the MuSig2 applet yet (FIDO2 UV is separate), documented in
// docs/tap-to-pay-concept.md.

export type SendConfig = {
  // ASP endpoints (from /arkade/info)
  aspSignUrl: string;         // https://arkade.nuri.com/v4/arkade/sign
  aspAuthUrl: string;         // https://arkade.nuri.com/v4/arkade/auth
  aspInfoUrl: string;         // https://arkade.nuri.com/v4/arkade/info
  intentUrl: string;          // https://arkade.nuri.com/v4/arkade/swap-intent/create
  prepareUrl: string;         // https://nuri.com/api/arkade/send/prepare
  cosignUrl: string;          // https://nuri.com/api/arkade/send/cosign
  completeUrl: string;        // https://nuri.com/api/arkade/send/complete
  nodeUrl: string;            // https://arkade.computer
  boltzNetwork: string;       // 'bitcoin'
  // Card receive credential (from the profile)
  credIdB64u: string;
  credPubkeyB64u: string;
  rpId: string;
  origin: string;
  pin: string;
  log?: LogSink;
};

export type SendResult = {
  status: string;
  invoice: string;
  send_intent_id: string;
  swap_id: string;
  funding_amount_sats: number;
  final_amount_sats: number;
  ark_txid: string;
  ark_address: string;
  complete: any;
};

function uint8ArrayToB64u(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uToUint8Array(b64u: string): Uint8Array {
  const base64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function postJson(url: string, body: any): Promise<any> {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-arkade-client': 'nuri-card-nfc',
      'x-arkade-sdk': 'nuri-card-nfc',
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data: any;
  try { data = JSON.parse(text); } catch { throw new Error(`${url} returned non-JSON: ${text.slice(0, 300)}`); }
  if (!res.ok) throw new Error(`${url} HTTP ${res.status}: ${data.error || data.reason || text.slice(0, 300)}`);
  return data;
}

// --- Card-backed MuSig2 identity for the SDK Wallet ---------------------------

export class NfcCardIdentity {
  clientPk33: Uint8Array;
  serverPk33: Uint8Array;
  sortedKeys: Uint8Array[];
  aggregatedPk33: Uint8Array;
  aggregatedXonly: Uint8Array;
  cfg: SendConfig;
  log: LogSink;
  sendState: any = null;
  sendSession: any = null;
  sendCosignDone = false;

  constructor(cfg: SendConfig, serverPk33: string) {
    this.cfg = cfg;
    this.log = cfg.log || (() => {});
    this.serverPk33 = hexToBytes(serverPk33);
    this.clientPk33 = new Uint8Array(33);
    this.sortedKeys = [];
    this.aggregatedPk33 = new Uint8Array(33);
    this.aggregatedXonly = new Uint8Array(32);
  }

  async initialize(): Promise<void> {
    const { pubkey } = await readCardPubkey(this.log);
    this.clientPk33 = pubkey;
    this.log(`card pubkey: ${bytesToHex(this.clientPk33)}`);
    // Don't compute aggregate yet — serverPk33 is still a placeholder.
    // The real aggregate is computed in sendLightning after ASP info.
  }

  async compressedPublicKey(): Promise<Uint8Array> { return this.aggregatedPk33; }
  async xOnlyPublicKey(): Promise<Uint8Array> { return this.aggregatedXonly; }

  signerSession(): any {
    throw new Error('signerSession() not supported for NFC card identity');
  }

  async signMessage(): Promise<Uint8Array> {
    throw new Error('signMessage() not supported for NFC card identity');
  }

  // The SDK calls this during wallet.send(). It finds the aggregate-key
  // script leaves, computes msg32, gets the approval token (card UV + prepare),
  // then runs the MuSig2 round for each input (card NFC + ASP HTTP).
  async sign(tx: any, inputIndexes?: number[]): Promise<any> {
    const txCopy = tx.clone();
    const targets = Array.isArray(inputIndexes)
      ? [...inputIndexes]
      : [...Array(txCopy.inputsLength).keys()];

    const prevScripts: any[] = [];
    const prevAmounts: bigint[] = [];
    for (let i = 0; i < txCopy.inputsLength; i += 1) {
      const input = txCopy.getInput(i);
      prevScripts.push(input?.witnessUtxo?.script || new Uint8Array());
      prevAmounts.push(input?.witnessUtxo?.amount || 0n);
    }

    // Pass 1: find aggregate-key script leaves, compute msg32.
    const plan: any[] = [];
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
          let decoded: any[] = [];
          try { decoded = btc.Script.decode(leafScript); } catch { continue; }
          if (!scriptContainsXOnly(decoded, this.aggregatedXonly)) continue;
          const msg32 = txCopy.preimageWitnessV1(
            idx, prevScripts, sighashType, prevAmounts, undefined, leafScript, leafVersion,
          );
          plan.push({ idx, msg32, leafScript, leafVersion, sighashType });
          matched = true;
          break;
        }
      }
      if (!matched) throw new Error(`input ${idx}: no aggregate-key script leaf found`);
    }
    if (!plan.length) throw new Error('no signable inputs for the card aggregate key');

    // Approve: send/prepare + card FIDO2 UV assertion.
    const signRequests = plan.map((p) => ({
      kind: 'direct',
      input_index: p.idx,
      msg32: bytesToHex(p.msg32),
      client_pk33: bytesToHex(this.clientPk33),
    }));
    const psbtB64 = uint8ArrayToB64u(txCopy.toPSBT());
    const session = await this.prepareNuriSend(psbtB64, signRequests);

    // Pass 2: card+ASP sign each input.
    for (const p of plan) {
      const sig64 = await this.cardSign(bytesToHex(p.msg32), session, p.idx);
      const leafSig = appendSighash(sig64, p.sighashType);
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

  // send/prepare -> challenge_token + challenge. Then one card FIDO2 UV
  // assertion over the challenge. Returns the session used for cosign.
  private async prepareNuriSend(psbtB64: string, signRequests: any[]): Promise<any> {
    if (this.sendSession) return this.sendSession;
    const s = this.sendState;
    if (!s) throw new Error('send state not initialized before prepare');

    const fullPackage = {
      kind: 'lightning_invoice',
      cred_id_b64u: this.cfg.credIdB64u,
      client_signer_pubkey: bytesToHex(this.clientPk33),
      send_intent_id: s.send_intent_id,
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

    this.log('send/prepare...');
    const prep = await postJson(this.cfg.prepareUrl, fullPackage);
    if (!prep.challenge_token || !prep.challenge) {
      throw new Error(`send/prepare failed: ${JSON.stringify(prep)}`);
    }

    // Card FIDO2 UV assertion over the prepare challenge.
    this.log('card UV assertion...');
    const assertion = await webauthnAssert({
      rpId: this.cfg.rpId,
      origin: this.cfg.origin,
      credentialIdB64u: this.cfg.credIdB64u,
      challengeB64u: prep.challenge,
      log: this.log,
    });

    const corePackage: any = { ...fullPackage };
    corePackage.psbt_b64 = undefined;
    corePackage.sign_requests = undefined;

    this.sendSession = {
      challenge_token: prep.challenge_token,
      fullPackage,
      corePackage,
      assertion: {
        client_data_b64u: assertion.clientDataB64u,
        auth_data_b64u: assertion.authDataB64u,
        sig_b64u: assertion.sigB64u,
      },
    };
    return this.sendSession;
  }

  // One MuSig2 round: card (NFC) + ASP (HTTP via send/cosign) -> aggregate sig.
  private async cardSign(msg32Hex: string, session: any, inputIndex: number): Promise<Uint8Array> {
    const firstCosign = !this.sendCosignDone;
    const msg32 = hexToBytes(msg32Hex);

    const result = await musig2SignOverNfc({
      msg32,
      aggregateXonly: this.aggregatedXonly,
      log: this.log,
      getAspPartial: async (cardPubnonce66: Uint8Array) => {
        const context = {
          challenge_token: session.challenge_token,
          server_pk33: bytesToHex(this.serverPk33),
          client_pk33: bytesToHex(this.clientPk33),
          send_package: firstCosign ? session.fullPackage : session.corePackage,
          assertion: firstCosign ? session.assertion : null,
        };
        const body = {
          msg32: msg32Hex,
          input_index: inputIndex,
          client_pub_nonce66: bytesToHex(cardPubnonce66),
          context,
        };
        this.log('send/cosign...');
        const resp = await postJson(this.cfg.cosignUrl, body);
        const serverPk = resp.server_pubkey || resp.server_pubkey33;
        const pubnonce = resp.server_pub_nonce66 || resp.server_pubnonce66;
        const partial = resp.server_partial32;
        if (!serverPk || !pubnonce || !partial) {
          throw new Error(`send/cosign response missing fields: ${JSON.stringify(resp).slice(0, 300)}`);
        }
        return {
          serverPubkey33: hexToBytes(serverPk),
          serverPubnonce66: hexToBytes(pubnonce),
          serverPartial32: hexToBytes(partial),
        };
      },
    });

    this.sendCosignDone = true;
    return result.finalSignature64;
  }
}

function appendSighash(sig64: Uint8Array, sighashType: number): Uint8Array {
  if (sighashType === btc.SigHash.DEFAULT) return sig64;
  const out = new Uint8Array(sig64.length + 1);
  out.set(sig64, 0);
  out[sig64.length] = sighashType & 0xff;
  return out;
}

function scriptContainsXOnly(scriptOps: any[], xOnlyPubkey: Uint8Array): boolean {
  const xOnlyHex = bytesToHex(xOnlyPubkey);
  for (const op of scriptOps) {
    if (!(op instanceof Uint8Array)) continue;
    if (op.length === 32 && bytesToHex(op) === xOnlyHex) return true;
    if (op.length === 33 && bytesToHex(op.slice(1)) === xOnlyHex) return true;
  }
  return false;
}

// --- The send: Ark -> Lightning submarine swap -------------------------------

export async function sendLightning(cfg: SendConfig, invoice: string): Promise<SendResult> {
  const log = cfg.log || (() => {});

  // Open NFC once and keep it open for the entire flow.
  log('Hold card on phone — starting...');
  const NfcManager = (await import('react-native-nfc-manager')).default;
  const { NfcTech } = await import('react-native-nfc-manager');
  const { setNfcSessionOpen: setMusig2Open } = await import('./musig2Card');
  const { setNfcSessionOpen: setCtapOpen } = await import('./ctapPrf');
  await NfcManager.start();
  await NfcManager.requestTechnology(NfcTech.IsoDep, {
    alertMessage: 'Hold the Nuri card near the phone for the entire payment.',
  });
  setMusig2Open(true);
  setCtapOpen(true);

  try {
  // 1. Read the card pubkey first (needed for /arkade/info)
  log('reading card pubkey...');
  const identity = new NfcCardIdentity(cfg, '00'.repeat(33));
  await identity.initialize();

  // 2. Get the ASP server pubkey from /arkade/info?client_pk33=<cardPk>
  log('fetching ASP info...');
  const infoUrl = new URL(cfg.aspInfoUrl);
  infoUrl.searchParams.set('client_pk33', bytesToHex(identity.clientPk33));
  if (cfg.credIdB64u) infoUrl.searchParams.set('cred_id_b64u', cfg.credIdB64u);
  const infoRes = await fetch(infoUrl.toString(), { headers: { accept: 'application/json' } });
  const infoText = await infoRes.text();
  let info: any;
  try { info = JSON.parse(infoText); } catch { throw new Error(`/arkade/info returned non-JSON: ${infoText.slice(0, 300)}`); }
  if (!infoRes.ok) throw new Error(`/arkade/info HTTP ${infoRes.status}: ${info.error || infoText.slice(0, 200)}`);

  const serverPk33 = info.server_pubkey || info.asp_pubkey;
  if (!serverPk33) throw new Error(`ASP info missing server_pubkey: ${JSON.stringify(info).slice(0, 300)}`);
  log(`ASP server pubkey: ${serverPk33}`);

  // 3. Now set the real server pubkey and recompute the aggregate
  identity.serverPk33 = hexToBytes(serverPk33);
  identity.sortedKeys = musig2.sortKeys([identity.clientPk33, identity.serverPk33]);
  identity.aggregatedPk33 = musig2.keyAggregate(identity.sortedKeys).aggPublicKey.toBytes(true);
  identity.aggregatedXonly = identity.aggregatedPk33.slice(1);

  // 3. Create the SDK wallet
  log('creating wallet...');
  const wallet = await Wallet.create({
    identity: identity as any,
    arkProvider: new ExpoArkProvider(cfg.nodeUrl),
    indexerProvider: new ExpoIndexerProvider(cfg.nodeUrl),
    storage: {
      walletRepository: new InMemoryWalletRepository(),
      contractRepository: new InMemoryContractRepository(),
    },
    settlementConfig: false,
  });

  // 4. Create the Boltz submarine swap
  log('creating submarine swap...');
  const swaps = await ArkadeSwaps.create({
    wallet,
    swapProvider: new BoltzSwapProvider({ network: (cfg.boltzNetwork || 'bitcoin') as any }),
    swapRepository: new InMemorySwapRepository(),
    swapManager: false,
  });

  const pending = await swaps.createSubmarineSwap({ invoice });
  const lockup = pending.response.address;
  const fundingAmount = pending.response.expectedAmount;
  if (!lockup || !fundingAmount) throw new Error(`submarine swap missing lockup/amount: ${JSON.stringify(pending.response)}`);
  const decodedLockup = ArkAddress.decode(lockup);
  const lockupPkScript = decodedLockup.pkScript;
  const fundingScriptHex = bytesToHex(lockupPkScript);
  const paymentHash = getInvoicePaymentHash(invoice);
  const finalAmountSats = getInvoiceSatoshis(invoice);
  log(`swap created: lockup=${lockup}, funding=${fundingAmount} sats`);

  // 5. Create the swap intent on the ASP
  log('creating swap intent...');
  const intentRes = await postJson(cfg.intentUrl, {
    kind: 'lightning_invoice',
    cred_id_b64u: cfg.credIdB64u,
    client_signer_pubkey: bytesToHex(identity.clientPk33),
    final_recipient: invoice,
    final_amount_sats: finalAmountSats,
    funding_address: lockup,
    funding_script_hex: fundingScriptHex,
    funding_amount_sats: fundingAmount,
    payment_hash: paymentHash,
    invoice,
  });
  const sendIntentId = intentRes?.intent?.id;
  if (!sendIntentId) throw new Error(`swap-intent/create failed: ${JSON.stringify(intentRes).slice(0, 300)}`);
  log(`intent: ${sendIntentId}`);

  identity.sendState = {
    send_intent_id: sendIntentId,
    final_recipient: invoice,
    final_amount_sats: finalAmountSats,
    funding_address: lockup,
    funding_script_hex: fundingScriptHex,
    funding_amount_sats: fundingAmount,
    payment_hash: paymentHash,
    invoice,
  };

  // 6. Fund the lockup (triggers identity.sign -> prepare/assert/cosign)
  log('funding lockup (card signing)...');
  const txid = await wallet.send({ address: lockup, amount: fundingAmount });
  log(`funding txid: ${txid}`);

  // 7. Optimistic: wait for funded
  try { await swaps.waitForSwapFunded(pending); } catch { /* optimistic */ }

  // 8. Complete the intent
  let complete: any = null;
  try {
    complete = await postJson(cfg.completeUrl, {
      challenge_token: identity.sendSession?.challenge_token,
      send_intent_id: sendIntentId,
      txid,
    });
  } catch (e: any) { complete = { error: e.message }; }

  const address = await wallet.getAddress();
  return {
    status: 'NURI_CARD_ARKADE_SEND_OK',
    invoice,
    send_intent_id: sendIntentId,
    swap_id: pending.id,
    funding_amount_sats: fundingAmount,
    final_amount_sats: finalAmountSats,
    ark_txid: txid,
    ark_address: address,
    complete,
  };
  } finally {
    setMusig2Open(false);
    setCtapOpen(false);
    await NfcManager.cancelTechnologyRequest({ throwOnError: false });
  }
}
