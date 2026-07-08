// CardBackedAggregateIdentity for React Native / NFC.
// Implements the @arkade-os/sdk Identity interface.
// The card is the MuSig2 client signer (over NFC), the ASP is the cosigner.
// The phone holds no key material.

import * as btc from '@scure/btc-signer';
import { tapLeafHash } from '@scure/btc-signer/payment.js';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils';
import { musig2SignOverNfc, readCardPubkey, type LogSink } from './musig2Card';

const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

export type AspSignParams = {
  signUrl: string;
  approvalToken: string;
  clientPk33: string;
};

export type CardBackedIdentityConfig = {
  serverPk33: string;        // ASP's public key (from /arkade/info)
  aspSignUrl: string;        // /arkade/sign endpoint
  getApprovalToken: (psbtB64: string, signRequests: any[]) => Promise<string>;
  log?: LogSink;
};

function appendTaprootSighash(sig64: Uint8Array, sighashType: number): Uint8Array {
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

async function postJson(url: string, body: any): Promise<any> {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
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

export class CardBackedAggregateIdentity {
  clientPk33: Uint8Array;
  serverPk33: Uint8Array;
  sortedKeys: Uint8Array[];
  aggregatedPk33: Uint8Array;
  aggregatedXonly: Uint8Array;
  config: CardBackedIdentityConfig;
  log: LogSink;

  constructor(config: CardBackedIdentityConfig) {
    this.config = config;
    this.serverPk33 = hexToBytes(config.serverPk33);
    this.log = config.log || (() => {});
    // clientPk33 is set after reading from the card
    this.clientPk33 = new Uint8Array(33);
    this.sortedKeys = [];
    this.aggregatedPk33 = new Uint8Array(33);
    this.aggregatedXonly = new Uint8Array(32);
  }

  // Call this once after construction, with the card on the NFC reader.
  // Reads the card pubkey. The aggregate is computed after the server pubkey is known.
  async initialize(): Promise<void> {
    const { pubkey } = await readCardPubkey(this.log);
    this.clientPk33 = pubkey;
  }

  async compressedPublicKey(): Promise<Uint8Array> { return this.aggregatedPk33; }
  async xOnlyPublicKey(): Promise<Uint8Array> { return this.aggregatedXonly; }

  signerSession(): any {
    throw new Error('signerSession() not supported for NFC card identity — the card does MuSig2 partials, not tree sessions');
  }

  async signMessage(): Promise<Uint8Array> {
    throw new Error('signMessage() not supported for NFC card identity');
  }

  // The core: sign a Bitcoin transaction using the card (NFC) + ASP (HTTP).
  // The SDK calls this during wallet.send() or swaps.claimVHTLC().
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

    // Pass 1: find the aggregate-key script leaves and compute msg32 for each.
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
      if (!matched) {
        throw new Error(`input ${idx}: no aggregate-key script leaf found`);
      }
    }
    if (!plan.length) throw new Error('no signable inputs for the card aggregate key');

    // Approve: get the approval token (card UV assertion via FIDO2).
    const signRequests = plan.map((p) => ({
      kind: 'direct',
      input_index: p.idx,
      msg32: bytesToHex(p.msg32),
      client_pk33: bytesToHex(this.clientPk33),
    }));
    const psbtB64 = uint8ArrayToBase64(txCopy.toPSBT());
    const approvalToken = await this.config.getApprovalToken(psbtB64, signRequests);

    // Pass 2: for each input, run the MuSig2 round (card over NFC + ASP over HTTP).
    for (const p of plan) {
      const sig64 = await this.cardSign(bytesToHex(p.msg32), approvalToken);
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

  // One MuSig2 round: card (NFC) + ASP (HTTP) → aggregate BIP340 signature.
  private async cardSign(msg32Hex: string, approvalToken: string): Promise<Uint8Array> {
    const msg32 = hexToBytes(msg32Hex);

    const result = await musig2SignOverNfc({
      msg32,
      aggregateXonly: this.aggregatedXonly,
      log: this.log,
      getAspPartial: async (cardPubnonce66: Uint8Array) => {
        const body = {
          approval_token: approvalToken,
          msg32: msg32Hex,
          client_pk33: bytesToHex(this.clientPk33),
          client_pub_nonce: bytesToHex(cardPubnonce66),
          tweak32: '',
        };
        const resp = await postJson(this.config.aspSignUrl, body);
        const serverPk = resp.server_pubkey || resp.server_pubkey33;
        const pubnonce = resp.server_pub_nonce66 || resp.server_pubnonce66;
        const partial = resp.server_partial32;
        if (!serverPk || !pubnonce || !partial) {
          throw new Error(`/arkade/sign response missing fields: ${JSON.stringify(resp)}`);
        }
        return {
          serverPubkey33: hexToBytes(serverPk),
          serverPubnonce66: hexToBytes(pubnonce),
          serverPartial32: hexToBytes(partial),
        };
      },
    });

    return result.finalSignature64;
  }
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
