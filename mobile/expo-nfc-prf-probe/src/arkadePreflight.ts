/** Read-only send preflight and a separate NON-BROADCAST signer proof.
 * No transaction construction, submission, settlement or broadcast capability.
 */
import { ArkAddress } from '@arkade-os/sdk';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha256.js';
import { hex } from '@scure/base';
import { openWallet, type ArkadeWalletSnapshot } from './arkadeWallet';
import { prepareDemoSession } from './cardDemoMath';
import type { CardSigner } from './musig2CardPin';

const PROOF_MESSAGE = 'Nuri Card demo signer proof v1 — NON-BROADCAST; not a transaction or payment authorization.';
type Log = (message: string) => void;
const same = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);

function checkedPubkey(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 33 || (value[0] !== 2 && value[0] !== 3)) {
    throw new Error('Invalid signer public key: expected compressed secp256k1');
  }
  secp256k1.Point.fromBytes(value).assertValidity();
  return value.slice();
}
function checkedHexPubkey(value: string): Uint8Array {
  if (typeof value !== 'string' || !/^(02|03)[0-9a-f]{64}$/i.test(value)) {
    throw new Error('Invalid wallet public key');
  }
  return checkedPubkey(hex.decode(value));
}
function checkedDestination(destination: string): ArkAddress {
  if (typeof destination !== 'string' || !destination || destination !== destination.trim()) {
    throw new Error('Invalid Ark destination address');
  }
  try {
    const address = ArkAddress.decode(destination);
    if (address.hrp !== 'ark' || address.version !== 0) throw new Error('Expected mainnet Ark version 0');
    // SDK decoding checks checksum/length; also reject non-curve x coordinates.
    for (const key of [address.serverPubKey, address.vtxoTaprootKey]) {
      const compressed = new Uint8Array(33);
      compressed[0] = 2; compressed.set(key, 1);
      checkedPubkey(compressed);
    }
    return address;
  } catch {
    throw new Error('Invalid Ark destination address (expected Bitcoin mainnet Ark version 0)');
  }
}
function sats(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

/** Always rejects: zero wallets reach insufficient funds; funded wallets remain
 * disabled even when sufficient. Only openWallet's public GET discovery is used.
 * No nonce generation or signing occurs in this path. Errors remain errors rather
 * than being converted into a zero balance or a fabricated submitted state.
 */
export async function preflightSend(
  snapshot: ArkadeWalletSnapshot, destination: string, amount: number,
  signer: CardSigner, log: Log = () => {},
): Promise<never> {
  const recipient = checkedDestination(destination);
  if (!Number.isSafeInteger(amount) || amount <= 0) {
    throw new Error('Amount must be a positive safe integer in satoshis');
  }
  const client = checkedPubkey(await signer.pubkey());
  if (!same(client, checkedHexPubkey(snapshot.clientPubkey))) {
    throw new Error('Signer public key does not match wallet snapshot');
  }
  log('Refreshing live wallet balance (read-only)');
  const live = await openWallet(client);
  if (!same(client, checkedHexPubkey(live.clientPubkey))) {
    throw new Error('Live wallet public key does not match signer');
  }
  const operator = checkedHexPubkey(live.arkSignerPubkey).slice(1);
  if (!same(recipient.serverPubKey, operator)) {
    throw new Error('Ark destination belongs to a different operator');
  }
  if (!sats(live.balance) || !sats(live.total) || live.total < live.balance) {
    throw new Error('Invalid live wallet balance');
  }
  log(`Live spendable balance: ${live.balance} sats; total including recovery/boarding: ${live.total} sats`);
  if (live.total === 0) {
    throw new Error(`Insufficient funds: need ${amount} sats, available ${live.balance} sats. No transaction created or broadcast.`);
  }
  // Even recovery-only/boarding-only funds trigger the funded-wallet stop.
  throw new Error('Demo broadcasting disabled: funded wallet detected. No transaction created, signed, submitted, settled or broadcast.');
}

/** Independent cryptographic proof, NOT a Nuri server co-sign or Arkade payment.
 * prepareDemoSession uses an ephemeral LOCAL cosigner. The message is fixed and
 * domain-separated from any transaction; finalize receives exactly 231 bytes.
 */
export async function proveSigner(signer: CardSigner) {
  const cardPubkey = checkedPubkey(await signer.pubkey());
  const messageHash = sha256(new TextEncoder().encode(PROOF_MESSAGE));
  const session = prepareDemoSession(cardPubkey, await signer.nonces(), messageHash);
  if (session.payload.length !== 231) throw new Error('Signer proof requires a 231-byte finalize payload');
  const result = session.finish(await signer.finalize(session.payload));
  if (!result.verified || result.signature.length !== 64 || result.pubkey.length !== 32
    || !schnorr.verify(result.signature, messageHash, result.pubkey)) {
    throw new Error('Signer proof aggregate Schnorr verification failed');
  }
  return {
    cardPubkey: hex.encode(cardPubkey), aggregateKey: hex.encode(result.pubkey),
    signature: hex.encode(result.signature), messageHash: hex.encode(messageHash),
    message: PROOF_MESSAGE, verified: true as const, payloadBytes: 231 as const,
    cosigner: 'ephemeral-local-demo' as const, nuriServerCosigned: false as const,
    broadcast: false as const,
  };
}
