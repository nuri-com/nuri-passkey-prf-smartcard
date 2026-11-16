/** Read-only recovery-wallet discovery plus explicit SOFTWARE-ONLY registration.
 * Pure three-leaf construction adapted from nuri-expo (read-only reference):
 * services/arkade/{ArkadeServerDecayPolicy,ArkadeClientRecoveryContract}.ts
 * and internal/recoveryDefaults.ts. No Wallet/send/settle/broadcast API is used.
 */
import { CSVMultisigTapscript, MultisigTapscript, VtxoScript,
  type RelativeTimelock, type VirtualCoin } from '@arkade-os/sdk';
import { keyAggregate, keyAggExport, sortKeys } from '@scure/btc-signer/musig2.js';
import { NETWORK } from '@scure/btc-signer';
import { base64urlnopad, hex } from '@scure/base';
import { p256 } from '@noble/curves/p256.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha256.js';
import { deriveOnchainAddress, validateUtxos } from './onchainWallet';
import { SoftwareCard } from './softwareCard';

const NURI = 'https://arkade.nuri.com/v4/arkade';
const OPERATOR = 'https://arkade.computer';
const ONCHAIN = 'https://mempool.space/api';
type Json = Record<string, any>;
export interface RegistrationEvidence {
  verified: true;
  readbackUrl: string;
  clientPubkey: string;
  credentialId: string;
  credentialPublicKey: string;
  identityId: string;
  credentialFingerprint: string;
  checkedAt: string;
}
export interface SoftwareRegistration {
  clientPubkey: string;
  cred_id_b64u: string;
  cred_pubkey_b64u: string;
  token: string;
  challenge: string;
  rp_id: string;
  origin: string | string[];
  auth: Json;
  evidence: RegistrationEvidence;
}
export interface ArkadeWalletSnapshot {
  arkAddress: string;
  boardingAddress: string;
  onchainAddress: string;
  onchainBalance: number;
  homeBalance: number;
  /** Satoshis: settled + preconfirmed, never includes boarding/recoverable. */
  balance: number;
  total: number;
  clientPubkey: string;
  serverPubkey: string;
  aggregatePubkey: string;
  arkSignerPubkey: string;
  registered: boolean;
  /** false without a known software credential; not a claim of unregistration. */
  registrationKnown: boolean;
  registrationEvidence?: RegistrationEvidence;
  offchainScript: string;
  boardingScript: string;
  settled: number;
  preconfirmed: number;
  recoverable: number;
  boarding: { confirmed: number; unconfirmed: number; total: number };
  vtxos: VirtualCoin[];
  boardingUtxos: Json[];
  checkedAt: string;
  nuriInfo: Json;
  operatorInfo: Json;
  sources: { nuri: string; operator: string; indexer: string; onchain: string; directOnchain: string };
  scope: 'current-live-signer-only';
}
type SoftwareState = {
  secret: Uint8Array; credentialId: string; publicKey: string;
  result?: SoftwareRegistration; pending?: Promise<SoftwareRegistration>;
};
// Credentials and keys are volatile. Never silently rotate a credential on retry.
const software = new Map<string, SoftwareState>();

function clientHex(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 33 || (bytes[0] !== 2 && bytes[0] !== 3)) {
    throw new Error('clientPubkey must be compressed secp256k1 (33 bytes)');
  }
  secp256k1.Point.fromHex(hex.encode(bytes)).assertValidity();
  return hex.encode(bytes);
}
function publicKey(value: unknown): Uint8Array {
  if (typeof value !== 'string' || !/^(02|03)[0-9a-f]{64}$/i.test(value)) throw new Error('Invalid live compressed public key');
  const bytes = hex.decode(value);
  clientHex(bytes);
  return bytes;
}
const READ_TIMEOUT_MS = 10000;
// Native Android fetch permits User-Agent; the operator WAF rejects default clients.
const READ_HEADERS = { Accept: 'application/json', 'User-Agent': 'Mozilla/5.0 NuriWallet/1.0' };
async function request(url: string, body?: Json): Promise<Json> {
  const controller = new AbortController();
  const endpoint = url.split('?')[0], method = body ? 'POST' : 'GET';
  const started = Date.now(), timeout = body ? 25000 : READ_TIMEOUT_MS;
  console.info('[NuriWallet]', method, endpoint);
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, {
      method, signal: controller.signal,
      headers: body ? { ...READ_HEADERS, 'Content-Type': 'application/json' } : READ_HEADERS,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    const reason = controller.signal.aborted ? `timeout after ${timeout}ms` : error instanceof Error ? error.message : String(error);
    throw new Error(`${method} ${endpoint} failed (${Date.now() - started}ms): ${reason}`);
  } finally { clearTimeout(timer); }
}
async function boardingUtxosAt(address: string): Promise<{ utxos: Json; url: string }> {
  const failures: string[] = [];
  // This fallback is ONLY the same read-only Esplora address/utxo query.
  for (const base of [ONCHAIN, 'https://blockstream.info/api']) {
    const url = `${base}/address/${address}/utxo`;
    try {
      const utxos = await request(url);
      if (!Array.isArray(utxos)) throw new Error(`Invalid UTXO response at ${url}`);
      return { utxos, url };
    } catch (error) { failures.push(error instanceof Error ? error.message : String(error)); }
  }
  throw new Error(`Boarding UTXO providers failed: ${failures.join('; ')}`);
}
function infoUrl(client: string, credentialId?: string): string {
  return `${NURI}/info?client_pk33=${client}${credentialId ? `&cred_id_b64u=${encodeURIComponent(credentialId)}` : ''}`;
}
function identityId(client: string): string {
  return hex.encode(sha256(new TextEncoder().encode(`nuri:arkade:v4:identity|${client}`)));
}
function fingerprint(key: string): string {
  return hex.encode(sha256(new TextEncoder().encode(key))).slice(0, 16);
}
function verifyRegistration(info: Json, client: string, state: SoftwareState): void {
  // GET recovery lookup is credential-only: registered=true alone is NOT pair proof.
  if (info.recovery?.registered !== true || info.recovery?.identity_id !== identityId(client)
    || info.recovery?.passkey_pubkey_present !== true
    || info.recovery?.passkey_pubkey_fingerprint !== fingerprint(state.publicKey)
    || info.cosigner_derivation?.client_pubkey !== client) {
    throw new Error('Credential/client registration readback mismatch');
  }
}

/** Create the software signer HERE to authorize registration of only its fresh key.
 * Use the returned SoftwareCard in the UI's existing software signing flow.
 * Hardware keys, externally supplied keys and card credential IDs cannot register.
 */
export async function createSoftwareWallet(): Promise<SoftwareCard> {
  const card = new SoftwareCard();
  const client = clientHex(await card.pubkey());
  const secret = p256.utils.randomPrivateKey();
  software.set(client, { secret,
    credentialId: base64urlnopad.encode(globalThis.crypto.getRandomValues(new Uint8Array(32))),
    publicKey: base64urlnopad.encode(p256.getPublicKey(secret, false)),
  });
  return card;
}

/** The ONLY POST in this module. No real-card registration and no money movement. */
export async function registerSoftwareWallet(clientPubkey: Uint8Array): Promise<SoftwareRegistration> {
  const client = clientHex(clientPubkey);
  const state = software.get(client);
  if (!state) throw new Error('Software registration requires a fresh signer from createSoftwareWallet(); hardware/external keys are read-only');
  if (state.pending) return state.pending;
  state.pending = (async () => {
    // Reuse the same credential even after a lost POST response. Cached successes
    // are GET-verified again, without issuing another auth or creating a record.
    const auth = state.result?.auth ?? await request(`${NURI}/auth`, {
      cred_id_b64u: state.credentialId, cred_pubkey_b64u: state.publicKey,
      client_signer_pubkey: client,
    });
    if (auth.cred_pubkey_b64u !== state.publicKey || typeof auth.token !== 'string'
      || !auth.token || typeof auth.challenge !== 'string' || !auth.challenge
      || typeof auth.rp_id !== 'string' || !auth.rp_id
      || !(typeof auth.origin === 'string' || Array.isArray(auth.origin))) {
      throw new Error('Invalid software auth response');
    }
    verifyRegistration(auth, client, state);
    const url = infoUrl(client, state.credentialId);
    const readback = await request(url);
    verifyRegistration(readback, client, state);
    if (readback.server_pubkey !== auth.server_pubkey) throw new Error('Registration server key changed');
    const evidence: RegistrationEvidence = {
      verified: true, readbackUrl: url, clientPubkey: client,
      credentialId: state.credentialId, credentialPublicKey: state.publicKey,
      identityId: readback.recovery.identity_id,
      credentialFingerprint: readback.recovery.passkey_pubkey_fingerprint,
      checkedAt: new Date().toISOString(),
    };
    return state.result = { clientPubkey: client, cred_id_b64u: state.credentialId,
      cred_pubkey_b64u: state.publicKey, token: auth.token, challenge: auth.challenge,
      rp_id: auth.rp_id, origin: auth.origin, auth, evidence };
  })();
  try { return await state.pending; } finally { state.pending = undefined; }
}

function timelock(value: unknown, type: unknown): RelativeTimelock {
  const n = Number(value);
  if ((type !== 'seconds' && type !== 'blocks') || !Number.isSafeInteger(n) || n <= 0
    || (type === 'seconds' ? n % 512 !== 0 || n / 512 > 65535 : n > 65535)) {
    throw new Error('Live CSV is not exactly BIP68-encodable');
  }
  return { value: BigInt(n), type };
}
function operatorLock(value: unknown): RelativeTimelock {
  // Arkd reports seconds above the BIP68 block limit, blocks otherwise (SDK rule).
  return timelock(value, Number(value) < 512 ? 'blocks' : 'seconds');
}
function script(aggregate: Uint8Array, client: Uint8Array, signer: Uint8Array,
  arkCsv: RelativeTimelock, nuriCsv: RelativeTimelock): VtxoScript {
  if (arkCsv.type !== nuriCsv.type) throw new Error('Mixed recovery CSV units');
  const combined = timelock(Number(arkCsv.value + nuriCsv.value), arkCsv.type);
  return new VtxoScript([
    MultisigTapscript.encode({ pubkeys: [aggregate, signer] }).script,
    CSVMultisigTapscript.encode({ pubkeys: [aggregate], timelock: arkCsv }).script,
    CSVMultisigTapscript.encode({ pubkeys: [client], timelock: combined }).script,
  ]);
}
function sats(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error('Invalid satoshi amount');
  return value;
}
function sum(coins: { value: number }[]): number {
  return sats(coins.reduce((acc, coin) => acc + sats(coin.value), 0));
}
async function scan(scriptHex: string): Promise<VirtualCoin[]> {
  const coins = new Map<string, VirtualCoin>();
  // Use the same SDK REST wire format with bounded, contextual Android fetch.
  // Do not monkeypatch global fetch (concurrent registration may be in flight).
  // Explicit paging: do not silently return a first-page partial balance.
  for (let pageIndex = 1; pageIndex < 10000; pageIndex++) {
    const pageSize = 1000;
    const result = await request(`${OPERATOR}/v1/indexer/vtxos?scripts=${scriptHex}&page.index=${pageIndex}&page.size=${pageSize}`);
    if (!Array.isArray(result.vtxos)) throw new Error('Invalid indexer VTXO response');
    for (const raw of result.vtxos) {
      if (!raw.outpoint || !/^[0-9a-f]{64}$/.test(raw.outpoint.txid)
        || !Number.isSafeInteger(raw.outpoint.vout) || raw.outpoint.vout < 0
        || typeof raw.isSpent !== 'boolean' || typeof raw.isSwept !== 'boolean'
        || typeof raw.isPreconfirmed !== 'boolean' || typeof raw.isUnrolled !== 'boolean'
        || !/^[0-9]+$/.test(String(raw.amount))) throw new Error('Malformed indexer VTXO');
      const coin: VirtualCoin = {
        txid: raw.outpoint.txid, vout: raw.outpoint.vout, value: sats(Number(raw.amount)),
        status: { confirmed: !raw.isSwept && !raw.isPreconfirmed, isLeaf: !raw.isPreconfirmed },
        virtualStatus: { state: raw.isSpent ? 'spent' : raw.isSwept ? 'swept' : raw.isPreconfirmed ? 'preconfirmed' : 'settled',
          commitmentTxIds: raw.commitmentTxids, batchExpiry: raw.expiresAt ? Number(raw.expiresAt) * 1000 : undefined },
        spentBy: raw.spentBy ?? '', settledBy: raw.settledBy, arkTxId: raw.arkTxid,
        createdAt: new Date(Number(raw.createdAt) * 1000), isUnrolled: raw.isUnrolled,
        isSpent: raw.isSpent, script: raw.script,
        assets: raw.assets?.map((a: Json) => ({ assetId: a.assetId, amount: BigInt(a.amount) })),
      };
      if (coin.script !== scriptHex) throw new Error('Indexer returned another script');
      sats(coin.value);
      coins.set(`${coin.txid}:${coin.vout}`, coin);
    }
    if (result.page && (!Number.isSafeInteger(result.page.total) || result.page.total < 0
      || result.page.current !== pageIndex)) throw new Error('Invalid indexer pagination');
    if (!result.page || pageIndex >= result.page.total) return [...coins.values()];
  }
  throw new Error('Indexer pagination limit exceeded');
}

/** Public GET-only discovery. Failure rejects; there is no error-to-zero fallback.
 * No signing capability is required. Only current live signer scripts are scanned;
 * historical rotated-signer contracts are intentionally outside this snapshot.
 */
export type ArkadeReceiveWallet = Pick<ArkadeWalletSnapshot,
  'arkAddress' | 'boardingAddress' | 'onchainAddress' | 'clientPubkey' | 'serverPubkey' | 'aggregatePubkey'
  | 'arkSignerPubkey' | 'registered' | 'registrationKnown' | 'registrationEvidence'
  | 'offchainScript' | 'boardingScript' | 'nuriInfo' | 'operatorInfo' | 'scope'>;

/** Derive current live receive addresses; never queries balances or UTXOs. */
export async function receiveWallet(clientPubkey: Uint8Array): Promise<ArkadeReceiveWallet> {
  const client = clientHex(clientPubkey);
  const state = software.get(client);
  const url = infoUrl(client, state?.credentialId);
  const [nuriInfo, operatorInfo] = await Promise.all([request(url), request(`${OPERATOR}/v1/info`)]);
  if (operatorInfo.network !== 'bitcoin') throw new Error('Expected live Bitcoin mainnet operator');
  if (nuriInfo.nuri_contract_type !== 'nuri_client_recovery_v1'
    || nuriInfo.cosigner_derivation?.client_pubkey !== client
    || nuriInfo.recovery_policy?.server_key_expires !== true) throw new Error('Unsupported recovery contract');
  const server = publicKey(nuriInfo.server_pubkey);
  const arkSigner = publicKey(operatorInfo.signerPubkey);
  const nuriCsv = timelock(nuriInfo.nuri_server_csv?.value, nuriInfo.nuri_server_csv?.type);
  const policyCsv = nuriInfo.recovery_policy?.nuri_server_csv;
  if (policyCsv?.type !== nuriCsv.type || Number(policyCsv?.value) !== Number(nuriCsv.value)) throw new Error('Recovery policy CSV mismatch');
  const aggregate = keyAggExport(keyAggregate(sortKeys([clientPubkey, server])));
  const offchain = script(aggregate, clientPubkey.slice(1), arkSigner.slice(1), operatorLock(operatorInfo.unilateralExitDelay), nuriCsv);
  const boarding = script(aggregate, clientPubkey.slice(1), arkSigner.slice(1), operatorLock(operatorInfo.boardingExitDelay), nuriCsv);
  const onchainAddress = deriveOnchainAddress(clientPubkey, aggregate, nuriCsv);
  const arkAddress = offchain.address('ark', arkSigner.slice(1)).encode();
  const boardingAddress = boarding.onchainAddress(NETWORK);
  const offchainScript = hex.encode(offchain.pkScript), boardingScript = hex.encode(boarding.pkScript);
  let registered = false;
  if (state && nuriInfo.recovery?.registered) { verifyRegistration(nuriInfo, client, state); registered = true; }
  return { arkAddress, boardingAddress, onchainAddress, clientPubkey: client,
    serverPubkey: hex.encode(server), aggregatePubkey: hex.encode(aggregate),
    arkSignerPubkey: hex.encode(arkSigner), registered, registrationKnown: !!state,
    registrationEvidence: registered ? state?.result?.evidence : undefined,
    offchainScript, boardingScript, nuriInfo, operatorInfo, scope: 'current-live-signer-only' };
}

/** Fully accurate balance: any unavailable source rejects, never becomes zero. */
export async function openWallet(clientPubkey: Uint8Array): Promise<ArkadeWalletSnapshot> {
  const receive = await receiveWallet(clientPubkey);
  const { offchainScript, boardingScript, boardingAddress } = receive;
  const [offchainCoins, boardingCoins, onchain, directOnchain] = await Promise.all([
    scan(offchainScript), scan(boardingScript), boardingUtxosAt(boardingAddress),
    boardingUtxosAt(receive.onchainAddress),
  ]);
  const directCoins = validateUtxos(directOnchain.utxos);
  const onchainBalance = sum(directCoins);
  const utxos = onchain.utxos;
  if (!Array.isArray(utxos)) throw new Error('Invalid onchain UTXO response');
  const utxoMap = new Map<string, Json>();
  for (const coin of utxos) {
    if (!/^[0-9a-f]{64}$/.test(coin.txid) || !Number.isSafeInteger(coin.vout) || coin.vout < 0
      || typeof coin.status?.confirmed !== 'boolean') throw new Error('Malformed onchain UTXO');
    sats(coin.value);
    utxoMap.set(`${coin.txid}:${coin.vout}`, coin);
  }
  const boardingUtxos = [...utxoMap.values()];
  const vtxos = [...new Map([...offchainCoins, ...boardingCoins].map(coin => [`${coin.txid}:${coin.vout}`, coin])).values()]
    .filter(coin => !coin.isSpent && !coin.spentBy && !coin.isUnrolled);
  for (const coin of vtxos) {
    if (!['settled', 'preconfirmed', 'swept'].includes(coin.virtualStatus.state)) throw new Error('Unknown VTXO balance state');
  }
  const settled = sum(vtxos.filter(coin => coin.virtualStatus.state === 'settled'));
  const preconfirmed = sum(vtxos.filter(coin => coin.virtualStatus.state === 'preconfirmed'));
  const recoverable = sum(vtxos.filter(coin => coin.virtualStatus.state === 'swept'));
  const confirmed = sum(boardingUtxos.filter(coin => coin.status.confirmed) as { value: number }[]);
  const unconfirmed = sum(boardingUtxos.filter(coin => !coin.status.confirmed) as { value: number }[]);
  return {
    ...receive, balance: sats(settled + preconfirmed),
    onchainBalance, homeBalance: sats(settled + preconfirmed + confirmed + unconfirmed + onchainBalance),
    total: sats(settled + preconfirmed + recoverable + confirmed + unconfirmed + onchainBalance),
    offchainScript, boardingScript, settled, preconfirmed, recoverable,
    boarding: { confirmed, unconfirmed, total: sats(confirmed + unconfirmed) },
    vtxos, boardingUtxos, checkedAt: new Date().toISOString(),
    sources: { nuri: infoUrl(receive.clientPubkey, software.get(receive.clientPubkey)?.credentialId),
      operator: `${OPERATOR}/v1/info`, indexer: `${OPERATOR}/v1/indexer/vtxos`, onchain: onchain.url, directOnchain: directOnchain.url },
    scope: 'current-live-signer-only',
  };
}
