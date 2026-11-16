import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import { encode, decode } from 'cborg';
import { fromByteArray, toByteArray } from 'base64-js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { cbc } from '@noble/ciphers/aes.js';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import { webauthnAssert, bytesToHex, setNfcSessionOpen } from './ctapPrf';
import { PIN2_AID } from './musig2CardPin';

/** Approval only: no cosign, transaction signing, broadcast, swap or completion calls. */
export type CardCredential = {
  credentialIdB64u: string;
  /** CBOR-encoded COSE EC2 ES256 public key, NOT a MuSig2 key. */
  credentialPublicKeyB64u: string;
  rpId: string;
  origin: string;
};
export type CardApprovalOptions = {
  credential: CardCredential;
  /** FIDO2 PIN; never logged or persisted by this adapter. */
  pin: string;
  onStatus?: (status: string) => void;
  /** Optional injectable fetch for isolated tests. */
  fetch?: typeof fetch;
};
export type CardNameClaimOptions = CardApprovalOptions & {
  username: string;
  /** HTTPS origin only, e.g. https://arkade.nuri.com (no /v4 suffix). */
  signerOrigin: string;
  /** Optional MuSig2 PIN. GET_PUBKEY itself does not require VERIFY. */
  signerPin?: string;
};
export type CardNameClaimResult = {
  username: string;
  lightningAddress?: string;
  clientSignerPubkey: string;
  response: Record<string, unknown>;
};
export type CardSpendRequest = {
  kind: 'direct';
  input_index: number;
  msg32: string;
  tweak32?: string;
};
export type CardSpendApprovalOptions = CardApprovalOptions & {
  /** Exact HTTPS endpoints; only /send/prepare and /spend/approve are accepted. */
  prepareUrl: string;
  approveUrl: string;
  sendIntentId: string;
  psbtB64: string;
  requests: CardSpendRequest[];
  approvalSummary: {
    kind: string;
    title: string;
    recipient: string;
    amount_sats: number;
    final_amount_sats?: number;
    payment_hash?: string;
    note?: string;
    source?: string;
  };
};
export type CardSpendApprovalResult = {
  approvalToken: string;
  challengeToken: string;
  clientSignerPubkey: string;
  canonicalSendSummary?: unknown;
  expiresAtMs?: number;
};

const utf8 = (text: string) => new TextEncoder().encode(text);
const b64u = (bytes: Uint8Array) => fromByteArray(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function unb64u(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) throw new Error('Invalid unpadded base64url');
  const result = toByteArray(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4));
  if (b64u(result) !== text) throw new Error('Noncanonical base64url');
  return result;
}
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let pos = 0; for (const part of parts) { out.set(part, pos); pos += part.length; }
  return out;
};
function required(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) throw new Error(`Missing or invalid ${field}`);
  return value;
}
function checkProfile(credential: CardCredential) {
  unb64u(credential.credentialIdB64u);
  const key = decode(unb64u(credential.credentialPublicKeyB64u), { useMaps: true });
  if (!(key instanceof Map) || key.get(1) !== 2 || key.get(3) !== -7 || key.get(-1) !== 1) throw new Error('Credential requires an ES256 COSE public key');
  const x = key.get(-2), y = key.get(-3);
  if (!(x instanceof Uint8Array) || x.length !== 32 || !(y instanceof Uint8Array) || y.length !== 32) throw new Error('Invalid credential public key');
  p256.ProjectivePoint.fromHex(concat(new Uint8Array([4]), x, y));
  const origin = new URL(credential.origin);
  if (origin.protocol !== 'https:' || origin.origin !== credential.origin || !(origin.hostname === credential.rpId || origin.hostname.endsWith(`.${credential.rpId}`))) throw new Error('Credential origin does not match RP ID');
}
function endpoint(value: string, path: string) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== path) throw new Error(`Expected HTTPS ${path} endpoint`);
  return url.toString();
}
async function post(options: CardApprovalOptions, url: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
  const response = await (options.fetch ?? fetch)(url, {
    method: 'POST', redirect: 'error', headers: { 'content-type': 'application/json', 'x-arkade-client': 'nuri-card-nfc', 'x-arkade-sdk': 'nuri-card-nfc' },
    body: JSON.stringify(body), signal: AbortSignal.timeout(30000),
  });
  const data: unknown = await response.json();
  if (!response.ok || !data || typeof data !== 'object' || Array.isArray(data) || (data as Record<string, unknown>).error) throw new Error(`Card approval request failed (HTTP ${response.status})`);
  return data as Record<string, unknown>;
}
async function assertion(options: CardApprovalOptions, challenge: Record<string, unknown>) {
  if (challenge.rp_id !== options.credential.rpId) throw new Error('Server challenge RP ID mismatch');
  const origins = required(challenge.origin, 'origin').split(',').map(value => value.trim());
  if (!origins.includes(options.credential.origin)) throw new Error('Server challenge origin mismatch');
  const value = required(challenge.challenge, 'challenge'); unb64u(value);
  options.onStatus?.('Verify with your card PIN. Hold card to phone');
  // Never forward the CTAP APDU logger to UI: it includes credential/assertion data.
  const proof = await webauthnAssert({ ...options.credential, challengeB64u: value, pin: options.pin });
  return { client_data_b64u: proof.clientDataB64u, auth_data_b64u: proof.authDataB64u, sig_b64u: proof.sigB64u };
}

let active = false;
async function withCard<T>(status: CardApprovalOptions['onStatus'], operation: () => Promise<T>): Promise<T> {
  if (active) throw new Error('Another card approval is in progress');
  active = true;
  try {
    await NfcManager.start(); status?.('Hold card to phone');
    await NfcManager.requestTechnology(NfcTech.IsoDep, { isReaderModeEnabled: true, readerModeFlags: 0x81, readerModeDelay: 5000 });
    setNfcSessionOpen(true);
    return await operation();
  } finally {
    setNfcSessionOpen(false);
    await NfcManager.cancelTechnologyRequest({ throwOnError: false }).catch(() => {});
    active = false;
  }
}
async function apdu(cla: number, ins: number, p1: number, data = new Uint8Array(0)): Promise<Uint8Array> {
  async function exchange(command: Uint8Array) {
    const result = await NfcManager.isoDepHandler.transceive(Array.from(command));
    if (result.length < 2) throw new Error('Short card response');
    return { data: new Uint8Array(result.slice(0, -2)), sw: (result[result.length - 2] << 8) | result[result.length - 1] };
  }
  let rest = data;
  while (rest.length > 250) {
    const r = await exchange(concat(new Uint8Array([cla | 0x10, ins, p1, 0, 250]), rest.slice(0, 250)));
    if (r.sw !== 0x9000) throw new Error(`Card APDU failed (${r.sw.toString(16)})`);
    rest = rest.slice(250);
  }
  let r = await exchange(rest.length ? concat(new Uint8Array([cla, ins, p1, 0, rest.length]), rest, new Uint8Array([0])) : new Uint8Array([cla, ins, p1, 0, 0]));
  for (let i = 0; r.sw === 0x9100 && cla === 0x80; i++) {
    if (i >= 1200) throw new Error('Card CTAP operation timed out');
    await new Promise(resolve => setTimeout(resolve, 100));
    r = await exchange(new Uint8Array([0x80, 0x11, 0, 0, 0]));
  }
  let out = r.data;
  for (let i = 0; (r.sw >>> 8) === 0x61; i++) {
    if (i >= 32) throw new Error('Too many card response fragments');
    r = await exchange(new Uint8Array([0, 0xc0, 0, 0, r.sw & 255])); out = concat(out, r.data);
  }
  if (r.sw !== 0x9000) throw new Error(`Card APDU failed (${r.sw.toString(16)}); do not retry PIN automatically`);
  return out;
}
async function runtimeSignerPubkey(pin?: string): Promise<string> {
  const aid = new Uint8Array(PIN2_AID.match(/../g)!.map((byte: string) => parseInt(byte, 16)));
  await apdu(0, 0xa4, 4, aid);
  if (pin !== undefined) {
    if (!/^[\x20-\x7e]{4,12}$/.test(pin)) throw new Error('MuSig2 PIN must be 4–12 ASCII characters');
    const bytes = utf8(pin); try { await apdu(0, 0x20, 0, bytes); } finally { bytes.fill(0); }
  }
  const key = await apdu(0, 3, 0); // Runtime GET_PUBKEY, never KEYGEN/nonces/FINALIZE.
  if (key.length !== 33 || (key[0] !== 2 && key[0] !== 3)) throw new Error('Invalid card MuSig2 public key');
  secp256k1.ProjectivePoint.fromHex(key);
  return bytesToHex(key);
}

/** Existing real-card credential metadata must come from createCardWalletCredential
 * or a previously saved card profile. An assertion proves card possession to server.
 * Explicit user action only: calling this function registers the requested name.
 */
export async function claimCardWalletName(options: CardNameClaimOptions): Promise<CardNameClaimResult> {
  checkProfile(options.credential);
  if (!/^[a-z0-9_]{3,32}$/.test(options.username)) throw new Error('Name must be 3–32 lowercase letters, numbers or underscores');
  const origin = new URL(options.signerOrigin);
  if (origin.origin !== options.signerOrigin) throw new Error('signerOrigin must be an HTTPS origin only');
  const authUrl = endpoint(`${options.signerOrigin}/v4/arkade/auth`, '/v4/arkade/auth');
  const registerUrl = endpoint(`${options.signerOrigin}/v4/arkade/lnurl/register`, '/v4/arkade/lnurl/register');
  return withCard(options.onStatus, async () => {
    const clientSignerPubkey = await runtimeSignerPubkey(options.signerPin);
    options.onStatus?.('Requesting name claim challenge');
    const auth = await post(options, authUrl, { cred_id_b64u: options.credential.credentialIdB64u, cred_pubkey_b64u: options.credential.credentialPublicKeyB64u, client_signer_pubkey: clientSignerPubkey });
    const token = required(auth.token, 'token');
    const proof = await assertion(options, auth);
    options.onStatus?.('Claiming name');
    const response = await post(options, registerUrl, { token, username: options.username, client_pk33: clientSignerPubkey, ...proof });
    if (response.username !== options.username) throw new Error('Name claim response does not confirm requested username');
    options.onStatus?.('Name claimed');
    return { username: options.username, lightningAddress: typeof response.lightning_address === 'string' ? response.lightning_address : undefined, clientSignerPubkey, response };
  });
}

/** Legacy /spend/approve adapter. Current nuri-expo uses prepare→assert→cosign;
 * this intentionally stops at approval and never calls cosign or sign.
 * Caller must supply a previously created intent and exact PSBT/signing requests.
 */
export async function prepareCardSpendApproval(options: CardSpendApprovalOptions): Promise<CardSpendApprovalResult> {
  checkProfile(options.credential);
  const preparePath = new URL(options.prepareUrl).pathname;
  if (!['/api/arkade/send/prepare', '/v4/arkade/send/prepare'].includes(preparePath)) throw new Error('Expected /api/arkade/send/prepare or /v4/arkade/send/prepare');
  const prepareUrl = endpoint(options.prepareUrl, preparePath);
  const approveUrl = endpoint(options.approveUrl, '/v4/arkade/spend/approve');
  required(options.sendIntentId, 'sendIntentId'); required(options.psbtB64, 'psbtB64');
  if (!options.requests.length || options.requests.some(r => r.kind !== 'direct' || !Number.isSafeInteger(r.input_index) || r.input_index < 0 || !/^[0-9a-fA-F]{64}$/.test(r.msg32) || (r.tweak32 !== undefined && !/^[0-9a-fA-F]{64}$/.test(r.tweak32)))) throw new Error('Invalid direct signing requests');
  if (!Number.isSafeInteger(options.approvalSummary.amount_sats) || options.approvalSummary.amount_sats <= 0) throw new Error('Invalid approval amount');
  // Freeze caller-owned payload before any asynchronous work.
  const summary = { ...options.approvalSummary };
  const requests = options.requests.map(r => ({ ...r }));
  const psbt = options.psbtB64, intent = options.sendIntentId;
  return withCard(options.onStatus, async () => {
    const clientSignerPubkey = await runtimeSignerPubkey();
    const payload = { cred_id_b64u: options.credential.credentialIdB64u, client_signer_pubkey: clientSignerPubkey, route_scope: 'direct_send_session', approval_scope: 'direct_send_session', approval_summary: summary, psbt_b64: psbt, send_intent_id: intent, sign_requests: requests.map(r => ({ ...r, client_pk33: clientSignerPubkey })) };
    options.onStatus?.('Preparing spend approval');
    const prepared = await post(options, prepareUrl, payload);
    const challengeToken = required(prepared.challenge_token, 'challenge_token');
    if (typeof prepared.expires_at_ms === 'number' && prepared.expires_at_ms <= Date.now()) throw new Error('Spend challenge expired');
    const proof = await assertion(options, prepared);
    options.onStatus?.('Submitting approval only');
    const approved = await post(options, approveUrl, { ...payload, token: challengeToken, challenge_token: challengeToken, assertion_cred_id_b64u: options.credential.credentialIdB64u, ...proof });
    return { approvalToken: required(approved.approval_token, 'approval_token'), challengeToken, clientSignerPubkey, canonicalSendSummary: prepared.canonical_send_summary, expiresAtMs: typeof prepared.expires_at_ms === 'number' ? prepared.expires_at_ms : undefined };
  });
}

/** Creates a genuine ES256 FIDO2 credential via NFC CTAP2 makeCredential.
 * This modifies only the card, not the server. Save the returned public metadata;
 * never recreate a credential automatically on login or network failure.
 * PIN protocol 1 matches ctapPrf.ts; no PIN initialization/reset or automatic retry.
 */
export async function createCardWalletCredential(options: { rpId: string; origin: string; userId: Uint8Array; userName: string; pin: string; onStatus?: (status: string) => void }): Promise<CardCredential> {
  if (!options.pin || options.userId.length < 1 || options.userId.length > 64) throw new Error('PIN and 1–64 byte user ID required');
  const origin = new URL(options.origin);
  if (origin.protocol !== 'https:' || origin.origin !== options.origin || !(origin.hostname === options.rpId || origin.hostname.endsWith(`.${options.rpId}`))) throw new Error('Origin/RP mismatch');
  return withCard(options.onStatus, async () => {
    await apdu(0, 0xa4, 4, new Uint8Array([0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1]));
    async function ctap(command: number, fields: Map<number, unknown>): Promise<Map<unknown, unknown>> {
      const response = await apdu(0x80, 0x10, 0x80, concat(new Uint8Array([command]), encode(fields)));
      if (!response.length || response[0] !== 0) throw new Error(`CTAP failed (${response[0]?.toString(16)}); no automatic retry`);
      const data = decode(response.slice(1), { useMaps: true });
      if (!(data instanceof Map)) throw new Error('Malformed CTAP response'); return data;
    }
    const agreement = await ctap(6, new Map<number, unknown>([[1, 1], [2, 2]]));
    const peer = agreement.get(1);
    if (!(peer instanceof Map)) throw new Error('Missing PIN key agreement');
    const x = peer.get(-2), y = peer.get(-3);
    if (!(x instanceof Uint8Array) || x.length !== 32 || !(y instanceof Uint8Array) || y.length !== 32) throw new Error('Invalid PIN key agreement');
    const secret = p256.utils.randomPrivateKey();
    const publicKey = p256.getPublicKey(secret, false);
    const shared = sha256(p256.getSharedSecret(secret, concat(new Uint8Array([4]), x, y), false).slice(1, 33)); secret.fill(0);
    const agreementKey = new Map<number, unknown>([[1, 2], [3, -25], [-1, 1], [-2, publicKey.slice(1, 33)], [-3, publicKey.slice(33)]]);
    let token: Uint8Array | undefined;
    try {
      const encrypted = cbc(shared, new Uint8Array(16), { disablePadding: true }).encrypt(sha256(utf8(options.pin)).slice(0, 16));
      const pinResponse = await ctap(6, new Map<number, unknown>([[1, 1], [2, 5], [3, agreementKey], [6, encrypted]]));
      const encryptedToken = pinResponse.get(2);
      if (!(encryptedToken instanceof Uint8Array)) throw new Error('Missing PIN token');
      token = cbc(shared, new Uint8Array(16), { disablePadding: true }).decrypt(encryptedToken);
      const challenge = p256.utils.randomPrivateKey();
      const hash = sha256(utf8(JSON.stringify({ type: 'webauthn.create', challenge: b64u(challenge), origin: options.origin, crossOrigin: false })));
      options.onStatus?.('Creating card credential');
      const result = await ctap(1, new Map<number, unknown>([[1, hash], [2, { id: options.rpId, name: 'Nuri' }], [3, { id: options.userId, name: options.userName, displayName: options.userName }], [4, [{ type: 'public-key', alg: -7 }]], [7, { rk: false }], [8, hmac(sha256, token, hash).slice(0, 16)], [9, 1]]));
      const auth = result.get(2);
      if (!(auth instanceof Uint8Array) || auth.length < 55 || !(auth[32] & 0x40) || !(auth[32] & 4) || bytesToHex(auth.slice(0, 32)) !== bytesToHex(sha256(utf8(options.rpId)))) throw new Error('Invalid makeCredential authenticator data');
      const length = (auth[53] << 8) | auth[54];
      if (!length || auth.length <= 55 + length) throw new Error('Missing credential ID/key');
      if (auth[32] & 0x80) throw new Error('Unexpected makeCredential extensions');
      const credential = { credentialIdB64u: b64u(auth.slice(55, 55 + length)), credentialPublicKeyB64u: b64u(auth.slice(55 + length)), rpId: options.rpId, origin: options.origin };
      checkProfile(credential); return credential;
    } finally { shared.fill(0); token?.fill(0); }
  });
}
