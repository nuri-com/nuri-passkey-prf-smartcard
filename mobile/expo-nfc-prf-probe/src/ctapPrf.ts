import { cbc } from '@noble/ciphers/aes.js';
import { p256 } from '@noble/curves/nist.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { decode, encode } from 'cborg';
import { toByteArray } from 'base64-js';
import NfcManager, { NfcTech } from 'react-native-nfc-manager';

const FIDO_AID = 'A0000006472F0001';
const ZERO_IV = new Uint8Array(16);
const CBOR_DECODE_OPTIONS = { useMaps: true };

export type LogSink = (line: string) => void;

export type ProbeInfo = {
  versions: unknown;
  extensions: unknown;
  options: unknown;
  raw: unknown;
};

export type PrfResult = {
  credentialIdHex: string;
  rpId: string;
  saltHex: string;
  prfHex: string;
  authDataFlagsHex: string;
  authDataHasExtensions: boolean;
};

function utf8(value: string): Uint8Array {
  const encoded = encodeURIComponent(value);
  const bytes: number[] = [];
  for (let i = 0; i < encoded.length; i += 1) {
    if (encoded[i] === '%') {
      bytes.push(Number.parseInt(encoded.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(encoded.charCodeAt(i));
    }
  }
  return new Uint8Array(bytes);
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function hexToBytes(value: string): Uint8Array {
  const clean = value.replace(/[^0-9a-f]/gi, '');
  if (clean.length % 2 !== 0) {
    throw new Error('Hex input has an odd length.');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = Number.parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array | number[]): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export function credentialIdToBytes(value: string): Uint8Array {
  const clean = value.trim();
  if (!clean) {
    throw new Error('Credential ID is empty.');
  }
  if (/^[0-9a-fA-F:\s]+$/.test(clean) && clean.replace(/[^0-9a-fA-F]/g, '').length % 2 === 0) {
    return hexToBytes(clean);
  }
  const base64 = clean.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return new Uint8Array(toByteArray(padded));
}

function mapGet(map: unknown, key: unknown): any {
  if (map instanceof Map) {
    return map.get(key);
  }
  if (typeof map === 'object' && map !== null) {
    return (map as Record<string, unknown>)[String(key)];
  }
  return undefined;
}

function normalize(value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return `h'${bytesToHex(value)}'`;
  }
  if (Array.isArray(value)) {
    return value.map(normalize);
  }
  if (value instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of value.entries()) {
      out[String(key)] = normalize(entry);
    }
    return out;
  }
  if (typeof value === 'object' && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      out[key] = normalize(entry);
    }
    return out;
  }
  return value;
}

function decodeCbor(bytes: Uint8Array): unknown {
  return decode(bytes, CBOR_DECODE_OPTIONS);
}

async function transceive(apdu: Uint8Array, log: LogSink): Promise<{ data: Uint8Array; sw1: number; sw2: number }> {
  log(`> ${bytesToHex(apdu)}`);
  const response = await NfcManager.isoDepHandler.transceive(Array.from(apdu));
  if (response.length < 2) {
    throw new Error('Short APDU response.');
  }
  const sw1 = response[response.length - 2];
  const sw2 = response[response.length - 1];
  const data = new Uint8Array(response.slice(0, -2));
  log(`< ${bytesToHex(data)} ${sw1.toString(16).padStart(2, '0')}${sw2.toString(16).padStart(2, '0')}`);
  return { data, sw1, sw2 };
}

async function exchangeChainedApdu(
  cla: number,
  ins: number,
  p1: number,
  p2: number,
  data: Uint8Array,
  log: LogSink
): Promise<{ data: Uint8Array; sw1: number; sw2: number }> {
  let remaining = data;
  while (remaining.length > 250) {
    const chunk = remaining.slice(0, 250);
    remaining = remaining.slice(250);
    const response = await transceive(concatBytes(new Uint8Array([cla | 0x10, ins, p1, p2, chunk.length]), chunk), log);
    if (response.sw1 !== 0x90 || response.sw2 !== 0x00) {
      return response;
    }
  }

  const body = remaining.length
    ? concatBytes(new Uint8Array([cla, ins, p1, p2, remaining.length]), remaining, new Uint8Array([0x00]))
    : new Uint8Array([cla, ins, p1, p2, 0x00]);
  let response = await transceive(body, log);
  let out = response.data;

  while (response.sw1 === 0x61) {
    response = await transceive(new Uint8Array([0x00, 0xc0, 0x00, 0x00, response.sw2]), log);
    out = concatBytes(out, response.data);
  }

  return { data: out, sw1: response.sw1, sw2: response.sw2 };
}

async function selectFido(log: LogSink): Promise<void> {
  const aid = hexToBytes(FIDO_AID);
  const response = await exchangeChainedApdu(0x00, 0xa4, 0x04, 0x00, aid, log);
  if (response.sw1 !== 0x90 || response.sw2 !== 0x00) {
    throw new Error(`FIDO AID select failed: ${response.sw1.toString(16)}${response.sw2.toString(16)}`);
  }
}

async function callCtapCbor(payload: Uint8Array, log: LogSink): Promise<Uint8Array> {
  let response = await exchangeChainedApdu(0x80, 0x10, 0x80, 0x00, payload, log);
  while (response.sw1 === 0x91 && response.sw2 === 0x00) {
    if (response.data.length > 0) {
      log(`keepalive=${response.data[0]}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
    response = await exchangeChainedApdu(0x80, 0x11, 0x00, 0x00, new Uint8Array(), log);
  }
  if (response.sw1 !== 0x90 || response.sw2 !== 0x00) {
    throw new Error(`CTAP APDU failed: ${response.sw1.toString(16)}${response.sw2.toString(16)}`);
  }
  return response.data;
}

async function sendCbor(cmd: number, args: Map<unknown, unknown> | null, log: LogSink): Promise<unknown> {
  const request = args ? concatBytes(new Uint8Array([cmd]), encode(args)) : new Uint8Array([cmd]);
  const response = await callCtapCbor(request, log);
  if (response.length === 0) {
    throw new Error('Empty CTAP response.');
  }
  const status = response[0];
  if (status !== 0x00) {
    throw new Error(`CTAP status 0x${status.toString(16).padStart(2, '0')}`);
  }
  if (response.length === 1) {
    return new Map();
  }
  return decodeCbor(response.slice(1));
}

async function withIsoDep<T>(operation: () => Promise<T>): Promise<T> {
  if (_nfcOpen) return operation();
  await NfcManager.start();
  await NfcManager.requestTechnology(NfcTech.IsoDep, {
    alertMessage: 'Hold the FIDO2 smartcard near the phone.',
  });
  try {
    return await operation();
  } finally {
    if (!_nfcOpen) await NfcManager.cancelTechnologyRequest({ throwOnError: false });
  }
}

let _nfcOpen = false;
export function setNfcSessionOpen(open: boolean) { _nfcOpen = open; }

export async function readFidoInfo(log: LogSink): Promise<ProbeInfo> {
  return withIsoDep(async () => {
    await selectFido(log);
    const raw = await sendCbor(0x04, null, log);
    return {
      versions: mapGet(raw, 1),
      extensions: mapGet(raw, 2),
      options: mapGet(raw, 4),
      raw: normalize(raw),
    };
  });
}

function aesCbcNoPaddingEncrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return cbc(key, ZERO_IV, { disablePadding: true }).encrypt(plaintext);
}

function aesCbcNoPaddingDecrypt(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return cbc(key, ZERO_IV, { disablePadding: true }).decrypt(ciphertext);
}

async function getSharedSecretV1(log: LogSink): Promise<{ keyAgreement: Map<number, unknown>; sharedSecret: Uint8Array }> {
  const response = await sendCbor(
    0x06,
    new Map([
      [1, 1],
      [2, 2],
    ]),
    log
  );
  const peer = mapGet(response, 1);
  const peerX = mapGet(peer, -2);
  const peerY = mapGet(peer, -3);
  if (!(peerX instanceof Uint8Array) || !(peerY instanceof Uint8Array)) {
    throw new Error('Authenticator returned an invalid P-256 key agreement key.');
  }

  const secretKey = p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(secretKey, false);
  const peerPublicKey = concatBytes(new Uint8Array([0x04]), peerX, peerY);
  const sharedPoint = p256.getSharedSecret(secretKey, peerPublicKey, false);
  const sharedSecret = sha256(sharedPoint.slice(1, 33));
  const keyAgreement = new Map<number, unknown>([
    [1, 2],
    [3, -25],
    [-1, 1],
    [-2, publicKey.slice(1, 33)],
    [-3, publicKey.slice(33, 65)],
  ]);

  return { keyAgreement, sharedSecret };
}

async function getPinUvAuthTokenV1(pin: string, log: LogSink): Promise<Uint8Array> {
  if (!pin) throw new Error('Card PIN is required for user verification.');
  const { keyAgreement, sharedSecret } = await getSharedSecretV1(log);
  const pinHashEnc = aesCbcNoPaddingEncrypt(sharedSecret, sha256(utf8(pin)).slice(0, 16));
  const response = await sendCbor(
    0x06,
    new Map<number, unknown>([
      [1, 1],
      [2, 5],
      [3, keyAgreement],
      [6, pinHashEnc],
    ]),
    log,
  );
  const encryptedToken = mapGet(response, 2);
  if (!(encryptedToken instanceof Uint8Array) || encryptedToken.length === 0) {
    throw new Error('Authenticator returned no PIN UV auth token.');
  }
  return aesCbcNoPaddingDecrypt(sharedSecret, encryptedToken);
}

function webauthnPrfSalt(input: Uint8Array): Uint8Array {
  return sha256(concatBytes(utf8('WebAuthn PRF\0'), input));
}

export async function derivePrfOverNfc(params: {
  rpId: string;
  credentialId: string;
  salt: string;
  log: LogSink;
}): Promise<PrfResult> {
  return withIsoDep(async () => {
    const credentialId = credentialIdToBytes(params.credentialId);
    await selectFido(params.log);
    const { keyAgreement, sharedSecret } = await getSharedSecretV1(params.log);

    const prfSalt = webauthnPrfSalt(utf8(params.salt));
    const saltEnc = aesCbcNoPaddingEncrypt(sharedSecret, prfSalt);
    const saltAuth = hmac(sha256, sharedSecret, saltEnc).slice(0, 16);
    const hmacSecret = new Map<number, unknown>([
      [1, keyAgreement],
      [2, saltEnc],
      [3, saltAuth],
      [4, 1],
    ]);
    const allowList = [
      new Map<string, unknown>([
        ['type', 'public-key'],
        ['id', credentialId],
      ]),
    ];
    const extensions = new Map<string, unknown>([['hmac-secret', hmacSecret]]);
    const clientDataHash = sha256(utf8(`nuri-mobile-prf-probe:${Date.now()}:${params.salt}`));
    const request = new Map<number, unknown>([
      [1, params.rpId],
      [2, clientDataHash],
      [3, allowList],
      [4, extensions],
      [5, new Map<string, unknown>([['up', false]])],
    ]);
    const response = await sendCbor(0x02, request, params.log);
    const authData = mapGet(response, 2);
    if (!(authData instanceof Uint8Array) || authData.length < 37) {
      throw new Error('getAssertion returned invalid authenticatorData.');
    }
    const flags = authData[32];
    const hasExtensions = (flags & 0x80) !== 0;
    if (!hasExtensions) {
      throw new Error('getAssertion succeeded but authenticatorData has no extension data.');
    }
    const extensionData = decodeCbor(authData.slice(37));
    const encryptedOutput = mapGet(extensionData, 'hmac-secret');
    if (!(encryptedOutput instanceof Uint8Array)) {
      throw new Error('No hmac-secret output in authenticatorData extensions.');
    }
    const decrypted = aesCbcNoPaddingDecrypt(sharedSecret, encryptedOutput);
    const prf = decrypted.slice(0, 32);
    if (prf.length !== 32) {
      throw new Error('Invalid PRF output length.');
    }
    return {
      credentialIdHex: bytesToHex(credentialId),
      rpId: params.rpId,
      saltHex: bytesToHex(utf8(params.salt)),
      prfHex: bytesToHex(prf),
      authDataFlagsHex: `0x${flags.toString(16).padStart(2, '0')}`,
      authDataHasExtensions: hasExtensions,
    };
  });
}

// WebAuthn assertion (CTAP2 getAssertion) for the Arkade send/prepare challenge.
// Produces client_data_b64u, auth_data_b64u, sig_b64u — same fields the Python
// bridge returns for the server's send/prepare flow.
export type WebAuthnAssertion = {
  credentialIdB64u: string;
  clientDataB64u: string;
  authDataB64u: string;
  sigB64u: string;
};

export async function webauthnAssert(params: {
  rpId: string;
  origin: string;
  credentialIdB64u: string;
  challengeB64u: string;
  pin: string;
  log?: LogSink;
}): Promise<WebAuthnAssertion> {
  const log = params.log || (() => {});
  return withIsoDep(async () => {
    await selectFido(log);
    const credentialId = credentialIdToBytes(params.credentialIdB64u);
    const challenge = credentialIdToBytes(params.challengeB64u);
    const clientDataJson = JSON.stringify({
      type: 'webauthn.get',
      challenge: params.challengeB64u,
      origin: params.origin,
      crossOrigin: false,
    });
    const clientDataHash = sha256(utf8(clientDataJson));
    log('requesting card PIN UV token...');
    const pinUvAuthToken = await getPinUvAuthTokenV1(params.pin, log);
    const pinUvAuthParam = hmac(sha256, pinUvAuthToken, clientDataHash).slice(0, 16);
    const allowList = [
      new Map<string, unknown>([
        ['type', 'public-key'],
        ['id', credentialId],
      ]),
    ];
    const request = new Map<number, unknown>([
      [1, params.rpId],
      [2, clientDataHash],
      [3, allowList],
      [6, pinUvAuthParam],
      [7, 1],
    ]);
    const response = await sendCbor(0x02, request, log);
    const authData = mapGet(response, 2);
    if (!(authData instanceof Uint8Array) || authData.length < 37) {
      throw new Error('getAssertion returned invalid authenticatorData.');
    }
    const sig = mapGet(response, 3);
    if (!(sig instanceof Uint8Array)) {
      throw new Error('getAssertion returned no signature.');
    }
    return {
      credentialIdB64u: params.credentialIdB64u,
      clientDataB64u: uint8ArrayToB64u(new TextEncoder().encode(clientDataJson)),
      authDataB64u: uint8ArrayToB64u(authData),
      sigB64u: uint8ArrayToB64u(sig),
    };
  });
}

function uint8ArrayToB64u(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
