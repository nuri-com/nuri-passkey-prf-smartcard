import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import { prepareDemoSession } from './cardDemoMath';

export const PIN2_AID = process.env.EXPO_PUBLIC_NURI_CARD_AID || '4E5552494D55473301';
if (!/^[0-9A-Fa-f]{10,32}$/.test(PIN2_AID) || PIN2_AID.length % 2) throw new Error('Invalid configured card AID');
export interface CardSigner {
  pubkey(): Promise<Uint8Array>;
  nonces(): Promise<Uint8Array>;
  finalize(payload: Uint8Array): Promise<Uint8Array>;
}
export async function withPinCard<T>(pin: string, status: (text: string) => void, operation: (card: CardSigner) => Promise<T>): Promise<T> {
  if (pin && !/^[\x20-\x7e]{4,12}$/.test(pin)) throw new Error('Check PIN');
  const secret = utf8ToBytes(pin); pin = '';
  try {
    await NfcManager.start(); status('Hold card to phone');
    let timer: ReturnType<typeof setTimeout> | undefined;
    try { await Promise.race([
      NfcManager.requestTechnology(NfcTech.IsoDep, { isReaderModeEnabled: true, readerModeFlags: 0x1 | 0x80, readerModeDelay: 5000 }),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('No card found. Try again.')), 30000); }),
    ]); } finally { clearTimeout(timer); }
    await (NfcManager as any).setTimeout?.(15000);
    await exchange(0xa4, new Uint8Array(PIN2_AID.match(/../g)!.map((b: string) => parseInt(b, 16))), 4);
    if (secret.length) await exchange(0x20, secret); secret.fill(0);
    return await operation({ pubkey: () => exchange(0x03), nonces: () => exchange(0x40),
      finalize: (payload) => { if (payload.length !== 231) throw new Error('Invalid signing payload'); return exchange(0x41, payload, 0, 0x20); } });
  } finally { secret.fill(0); await NfcManager.cancelTechnologyRequest({ throwOnError: false }).catch(() => {}); }
}
export const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
};

export class CardStatusError extends Error {
  triesLeft?: number;
  constructor(operation: string, sw1: number, sw2: number) {
    const tries = sw1 === 0x63 && (sw2 & 0xf0) === 0xc0 ? sw2 & 0x0f : undefined;
    super(tries !== undefined ? `Incorrect PIN. PIN tries left: ${tries}.` : `${operation} failed (SW ${sw1.toString(16).padStart(2, '0')}${sw2.toString(16).padStart(2, '0')}).`);
    this.triesLeft = tries;
  }
}

// Deliberately no APDU logging: VERIFY carries the PIN in cleartext to the card.
async function transceive(apdu: Uint8Array) {
  const response = await NfcManager.isoDepHandler.transceive(Array.from(apdu));
  if (response.length < 2) throw new Error('Short card response.');
  return { data: new Uint8Array(response.slice(0, -2)), sw1: response[response.length - 2], sw2: response[response.length - 1] };
}
async function exchange(ins: number, data: Uint8Array = new Uint8Array(0), p1 = 0, le = 0) {
  let remaining = data;
  while (remaining.length > 250) {
    const chunk = remaining.slice(0, 250);
    remaining = remaining.slice(250);
    const r = await transceive(concat(new Uint8Array([0x10, ins, p1, 0, chunk.length]), chunk));
    if (r.sw1 !== 0x90 || r.sw2 !== 0) throw new CardStatusError('APDU chain', r.sw1, r.sw2);
  }
  const apdu = remaining.length ? concat(new Uint8Array([0, ins, p1, 0, remaining.length]), remaining, new Uint8Array([le])) : new Uint8Array([0, ins, p1, 0, le]);
  let r = await transceive(apdu);
  let out = r.data;
  for (let count = 0; r.sw1 === 0x61; count++) {
    if (count >= 32) throw new Error('Too many GET RESPONSE fragments.');
    r = await transceive(new Uint8Array([0, 0xc0, 0, 0, r.sw2]));
    out = concat(out, r.data);
  }
  if (r.sw1 !== 0x90 || r.sw2 !== 0) throw new CardStatusError(ins === 0x20 ? 'VERIFY PIN' : `INS ${ins.toString(16)}`, r.sw1, r.sw2);
  return out;
}

export async function signCardDemo(message: string, pin: string, status: (text: string) => void) {
  if (pin && !/^[\x20-\x7e]{4,12}$/.test(pin)) throw new Error('Check PIN');
  const pinBytes = utf8ToBytes(pin);
  pin = '';
  const msg32 = sha256(utf8ToBytes(message));
  const pinCopy = () => pinBytes.slice();
  try {
    await NfcManager.start();
    let lastError: unknown;
    for (let attempt = 1; attempt <= 1; attempt++) {
      status(attempt === 1 ? 'Hold card to phone' : 'Hold card still');
      try { return await runOnce(msg32, pinCopy(), status); }
      catch (error) {
        lastError = error;
        if (!(error instanceof Error) || !/lost|transceive|IOException/i.test(error.message)) throw error;
        await NfcManager.cancelTechnologyRequest({ throwOnError: false }).catch(() => {});
      }
    }
    throw lastError instanceof Error && /lost|transceive/i.test(lastError.message) ? new Error('Card lost. Keep it on the phone and try again.') : lastError;
  } finally {
    pinBytes.fill(0);
    await NfcManager.cancelTechnologyRequest({ throwOnError: false }).catch(() => {});
  }
}

async function runOnce(msg32: Uint8Array, pinBytes: Uint8Array, status: (text: string) => void) {
  try {
    // Reader mode, NFC-A, skip NDEF probe; slow presence checks so they don't drop the card mid-APDU.
    const tag = NfcManager.requestTechnology(NfcTech.IsoDep, { isReaderModeEnabled: true, readerModeFlags: 0x1 | 0x80, readerModeDelay: 5000 });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('No card found. Try again.')), 30000); });
    try { await Promise.race([tag, timeout]); } finally { clearTimeout(timer); }
    await (NfcManager as any).setTimeout?.(15000)?.catch?.(() => {});
    await exchange(0xa4, new Uint8Array(PIN2_AID.match(/../g)!.map((b: string) => parseInt(b, 16))), 4);
    status('Checking PIN');
    await exchange(0x20, pinBytes);
    const cardPubkey = await exchange(0x03);
    if (cardPubkey.length !== 33) throw new Error('Card returned an invalid public key.');
    const nonces = await exchange(0x40);
    status("Signing. Keep card on phone, about 80 s");
    const session = prepareDemoSession(cardPubkey, nonces, msg32);
    const partial = await exchange(0x41, session.payload, 0, 0x20);
    status('Verifying');
    const result = session.finish(partial);
    return { cardPubkey: hex(cardPubkey), aggregateKey: hex(result.pubkey), signature: hex(result.signature), verified: result.verified, messageHash: hex(msg32) };
  } finally {
    pinBytes.fill(0);
  }
}
