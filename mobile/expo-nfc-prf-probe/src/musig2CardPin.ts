import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import { prepareDemoSession } from './cardDemoMath';

export const PIN2_AID = '4E5552494D55473201';
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
  if (!/^[\x20-\x7e]{4,12}$/.test(pin)) throw new Error('Enter a 4–12 character ASCII card PIN.');
  const pinBytes = utf8ToBytes(pin);
  pin = '';
  const msg32 = sha256(utf8ToBytes(message));
  try {
    await NfcManager.start();
    status('Hold the card against the back of the phone until finished.');
    await NfcManager.requestTechnology(NfcTech.IsoDep, { alertMessage: 'Hold your Nuri card against the phone.' });
    await exchange(0xa4, new Uint8Array(PIN2_AID.match(/../g)!.map(b => parseInt(b, 16))), 4);
    status('Verifying card PIN…');
    try { await exchange(0x20, pinBytes); } finally { pinBytes.fill(0); }
    const cardPubkey = await exchange(0x03);
    if (cardPubkey.length !== 33) throw new Error('Card returned an invalid public key.');
    const nonces = await exchange(0x40);
    status('Card signing MuSig2 partial…');
    const session = prepareDemoSession(cardPubkey, nonces, msg32);
    const partial = await exchange(0x41, session.payload, 0, 0x20);
    status('Verifying card partial and final BIP340 signature…');
    const result = session.finish(partial);
    return { cardPubkey: hex(cardPubkey), aggregateKey: hex(result.pubkey), signature: hex(result.signature), verified: result.verified, messageHash: hex(msg32) };
  } finally {
    pinBytes.fill(0);
    await NfcManager.cancelTechnologyRequest({ throwOnError: false }).catch(() => {});
  }
}
