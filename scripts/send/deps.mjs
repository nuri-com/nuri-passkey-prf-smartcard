import * as sdk from '@arkade-os/sdk';
import * as musig from '@scure/btc-signer/musig2.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { tapLeafHash } from '@scure/btc-signer/payment.js';
export { sdk, musig, schnorr, tapLeafHash };
export { JsonRpcProvider, EtherscanProvider } from 'ethers';
export { finalizeSession, SoftwareCardSigner, deriveAddresses } from '../arkade-card-e2e.mjs';
export const hex = b => Buffer.from(b).toString('hex');
export const bytes = h => {
 if (typeof h !== 'string' || !/^(?:[0-9a-fA-F]{2})*$/.test(h)) throw new Error('invalid hex');
 return Uint8Array.from(Buffer.from(h, 'hex'));
};
