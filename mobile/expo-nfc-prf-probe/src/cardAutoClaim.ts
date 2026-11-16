/** Public-metadata lookup only. Never provisions a credential or writes to a server.
 * Bootstrap is intentionally unavailable: createCardWalletCredential does not
 * expose the challenge-bound attestation required by register-bootstrap/attestation.
 * Do not substitute the legacy name-claim endpoint for that ceremony.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { fromByteArray, toByteArray } from 'base64-js';

const API = 'https://arkade.nuri.com/v4/arkade';
export const CARD_PROFILE_STORAGE_DEPENDENCY =
  'Public card profile is not persisted: @react-native-async-storage/async-storage is not installed. Install it with npx expo install @react-native-async-storage/async-storage, rebuild the native app, and wire durable public-profile storage before relying on restore after restart.';

/** The public hint exposes an ID, not necessarily the credential's COSE key.
 * This is lookup metadata, NOT a CardCredential or proof of card possession.
 */
export type AutoClaimCredential = {
  credentialIdB64u: string;
  credentialPublicKeyB64u?: string;
  rpId: 'nuri.com';
  origin: 'https://arkade.nuri.com';
};
export type AutoClaimCardResult = {
  name: string;
  username: string;
  credential: AutoClaimCredential;
  clientPubkey: string;
  claimed: false;
  persisted: false;
  persistenceWarning: string;
};

async function readJson(url: string): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(url, {
      method: 'GET', redirect: 'error', signal: controller.signal,
      headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
    });
    if (!response.ok) throw new Error(`Card profile lookup failed (HTTP ${response.status}); no claim attempted`);
    const data: unknown = await response.json();
    if (!data || typeof data !== 'object' || Array.isArray(data) || (data as Record<string, unknown>).error) {
      throw new Error('Invalid card profile lookup response; no claim attempted');
    }
    return data as Record<string, unknown>;
  } finally { clearTimeout(timer); }
}

function publicId(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error('Credential hint is missing a valid public credential ID');
  }
  const bytes = toByteArray(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
  if (!bytes.length || fromByteArray(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') !== value) {
    throw new Error('Credential hint contains a noncanonical credential ID');
  }
  return value;
}

/** The caller supplies the runtime GET_PUBKEY result; no KEYGEN or PC/SC here.
 * PIN is accepted for API compatibility but never read, persisted or transmitted.
 * Missing username does not authorize guessing a name or retrying a write.
 * No bootstrap ceremony runs until a challenge-bound makeCredential attestation,
 * fresh assertion-scoped PIN token, verified signature, and durable public handle
 * can all be retained safely. Existing aliases can still be discovered.
 */
export async function autoClaimCard(
  clientPubkey: string,
  _pin: string,
  onStatus: (status: string) => void = () => {},
): Promise<AutoClaimCardResult> {
  if (!/^(02|03)[0-9a-fA-F]{64}$/.test(clientPubkey)) {
    throw new Error('clientPubkey must be the runtime compressed 33-byte secp256k1 public key');
  }
  secp256k1.ProjectivePoint.fromHex(clientPubkey).assertValidity();
  onStatus('Looking up card name');
  const query = `client_signer_pubkey=${encodeURIComponent(clientPubkey)}`;
  const info = await readJson(`${API}/info?${query}`);
  if (info.username === undefined || info.username === null || info.username === '') {
    throw new Error('Automatic card bootstrap unavailable: signer-only lookup returned no username (this does not prove the card is unclaimed). This build cannot safely perform challenge-bound attestation with a fresh PIN token after makeCredential and durable credential storage. No credential was created and no name was claimed.');
  }
  if (typeof info.username !== 'string' || !/^[a-z0-9_]{3,32}$/.test(info.username)) {
    throw new Error('Card lookup returned an invalid username; no claim attempted');
  }
  const name = info.username;
  onStatus('Loading public card credential');
  const hint = await readJson(`${API}/lnurl/credential-hint/${encodeURIComponent(name)}`);
  if (hint.username !== name) throw new Error('Credential hint username does not match the card lookup');
  const credentialIdB64u = publicId(hint.credential_id_b64u);
  // Re-read with BOTH identifiers: /info binds an alias to credential + signer.
  const bound = await readJson(`${API}/info?${query}&cred_id_b64u=${encodeURIComponent(credentialIdB64u)}`);
  if (bound.username !== name) throw new Error('Card signer and credential alias binding was not confirmed');
  const credential: AutoClaimCredential = {
    credentialIdB64u, rpId: 'nuri.com', origin: 'https://arkade.nuri.com',
  };
  // credential-hint intentionally does not expose a public key. Never manufacture
  // one, or label a server SPKI value as the COSE key expected by approval code.
  onStatus(CARD_PROFILE_STORAGE_DEPENDENCY);
  return {
    name, username: name, credential, clientPubkey,
    claimed: false, persisted: false,
    persistenceWarning: CARD_PROFILE_STORAGE_DEPENDENCY,
  };
}
