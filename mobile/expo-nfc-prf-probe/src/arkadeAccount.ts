import { webauthnAssert, type LogSink } from './ctapPrf';

export type AuthenticatedLightningAccount = {
  username: string;
  lightningAddress: string;
};

type AccountParams = {
  authUrl: string;
  statusUrl: string;
  credentialIdB64u: string;
  credentialPublicKeyB64u: string;
  clientPublicKey33Hex: string;
  expectedServerPublicKey33Hex: string;
  rpId: string;
  origin: string;
  pin: string;
  log?: LogSink;
};

export async function readAuthenticatedLightningAccount(
  params: AccountParams,
): Promise<AuthenticatedLightningAccount> {
  // The caller has already required /arkade/info recovery.registered=true.
  // This auth call therefore authenticates an existing exact binding; it is
  // never used as an implicit registration attempt.
  const auth = await postJson(params.authUrl, {
    cred_id_b64u: params.credentialIdB64u,
    cred_pubkey_b64u: params.credentialPublicKeyB64u,
    client_signer_pubkey: params.clientPublicKey33Hex,
  });
  const token = typeof auth?.token === 'string' ? auth.token.trim() : '';
  const challenge = typeof auth?.challenge === 'string' ? auth.challenge.trim() : '';
  if (!token || !challenge) throw new Error('Nuri Arkade auth returned no account challenge');
  if (auth.rp_id !== params.rpId) throw new Error('Nuri Arkade auth returned a different RP ID');
  const allowedOrigins = typeof auth.origin === 'string'
    ? auth.origin.split(',').map((value: string) => value.trim()).filter(Boolean)
    : [];
  if (!allowedOrigins.includes(params.origin)) {
    throw new Error('Nuri Arkade auth does not allow the credential profile origin');
  }
  const authServerKey = typeof auth.server_pubkey === 'string' ? auth.server_pubkey.trim().toLowerCase() : '';
  if (authServerKey !== params.expectedServerPublicKey33Hex.toLowerCase()) {
    throw new Error('Nuri Arkade auth returned a different server public key');
  }

  const assertion = await webauthnAssert({
    rpId: params.rpId,
    origin: params.origin,
    credentialIdB64u: params.credentialIdB64u,
    challengeB64u: challenge,
    pin: params.pin,
    log: params.log,
  });
  const status = await postJson(params.statusUrl, {
    token,
    client_signer_pubkey: params.clientPublicKey33Hex,
    client_data_b64u: assertion.clientDataB64u,
    auth_data_b64u: assertion.authDataB64u,
    sig_b64u: assertion.sigB64u,
  });
  const username = typeof status?.username === 'string' ? status.username.trim() : '';
  const lightningAddress = typeof status?.lightning_address === 'string' ? status.lightning_address.trim() : '';
  if (status?.registered !== true || !username || !lightningAddress) {
    throw new Error('Nuri Arkade returned no registered Lightning username for this card credential');
  }
  return { username, lightningAddress };
}

async function postJson(url: string, body: unknown): Promise<any> {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-arkade-client': 'nuri-card-nfc',
      'x-arkade-sdk': 'nuri-card-nfc',
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let data: any;
  try { data = JSON.parse(text); } catch { throw new Error(`${url} returned non-JSON: ${text.slice(0, 300)}`); }
  if (!response.ok) throw new Error(`${url} HTTP ${response.status}: ${data.error || data.details || text.slice(0, 300)}`);
  if (data?.error) throw new Error(String(data.error));
  return data;
}
