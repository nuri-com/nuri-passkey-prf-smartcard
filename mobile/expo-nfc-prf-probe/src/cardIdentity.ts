// Public credential hints only. AsyncStorage is not installed in this demo;
// keep the known-card fallback in memory, never persist card secrets here.
export const knownCards: Record<string, string> = {
  '02b935bfc0d6d379243205d5c110732400cc8ae82e2fe94d6384963c7c9a62cae6':
    'SUulp_FdnSxmGnT_KExCDld8_Ibwt1NOw1AlLau0xsKs8th4iw0sXrvcwHjHAwidXkbJYxzhk1R3WB5gP1GQTY65PbDUpQq2G969WwHhf_23f6upE7cHbUa2a9iWy0HPMSX29OelLq5w4Qr62BVIPg',
};

export function cardInfoUrl(clientPubkey: string): string {
  const query = new URLSearchParams({ client_pk33: clientPubkey });
  const credential = knownCards[clientPubkey];
  if (credential) query.set('cred_id_b64u', credential);
  return `https://arkade.nuri.com/v4/arkade/info?${query}`;
}

export function displayUsername(username: unknown): string {
  if (typeof username !== 'string' || !username.trim()) return '';
  return '@' + username.trim().replace(/^@/, '').replace(/@nuri\.com$/, '');
}

export function displayBalance(balance: number): string {
  return balance.toLocaleString('en-US') + ' sats';
}
