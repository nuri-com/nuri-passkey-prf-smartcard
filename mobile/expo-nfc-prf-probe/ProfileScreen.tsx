import { useEffect, useState } from 'react';
import { ActivityIndicator, Pressable } from 'react-native';
import { Stack, Scroll, Typography } from './src/ds/primitives';
import { Button } from './src/ds/recipes';
import { colors, space, radius } from './src/ds/tokens';
import { readCardPubkey } from './src/musig2Card';
import { Wallet, InMemoryWalletRepository, InMemoryContractRepository } from '@arkade-os/sdk';
import { ExpoArkProvider, ExpoIndexerProvider } from '@arkade-os/sdk/adapters/expo';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { hexToBytes } from '@noble/curves/abstract/utils';
import { bech32m } from '@scure/base';

type Props = { aspInfoUrl: string; nodeUrl: string; credIdB64u: string };

export function ProfileScreen({ aspInfoUrl, nodeUrl, credIdB64u }: Props) {
  const [cardPk, setCardPk] = useState('');
  const [serverPk, setServerPk] = useState('');
  const [registered, setRegistered] = useState(false);
  const [arkAddress, setArkAddress] = useState('');
  const [balance, setBalance] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function loadCard() {
    setBusy(true); setError(''); setBalance(null);
    try {
      const { pubkey } = await readCardPubkey(() => {});
      const pkHex = pubkeyHex(pubkey);
      setCardPk(pkHex);

      const url = new URL(aspInfoUrl);
      url.searchParams.set('client_pk33', pkHex);
      if (credIdB64u) url.searchParams.set('cred_id_b64u', credIdB64u);
      const res = await fetch(url.toString(), { headers: { accept: 'application/json' } });
      const data = await res.json();
      const sPk = data.server_pubkey || data.asp_pubkey || '';
      setServerPk(sPk || '—');
      setRegistered(data.recovery?.registered === true);
      if (!sPk) throw new Error('ASP info missing server_pubkey');

      const sortedKeys = musig2.sortKeys([pubkey, hexToBytes(sPk)]);
      const aggPk33 = musig2.keyAggregate(sortedKeys).aggPublicKey.toBytes(true);
      const xonly = aggPk33.slice(1);
      const words = [1, ...bech32m.toWords(xonly)];
      setArkAddress(bech32m.encode('bc', words));

      const identity = {
        compressedPublicKey: async () => aggPk33,
        xOnlyPublicKey: async () => xonly,
        signerSession: () => { throw new Error('read-only'); },
        signMessage: () => { throw new Error('read-only'); },
        sign: () => { throw new Error('read-only'); },
      };

      const wallet = await Wallet.create({
        identity: identity as any,
        arkProvider: new ExpoArkProvider(nodeUrl),
        indexerProvider: new ExpoIndexerProvider(nodeUrl),
        storage: { walletRepository: new InMemoryWalletRepository(), contractRepository: new InMemoryContractRepository() },
        settlementConfig: false,
      });

      const bal = await wallet.getBalance();
      setBalance(`${Number(bal?.available ?? 0)} sats (total ${Number(bal?.total ?? 0)})`);
    } catch (e: any) {
      setError(e.message || 'Failed to read card or fetch balance');
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => { loadCard().catch(() => {}); }, []);

  return (
    <Scroll padding="lg" paddingBottom="xl" gap="lg">
      <Stack gap="md" padding="xl" radius="md" chrome="canvas" style={{ borderWidth: 1, borderColor: colors.borderSubtle }}>
        <Typography step="lg" emphasis>Wallet</Typography>
        <Stack gap="2xs">
          <Typography step="xs" emphasis muted>Ark address</Typography>
          <Typography step="xs" style={{ fontFamily: 'Courier', backgroundColor: colors.bgSubtle, padding: space.md, borderRadius: radius.sm, overflow: 'hidden' }}>
            {arkAddress || (busy ? 'Loading…' : '—')}
          </Typography>
        </Stack>
        <Stack gap="2xs">
          <Typography step="xs" emphasis muted>Balance</Typography>
          <Typography step="xl" emphasis>{balance || (busy ? 'Loading…' : '—')}</Typography>
        </Stack>
      </Stack>

      <Stack gap="md" padding="xl" radius="md" chrome="canvas" style={{ borderWidth: 1, borderColor: colors.borderSubtle }}>
        <Typography step="lg" emphasis>Card</Typography>
        <Stack gap="2xs">
          <Typography step="xs" emphasis muted>Card MuSig2 pubkey</Typography>
          <Typography step="xs" style={{ fontFamily: 'Courier', backgroundColor: colors.bgSubtle, padding: space.md, borderRadius: radius.sm, overflow: 'hidden' }}>
            {cardPk || (busy ? 'Reading card…' : '—')}
          </Typography>
        </Stack>
      </Stack>

      <Stack gap="md" padding="xl" radius="md" chrome="canvas" style={{ borderWidth: 1, borderColor: colors.borderSubtle }}>
        <Typography step="lg" emphasis>Arkade</Typography>
        <Stack gap="2xs">
          <Typography step="xs" emphasis muted>ASP server pubkey</Typography>
          <Typography step="xs" style={{ fontFamily: 'Courier' }}>{serverPk || '—'}</Typography>
        </Stack>
        <Stack gap="2xs">
          <Typography step="xs" emphasis muted>Recovery registered</Typography>
          <Typography step="sm">{registered ? 'yes' : 'no'}</Typography>
        </Stack>
      </Stack>

      {busy ? <ActivityIndicator style={{ alignSelf: 'center' }} /> : null}
      {error ? <Typography step="sm" style={{ color: '#a52820', textAlign: 'center' }}>{error}</Typography> : null}

      <Button variant="solid" onPress={loadCard} disabled={busy}>
        {busy ? '…' : 'Refresh (tap card)'}
      </Button>
    </Scroll>
  );
}

function pubkeyHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}