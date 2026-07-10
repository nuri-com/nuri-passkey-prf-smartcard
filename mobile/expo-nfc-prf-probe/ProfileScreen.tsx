import { useState } from 'react';
import { ActivityIndicator } from 'react-native';
import { View, Stack, Scroll, Text, Button } from '@nuri/rn';
import { readCardPubkey } from './src/musig2Card';
import { Wallet, InMemoryWalletRepository, InMemoryContractRepository } from '@arkade-os/sdk';
import { ExpoArkProvider, ExpoIndexerProvider } from '@arkade-os/sdk/adapters/expo';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { hexToBytes } from '@noble/curves/abstract/utils';
import { bech32m } from '@scure/base';

type Props = { aspInfoUrl: string; nodeUrl: string; credIdB64u: string };

// The card's Nuri account — card@nuri.com is the LNURL receive address
// registered on the Nuri server for this card's MuSig2 aggregate key.
const ACCOUNT_NAME = 'Nuri';
const LIGHTNING_ADDRESS = 'card@nuri.com';

export function ProfileScreen({ aspInfoUrl, nodeUrl, credIdB64u }: Props) {
  const [cardPk, setCardPk] = useState('');
  const [serverPk, setServerPk] = useState('');
  const [registered, setRegistered] = useState(false);
  const [arkAddress, setArkAddress] = useState('');
  const [balance, setBalance] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [loaded, setLoaded] = useState(false);

  async function loadCard() {
    setBusy(true); setError(''); setBalance(null);
    try {
      // 1. Read card pubkey via NFC
      const { pubkey } = await readCardPubkey(() => {});
      const pkHex = pubkeyHex(pubkey);
      setCardPk(pkHex);

      // 2. Fetch ASP info
      const url = new URL(aspInfoUrl);
      url.searchParams.set('client_pk33', pkHex);
      if (credIdB64u) url.searchParams.set('cred_id_b64u', credIdB64u);
      const res = await fetch(url.toString(), { headers: { accept: 'application/json' } });
      const data = await res.json();
      const sPk = data.server_pubkey || data.asp_pubkey || '';
      setServerPk(sPk || '—');
      setRegistered(data.recovery?.registered === true);
      if (!sPk) throw new Error('ASP info missing server_pubkey');

      // 3. Compute aggregate key and Ark address
      const sortedKeys = musig2.sortKeys([pubkey, hexToBytes(sPk)]);
      const aggPk33 = musig2.keyAggregate(sortedKeys).aggPublicKey.toBytes(true);
      const xonly = aggPk33.slice(1);
      const words = [1, ...bech32m.toWords(xonly)];
      setArkAddress(bech32m.encode('bc', words));

      // 4. Create read-only wallet and fetch balance
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
      const available = Number(bal?.available ?? 0);
      const total = Number(bal?.total ?? 0);
      setBalance(`${available} sats (total ${total})`);
      setLoaded(true);
    } catch (e: any) {
      setError(e.message || 'Failed to read card or fetch balance');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Scroll>
      <View padding="lg" paddingBottom="xl" gap="lg">
        {loaded ? (
          <>
            <View chrome="canvas" radius="md" padding="xl" gap="md">
              <Text size="lg" emphasis>{ACCOUNT_NAME}</Text>
              <Text size="sm" muted>{LIGHTNING_ADDRESS}</Text>
              <Stack gap="xs">
                <Text size="xs" emphasis muted>Ark address</Text>
                <Text size="xs" flow="truncate" lines={1}>{arkAddress}</Text>
              </Stack>
              <Stack gap="xs">
                <Text size="xs" emphasis muted>Balance</Text>
                <Text size="xl" emphasis>{balance}</Text>
              </Stack>
            </View>

            <View chrome="canvas" radius="md" padding="xl" gap="md">
              <Text size="lg" emphasis>Card</Text>
              <Stack gap="xs">
                <Text size="xs" emphasis muted>Card MuSig2 pubkey</Text>
                <Text size="xs" flow="truncate" lines={1}>{cardPk}</Text>
              </Stack>
              <Stack gap="xs">
                <Text size="xs" emphasis muted>Registered</Text>
                <Text size="sm">{registered ? 'yes' : 'no'}</Text>
              </Stack>
            </View>

            <View chrome="canvas" radius="md" padding="xl" gap="md">
              <Text size="lg" emphasis>Arkade ASP</Text>
              <Stack gap="xs">
                <Text size="xs" emphasis muted>ASP server pubkey</Text>
                <Text size="xs" flow="truncate" lines={1}>{serverPk}</Text>
              </Stack>
            </View>
          </>
        ) : (
          <View chrome="canvas" radius="md" padding="xl" gap="md" align="center">
            <Text size="lg" emphasis>Card Profile</Text>
            <Text size="sm" muted>Tap the button below and hold your card on the phone to see your wallet balance, Ark address, and registration status.</Text>
          </View>
        )}

        {busy ? <ActivityIndicator style={{ alignSelf: 'center' }} /> : null}
        {error ? <Text size="sm" muted align="center">{error}</Text> : null}

        <Button variant="solid" size="lg" onPress={loadCard} disabled={busy}>
          {busy ? 'Reading card…' : loaded ? 'Refresh (tap card)' : 'Read card'}
        </Button>
      </View>
    </Scroll>
  );
}

function pubkeyHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}