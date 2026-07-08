// Profile screen — shows card balance, Ark address, receive info.
// Mirrors web/nuri-profile.html. Reads the card pubkey via NFC, fetches
// ASP /arkade/info for the server pubkey, then creates a read-only SDK
// wallet to show the balance and Ark address.

import { useEffect, useState } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { readCardPubkey } from './src/musig2Card';
import { Wallet, InMemoryWalletRepository, InMemoryContractRepository } from '@arkade-os/sdk';
import { ExpoArkProvider, ExpoIndexerProvider } from '@arkade-os/sdk/adapters/expo';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils';
import { bech32m } from '@scure/base';

type Props = {
  aspInfoUrl: string;
  nodeUrl: string;
  credIdB64u: string;
};

export function ProfileScreen({ aspInfoUrl, nodeUrl, credIdB64u }: Props) {
  const [cardPk, setCardPk] = useState('');
  const [serverPk, setServerPk] = useState('');
  const [registered, setRegistered] = useState(false);
  const [arkAddress, setArkAddress] = useState('');
  const [balance, setBalance] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function loadCard() {
    setBusy(true);
    setError('');
    setBalance(null);
    try {
      // 1. Read card pubkey via NFC
      const { pubkey } = await readCardPubkey(() => {});
      const pkHex = pubkeyHex(pubkey);
      setCardPk(pkHex);

      // 2. Fetch /arkade/info?client_pk33=<cardPk>
      const url = new URL(aspInfoUrl);
      url.searchParams.set('client_pk33', pkHex);
      if (credIdB64u) url.searchParams.set('cred_id_b64u', credIdB64u);
      const res = await fetch(url.toString(), { headers: { accept: 'application/json' } });
      const data = await res.json();
      const sPk = data.server_pubkey || data.asp_pubkey || '';
      setServerPk(sPk || '—');
      setRegistered(data.recovery?.registered === true);

      if (!sPk) throw new Error('ASP info missing server_pubkey');

      // 3. Compute the aggregate key (card + ASP) and derive the Ark address
      const sortedKeys = musig2.sortKeys([pubkey, hexToBytes(sPk)]);
      const aggPk33 = musig2.keyAggregate(sortedKeys).aggPublicKey.toBytes(true);
      const xonly = aggPk33.slice(1);
      // Taproot address: bech32m with witness version 1
      const words = [1, ...bech32m.toWords(xonly)];
      const address = bech32m.encode('bc', words);
      setArkAddress(address);

      // 4. Create a read-only wallet to fetch the balance
      // ponytail: the wallet needs an Identity even for read-only balance.
      // We use a minimal identity that just returns the aggregate pubkey.
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
        storage: {
          walletRepository: new InMemoryWalletRepository(),
          contractRepository: new InMemoryContractRepository(),
        },
        settlementConfig: false,
      });

      const bal = await wallet.getBalance();
      const available = Number(bal?.available ?? 0);
      const total = Number(bal?.total ?? 0);
      setBalance(`${available} sats (total ${total})`);
    } catch (e: any) {
      setError(e.message || 'Failed to read card or fetch balance');
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    loadCard().catch(() => {});
  }, []);

  return (
    <ScrollView contentContainerStyle={s.content}>
      <View style={s.section}>
        <Text style={s.h2}>Wallet</Text>
        <Text style={s.label}>Ark address</Text>
        <Text style={s.address}>{arkAddress || (busy ? 'Loading…' : '—')}</Text>
        <Text style={s.label}>Balance</Text>
        <Text style={s.balanceValue}>{balance || (busy ? 'Loading…' : '—')}</Text>
      </View>

      <View style={s.section}>
        <Text style={s.h2}>Card</Text>
        <Text style={s.label}>Card MuSig2 pubkey</Text>
        <Text style={s.address}>{cardPk || (busy ? 'Reading card…' : '—')}</Text>
      </View>

      <View style={s.section}>
        <Text style={s.h2}>Arkade</Text>
        <Text style={s.label}>ASP server pubkey</Text>
        <Text style={s.address}>{serverPk || '—'}</Text>
        <Text style={s.label}>Recovery registered</Text>
        <Text style={s.value}>{registered ? 'yes' : 'no'}</Text>
      </View>

      {busy ? <ActivityIndicator style={{ alignSelf: 'center' }} /> : null}
      {error ? <Text style={s.error}>{error}</Text> : null}

      <Pressable style={s.btn} onPress={loadCard} disabled={busy}>
        <Text style={s.btnText}>{busy ? '…' : 'Refresh (tap card)'}</Text>
      </Pressable>
    </ScrollView>
  );
}

function pubkeyHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

const s = StyleSheet.create({
  content: { padding: 20, paddingBottom: 40, gap: 16 },
  section: {
    backgroundColor: '#fff', borderColor: '#d8dde5', borderRadius: 8, borderWidth: 1, padding: 20,
  },
  h2: { fontSize: 18, fontWeight: '700', color: '#17202a', marginBottom: 14 },
  label: {
    color: '#657080', fontSize: 12, fontWeight: '700',
    textTransform: 'uppercase', letterSpacing: 0.4, marginTop: 13,
  },
  address: {
    fontFamily: 'Courier', fontSize: 13, color: '#17202a',
    backgroundColor: '#fafbfc', borderColor: '#d8dde5', borderRadius: 6,
    borderWidth: 1, padding: 12, marginTop: 4, overflow: 'hidden',
  },
  balanceValue: { fontSize: 22, fontWeight: '700', color: '#17202a', marginTop: 4 },
  value: { fontSize: 14, color: '#17202a', marginTop: 4 },
  btn: {
    backgroundColor: '#274c77', borderRadius: 6, paddingVertical: 11,
    paddingHorizontal: 14, alignItems: 'center',
  },
  btnText: { color: '#fff', fontWeight: '700' },
  error: { color: '#a52820', fontSize: 13, textAlign: 'center' },
});
