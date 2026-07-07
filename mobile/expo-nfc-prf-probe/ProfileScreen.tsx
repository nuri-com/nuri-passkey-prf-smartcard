// Profile screen — shows card balance, Ark address, receive info.
// Mirrors web/nuri-profile.html. The ASP server pubkey comes from
// /arkade/info?client_pk33=<cardPubkey>, same as the server's
// fetchArkadeInfo() which needs the card on the reader.

import { useEffect, useState } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { readCardPubkey } from './src/musig2Card';

type Props = {
  aspInfoUrl: string;  // base: https://arkade.nuri.com/v4/arkade/info
  nodeUrl: string;
  credIdB64u: string;
};

export function ProfileScreen({ aspInfoUrl, nodeUrl, credIdB64u }: Props) {
  const [cardPk, setCardPk] = useState('');
  const [serverPk, setServerPk] = useState('');
  const [registered, setRegistered] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function loadCard() {
    setBusy(true);
    setError('');
    try {
      const { pubkey } = await readCardPubkey(() => {});
      const pkHex = pubkeyHex(pubkey);
      setCardPk(pkHex);

      // Fetch /arkade/info?client_pk33=<cardPk>&cred_id_b64u=<credId>
      // Same as the server's fetchArkadeInfo().
      const url = new URL(aspInfoUrl);
      url.searchParams.set('client_pk33', pkHex);
      if (credIdB64u) url.searchParams.set('cred_id_b64u', credIdB64u);
      const res = await fetch(url.toString(), { headers: { accept: 'application/json' } });
      const data = await res.json();
      setServerPk(data.server_pubkey || data.asp_pubkey || '—');
      setRegistered(data.recovery?.registered === true);
    } catch (e: any) {
      setError(e.message || 'Failed to read card or fetch ASP info');
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
        <Text style={s.h2}>Card</Text>
        <Text style={s.label}>Card MuSig2 pubkey</Text>
        <Text style={s.address}>{cardPk || (busy ? 'Reading card…' : '—')}</Text>
        {busy ? <ActivityIndicator style={{ marginTop: 8 }} /> : null}
      </View>

      <View style={s.section}>
        <Text style={s.h2}>Arkade</Text>
        <Text style={s.label}>ASP server pubkey</Text>
        <Text style={s.address}>{serverPk || '—'}</Text>
        <Text style={s.label}>Recovery registered</Text>
        <Text style={s.value}>{registered ? 'yes' : 'no'}</Text>
        <Text style={s.label}>Node URL</Text>
        <Text style={s.address}>{nodeUrl}</Text>
      </View>

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
  content: { padding: 16, gap: 16 },
  section: {
    backgroundColor: '#fff', borderColor: '#d8dde5', borderRadius: 8, borderWidth: 1, padding: 20,
  },
  h2: { fontSize: 18, fontWeight: '700', color: '#17202a', marginBottom: 14 },
  label: {
    color: '#657080', fontSize: 12, fontWeight: '700',
    textTransform: 'uppercase', letterSpacing: 0.4, marginTop: 13,
  },
  address: {
    fontFamily: 'Courier', fontSize: 14, color: '#17202a',
    backgroundColor: '#fafbfc', borderColor: '#d8dde5', borderRadius: 6,
    borderWidth: 1, padding: 12, marginTop: 4, overflow: 'hidden',
  },
  value: { fontSize: 14, color: '#17202a', marginTop: 4 },
  btn: {
    backgroundColor: '#274c77', borderRadius: 6, paddingVertical: 11,
    paddingHorizontal: 14, alignItems: 'center',
  },
  btnText: { color: '#fff', fontWeight: '700' },
  error: { color: '#a52820', fontSize: 13, textAlign: 'center' },
});
