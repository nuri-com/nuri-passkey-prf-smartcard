import { StatusBar } from 'expo-status-bar';
import { useState } from 'react';
import { Pressable, SafeAreaView, ScrollView, StyleSheet, Text, View } from 'react-native';
import { TerminalScreen } from './TerminalScreen';
import { ApproveScreen } from './ApproveScreen';
import { ProfileScreen } from './ProfileScreen';
import type { SendConfig } from './src/sendFlow';

// ASP endpoints (live Nuri).
const ASP_BASE = process.env.EXPO_PUBLIC_ASP_BASE || 'https://arkade.nuri.com/v4';
const NURI_BASE = ASP_BASE.replace(/\/+$/, '').replace(/\/v4$/i, '');
const NODE_URL = process.env.EXPO_PUBLIC_NODE_URL || 'https://arkade.computer';
const PROFILE_RP_ID = process.env.EXPO_PUBLIC_NURI_RP_ID || 'nuri.com';
const PROFILE_CREDENTIAL_ID = process.env.EXPO_PUBLIC_NURI_CREDENTIAL_ID || '';

type Tab = 'terminal' | 'profile';

type Checkout = {
  amountSats: number;
  invoice: string;
  memo: string;
  merchantName: string;
};

export default function App() {
  const [tab, setTab] = useState<Tab>('terminal');
  const [checkout, setCheckout] = useState<Checkout | null>(null);

  const config: SendConfig = {
    aspSignUrl: `${ASP_BASE}/arkade/sign`,
    aspAuthUrl: `${ASP_BASE}/arkade/auth`,
    aspInfoUrl: `${ASP_BASE}/arkade/info`,
    intentUrl: `${ASP_BASE}/arkade/swap-intent/create`,
    prepareUrl: `${NURI_BASE}/api/arkade/send/prepare`,
    cosignUrl: `${NURI_BASE}/api/arkade/send/cosign`,
    completeUrl: `${NURI_BASE}/api/arkade/send/complete`,
    nodeUrl: NODE_URL,
    boltzNetwork: 'bitcoin',
    credIdB64u: PROFILE_CREDENTIAL_ID,
    credPubkeyB64u: '',
    rpId: PROFILE_RP_ID,
    origin: `https://${PROFILE_RP_ID}`,
    pin: '',
  };

  // If a checkout is active, show the Approve screen full-screen.
  if (checkout) {
    return (
      <SafeAreaView style={styles.screen}>
        <StatusBar style="dark" />
        <ScrollView contentContainerStyle={styles.content}>
          <ApproveScreen
            config={config}
            merchantName={checkout.merchantName}
            amountSats={checkout.amountSats}
            memo={checkout.memo}
            invoice={checkout.invoice}
            onBack={() => { setCheckout(null); setTab('terminal'); }}
          />
        </ScrollView>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.screen}>
      <StatusBar style="dark" />
      <View style={styles.nav}>
        <Text style={styles.navTitle}>Nuri Terminal</Text>
        <View style={styles.navTabs}>
          <NavTab active={tab === 'terminal'} label="Terminal" onPress={() => setTab('terminal')} />
          <NavTab active={tab === 'profile'} label="Profile" onPress={() => setTab('profile')} />
        </View>
      </View>
      {tab === 'terminal' ? (
        <ScrollView contentContainerStyle={styles.content}>
          <TerminalScreen
            onCharge={(amountSats, invoice, memo) =>
              setCheckout({ amountSats, invoice, memo, merchantName: 'Nuri demo coffee' })
            }
          />
        </ScrollView>
      ) : (
        <ProfileScreen aspInfoUrl={config.aspInfoUrl} nodeUrl={NODE_URL} credIdB64u={PROFILE_CREDENTIAL_ID} />
      )}
    </SafeAreaView>
  );
}

function NavTab({ active, label, onPress }: { active: boolean; label: string; onPress: () => void }) {
  return (
    <Pressable onPress={onPress} style={[styles.navTab, active && styles.navTabActive]}>
      <Text style={[styles.navTabText, active && styles.navTabTextActive]}>{label}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#f5f6f8' },
  nav: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
    paddingHorizontal: 20, paddingVertical: 14, backgroundColor: '#fff',
    borderBottomColor: '#d7dce3', borderBottomWidth: 1,
  },
  navTitle: { fontSize: 17, fontWeight: '700', color: '#17202a' },
  navTabs: { flexDirection: 'row', gap: 4 },
  navTab: { paddingHorizontal: 14, paddingVertical: 6, borderRadius: 8 },
  navTabActive: { backgroundColor: '#eef1f4' },
  navTabText: { fontSize: 15, fontWeight: '600', color: '#657080' },
  navTabTextActive: { color: '#17202a' },
  content: { padding: 20, paddingTop: 36, paddingBottom: 60 },
});
