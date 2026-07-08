import { useState } from 'react';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { Screen, Stack, Scroll, Typography } from './src/ds/primitives';
import { Topbar, TabBar, TabBarItem } from './src/ds/recipes';
import { colors } from './src/ds/tokens';
import { TerminalScreen } from './TerminalScreen';
import { ApproveScreen } from './ApproveScreen';
import { ProfileScreen } from './ProfileScreen';
import type { SendConfig } from './src/sendFlow';

const ASP_BASE = process.env.EXPO_PUBLIC_ASP_BASE || 'https://arkade.nuri.com/v4';
const NURI_BASE = ASP_BASE.replace(/\/+$/, '').replace(/\/v4$/i, '');
const NODE_URL = process.env.EXPO_PUBLIC_NODE_URL || 'https://arkade.computer';
const PROFILE_RP_ID = process.env.EXPO_PUBLIC_NURI_RP_ID || 'nuri.com';
const PROFILE_CREDENTIAL_ID = process.env.EXPO_PUBLIC_NURI_CREDENTIAL_ID || '';

type Tab = 'terminal' | 'profile';
type Checkout = { amountSats: number; invoice: string; memo: string; merchantName: string };

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

  if (checkout) {
    return (
      <SafeAreaProvider>
        <SafeAreaView style={{ flex: 1 }} edges={['top', 'bottom']}>
          <StatusBar style="dark" />
          <Screen>
            <Scroll padding="lg" paddingBottom="2xl">
              <ApproveScreen
                config={config}
                merchantName={checkout.merchantName}
                amountSats={checkout.amountSats}
                memo={checkout.memo}
                invoice={checkout.invoice}
                onBack={() => { setCheckout(null); setTab('terminal'); }}
              />
            </Scroll>
          </Screen>
        </SafeAreaView>
      </SafeAreaProvider>
    );
  }

  return (
    <SafeAreaProvider>
      <SafeAreaView style={{ flex: 1 }} edges={['top']}>
        <StatusBar style="dark" />
        <Screen>
          <Topbar
            center={<Typography step="md" emphasis>Nuri Terminal</Typography>}
          />
          {tab === 'terminal' ? (
            <Scroll padding="lg" paddingBottom="xl">
              <TerminalScreen
                onCharge={(amountSats, invoice, memo) =>
                  setCheckout({ amountSats, invoice, memo, merchantName: 'Nuri demo coffee' })
                }
              />
            </Scroll>
          ) : (
            <ProfileScreen aspInfoUrl={config.aspInfoUrl} nodeUrl={NODE_URL} credIdB64u={PROFILE_CREDENTIAL_ID} />
          )}
          <TabBar>
            <TabBarItem
              label="Terminal"
              selected={tab === 'terminal'}
              onPress={() => setTab('terminal')}
            />
            <TabBarItem
              label="Profile"
              selected={tab === 'profile'}
              onPress={() => setTab('profile')}
            />
          </TabBar>
        </Screen>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}