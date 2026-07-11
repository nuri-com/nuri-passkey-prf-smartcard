import { useState } from 'react';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import {
  NuriThemeProvider,
  Screen,
  Text,
  Topbar,
  TopbarCenter,
  TabBar,
  TabBarItem,
} from '@nuri/rn';
import { TerminalScreen } from './TerminalScreen';
import { ApproveScreen } from './ApproveScreen';
import { ProfileScreen } from './ProfileScreen';
import type { SendConfig } from './src/sendFlow';

function requiredEnv(name: string, value: string | undefined): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${name} is required`);
  return normalized;
}

const ASP_BASE = requiredEnv('EXPO_PUBLIC_ASP_BASE', process.env.EXPO_PUBLIC_ASP_BASE).replace(/\/+$/, '');
const NURI_BASE = ASP_BASE.replace(/\/+$/, '').replace(/\/v4$/i, '');
const NODE_URL = requiredEnv('EXPO_PUBLIC_NODE_URL', process.env.EXPO_PUBLIC_NODE_URL);
const PROFILE_RP_ID = requiredEnv('EXPO_PUBLIC_NURI_RP_ID', process.env.EXPO_PUBLIC_NURI_RP_ID);
const PROFILE_ORIGIN = requiredEnv('EXPO_PUBLIC_NURI_ORIGIN', process.env.EXPO_PUBLIC_NURI_ORIGIN);
const PROFILE_CREDENTIAL_ID = requiredEnv('EXPO_PUBLIC_NURI_CREDENTIAL_ID', process.env.EXPO_PUBLIC_NURI_CREDENTIAL_ID);
const PROFILE_CREDENTIAL_PUBLIC_KEY = requiredEnv('EXPO_PUBLIC_NURI_CREDENTIAL_PUBLIC_KEY', process.env.EXPO_PUBLIC_NURI_CREDENTIAL_PUBLIC_KEY);
type Tab = 'terminal' | 'profile';
type Checkout = { amountSats: number; invoice: string };

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
    credPubkeyB64u: PROFILE_CREDENTIAL_PUBLIC_KEY,
    rpId: PROFILE_RP_ID,
    origin: PROFILE_ORIGIN,
    pin: '',
  };

  if (checkout) {
    return (
      <SafeAreaProvider>
        <NuriThemeProvider>
          <SafeAreaView style={{ flex: 1 }} edges={['top', 'bottom']}>
            <StatusBar style="dark" />
            <Screen>
              <ApproveScreen
                config={config}
                amountSats={checkout.amountSats}
                invoice={checkout.invoice}
                onBack={() => { setCheckout(null); setTab('terminal'); }}
              />
            </Screen>
          </SafeAreaView>
        </NuriThemeProvider>
      </SafeAreaProvider>
    );
  }

  return (
    <SafeAreaProvider>
      <NuriThemeProvider>
        <SafeAreaView style={{ flex: 1 }} edges={['top', 'bottom']}>
          <StatusBar style="dark" />
          <Screen>
            <Topbar>
              <TopbarCenter>
                <Text size="md" emphasis>Nuri Terminal</Text>
              </TopbarCenter>
            </Topbar>
            {tab === 'terminal' ? (
              <TerminalScreen
                onCharge={(amountSats, invoice) =>
                  setCheckout({ amountSats, invoice })
                }
              />
            ) : (
              <ProfileScreen
                aspInfoUrl={config.aspInfoUrl}
                nodeUrl={NODE_URL}
                credIdB64u={PROFILE_CREDENTIAL_ID}
                credPubkeyB64u={PROFILE_CREDENTIAL_PUBLIC_KEY}
                rpId={PROFILE_RP_ID}
                origin={PROFILE_ORIGIN}
              />
            )}
            <TabBar>
              <TabBarItem
                icon="card"
                label="Terminal"
                selected={tab === 'terminal'}
                onPress={() => setTab('terminal')}
              />
              <TabBarItem
                icon="bitcoin-wallet"
                label="Profile"
                selected={tab === 'profile'}
                onPress={() => setTab('profile')}
              />
            </TabBar>
          </Screen>
        </SafeAreaView>
      </NuriThemeProvider>
    </SafeAreaProvider>
  );
}
