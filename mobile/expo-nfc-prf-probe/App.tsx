import 'react-native-get-random-values';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { NuriThemeProvider, Screen, Text, Topbar, TopbarCenter } from '@nuri/rn';
import { DemoScreen } from './DemoScreen';

// Offline demo entry: intentionally does not import the legacy payment screens
// or require any profile, ASP, Boltz, LNURL, or EXPO_PUBLIC configuration.
export default function App() {
  return <SafeAreaProvider><NuriThemeProvider>
    <SafeAreaView style={{ flex: 1 }} edges={['top', 'bottom']}>
      <StatusBar style="dark" />
      <Screen>
        <Topbar><TopbarCenter><Text size="lg" emphasis>Nuri Card · Demo</Text></TopbarCenter></Topbar>
        <DemoScreen />
      </Screen>
    </SafeAreaView>
  </NuriThemeProvider></SafeAreaProvider>;
}
