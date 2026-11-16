import 'react-native-get-random-values';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { WalletScreen } from './WalletScreen';
export default function App(){return <SafeAreaProvider><SafeAreaView style={{flex:1,backgroundColor:'#fdf6e3'}}><StatusBar style="dark"/><WalletScreen/></SafeAreaView></SafeAreaProvider>;}
