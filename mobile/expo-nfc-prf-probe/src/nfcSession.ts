import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import { setNfcSessionOpen as setCtapSessionOpen } from './ctapPrf';
import { setNfcSessionOpen as setMusig2SessionOpen } from './musig2Card';

export async function withNfcCardSession<T>(
  alertMessage: string,
  operation: () => Promise<T>,
): Promise<T> {
  await NfcManager.start();
  await NfcManager.requestTechnology(NfcTech.IsoDep, { alertMessage });
  setMusig2SessionOpen(true);
  setCtapSessionOpen(true);
  try {
    return await operation();
  } finally {
    setMusig2SessionOpen(false);
    setCtapSessionOpen(false);
    await NfcManager.cancelTechnologyRequest({ throwOnError: false });
  }
}
