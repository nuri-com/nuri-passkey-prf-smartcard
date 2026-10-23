import { useRef, useState } from 'react';
import NfcManager from 'react-native-nfc-manager';
import { Scroll, View, Text, Button, TextField, TextFieldLabel } from '@nuri/rn';
import { signCardDemo } from './src/musig2CardPin';

type Result = Awaited<ReturnType<typeof signCardDemo>>;
export function DemoScreen() {
  const [message, setMessage] = useState('Nuri card demo');
  const [pin, setPin] = useState('');
  const [busy, setBusy] = useState(false);
  const locked = useRef(false);
  const [status, setStatus] = useState('');
  const [result, setResult] = useState<Result | null>(null);
  async function sign() {
    if (locked.current) return;
    locked.current = true;
    setBusy(true);
    setResult(null);
    const pending = signCardDemo(message, pin, setStatus);
    setPin('');
    try { setResult(await pending); setStatus(''); }
    catch (error) { setStatus(error instanceof Error ? error.message : 'Signing failed'); }
    finally { locked.current = false; setBusy(false); }
  }
  function cancel() { NfcManager.cancelTechnologyRequest({ throwOnError: false }).catch(() => {}); }
  return <Scroll><View padding="lg" gap="lg">
    <Text size="lg" emphasis>Sign with card</Text>
    <TextField value={message} onChangeText={setMessage} disabled={busy} accessibilityLabel="Message"><TextFieldLabel>Message</TextFieldLabel></TextField>
    <TextField value={pin} onChangeText={setPin} secureTextEntry inputMode="numeric" disabled={busy} accessibilityLabel="PIN"><TextFieldLabel>PIN</TextFieldLabel></TextField>
    {busy
      ? <Button variant="soft" size="lg" onPress={cancel}>Cancel</Button>
      : <Button variant="solid" size="lg" disabled={!pin} onPress={sign}>Sign</Button>}
    {status ? <Text size="md">{status}</Text> : null}
    {result && <View gap="md">
      <Text size="lg" emphasis>{result.verified ? 'Signature valid' : 'Signature invalid'}</Text>
      <Text size="md" muted>Signature</Text><Text size="md">{result.signature}</Text>
      <Text size="md" muted>Card key</Text><Text size="md">{result.cardPubkey}</Text>
    </View>}
  </View></Scroll>;
}
