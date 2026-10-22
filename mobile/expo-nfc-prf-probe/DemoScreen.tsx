import { useRef, useState } from 'react';
import { Scroll, View, Text, Button, TextField, TextFieldLabel } from '@nuri/rn';
import { signCardDemo } from './src/musig2CardPin';

type Result = Awaited<ReturnType<typeof signCardDemo>>;
export function DemoScreen() {
  const [message, setMessage] = useState('Nuri card demo');
  const [pin, setPin] = useState('');
  const [busy, setBusy] = useState(false);
  const locked = useRef(false);
  const [status, setStatus] = useState('Enter your PIN, then hold the card to the phone.');
  const [result, setResult] = useState<Result | null>(null);
  async function sign() {
    if (locked.current) return;
    locked.current = true;
    setBusy(true);
    setResult(null);
    const pending = signCardDemo(message, pin, setStatus);
    setPin('');
    try { setResult(await pending); setStatus('Signature verified. You can remove the card.'); }
    catch (error) { setStatus(error instanceof Error ? error.message : 'Card signing failed.'); }
    finally { locked.current = false; setBusy(false); }
  }
  return <Scroll><View padding="lg" gap="lg">
    <Text size="lg" emphasis>Card signature</Text>
    <Text size="sm" muted>2-of-2 MuSig2 (BIP327). The second signer is a demo cosigner in app memory, not Nuri server. No payment is sent.</Text>
    <TextField value={message} onChangeText={setMessage} disabled={busy} accessibilityLabel="Message"><TextFieldLabel>Message</TextFieldLabel></TextField>
    <TextField value={pin} onChangeText={setPin} secureTextEntry inputMode="numeric" disabled={busy} accessibilityLabel="Card PIN"><TextFieldLabel>Card PIN</TextFieldLabel></TextField>
    <Button variant="solid" size="lg" disabled={busy || !pin} onPress={sign}>{busy ? 'Signing…' : 'Tap card and sign'}</Button>
    <Text size="sm">{status}</Text>
    {result && <View gap="md">
      <Text emphasis>Valid BIP340 signature: {result.verified ? 'yes' : 'no'}</Text>
      <Text size="sm">Card public key</Text><Text size="sm">{result.cardPubkey}</Text>
      <Text size="sm">Aggregate x-only key</Text><Text size="sm">{result.aggregateKey}</Text>
      <Text size="sm">Message SHA-256</Text><Text size="sm">{result.messageHash}</Text>
      <Text size="sm">Final signature (64 bytes)</Text><Text size="sm">{result.signature}</Text>
    </View>}
  </View></Scroll>;
}
