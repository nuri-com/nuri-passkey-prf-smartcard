import { useEffect, useState } from 'react';
import { ActivityIndicator, Animated } from 'react-native';
import { View, Stack, Text, Button, TextField, TextFieldLabel } from '@nuri/rn';
import { sendLightning, type SendConfig, type SendResult } from './src/sendFlow';

const PIN_LEN = 4;
const SCAN_SECONDS = 21;

type Props = {
  config: SendConfig;
  merchantName: string;
  amountSats: number;
  memo: string;
  invoice: string;
  onBack: () => void;
};

type Phase = 'pin' | 'scanning' | 'signing' | 'done' | 'error';

export function ApproveScreen({ config, merchantName, amountSats, memo, invoice, onBack }: Props) {
  const [pin, setPin] = useState('');
  const [phase, setPhase] = useState<Phase>('pin');
  const [count, setCount] = useState(SCAN_SECONDS);
  const [status, setStatus] = useState('');
  const [result, setResult] = useState<SendResult | null>(null);
  const [error, setError] = useState('');
  const [pulseAnim] = useState(new Animated.Value(1));

  useEffect(() => {
    if (phase === 'scanning' || phase === 'signing') {
      const pulse = Animated.loop(
        Animated.sequence([
          Animated.timing(pulseAnim, { toValue: 1.15, duration: 550, useNativeDriver: true }),
          Animated.timing(pulseAnim, { toValue: 1, duration: 550, useNativeDriver: true }),
        ]),
      );
      pulse.start();
      return () => pulse.stop();
    }
  }, [phase, pulseAnim]);

  useEffect(() => {
    if (phase !== 'scanning') return;
    const timer = setInterval(() => {
      setCount((c) => {
        if (c <= 1) { setPhase('error'); setError('No card detected — try again'); return 0; }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [phase]);

  async function startScan(enteredPin: string) {
    setPhase('scanning'); setStatus('Hold your card on the reader…');
    setCount(SCAN_SECONDS); setError('');
    await new Promise(r => setTimeout(r, 2000));
    setPhase('signing'); setStatus('Card read — approving payment…');
    try {
      const cfg = { ...config, pin: enteredPin, invoice };
      const res = await sendLightning(cfg, invoice);
      setResult(res); setPhase('done'); setStatus('Approved — payment broadcast');
    } catch (e: any) {
      setPhase('error'); setError(e.message || 'Payment failed'); setStatus('');
    }
  }

  function reset() {
    setPin(''); setPhase('pin'); setStatus(''); setError(''); setResult(null); setCount(SCAN_SECONDS);
  }

  const ringProgress = phase === 'scanning' ? count / SCAN_SECONDS : 0;

  return (
    <View variant="outline" radius="lg" padding="xl" gap="lg">
      <Stack gap="xs">
        <Text size="sm" emphasis muted>{merchantName}</Text>
        <Stack direction="row" align="baseline" gap="xs">
          <Text size="3xl" emphasis>{Number(amountSats).toLocaleString('en-US')}</Text>
          <Text size="lg" muted>sats</Text>
        </Stack>
        <Text size="xs" muted>Pays {memo} · mainnet</Text>
      </Stack>

      {phase === 'pin' && (
        <View gap="md">
          <TextField
            value={pin}
            onChangeText={setPin}
            inputMode="numeric"
            secureTextEntry
            placeholder="Enter card PIN"
            accessibilityLabel="Card PIN"
          >
            <TextFieldLabel>Card PIN</TextFieldLabel>
          </TextField>

          <Button variant="solid" size="lg" onPress={() => startScan(pin)} disabled={pin.length < 1}>
            Tap card & approve
          </Button>
        </View>
      )}

      {(phase === 'scanning' || phase === 'signing') && (
        <View align="center" gap="sm" paddingY="lg">
          <Animated.Text style={{ fontSize: 40, transform: [{ scale: pulseAnim }] }}>
            {phase === 'scanning' ? '💳' : '⚙️'}
          </Animated.Text>
          {phase === 'scanning' && (
            <View radius="full" width="sm" height="sm" style={{ overflow: 'hidden' }}>
              <View chrome="subtle" radius="full" width="sm" height="sm" style={{ overflow: 'hidden' }}>
                <View variant="solid" radius="full" style={{ height: '100%', width: `${ringProgress * 100}%` }} />
              </View>
            </View>
          )}
          <Text size="sm" emphasis muted align="center">{status}</Text>
          {phase === 'scanning' && <Text size="xs" emphasis muted>{count}s</Text>}
          {phase === 'signing' && <ActivityIndicator style={{ marginTop: 6 }} />}
        </View>
      )}

      {phase === 'done' && result && (
        <View align="center" gap="md" paddingY="lg">
          <Text size="xl">✅</Text>
          <Text size="md" emphasis>Approved — payment broadcast</Text>
          <View gap="xs" paddingTop="md">
            <ReceiptRow label="Status" value="APPROVED" />
            <ReceiptRow label="Paid" value={`${result.final_amount_sats} sats (funded ${result.funding_amount_sats})`} />
            <ReceiptRow label="Ark txid" value={result.ark_txid || '—'} />
          </View>
          <Button variant="soft" size="lg" onPress={onBack}>New payment</Button>
        </View>
      )}

      {phase === 'error' && (
        <View align="center" gap="md" paddingY="lg">
          <Text size="xl">⚠️</Text>
          <Text size="sm" emphasis muted align="center">{error}</Text>
          <Button variant="soft" size="lg" onPress={reset}>Try again</Button>
        </View>
      )}
    </View>
  );
}

function ReceiptRow({ label, value }: { label: string; value: string }) {
  return (
    <View direction="row" justify="between" gap="md">
      <Text size="sm" muted>{label}</Text>
      <Text size="sm" align="end" flow="truncate" lines={1}>{value}</Text>
    </View>
  );
}