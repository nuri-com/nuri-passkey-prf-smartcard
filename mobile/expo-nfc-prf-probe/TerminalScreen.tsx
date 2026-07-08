import { useState } from 'react';
import { Pressable as RNPressable } from 'react-native';
import { View, Stack, Text, Button } from '@nuri/rn';

const MERCHANT_TARGET = 'nuri@cake.cash';
const MERCHANT_NAME = 'Nuri demo coffee';

type Props = {
  onCharge: (amountSats: number, invoice: string, memo: string) => void;
};

export function TerminalScreen({ onCharge }: Props) {
  const [digits, setDigits] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);

  const amount = Number(digits || '0');
  const canCharge = amount > 0 && !busy;

  function press(k: string) {
    if (busy) return;
    if (k === 'C') setDigits('');
    else if (k === 'back') setDigits((d) => d.slice(0, -1));
    else if (/^[0-9]$/.test(k) && digits.length < 9) setDigits((d) => (d + k).replace(/^0+/, ''));
    setStatus('');
  }

  async function charge() {
    if (amount <= 0) return;
    setBusy(true);
    setStatus(`Creating checkout for ${amount.toLocaleString('en-US')} sats…`);
    try {
      const { resolveLightningInvoice } = await import('./src/lnurl');
      const resolved = await resolveLightningInvoice(MERCHANT_TARGET, amount, 'Counter payment');
      setStatus('Forwarding to checkout…');
      onCharge(amount, resolved.invoice, 'Counter payment');
    } catch (e: any) {
      setStatus(e.message || 'Failed to create checkout');
      setBusy(false);
    }
  }

  const keys = ['1','2','3','4','5','6','7','8','9','C','0','back'];

  return (
    <View variant="outline" radius="lg" padding="xl" gap="md">
      <Text size="sm" emphasis muted>{MERCHANT_NAME}</Text>
      <Stack direction="row" align="baseline" gap="xs">
        <Text size="3xl" emphasis>{amount.toLocaleString('en-US')}</Text>
        <Text size="lg" muted>sats</Text>
      </Stack>
      <Text size="xs" muted>
        Charges <Text size="xs" emphasis>{MERCHANT_TARGET}</Text> · mainnet
      </Text>

      <View direction="row" wrap gap="xs" paddingY="lg">
        {keys.map((k) => (
          <RNPressable
            key={k}
            onPress={() => press(k)}
            disabled={busy}
            style={{
              width: '33.33%',
              paddingVertical: 24,
              alignItems: 'center',
              borderRadius: 9,
              borderWidth: 1,
              borderColor: '#dddac9',
              backgroundColor: '#fffdf2',
              marginBottom: 2,
            }}
          >
            <Text size="xl" emphasis>{k === 'back' ? '⌫' : k}</Text>
          </RNPressable>
        ))}
      </View>

      <Button variant="solid" size="lg" onPress={charge} disabled={!canCharge}>
        {busy ? '…' : 'Charge'}
      </Button>

      {status ? <Text size="sm" emphasis muted align="center">{status}</Text> : null}
    </View>
  );
}