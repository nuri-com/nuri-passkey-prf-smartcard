import { useState } from 'react';
import { View, Stack, Text, Button, TextField, TextFieldLabel } from '@nuri/rn';

const MERCHANT_TARGET = 'nuri@cake.cash';
const MERCHANT_NAME = 'Nuri demo coffee';

type Props = {
  onCharge: (amountSats: number, invoice: string, memo: string) => void;
};

export function TerminalScreen({ onCharge }: Props) {
  const [amount, setAmount] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);

  const amountSats = Number(amount || '0');
  const canCharge = amountSats > 0 && !busy;

  async function charge() {
    if (amountSats <= 0) return;
    setBusy(true);
    setStatus(`Creating checkout for ${amountSats.toLocaleString('en-US')} sats…`);
    try {
      const { resolveLightningInvoice } = await import('./src/lnurl');
      const resolved = await resolveLightningInvoice(MERCHANT_TARGET, amountSats, 'Counter payment');
      setStatus('Forwarding to checkout…');
      onCharge(amountSats, resolved.invoice, 'Counter payment');
    } catch (e: any) {
      setStatus(e.message || 'Failed to create checkout');
      setBusy(false);
    }
  }

  return (
    <View variant="outline" radius="lg" padding="xl" gap="lg">
      <Stack gap="xs">
        <Text size="sm" emphasis muted>{MERCHANT_NAME}</Text>
        <Text size="3xl" emphasis>{amountSats.toLocaleString('en-US')}</Text>
        <Text size="xs" muted>sats · Charges {MERCHANT_TARGET} · mainnet</Text>
      </Stack>

      <TextField
        value={amount}
        onChangeText={setAmount}
        inputMode="decimal"
        placeholder="Enter amount in sats"
        accessibilityLabel="Amount in satoshis"
      >
        <TextFieldLabel>Amount (sats)</TextFieldLabel>
      </TextField>

      <Button variant="solid" size="lg" onPress={charge} disabled={!canCharge}>
        {busy ? '…' : 'Charge'}
      </Button>

      {status ? <Text size="sm" emphasis muted align="center">{status}</Text> : null}
    </View>
  );
}