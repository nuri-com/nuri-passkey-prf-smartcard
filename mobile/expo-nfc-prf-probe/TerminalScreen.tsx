import { useState } from 'react';
import { View, Stack, Text, Button, TextField, TextFieldLabel } from '@nuri/rn';

type Props = {
  merchantName?: string;
  merchantTarget?: string;
  onCharge: (amountSats: number, invoice: string, memo: string, merchantName: string) => void;
};

export function TerminalScreen({ merchantName, merchantTarget, onCharge }: Props) {
  const [name, setName] = useState(() => String(merchantName || '').trim());
  const [target, setTarget] = useState(() => String(merchantTarget || '').trim());
  const [memo, setMemo] = useState('');
  const [amount, setAmount] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);

  const amountSats = amount.trim() ? Number(amount) : Number.NaN;
  const canCharge = Number.isInteger(amountSats) && amountSats > 0 && Boolean(name.trim()) && Boolean(target.trim()) && Boolean(memo.trim()) && !busy;

  async function charge() {
    if (!Number.isInteger(amountSats) || amountSats <= 0) {
      setStatus('Amount must be a positive whole number of sats');
      return;
    }
    const exactName = name.trim();
    const exactTarget = target.trim();
    const exactMemo = memo.trim();
    if (!exactName || !exactTarget || !exactMemo) {
      setStatus('Merchant name, Lightning address, and memo are required');
      return;
    }
    setBusy(true);
    setStatus(`Creating checkout for ${amountSats.toLocaleString('en-US')} sats…`);
    try {
      const { resolveLightningInvoice } = await import('./src/lnurl');
      const resolved = await resolveLightningInvoice(exactTarget, amountSats, exactMemo);
      setStatus('Forwarding to checkout…');
      onCharge(amountSats, resolved.invoice, exactMemo, exactName);
    } catch (e: any) {
      setStatus(e.message || 'Failed to create checkout');
      setBusy(false);
    }
  }

  return (
    <View chrome="canvas" radius="lg" padding="xl" gap="lg">
      <Stack gap="xs">
        <Text size="sm" emphasis muted>{name || 'Merchant not configured'}</Text>
        <Text size="3xl" emphasis>{Number.isFinite(amountSats) ? amountSats.toLocaleString('en-US') : '—'}</Text>
        <Text size="xs" muted>sats · Charges {target || 'no Lightning address'} · mainnet</Text>
      </Stack>

      <TextField
        value={name}
        onChangeText={setName}
        placeholder="Merchant name"
        accessibilityLabel="Merchant name"
      >
        <TextFieldLabel>Merchant</TextFieldLabel>
      </TextField>

      <TextField
        value={target}
        onChangeText={setTarget}
        inputMode="email"
        placeholder="merchant@example.com"
        accessibilityLabel="Merchant Lightning address"
      >
        <TextFieldLabel>Lightning address</TextFieldLabel>
      </TextField>

      <TextField
        value={memo}
        onChangeText={setMemo}
        placeholder="What is being paid for"
        accessibilityLabel="Payment memo"
      >
        <TextFieldLabel>Memo</TextFieldLabel>
      </TextField>

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
