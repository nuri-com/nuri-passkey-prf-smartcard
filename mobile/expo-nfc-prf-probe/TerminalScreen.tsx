import { useState } from 'react';
import {
  View,
  Stack,
  Text,
  Button,
  ButtonIcon,
  TextField,
  TextFieldButton,
  TextFieldLabel,
} from '@nuri/rn';

type Props = {
  onCharge: (amountSats: number, invoice: string, memo: string, merchantName: string) => void;
};

const DEFAULT_LIGHTNING_ADDRESS = 'smartcard@nuri.com';
const MERCHANT_NAME = 'Nuri Terminal';
const PAYMENT_MEMO = 'Nuri Terminal charge';

export function TerminalScreen({ onCharge }: Props) {
  const [target, setTarget] = useState(DEFAULT_LIGHTNING_ADDRESS);
  const [editingTarget, setEditingTarget] = useState(false);
  const [amount, setAmount] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);

  const amountSats = amount ? Number(amount) : Number.NaN;
  const canCharge = Number.isInteger(amountSats) && amountSats > 0 && Boolean(target.trim()) && !busy;

  function enterDigit(digit: string) {
    setAmount((current) => `${current}${digit}`.replace(/^0+(?=\d)/, ''));
    setStatus('');
  }

  function deleteDigit() {
    setAmount((current) => current.slice(0, -1));
    setStatus('');
  }

  async function charge() {
    if (!Number.isInteger(amountSats) || amountSats <= 0) {
      setStatus('Amount must be a positive whole number of sats');
      return;
    }
    const exactTarget = target.trim();
    if (!exactTarget) {
      setStatus('Lightning address is required');
      return;
    }
    setBusy(true);
    setStatus(`Creating checkout for ${amountSats.toLocaleString('en-US')} sats…`);
    try {
      const { resolveLightningInvoice } = await import('./src/lnurl');
      const resolved = await resolveLightningInvoice(exactTarget, amountSats, PAYMENT_MEMO);
      setStatus('Forwarding to checkout…');
      onCharge(amountSats, resolved.invoice, PAYMENT_MEMO, MERCHANT_NAME);
    } catch (e: any) {
      setStatus(e.message || 'Failed to create checkout');
      setBusy(false);
    }
  }

  return (
    <View direction="column" align="stretch" justify="between" gap="xl" padding="lg" fill="grow">
      <TextField
        value={target}
        onChangeText={setTarget}
        inputMode="email"
        disabled={!editingTarget}
        placeholder={DEFAULT_LIGHTNING_ADDRESS}
        accessibilityLabel="Lightning address"
      >
        <TextFieldLabel>Lightning address</TextFieldLabel>
        <TextFieldButton onPress={() => setEditingTarget((current) => !current)}>
          {editingTarget ? 'Done' : 'Edit'}
        </TextFieldButton>
      </TextField>

      <Stack gap="xs" align="center">
        <Text size="sm" muted>Amount</Text>
        <Text size="3xl" emphasis align="center">
          {amount ? Number(amount).toLocaleString('en-US') : '0'}
        </Text>
        <Text size="sm" muted>sats</Text>
      </Stack>

      <View direction="column" gap="sm">
        {[
          ['1', '2', '3'],
          ['4', '5', '6'],
          ['7', '8', '9'],
        ].map((row) => (
          <View key={row.join('')} direction="row" gap="sm">
            {row.map((digit) => (
              <View key={digit} fill="even">
                <Button size="lg" onPress={() => enterDigit(digit)}>{digit}</Button>
              </View>
            ))}
          </View>
        ))}
        <View direction="row" gap="sm">
          <View fill="even">
            <Button size="lg" disabled accessibilityLabel="Empty keypad key" />
          </View>
          <View fill="even">
            <Button size="lg" onPress={() => enterDigit('0')}>0</Button>
          </View>
          <View fill="even">
            <Button size="lg" onPress={deleteDigit} accessibilityLabel="Delete digit">
              <ButtonIcon name="chevron-left" />
            </Button>
          </View>
        </View>
      </View>

      <Button variant="solid" size="lg" onPress={charge} disabled={!canCharge}>
        {busy ? '…' : 'Charge'}
      </Button>

      {status ? <Text size="sm" emphasis muted align="center">{status}</Text> : null}
    </View>
  );
}
