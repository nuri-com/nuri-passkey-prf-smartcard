import { useState } from 'react';
import { Pressable } from 'react-native';
import { Stack, Typography } from './src/ds/primitives';
import { Button } from './src/ds/recipes';
import { colors, space, radius } from './src/ds/tokens';

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
    <Stack gap="md" padding="xl" radius="lg" chrome="canvas" style={{ borderWidth: 1, borderColor: colors.borderSubtle }}>
      <Typography step="sm" emphasis muted>{MERCHANT_NAME}</Typography>
      <Stack direction="row" align="baseline" gap="xs">
        <Typography step="3xl" weight="700">{amount.toLocaleString('en-US')}</Typography>
        <Typography step="lg" emphasis muted>sats</Typography>
      </Stack>
      <Typography step="xs" muted>
        Charges <Typography step="xs" emphasis style={{ color: colors.textPrimary }}>{MERCHANT_TARGET}</Typography> · mainnet
      </Typography>

      <Stack direction="row" wrap gap="2xs" paddingY="lg">
        {keys.map((k) => (
          <Pressable
            key={k}
            onPress={() => press(k)}
            disabled={busy}
            style={{
              width: '33.33%',
              paddingVertical: space.xl,
              alignItems: 'center',
              borderRadius: radius.md,
              borderWidth: 1,
              borderColor: colors.borderSubtle,
              backgroundColor: colors.bgCanvas,
              marginBottom: space['2xs'],
            }}
          >
            <Typography step="xl" emphasis>{k === 'back' ? '⌫' : k}</Typography>
          </Pressable>
        ))}
      </Stack>

      <Button variant="solid" onPress={charge} disabled={!canCharge}>
        {busy ? '…' : 'Charge'}
      </Button>

      {status ? <Typography step="sm" emphasis muted align="center">{status}</Typography> : null}
    </Stack>
  );
}