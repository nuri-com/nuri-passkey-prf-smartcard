import { useEffect, useState } from 'react';
import { ActivityIndicator, Animated, Pressable } from 'react-native';
import { Stack, Typography } from './src/ds/primitives';
import { Button } from './src/ds/recipes';
import { colors, space, radius } from './src/ds/tokens';
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

  const canCharge = pin.length >= 1 && phase === 'pin';

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

  function press(k: string) {
    if (phase !== 'pin') return;
    let newPin = pin;
    if (k === 'C') newPin = '';
    else if (k === 'back') newPin = pin.slice(0, -1);
    else if (/^[0-9]$/.test(k) && pin.length < 12) newPin = pin + k;
    setPin(newPin);
    if (newPin.length === PIN_LEN) setTimeout(() => startScan(newPin), 100);
  }

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
  const pinDots = Math.max(4, pin.length);
  const keys = ['1','2','3','4','5','6','7','8','9','C','0','back'];

  return (
    <Stack gap="md" padding="xl" radius="lg" chrome="canvas" style={{ borderWidth: 1, borderColor: colors.borderSubtle }}>
      <Typography step="sm" emphasis muted>{merchantName}</Typography>
      <Stack direction="row" align="baseline" gap="xs">
        <Typography step="3xl" weight="700">{Number(amountSats).toLocaleString('en-US')}</Typography>
        <Typography step="lg" emphasis muted>sats</Typography>
      </Stack>
      <Typography step="xs" muted>
        Pays <Typography step="xs" emphasis style={{ color: colors.textPrimary }}>{memo}</Typography> · mainnet
      </Typography>

      {phase === 'pin' && (
        <Stack gap="md">
          <Typography step="xs" emphasis muted>Enter card PIN</Typography>
          <Stack direction="row" justify="center" gap="lg" paddingY="md" style={{ height: 36 }}>
            {Array.from({ length: pinDots }).map((_, i) => (
              <Pressable key={i} style={{
                width: 12, height: 12, borderRadius: 6,
                borderWidth: 1.5,
                borderColor: i < pin.length ? colors.textPrimary : colors.borderSubtle,
                backgroundColor: i < pin.length ? colors.textPrimary : 'transparent',
              }} />
            ))}
          </Stack>

          <Stack direction="row" wrap gap="2xs" paddingY="md">
            {keys.map((k) => (
              <Pressable
                key={k}
                onPress={() => press(k)}
                style={{
                  width: '33.33%', paddingVertical: space.xl, alignItems: 'center',
                  borderRadius: radius.md, borderWidth: 1, borderColor: colors.borderSubtle,
                  backgroundColor: colors.bgCanvas, marginBottom: space['2xs'],
                }}
              >
                <Typography step="xl" emphasis>{k === 'back' ? '⌫' : k}</Typography>
              </Pressable>
            ))}
          </Stack>

          <Button variant="solid" onPress={() => startScan(pin)} disabled={!canCharge}>
            Tap card & approve
          </Button>
        </Stack>
      )}

      {(phase === 'scanning' || phase === 'signing') && (
        <Stack align="center" gap="sm" paddingY="lg">
          <Animated.Text style={{ fontSize: 40, transform: [{ scale: pulseAnim }] }}>
            {phase === 'scanning' ? '💳' : '⚙️'}
          </Animated.Text>
          {phase === 'scanning' && (
            <Pressable style={{
              width: 100, height: 6, borderRadius: 3, backgroundColor: colors.borderSubtle,
              overflow: 'hidden',
            }}>
              <Pressable style={{ height: '100%', width: `${ringProgress * 100}%`, backgroundColor: colors.accentSolid }} />
            </Pressable>
          )}
          <Typography step="sm" emphasis style={{ color: '#9a6b00' }}>{status}</Typography>
          {phase === 'scanning' && <Typography step="xs" emphasis muted>{count}s</Typography>}
          {phase === 'signing' && <ActivityIndicator style={{ marginTop: space.sm }} />}
        </Stack>
      )}

      {phase === 'done' && result && (
        <Stack align="center" gap="md" paddingY="lg">
          <Typography step="xl">✅</Typography>
          <Typography step="md" emphasis style={{ color: '#1f7a5a' }}>Approved — payment broadcast</Typography>
          <Stack gap="2xs" paddingTop="md" style={{ borderTopWidth: 1, borderTopColor: colors.borderSubtle, width: '100%' }}>
            <ReceiptRow label="Status" value="APPROVED" />
            <ReceiptRow label="Paid" value={`${result.final_amount_sats} sats (funded ${result.funding_amount_sats})`} />
            <ReceiptRow label="Ark txid" value={result.ark_txid || '—'} mono />
          </Stack>
          <Button variant="ghost" onPress={onBack} style={{ borderWidth: 1, borderColor: '#1f7a5a' }}>
            <Typography step="sm" emphasis style={{ color: '#1f7a5a' }}>New payment</Typography>
          </Button>
        </Stack>
      )}

      {phase === 'error' && (
        <Stack align="center" gap="md" paddingY="lg">
          <Typography step="xl">⚠️</Typography>
          <Typography step="sm" emphasis style={{ color: '#9a3412' }}>{error}</Typography>
          <Button variant="ghost" onPress={reset} style={{ borderWidth: 1, borderColor: '#1f7a5a' }}>
            <Typography step="sm" emphasis style={{ color: '#1f7a5a' }}>Try again</Typography>
          </Button>
        </Stack>
      )}
    </Stack>
  );
}

function ReceiptRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <Stack direction="row" justify="between" gap="md">
      <Typography step="sm" muted>{label}</Typography>
      <Typography step="sm" style={{ textAlign: 'right', flexShrink: 1, fontFamily: mono ? 'Courier' : undefined, fontSize: mono ? 11 : undefined }}>
        {value}
      </Typography>
    </Stack>
  );
}