import { useEffect, useState } from 'react';
import {
  View,
  Stack,
  Text,
  Button,
  ButtonIcon,
  IconAvatar,
} from '@nuri/rn';
import { sendLightning, type SendConfig, type SendResult } from './src/sendFlow';

const PIN_LEN = 4;
const SCAN_SECONDS = 21;

type Props = {
  config: SendConfig;
  amountSats: number;
  invoice: string;
  onBack: () => void;
};

type Phase = 'pin' | 'scanning' | 'signing' | 'done' | 'error';

function readableProgress(message: string): string {
  const text = message.toLowerCase();
  if (text.includes('hold card') || text.includes('starting')) return 'Hold your Nuri card near the phone.';
  if (text.includes('reading card pubkey')) return 'Reading your card…';
  if (text.includes('fetching asp info')) return 'Connecting securely…';
  if (text.includes('creating wallet')) return 'Preparing your payment…';
  if (text.includes('creating submarine swap')) return 'Preparing the Lightning payment…';
  if (text.includes('creating swap intent')) return 'Confirming the payment details…';
  if (text.includes('funding lockup') || text.includes('card signing')) return 'Card found. Please keep it in place while it signs.';
  if (text.includes('send/prepare') || text.includes('card uv assertion')) return 'Confirming with your card…';
  if (text.includes('send/cosign')) return 'Authorizing the payment…';
  if (text.includes('funding txid') || text.includes('send/complete')) return 'Payment sent. Waiting for confirmation…';
  if (text.includes('waiting for swap funded') || text.includes('swap funded')) return 'Completing the Lightning payment…';
  return 'Processing your payment…';
}

function readableError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const text = message.toLowerCase();
  if (text.includes('no card') || text.includes('tag') || text.includes('nfc')) {
    return 'We could not read the card. Keep it close to the phone and try again.';
  }
  if (text.includes('pin') || text.includes('verification failed') || text.includes('63c')) {
    return 'The PIN was not accepted. Check the PIN and try again.';
  }
  if (text.includes('network') || text.includes('fetch') || text.includes('http')) {
    return 'We could not connect to the payment service. Check your connection and try again.';
  }
  if (text.includes('swap funding monitor')) {
    return 'The payment was sent, but Lightning confirmation is still pending. Please try again shortly.';
  }
  return 'We could not complete the payment. Please try again.';
}

export function ApproveScreen({ config, amountSats, invoice, onBack }: Props) {
  const [pin, setPin] = useState('');
  const [phase, setPhase] = useState<Phase>('pin');
  const [count, setCount] = useState(SCAN_SECONDS);
  const [status, setStatus] = useState('Hold your Nuri card near the phone.');
  const [result, setResult] = useState<SendResult | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (phase !== 'scanning') return;
    const timer = setInterval(() => {
      setCount((current) => {
        if (current <= 1) {
          setPhase('error');
          setError('We could not read the card. Keep it close to the phone and try again.');
          return 0;
        }
        return current - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [phase]);

  function enterPinDigit(digit: string) {
    setPin((current) => current.length < PIN_LEN ? `${current}${digit}` : current);
    setError('');
  }

  function deletePinDigit() {
    setPin((current) => current.slice(0, -1));
    setError('');
  }

  async function startScan() {
    if (pin.length !== PIN_LEN) return;
    setPhase('scanning');
    setStatus('Hold your Nuri card near the phone.');
    setCount(SCAN_SECONDS);
    setError('');
    await new Promise((resolve) => setTimeout(resolve, 2000));
    setPhase('signing');
    setStatus('Reading your card…');
    try {
      const cfg = {
        ...config,
        pin,
        invoice,
        log: (message: string) => {
          console.log(`[nuri-send] ${message}`);
          setStatus(readableProgress(message));
        },
      };
      const paymentResult = await sendLightning(cfg, invoice);
      setResult(paymentResult);
      setPhase('done');
      setStatus('Payment completed.');
    } catch (caughtError: unknown) {
      console.error('[nuri-send] failed', caughtError);
      setPhase('error');
      setError(readableError(caughtError));
    }
  }

  function reset() {
    setPin('');
    setPhase('pin');
    setStatus('Hold your Nuri card near the phone.');
    setError('');
    setResult(null);
    setCount(SCAN_SECONDS);
  }

  return (
    <View direction="column" align="stretch" justify="between" gap="xl" padding="lg" fill="grow">
      <Stack gap="xs">
        <Text size="sm" emphasis muted>Confirm payment</Text>
        <Stack direction="row" align="baseline" gap="xs">
          <Text size="3xl" emphasis>{Number(amountSats).toLocaleString('en-US')}</Text>
          <Text size="lg" muted>sats</Text>
        </Stack>
        <Text size="sm" muted>Lightning payment</Text>
      </Stack>

      {phase === 'pin' ? (
        <View direction="column" align="stretch" justify="end" gap="xl">
          <Stack align="center" gap="sm">
            <Text size="lg" emphasis align="center">Enter your card PIN</Text>
            <Text size="3xl" emphasis align="center">{pin.padEnd(PIN_LEN, '○').replaceAll(/\d/g, '●')}</Text>
          </Stack>

          <PinPad onDigit={enterPinDigit} onDelete={deletePinDigit} />

          <Button variant="solid" size="lg" onPress={startScan} disabled={pin.length !== PIN_LEN}>
            Confirm
          </Button>
          <Button variant="soft" size="lg" onPress={onBack}>Back</Button>
        </View>
      ) : null}

      {(phase === 'scanning' || phase === 'signing') ? (
        <View direction="column" align="center" justify="center" gap="lg" fill="grow">
          <IconAvatar icon="card" variant="soft" />
          <Stack align="center" gap="xs">
            <Text size="lg" emphasis align="center">
              {phase === 'scanning' ? 'Ready to read your card' : 'Card connected'}
            </Text>
            <Text size="sm" muted align="center">{status}</Text>
            {phase === 'scanning' ? <Text size="sm" emphasis muted>{count} seconds remaining</Text> : null}
          </Stack>
        </View>
      ) : null}

      {phase === 'done' && result ? (
        <View direction="column" align="stretch" justify="between" gap="xl" fill="grow">
          <View direction="column" align="center" justify="center" gap="lg" fill="grow">
            <IconAvatar icon="check-circle" variant="soft" accent="lilac" />
            <Stack align="center" gap="xs">
              <Text size="xl" emphasis align="center">Payment successful</Text>
              <Text size="sm" muted align="center">The Lightning payment has been funded and confirmed.</Text>
            </Stack>
            <View direction="column" align="stretch" gap="sm">
              <ReceiptRow label="Recipient receives" value={`${result.final_amount_sats.toLocaleString('en-US')} sats`} />
              <ReceiptRow label="Amount sent" value={`${result.funding_amount_sats.toLocaleString('en-US')} sats`} />
              <ReceiptRow label="Payment reference" value={shortReference(result.ark_txid)} />
            </View>
          </View>
          <Button variant="solid" size="lg" onPress={onBack}>New payment</Button>
        </View>
      ) : null}

      {phase === 'error' ? (
        <View direction="column" align="stretch" justify="between" gap="xl" fill="grow">
          <View direction="column" align="center" justify="center" gap="lg" fill="grow">
            <IconAvatar icon="warning-circle" variant="soft" accent="orange" />
            <Stack align="center" gap="xs">
              <Text size="xl" emphasis align="center">Payment not completed</Text>
              <Text size="sm" muted align="center">{error}</Text>
            </Stack>
          </View>
          <Stack gap="sm">
            <Button variant="solid" size="lg" onPress={reset}>Try again</Button>
            <Button variant="soft" size="lg" onPress={onBack}>Back to terminal</Button>
          </Stack>
        </View>
      ) : null}
    </View>
  );
}

function PinPad({ onDigit, onDelete }: { onDigit: (digit: string) => void; onDelete: () => void }) {
  return (
    <View direction="column" gap="sm">
      {[
        ['1', '2', '3'],
        ['4', '5', '6'],
        ['7', '8', '9'],
      ].map((row) => (
        <View key={row.join('')} direction="row" gap="sm">
          {row.map((digit) => (
            <View key={digit} fill="even">
              <Button size="lg" onPress={() => onDigit(digit)}>{digit}</Button>
            </View>
          ))}
        </View>
      ))}
      <View direction="row" gap="sm">
        <View fill="even">
          <Button size="lg" disabled accessibilityLabel="Empty keypad key" />
        </View>
        <View fill="even">
          <Button size="lg" onPress={() => onDigit('0')}>0</Button>
        </View>
        <View fill="even">
          <Button size="lg" onPress={onDelete} accessibilityLabel="Delete PIN digit">
            <ButtonIcon name="chevron-left" />
          </Button>
        </View>
      </View>
    </View>
  );
}

function ReceiptRow({ label, value }: { label: string; value: string }) {
  return (
    <View direction="row" justify="between" gap="md">
      <Text size="sm" muted>{label}</Text>
      <Text size="sm" emphasis align="end" flow="truncate" lines={1}>{value}</Text>
    </View>
  );
}

function shortReference(value: string | undefined): string {
  if (!value) return 'Unavailable';
  if (value.length <= 16) return value;
  return `${value.slice(0, 8)}…${value.slice(-8)}`;
}
