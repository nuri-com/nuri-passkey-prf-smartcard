// Approve screen — Visa-style tap-to-pay. Mirrors web/nuri-checkout.html.
// Shows amount, card selector, PIN pad. Auto-starts scanning at 4 digits.
// 21-second scan ring → card read → cosign + send → receipt.

import { useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Animated,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';
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
  const [account, setAccount] = useState<'nuri' | 'pure'>('nuri');
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
        if (c <= 1) {
          setPhase('error');
          setError('No card detected — try again');
          return 0;
        }
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
    if (newPin.length === PIN_LEN) {
      setTimeout(() => startScan(newPin), 100);
    }
  }

  async function startScan(enteredPin: string) {
    setPhase('scanning');
    setStatus('Hold your card on the reader…');
    setCount(SCAN_SECONDS);
    setError('');

    // The scanning countdown gives the user time to tap the card.
    // The actual card read happens inside sendLightning (readCardPubkey +
    // webauthnAssert). We transition to signing after a brief tap window.
    await sleep(2000);

    setPhase('signing');
    setStatus('Card read — approving payment…');

    try {
      const cfg = { ...config, pin: enteredPin, invoice };
      const res = await sendLightning(cfg, invoice);
      setResult(res);
      setPhase('done');
      setStatus('Approved — payment broadcast');
    } catch (e: any) {
      setPhase('error');
      setError(e.message || 'Payment failed');
      setStatus('');
    }
  }

  function reset() {
    setPin('');
    setPhase('pin');
    setStatus('');
    setError('');
    setResult(null);
    setCount(SCAN_SECONDS);
  }

  const ringProgress = phase === 'scanning' ? count / SCAN_SECONDS : 0;
  const pinDots = Math.max(4, pin.length);

  return (
    <View style={s.pos}>
      <Text style={s.merchant}>{merchantName}</Text>
      <View style={s.amountRow}>
        <Text style={s.amount}>{Number(amountSats).toLocaleString('en-US')}</Text>
        <Text style={s.unit}>sats</Text>
      </View>
      <Text style={s.pays}>Pays <Text style={s.paysBold}>{memo}</Text> · mainnet</Text>

      {phase === 'pin' && (
        <View>
          <Text style={s.secLabel}>Pay with card</Text>
          <View style={s.cards}>
            <Pressable
              style={[s.cardOpt, account === 'nuri' && s.cardSel]}
              onPress={() => setAccount('nuri')}
            >
              <View style={s.chip} />
              <Text style={s.cardT}>Nuri Card</Text>
              <Text style={s.cardS}>card@nuri.com</Text>
            </Pressable>
            <Pressable
              style={[s.cardOpt, account === 'pure' && s.cardSel]}
              onPress={() => setAccount('pure')}
            >
              <View style={s.chip} />
              <Text style={s.cardT}>Pure Arkade</Text>
              <Text style={s.cardS}>no Nuri · card only</Text>
            </Pressable>
          </View>

          <Text style={s.secLabel}>Enter card PIN</Text>
          <View style={s.pinView}>
            {Array.from({ length: pinDots }).map((_, i) => (
              <View key={i} style={[s.pinDot, i < pin.length && s.pinDotOn]} />
            ))}
          </View>

          <View style={s.pad}>
            {['1','2','3','4','5','6','7','8','9','C','0','back'].map((k) => (
              <Pressable
                key={k}
                style={s.padBtn}
                onPress={() => press(k)}
                android_ripple={{ color: '#eef1f4' }}
              >
                <Text style={s.padBtnText}>{k === 'back' ? '⌫' : k}</Text>
              </Pressable>
            ))}
          </View>

          <Pressable
            style={[s.charge, !canCharge && s.chargeDisabled]}
            disabled={!canCharge}
            onPress={() => startScan(pin)}
          >
            <Text style={s.chargeText}>Tap card &amp; approve</Text>
          </Pressable>
        </View>
      )}

      {(phase === 'scanning' || phase === 'signing') && (
        <View style={s.stage}>
          <View style={s.ringWrap}>
            <Animated.Text style={[s.cardAnim, { transform: [{ scale: pulseAnim }] }]}>
              {phase === 'scanning' ? '💳' : '⚙️'}
            </Animated.Text>
            {phase === 'scanning' && (
              <View style={s.ringBar}>
                <View style={[s.ringBarFill, { width: `${ringProgress * 100}%` }]} />
              </View>
            )}
          </View>
          <Text style={[s.status, s.statusWait]}>{status}</Text>
          {phase === 'scanning' && <Text style={s.countText}>{count}s</Text>}
          {phase === 'signing' && <ActivityIndicator style={{ marginTop: 8 }} />}
        </View>
      )}

      {phase === 'done' && result && (
        <View style={s.stage}>
          <Text style={s.cardAnim}>✅</Text>
          <Text style={[s.status, s.statusOk]}>Approved — payment broadcast</Text>
          <View style={s.receipt}>
            <ReceiptRow label="Status" value="APPROVED" />
            <ReceiptRow label="Card" value={account === 'pure' ? 'Pure Arkade' : 'Nuri (card@nuri.com)'} />
            <ReceiptRow label="Paid" value={`${result.final_amount_sats} sats (funded ${result.funding_amount_sats})`} />
            <ReceiptRow label="Ark txid" value={result.ark_txid || '—'} mono />
          </View>
          <Pressable style={s.againBtn} onPress={onBack}>
            <Text style={s.againText}>New payment</Text>
          </Pressable>
        </View>
      )}

      {phase === 'error' && (
        <View style={s.stage}>
          <Text style={s.cardAnim}>⚠️</Text>
          <Text style={[s.status, s.statusBad]}>{error}</Text>
          <Pressable style={s.againBtn} onPress={reset}>
            <Text style={s.againText}>Try again</Text>
          </Pressable>
        </View>
      )}
    </View>
  );
}

function ReceiptRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <View style={s.receiptRow}>
      <Text style={s.receiptLabel}>{label}</Text>
      <Text style={[s.receiptValue, mono && s.receiptMono]}>{value}</Text>
    </View>
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const s = StyleSheet.create({
  pos: {
    backgroundColor: '#fff', borderColor: '#d7dce3', borderRadius: 14, borderWidth: 1,
    padding: 22, shadowColor: '#000', shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.04, shadowRadius: 2, elevation: 1,
  },
  merchant: { color: '#657080', fontWeight: '700', fontSize: 14 },
  amountRow: { flexDirection: 'row', alignItems: 'baseline', marginTop: 6 },
  amount: { fontSize: 56, fontWeight: '800', letterSpacing: -1, color: '#17202a' },
  unit: { fontSize: 22, fontWeight: '700', color: '#657080', marginLeft: 8 },
  pays: { color: '#657080', fontSize: 13, marginTop: 6 },
  paysBold: { fontWeight: '700', color: '#17202a' },
  secLabel: {
    fontSize: 12, fontWeight: '700', color: '#657080',
    textTransform: 'uppercase', letterSpacing: 0.6,
    marginTop: 20, marginBottom: 8,
  },
  cards: { flexDirection: 'row', gap: 10 },
  cardOpt: {
    flex: 1, borderColor: '#d7dce3', borderRadius: 12, borderWidth: 1,
    padding: 12, backgroundColor: '#fff',
  },
  cardSel: { borderColor: '#1f7a5a', borderWidth: 2 },
  chip: {
    width: 26, height: 19, borderRadius: 4,
    backgroundColor: '#c99a2e', marginBottom: 9,
  },
  cardT: { fontWeight: '700', fontSize: 13, color: '#17202a' },
  cardS: { fontSize: 11, color: '#657080', marginTop: 2 },
  pinView: { flexDirection: 'row', justifyContent: 'center', gap: 14, paddingVertical: 12, height: 36 },
  pinDot: { width: 12, height: 12, borderRadius: 6, borderColor: '#d7dce3', borderWidth: 1.5 },
  pinDotOn: { backgroundColor: '#17202a', borderColor: '#17202a' },
  pad: { flexDirection: 'row', flexWrap: 'wrap', marginVertical: 14 },
  padBtn: {
    width: '32%', marginHorizontal: '1%', marginBottom: 10,
    borderRadius: 10, borderWidth: 1, borderColor: '#d7dce3',
    backgroundColor: '#fff', paddingVertical: 18, alignItems: 'center',
  },
  padBtnText: { fontSize: 22, fontWeight: '700', color: '#17202a' },
  charge: {
    backgroundColor: '#1f7a5a', borderColor: '#1f7a5a', borderRadius: 10,
    borderWidth: 1, paddingVertical: 16, alignItems: 'center',
  },
  chargeDisabled: { opacity: 0.5 },
  chargeText: { color: '#fff', fontSize: 18, fontWeight: '800' },
  stage: { alignItems: 'center', marginTop: 18 },
  ringWrap: { width: 132, height: 132, alignItems: 'center', justifyContent: 'center' },
  cardAnim: { fontSize: 40, lineHeight: 40 },
  ringBar: {
    width: 100, height: 6, borderRadius: 3, backgroundColor: '#e6e9ee',
    marginTop: 8, overflow: 'hidden',
  },
  ringBarFill: { height: '100%', backgroundColor: '#1f7a5a' },
  countText: { fontSize: 13, fontWeight: '700', color: '#657080', marginTop: 4 },
  status: { marginTop: 8, fontSize: 14, fontWeight: '600', textAlign: 'center', color: '#657080' },
  statusWait: { color: '#9a6b00' },
  statusOk: { color: '#1f7a5a' },
  statusBad: { color: '#9a3412' },
  receipt: {
    marginTop: 14, borderTopColor: '#d7dce3', borderTopWidth: 1,
    borderStyle: 'dashed', paddingTop: 12, width: '100%',
  },
  receiptRow: { flexDirection: 'row', justifyContent: 'space-between', gap: 12, marginVertical: 5 },
  receiptLabel: { color: '#657080', fontSize: 13 },
  receiptValue: { fontSize: 13, textAlign: 'right', flexShrink: 1, color: '#17202a' },
  receiptMono: { fontFamily: 'Courier', fontSize: 11 },
  againBtn: {
    marginTop: 16, backgroundColor: '#fff', borderColor: '#1f7a5a',
    borderRadius: 10, borderWidth: 1, paddingVertical: 12, paddingHorizontal: 24,
  },
  againText: { color: '#1f7a5a', fontSize: 15, fontWeight: '700' },
});
