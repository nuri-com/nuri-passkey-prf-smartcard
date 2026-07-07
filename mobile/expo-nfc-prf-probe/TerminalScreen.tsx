// Terminal screen — merchant enters amount on a numpad, hits Charge.
// Mirrors web/merchant-terminal.html exactly.
// Resolves the Lightning address to a BOLT11 invoice, then switches to Approve.

import { useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

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

  return (
    <View style={s.pos}>
      <Text style={s.merchant}>{MERCHANT_NAME}</Text>
      <View style={s.amountRow}>
        <Text style={s.amount}>{amount.toLocaleString('en-US')}</Text>
        <Text style={s.unit}>sats</Text>
      </View>
      <Text style={s.pays}>Charges <Text style={s.paysBold}>{MERCHANT_TARGET}</Text> · mainnet</Text>

      <View style={s.pad}>
        {['1','2','3','4','5','6','7','8','9','C','0','back'].map((k) => (
          <Pressable
            key={k}
            style={s.padBtn}
            onPress={() => press(k)}
            disabled={busy}
            android_ripple={{ color: '#eef1f4' }}
          >
            <Text style={s.padBtnText}>{k === 'back' ? '⌫' : k}</Text>
          </Pressable>
        ))}
      </View>

      <Pressable
        style={[s.charge, !canCharge && s.chargeDisabled]}
        disabled={!canCharge}
        onPress={charge}
      >
        <Text style={s.chargeText}>{busy ? '…' : 'Charge'}</Text>
      </Pressable>

      {status ? <Text style={s.status}>{status}</Text> : null}
    </View>
  );
}

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
  pad: { flexDirection: 'row', flexWrap: 'wrap', marginVertical: 22 },
  padBtn: {
    width: '33.33%', paddingVertical: 18, alignItems: 'center',
    borderRadius: 10, borderWidth: 1, borderColor: '#d7dce3',
    backgroundColor: '#fff', marginBottom: 2,
  },
  padBtnText: { fontSize: 22, fontWeight: '700', color: '#17202a' },
  charge: {
    backgroundColor: '#1f7a5a', borderColor: '#1f7a5a', borderRadius: 10,
    borderWidth: 1, paddingVertical: 16, alignItems: 'center',
  },
  chargeDisabled: { opacity: 0.5 },
  chargeText: { color: '#fff', fontSize: 18, fontWeight: '800' },
  status: { marginTop: 16, textAlign: 'center', color: '#657080', fontSize: 14, fontWeight: '600' },
});
