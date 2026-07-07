// LNURL-pay resolution + BOLT11 validation for the phone.
// Mirrors the server's resolveLightningInvoice + validateCheckoutInvoice.
// The phone resolves Lightning addresses directly via fetch (no server needed).

import { bech32 } from '@scure/base';

export type ResolvedInvoice = {
  invoice: string;
  amount_sats: number;
  payment_hash: string;
  expires_at: string;
  source: { kind: string; target?: string };
};

// Decode a Lightning address or LNURL string to an HTTPS LNURL-pay endpoint.
function decodeLnurl(raw: string): string {
  const value = raw.trim();
  if (!value) throw new Error('Lightning address, LNURL, or BOLT11 invoice is required');
  if (/^https:\/\//i.test(value)) return value;
  if (/^lnurl/i.test(value)) {
    const decoded = bech32.decode(value.toLowerCase() as any, 4096);
    return new TextDecoder().decode(Uint8Array.from(bech32.fromWords(decoded.words)));
  }
  const la = value.match(/^([^@\s]+)@([^@\s]+)$/);
  if (la) {
    const name = encodeURIComponent(la[1]);
    const domain = la[2].toLowerCase();
    return `https://${domain}/.well-known/lnurlp/${name}`;
  }
  throw new Error('target must be a Lightning address, LNURL-pay string, or BOLT11 invoice');
}

async function fetchJson(url: string): Promise<any> {
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  const text = await res.text();
  let body: any;
  try { body = JSON.parse(text); } catch { throw new Error(`non-JSON response from ${url}`); }
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${body.reason || text.slice(0, 160)}`);
  if (body.status && String(body.status).toUpperCase() === 'ERROR') {
    throw new Error(body.reason || 'LNURL error');
  }
  return body;
}

// Minimal BOLT11 amount parser. The SDK's getInvoicePaymentHash/ getInvoiceSatoshis
// does the full parse in sendFlow.ts, so here we only extract the amount for
// the checkout display. ponytail: no payment_hash parsing — sendFlow does it.
function parseBolt11Amount(invoice: string): { amount_sats: number; expires_at: string } {
  const lower = invoice.toLowerCase();
  if (!lower.startsWith('lnbc')) throw new Error('not a mainnet BOLT11 invoice');
  const match = lower.match(/^lnbc([0-9]+)([munp]?)/);
  if (!match) throw new Error('could not parse BOLT11 amount');
  const digits = BigInt(match[1]);
  const mult = match[2];
  let msats: bigint;
  if (mult === '') msats = digits * 1000n;
  else if (mult === 'm') msats = digits * 100000n;
  else if (mult === 'u') msats = digits * 100000000n;
  else if (mult === 'n') msats = digits * 100000000000n;
  else if (mult === 'p') msats = digits * 100000000000000n;
  else throw new Error('unsupported BOLT11 multiplier');
  if (msats % 1000n !== 0n) throw new Error('BOLT11 amount is below millisat precision');
  const sats = Number(msats / 1000n);

  // Extract timestamp from the data section (first 7 chars after prefix+1).
  const tsMatch = lower.match(/^ln[a-z]+1([0-9]+)/);
  const timestamp = tsMatch ? Number(BigInt(tsMatch[1])) : Math.floor(Date.now() / 1000);
  // Default expiry 3600s (BOLT11 spec default). ponytail: doesn't parse the
  // expiry tag, just uses the default. Fine for checkout display.
  const expiresAt = new Date(timestamp * 1000 + 3600 * 1000).toISOString();
  return { amount_sats: sats, expires_at: expiresAt };
}

export async function resolveLightningInvoice(
  target: string,
  amountSats: number,
  comment = '',
): Promise<ResolvedInvoice> {
  const trimmed = target.trim();

  // If it's already a BOLT11 invoice, use it directly.
  if (/^ln/i.test(trimmed) && !/^lnurl/i.test(trimmed)) {
    const parsed = parseBolt11Amount(trimmed);
    return {
      invoice: trimmed,
      amount_sats: parsed.amount_sats,
      payment_hash: '',
      expires_at: parsed.expires_at,
      source: { kind: 'bolt11' },
    };
  }

  // Resolve via LNURL-pay.
  const lnurl = decodeLnurl(trimmed);
  const metadata = await fetchJson(lnurl);
  if (metadata.tag !== 'payRequest') throw new Error('LNURL target is not a payRequest');

  const amountMsats = amountSats * 1000;
  if (amountMsats < Number(metadata.minSendable) || amountMsats > Number(metadata.maxSendable)) {
    throw new Error(`amount must be between ${Math.ceil(Number(metadata.minSendable) / 1000)} and ${Math.floor(Number(metadata.maxSendable) / 1000)} sats`);
  }

  const callback = new URL(metadata.callback);
  callback.searchParams.set('amount', String(amountMsats));
  if (comment && Number(metadata.commentAllowed || 0) > 0) {
    callback.searchParams.set('comment', comment.slice(0, Number(metadata.commentAllowed)));
  }

  const invoiceResponse = await fetchJson(callback.toString());
  if (!invoiceResponse.pr) throw new Error('LNURL callback did not return an invoice');

  const parsed = parseBolt11Amount(invoiceResponse.pr);
  return {
    invoice: invoiceResponse.pr,
    amount_sats: parsed.amount_sats,
    payment_hash: '',
    expires_at: parsed.expires_at,
    source: { kind: 'lnurl-pay', target: trimmed },
  };
}
