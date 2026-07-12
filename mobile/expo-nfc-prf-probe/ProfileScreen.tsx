import { useEffect, useRef, useState } from 'react';
import * as Clipboard from 'expo-clipboard';
import { NfcError } from 'react-native-nfc-manager';
import {
  View,
  Stack,
  Scroll,
  Text,
  Button,
  Alert,
  AlertIcon,
  List,
  ListAction,
  ListActionLeadingAvatar,
  ListActionText,
  ListActionTextMuted,
  ListActionTrailIcon,
  ListSeparator,
} from '@nuri/rn';
import { NumericKeypad } from './NumericKeypad';
import { readCardPubkey } from './src/musig2Card';
import { Wallet, InMemoryWalletRepository, InMemoryContractRepository } from '@arkade-os/sdk';
import { ExpoArkProvider, ExpoIndexerProvider } from '@arkade-os/sdk/adapters/expo';
import { ArkadeSwaps, BoltzSwapProvider, InMemorySwapRepository } from '@arkade-os/boltz-swap';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils';
import { bech32m } from '@scure/base';
import { NfcCardIdentity, type SendConfig } from './src/sendFlow';
import { readAuthenticatedLightningAccount } from './src/arkadeAccount';
import { withNfcCardSession } from './src/nfcSession';

type Props = {
  aspInfoUrl: string;
  nodeUrl: string;
  credIdB64u: string;
  credPubkeyB64u: string;
  rpId: string;
  origin: string;
};

type ProfileOperation = 'idle' | 'reading' | 'claiming';
type IncomingState = 'idle' | 'empty' | 'pending' | 'ready' | 'receiving' | 'received';

const CARD_READ_RETRY_MS = 21_000;
const RECEIVE_POLL_MS = 8_000;

export function ProfileScreen({ aspInfoUrl, nodeUrl, credIdB64u, credPubkeyB64u, rpId, origin }: Props) {
  const [cardPk, setCardPk] = useState('');
  const [registered, setRegistered] = useState(false);
  const [arkAddress, setArkAddress] = useState('');
  const [balance, setBalance] = useState<string | null>(null);
  const [username, setUsername] = useState('');
  const [lightningAddress, setLightningAddress] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [claimStatus, setClaimStatus] = useState('');
  const [incomingState, setIncomingState] = useState<IncomingState>('idle');
  const [receiveSyncError, setReceiveSyncError] = useState('');
  const [claimableCount, setClaimableCount] = useState(0);
  const [pin, setPin] = useState('');
  const [copied, setCopied] = useState('');
  const [operation, setOperation] = useState<ProfileOperation>('idle');
  const [operationStatus, setOperationStatus] = useState('');
  const receiveSyncInFlight = useRef(false);
  const lastAutoClaimKey = useRef('');

  const config: SendConfig = {
    aspSignUrl: aspInfoUrl.replace('/arkade/info', '/arkade/sign'),
    aspAuthUrl: aspInfoUrl.replace('/arkade/info', '/arkade/auth'),
    aspInfoUrl,
    intentUrl: aspInfoUrl.replace('/arkade/info', '/arkade/swap-intent/create'),
    prepareUrl: aspInfoUrl.replace('/v4/arkade/info', '/api/arkade/send/prepare'),
    cosignUrl: aspInfoUrl.replace('/v4/arkade/info', '/api/arkade/send/cosign'),
    completeUrl: aspInfoUrl.replace('/v4/arkade/info', '/api/arkade/send/complete'),
    nodeUrl,
    boltzNetwork: 'bitcoin',
    credIdB64u,
    credPubkeyB64u,
    rpId,
    origin,
    pin,
    log: (message: string) => console.log(`[nuri-receive] ${message}`),
  };

  useEffect(() => {
    if (!loaded || !cardPk || busy || operation !== 'idle') return;

    let cancelled = false;
    const poll = async () => {
      if (cancelled || receiveSyncInFlight.current) return;
      try {
        const { claimable } = await syncIncomingPayments(cardPk);
        if (cancelled || claimable.length === 0) return;
        const claimKey = claimable.map((row: any) => String(row.swap_id || '')).sort().join(':');
        if (!claimKey || lastAutoClaimKey.current === claimKey) return;
        lastAutoClaimKey.current = claimKey;
        console.log(`[nuri-receive] auto-claim starting for ${claimable.length} payment(s)`);
        void claimReceives(claimable);
      } catch (syncError: unknown) {
        if (cancelled) return;
        console.error('[nuri-receive] polling failed', syncError);
        setReceiveSyncError('Incoming payments could not be checked. Retrying automatically…');
      }
    };

    const timer = setInterval(() => void poll(), RECEIVE_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [loaded, cardPk, busy, operation]);

  async function loadCard() {
    setBusy(true); setError(''); setBalance(null); setClaimStatus(''); setIncomingState('idle'); setReceiveSyncError(''); setClaimableCount(0);
    lastAutoClaimKey.current = '';
    setCopied('');
    setLoaded(false); setRegistered(false); setUsername(''); setLightningAddress('');
    setOperation('reading');
    setOperationStatus('Waiting for your Nuri card. Keep it near the phone.');
    try {
      // Read the MuSig2 identity and authenticate the separate FIDO credential
      // in one NFC session. A lost/partial NFC connection retries until the
      // bounded read window expires; PIN/auth/server failures remain fail-closed.
      const deadline = Date.now() + CARD_READ_RETRY_MS;
      let card: Awaited<ReturnType<typeof readProfileCard>>;
      while (true) {
        try {
          card = await readProfileCard();
          break;
        } catch (readError: unknown) {
          if (!isRetryableCardReadError(readError) || Date.now() >= deadline) throw readError;
          setOperationStatus('Card connection lost. Keep the card in place while we try again.');
          await delay(350);
        }
      }

      async function readProfileCard() {
        return withNfcCardSession(
          'Hold the Nuri card near the phone while the account is authenticated.',
          async () => {
            const { pubkey } = await readCardPubkey(() => {});
            setOperationStatus('Card detected. Authenticating…');
            const pkHex = pubkeyHex(pubkey);

            const url = new URL(aspInfoUrl);
            url.searchParams.set('client_pk33', pkHex);
            url.searchParams.set('cred_id_b64u', credIdB64u);
            const data = await fetchJson(url.toString());
            const serverPublicKey = String(data.server_pubkey || '').trim();
            if (!/^(02|03)[0-9a-f]{64}$/i.test(serverPublicKey)) {
              throw new Error('ASP info returned no valid server public key');
            }
            if (data.recovery?.registered !== true) {
              throw new Error('credential is not registered for this card key');
            }

            const account = await readAuthenticatedLightningAccount({
              authUrl: aspInfoUrl.replace('/arkade/info', '/arkade/auth'),
              statusUrl: aspInfoUrl.replace('/arkade/info', '/arkade/lnurl/status'),
              credentialIdB64u: credIdB64u,
              credentialPublicKeyB64u: credPubkeyB64u,
              clientPublicKey33Hex: pkHex,
              expectedServerPublicKey33Hex: serverPublicKey,
              rpId,
              origin,
              pin,
            });
            setOperationStatus('Card read. Loading your profile…');
            return { pubkey, pkHex, serverPublicKey, account };
          },
        );
      }
      const { pubkey, pkHex, serverPublicKey: sPk, account } = card;
      setCardPk(pkHex);
      setRegistered(true);
      setUsername(account.username);
      setLightningAddress(account.lightningAddress);

      // 4. Compute aggregate key and Ark address
      const sortedKeys = musig2.sortKeys([pubkey, hexToBytes(sPk)]);
      const aggPk33 = musig2.keyAggregate(sortedKeys).aggPublicKey.toBytes(true);
      const xonly = aggPk33.slice(1);
      const words = [1, ...bech32m.toWords(xonly)];
      setArkAddress(bech32m.encode('bc', words));

      // 5. Create read-only wallet and fetch balance
      const identity = {
        compressedPublicKey: async () => aggPk33,
        xOnlyPublicKey: async () => xonly,
        signerSession: () => { throw new Error('read-only'); },
        signMessage: () => { throw new Error('read-only'); },
        sign: () => { throw new Error('read-only'); },
      };

      const wallet = await Wallet.create({
        identity: identity as any,
        arkProvider: new ExpoArkProvider(nodeUrl),
        indexerProvider: new ExpoIndexerProvider(nodeUrl),
        storage: { walletRepository: new InMemoryWalletRepository(), contractRepository: new InMemoryContractRepository() },
        settlementConfig: false,
      });

      const { available } = parseBalance(await wallet.getBalance());
      setBalance(`${available.toLocaleString('en-US')} sats`);

      // Receive sync is prompt-free. After this initial check the screen keeps
      // polling with the public card identity, even when the card is removed.
      const { claimable } = await syncIncomingPayments(pkHex, account);
      setLoaded(true);
      if (claimable.length > 0) {
        lastAutoClaimKey.current = claimable.map((row: any) => String(row.swap_id || '')).sort().join(':');
        await claimReceives(claimable);
      }
    } catch (e: any) {
      setError(readableProfileError(e));
    } finally {
      setBusy(false);
      setOperation('idle');
      setOperationStatus('');
    }
  }

  async function syncIncomingPayments(
    clientPublicKey33Hex: string,
    expectedAccount?: { username: string; lightningAddress: string },
  ): Promise<{ claimable: any[]; pendingCount: number; cleanupCount: number }> {
    if (receiveSyncInFlight.current) return { claimable: [], pendingCount: 0, cleanupCount: 0 };
    receiveSyncInFlight.current = true;
    setReceiveSyncError('');
    try {
      const syncUrl = aspInfoUrl.replace('/v4/arkade/info', '/api/arkade/receive/sync');
      const synced = await fetchJson(syncUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cred_id_b64u: credIdB64u, client_public_key_33_hex: clientPublicKey33Hex }),
      });
      if (expectedAccount && synced.account != null) {
        const syncUsername = typeof synced.account.username === 'string' ? synced.account.username.trim() : '';
        const syncAddress = typeof synced.account.lightning_address === 'string' ? synced.account.lightning_address.trim() : '';
        if (syncUsername !== expectedAccount.username || syncAddress !== expectedAccount.lightningAddress) {
          throw new Error('receive sync account does not match the authenticated Lightning account');
        }
      }
      if (!Array.isArray(synced.lightning)) throw new Error('receive sync returned no Lightning receive list');

      const receives = synced.lightning;
      const claimable = receives.filter((row: any) => row.status === 'claimable' && row.restore);
      const pending = receives.filter((row: any) => row.status !== 'claimable' && row.status !== 'cleanup_needed');
      const cleanupCount = receives.filter((row: any) => row.status === 'cleanup_needed').length;
      const claimableSats = claimable.reduce((sum: number, row: any) => sum + receiveAmountSats(row), 0);
      const pendingSats = pending.reduce((sum: number, row: any) => sum + receiveAmountSats(row), 0);

      setClaimableCount(claimable.length);
      if (claimable.length > 0) {
        setIncomingState('ready');
        setClaimStatus(`${claimable.length} incoming payment${claimable.length === 1 ? '' : 's'} ready (${claimableSats.toLocaleString('en-US')} sats). Hold your card near the phone to receive automatically.`);
      } else if (pending.length > 0) {
        setIncomingState('pending');
        setClaimStatus(`${pending.length} incoming payment${pending.length === 1 ? ' is' : 's are'} pending${pendingSats > 0 ? ` (${pendingSats.toLocaleString('en-US')} sats)` : ''}. Checking automatically…`);
      } else {
        setIncomingState('empty');
        setClaimStatus('No incoming payments are waiting. Checking automatically…');
      }
      console.log(`[nuri-receive] sync complete: ${claimable.length} ready, ${pending.length} pending, ${cleanupCount} closed`);
      return { claimable, pendingCount: pending.length, cleanupCount };
    } finally {
      receiveSyncInFlight.current = false;
    }
  }

  async function claimReceives(knownClaimable?: any[]) {
    setBusy(true); setError(''); setClaimStatus('Keep the card near the phone while the payment is received.');
    setIncomingState('receiving');
    setOperation('claiming');
    try {
      await withNfcCardSession(
        'Hold the Nuri card near the phone while incoming payments are claimed.',
        async () => {
          const identity = new NfcCardIdentity(config);
          await identity.initialize();

      // Re-fetch ASP info to get server pubkey
      const url = new URL(aspInfoUrl);
      url.searchParams.set('client_pk33', bytesToHex(identity.clientPk33));
      if (credIdB64u) url.searchParams.set('cred_id_b64u', credIdB64u);
      const info = await fetchJson(url.toString());
      const serverPk33 = String(info.server_pubkey || '').trim();
      if (!/^(02|03)[0-9a-f]{64}$/i.test(serverPk33)) throw new Error('ASP info returned no valid server public key');

      identity.serverPk33 = hexToBytes(serverPk33);
      identity.sortedKeys = musig2.sortKeys([identity.clientPk33, identity.serverPk33]);
      identity.aggregatedPk33 = musig2.keyAggregate(identity.sortedKeys).aggPublicKey.toBytes(true);
      identity.aggregatedXonly = identity.aggregatedPk33.slice(1);

          let claimable: any[] = knownClaimable ?? [];
          if (!knownClaimable) {
            const syncUrl = aspInfoUrl.replace('/v4/arkade/info', '/api/arkade/receive/sync');
            const synced = await fetchJson(syncUrl, {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ cred_id_b64u: credIdB64u, client_public_key_33_hex: bytesToHex(identity.clientPk33) }),
            });
            if (!Array.isArray(synced.lightning)) throw new Error('receive sync returned no Lightning receive list');
            claimable = synced.lightning.filter((r: any) => r.status === 'claimable' && r.restore);
          }

          if (claimable.length === 0) {
            setIncomingState('empty');
            setClaimStatus('No incoming payments are ready yet. Checking automatically…');
            return;
          }

          console.log(`[nuri-receive] card connected; claiming ${claimable.length} payment(s)`);

      // Create wallet + swaps with the card-backed identity
      const wallet = await Wallet.create({
        identity: identity as any,
        arkProvider: new ExpoArkProvider(nodeUrl),
        indexerProvider: new ExpoIndexerProvider(nodeUrl),
        storage: { walletRepository: new InMemoryWalletRepository(), contractRepository: new InMemoryContractRepository() },
        settlementConfig: false,
      });

      const swaps = await ArkadeSwaps.create({
        wallet,
        swapProvider: new BoltzSwapProvider({ network: 'bitcoin' as any }),
        swapRepository: new InMemorySwapRepository(),
        swapManager: false,
      });

      let claimed = 0;
      let totalSats = 0;

      for (const r of claimable) {
        identity.claimSwapId = r.swap_id;
        const pendingSwap = {
          id: r.swap_id,
          response: r.restore.response,
          request: r.restore.request,
          preimage: r.restore.preimage,
        };
        await swaps.claimVHTLC(pendingSwap as any);
        claimed++;
        const claimedSats = Number(r.restore?.request?.invoiceAmount);
        if (!Number.isFinite(claimedSats)) throw new Error(`claim ${r.swap_id} returned no invoice amount`);
        totalSats += claimedSats;
      }

      setClaimStatus(`${claimed} incoming payment${claimed === 1 ? '' : 's'} received (${totalSats.toLocaleString('en-US')} sats).`);

      // Refresh balance
      const { available } = parseBalance(await wallet.getBalance());
      setBalance(`${available.toLocaleString('en-US')} sats`);
      setClaimableCount(0);
      setIncomingState('received');
      lastAutoClaimKey.current = '';
      console.log(`[nuri-receive] claim complete: ${claimed} payment(s), ${totalSats} sats`);
        },
      );
    } catch (e: any) {
      console.error('[nuri-receive] claim failed', e);
      setError(readableProfileError(e));
      setIncomingState('ready');
      setClaimStatus('The incoming payment is still waiting. Keep the card nearby and try again.');
    } finally {
      setBusy(false);
      setOperation('idle');
    }
  }

  async function copyValue(label: string, value: string) {
    await Clipboard.setStringAsync(value);
    setCopied(`${label} copied`);
  }

  const retryingIncomingPayment = loaded && claimableCount > 0 && Boolean(error);

  function runPrimaryAction() {
    if (retryingIncomingPayment) {
      void claimReceives();
      return;
    }
    void loadCard();
  }

  const primaryLabel = busy
    ? operation === 'claiming' ? 'Receiving payment…' : 'Reading card…'
    : retryingIncomingPayment
      ? 'Try incoming payment again'
      : loaded ? 'Refresh profile' : 'Read card';

  return (
    <Scroll>
      <View direction="column" align="stretch" gap="lg" paddingY="md">
        {loaded ? (
          <View direction="column" align="stretch" gap="xl">
            <View paddingX="lg">
              <Stack align="center" gap="xs">
                <Text size="sm" muted>Balance</Text>
                <Text size="3xl" emphasis align="center">{balance}</Text>
              </Stack>
            </View>

            <List>
              <ListAction onPress={() => copyValue('Lightning address', lightningAddress)} accessibilityLabel="Copy Lightning address">
                <ListActionLeadingAvatar name="bitcoin-wallet" variant="soft" />
                <ListActionText>Lightning address</ListActionText>
                <ListActionTextMuted>{lightningAddress || username}</ListActionTextMuted>
                <ListActionTrailIcon name="copy" />
              </ListAction>
              <ListSeparator />
              <ListAction onPress={() => copyValue('Wallet address', arkAddress)} accessibilityLabel="Copy wallet address">
                <ListActionLeadingAvatar name="wallet" variant="soft" />
                <ListActionText>Wallet address</ListActionText>
                <ListActionTextMuted>{shortValue(arkAddress)}</ListActionTextMuted>
                <ListActionTrailIcon name="copy" />
              </ListAction>
              <ListSeparator />
              <ListAction accessibilityLabel="Card status">
                <ListActionLeadingAvatar name="check-circle" variant="soft" accent={registered ? 'lilac' : 'orange'} />
                <ListActionText>Card status</ListActionText>
                <ListActionTextMuted>{registered ? 'Connected and registered' : 'Not registered'}</ListActionTextMuted>
              </ListAction>
              <ListSeparator />
              <ListAction onPress={() => copyValue('Card reference', cardPk)} accessibilityLabel="Copy card reference">
                <ListActionLeadingAvatar name="card" variant="soft" />
                <ListActionText>Card reference</ListActionText>
                <ListActionTextMuted>{shortValue(cardPk)}</ListActionTextMuted>
                <ListActionTrailIcon name="copy" />
              </ListAction>
            </List>

            {copied || claimStatus ? (
              <View direction="column" gap="sm" paddingX="lg">
                {copied ? (
                  <Alert variant="ghost">
                    <AlertIcon name="check-circle" />
                    {copied}
                  </Alert>
                ) : null}
                {claimStatus ? (
                  <Alert accent={incomingState === 'received' ? 'lilac' : 'neutral'}>
                    <AlertIcon name={
                      incomingState === 'pending'
                        ? 'bitcoin-wallet'
                        : incomingState === 'ready' || incomingState === 'receiving'
                          ? 'card'
                          : 'check-circle'
                    } />
                    {claimStatus}
                  </Alert>
                ) : null}
              </View>
            ) : null}
          </View>
        ) : null}

        {operation === 'reading' && operationStatus ? (
          <View paddingX="lg">
            <Alert>
              <AlertIcon name="card" />
              {operationStatus}
            </Alert>
          </View>
        ) : null}

        {error ? (
          <View paddingX="lg">
            <Alert accent="orange">
              <AlertIcon name="warning-circle" />
              {error}
            </Alert>
          </View>
        ) : null}

        {receiveSyncError ? (
          <View paddingX="lg">
            <Alert accent="orange">
              <AlertIcon name="warning-circle" />
              {receiveSyncError}
            </Alert>
          </View>
        ) : null}

        {!loaded && operation !== 'reading' ? (
          <View direction="column" align="stretch" gap="xl" paddingX="lg">
            <Stack align="center" gap="sm">
              <Text size="lg" emphasis align="center">Enter your card PIN</Text>
              <Text size="3xl" emphasis align="center">{pin.padEnd(4, '○').replaceAll(/\d/g, '●')}</Text>
            </Stack>
            <NumericKeypad
              onDigit={(digit) => setPin((current) => current.length < 4 ? `${current}${digit}` : current)}
              onDelete={() => setPin((current) => current.slice(0, -1))}
              deleteAccessibilityLabel="Delete PIN digit"
            />
          </View>
        ) : null}

        <View paddingX="lg">
          <Button
            variant="solid"
            size="lg"
            onPress={runPrimaryAction}
            disabled={busy || (!loaded && pin.length !== 4)}
          >
            {primaryLabel}
          </Button>
        </View>
      </View>
    </Scroll>
  );
}


function pubkeyHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function shortValue(value: string): string {
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function receiveAmountSats(receive: any): number {
  const amountMsat = Number(receive?.amount_msat);
  if (Number.isFinite(amountMsat) && amountMsat >= 0) return Math.floor(amountMsat / 1000);
  const invoiceAmount = Number(receive?.restore?.request?.invoiceAmount);
  return Number.isFinite(invoiceAmount) && invoiceAmount >= 0 ? invoiceAmount : 0;
}

function isRetryableCardReadError(error: unknown): boolean {
  if (
    error instanceof NfcError.TagConnectionLost
    || error instanceof NfcError.RetryExceeded
    || error instanceof NfcError.SessionInvalidated
    || error instanceof NfcError.TagNotConnected
    || error instanceof NfcError.Timeout
  ) return true;

  const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  return message.includes('tag was lost')
    || message.includes('tag connection lost')
    || message.includes('tag not connected')
    || message.includes('transceive failed');
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function fetchJson(url: string, init?: RequestInit): Promise<any> {
  const response = await fetch(url, init);
  const data = await response.json();
  if (!response.ok) throw new Error(data?.error || `HTTP ${response.status}`);
  if (data?.error) throw new Error(data.error);
  return data;
}

function parseBalance(value: any): { available: number; total: number } {
  const available = Number(value?.available);
  const total = Number(value?.total);
  if (!Number.isFinite(available) || !Number.isFinite(total)) {
    throw new Error('Arkade returned an invalid wallet balance');
  }
  return { available, total };
}

function readableProfileError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const text = message.toLowerCase();
  if (text.includes('pin') || text.includes('verification') || text.includes('63c')) {
    return 'The PIN was not accepted. Check the PIN and try again.';
  }
  if (text.includes('nfc') || text.includes('card') || text.includes('tag')) {
    return 'We could not read the card. Keep it close to the phone and try again.';
  }
  if (text.includes('network') || text.includes('fetch') || text.includes('http')) {
    return 'We could not connect to the payment service. Check your connection and try again.';
  }
  if (text.includes('claim') || text.includes('swap')) {
    return 'The incoming payment could not be received. Keep the card nearby and try again.';
  }
  return 'We could not open the card profile. Please try again.';
}
