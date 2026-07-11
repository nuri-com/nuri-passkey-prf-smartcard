import { useState } from 'react';
import * as Clipboard from 'expo-clipboard';
import {
  View,
  Stack,
  Scroll,
  Text,
  Button,
  ButtonIcon,
  Alert,
  AlertIcon,
  List,
  ListAction,
  ListActionLeadingAvatar,
  ListActionText,
  ListActionTextMuted,
  ListActionTrailIcon,
} from '@nuri/rn';
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
  const [claimableCount, setClaimableCount] = useState(0);
  const [pin, setPin] = useState('');
  const [copied, setCopied] = useState('');

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
  };

  async function loadCard() {
    setBusy(true); setError(''); setBalance(null); setClaimStatus(''); setClaimableCount(0);
    setCopied('');
    setLoaded(false); setRegistered(false); setUsername(''); setLightningAddress('');
    try {
      // Read the MuSig2 identity and authenticate the separate FIDO credential
      // in one NFC session. This mirrors the working desktop bridge exactly.
      const card = await withNfcCardSession(
        'Hold the Nuri card near the phone while the account is authenticated.',
        async () => {
          const { pubkey } = await readCardPubkey(() => {});
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
          return { pubkey, pkHex, serverPublicKey, account };
        },
      );
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

      // 6. Sync receives — check for claimable incoming payments
      const syncUrl = aspInfoUrl.replace('/v4/arkade/info', '/api/arkade/receive/sync');
      const synced = await fetchJson(syncUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cred_id_b64u: credIdB64u, client_public_key_33_hex: pkHex }),
      });
      if (synced.account != null) {
        const syncUsername = typeof synced.account.username === 'string' ? synced.account.username.trim() : '';
        const syncAddress = typeof synced.account.lightning_address === 'string' ? synced.account.lightning_address.trim() : '';
        if (syncUsername !== account.username || syncAddress !== account.lightningAddress) {
          throw new Error('receive sync account does not match the authenticated Lightning account');
        }
      }
      if (!Array.isArray(synced.lightning)) throw new Error('receive sync returned no Lightning receive list');
      const receives = synced.lightning;
      const claimable = receives.filter((r: any) => r.status === 'claimable' && r.restore);
      setClaimableCount(claimable.length);
      if (claimable.length > 0) {
        const totalSats = claimable.reduce((sum: number, r: any) => sum + Number(r.restore.request.invoiceAmount), 0);
        setClaimStatus(`${claimable.length} incoming payment${claimable.length === 1 ? '' : 's'} found (${totalSats.toLocaleString('en-US')} sats). Receiving automatically…`);
      } else {
        setClaimStatus('No incoming payments are waiting.');
      }
      setLoaded(true);
      if (claimable.length > 0) await claimReceives(claimable);
    } catch (e: any) {
      setError(readableProfileError(e));
    } finally {
      setBusy(false);
    }
  }

  async function claimReceives(knownClaimable?: any[]) {
    setBusy(true); setError(''); setClaimStatus('Keep the card near the phone while the payment is received.');
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
            setClaimStatus('No incoming payments are waiting.');
            return;
          }

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
        },
      );
    } catch (e: any) {
      setError(readableProfileError(e));
      setClaimStatus('');
    } finally {
      setBusy(false);
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
    ? loaded ? 'Receiving payment…' : 'Reading card…'
    : retryingIncomingPayment
      ? 'Try incoming payment again'
      : loaded ? 'Refresh profile' : 'Read card';

  return (
    <Scroll>
      <View direction="column" align="stretch" gap="lg" paddingX="lg" paddingY="md">
        {loaded ? (
          <View direction="column" align="stretch" gap="xl">
            <Stack align="center" gap="xs">
              <Text size="sm" muted>Balance</Text>
              <Text size="3xl" emphasis align="center">{balance}</Text>
            </Stack>

            <List>
              <ListAction onPress={() => copyValue('Lightning address', lightningAddress)} accessibilityLabel="Copy Lightning address">
                <ListActionLeadingAvatar name="bitcoin-wallet" variant="soft" />
                <ListActionText>Lightning address</ListActionText>
                <ListActionTextMuted>{lightningAddress || username}</ListActionTextMuted>
                <ListActionTrailIcon name="copy" />
              </ListAction>
              <ListAction onPress={() => copyValue('Wallet address', arkAddress)} accessibilityLabel="Copy wallet address">
                <ListActionLeadingAvatar name="wallet" variant="soft" />
                <ListActionText>Wallet address</ListActionText>
                <ListActionTextMuted>{shortValue(arkAddress)}</ListActionTextMuted>
                <ListActionTrailIcon name="copy" />
              </ListAction>
              <ListAction accessibilityLabel="Card status">
                <ListActionLeadingAvatar name="check-circle" variant="soft" accent={registered ? 'lilac' : 'orange'} />
                <ListActionText>Card status</ListActionText>
                <ListActionTextMuted>{registered ? 'Connected and registered' : 'Not registered'}</ListActionTextMuted>
              </ListAction>
              <ListAction onPress={() => copyValue('Card reference', cardPk)} accessibilityLabel="Copy card reference">
                <ListActionLeadingAvatar name="card" variant="soft" />
                <ListActionText>Card reference</ListActionText>
                <ListActionTextMuted>{shortValue(cardPk)}</ListActionTextMuted>
                <ListActionTrailIcon name="copy" />
              </ListAction>
            </List>

            {copied ? (
              <Alert variant="ghost">
                <AlertIcon name="check-circle" />
                {copied}
              </Alert>
            ) : null}
            {claimStatus ? (
              <Alert accent={busy ? 'neutral' : 'lilac'}>
                <AlertIcon name={busy ? 'card' : 'check-circle'} />
                {claimStatus}
              </Alert>
            ) : null}
          </View>
        ) : null}

        {error ? (
          <Alert accent="orange">
            <AlertIcon name="warning-circle" />
            {error}
          </Alert>
        ) : null}

        {!loaded ? (
          <View direction="column" align="stretch" gap="xl">
            <Stack align="center" gap="sm">
              <Text size="lg" emphasis align="center">Enter your card PIN</Text>
              <Text size="3xl" emphasis align="center">{pin.padEnd(4, '○').replaceAll(/\d/g, '●')}</Text>
            </Stack>
            <PinPad
              onDigit={(digit) => setPin((current) => current.length < 4 ? `${current}${digit}` : current)}
              onDelete={() => setPin((current) => current.slice(0, -1))}
            />
          </View>
        ) : null}

        <Button
          variant="solid"
          size="lg"
          onPress={runPrimaryAction}
          disabled={busy || (!loaded && pin.length !== 4)}
        >
          {primaryLabel}
        </Button>
      </View>
    </Scroll>
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

function pubkeyHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function shortValue(value: string): string {
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
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
