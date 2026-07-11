import { useState } from 'react';
import { ActivityIndicator } from 'react-native';
import { View, Stack, Scroll, Text, Button } from '@nuri/rn';
import { readCardPubkey } from './src/musig2Card';
import { Wallet, InMemoryWalletRepository, InMemoryContractRepository } from '@arkade-os/sdk';
import { ExpoArkProvider, ExpoIndexerProvider } from '@arkade-os/sdk/adapters/expo';
import { ArkadeSwaps, BoltzSwapProvider, InMemorySwapRepository } from '@arkade-os/boltz-swap';
import * as musig2 from '@scure/btc-signer/musig2.js';
import { hexToBytes, bytesToHex } from '@noble/curves/abstract/utils';
import { bech32m } from '@scure/base';
import { NfcCardIdentity, type SendConfig } from './src/sendFlow';

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
  const [serverPk, setServerPk] = useState('');
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
    pin: '',
  };

  async function loadCard() {
    setBusy(true); setError(''); setBalance(null); setClaimStatus(''); setClaimableCount(0);
    setLoaded(false); setRegistered(false); setUsername(''); setLightningAddress('');
    try {
      // 1. Read card pubkey via NFC
      const { pubkey } = await readCardPubkey(() => {});
      const pkHex = pubkeyHex(pubkey);
      setCardPk(pkHex);

      // 2. Fetch ASP info
      const url = new URL(aspInfoUrl);
      url.searchParams.set('client_pk33', pkHex);
      if (credIdB64u) url.searchParams.set('cred_id_b64u', credIdB64u);
      const data = await fetchJson(url.toString());
      const sPk = String(data.server_pubkey || '').trim();
      if (!/^(02|03)[0-9a-f]{64}$/i.test(sPk)) throw new Error('ASP info returned no valid server public key');
      setServerPk(sPk);

      // 3. Read the existing binding. Profile reads must never create or replace
      // a credential/card association; registration is a separate explicit act.
      if (data.recovery?.registered !== true) {
        throw new Error('credential is not registered for this card key');
      }
      setRegistered(true);

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

      const { available, total } = parseBalance(await wallet.getBalance());
      setBalance(`${available} sats (total ${total})`);

      // 6. Sync receives — check for claimable incoming payments
      const syncUrl = aspInfoUrl.replace('/v4/arkade/info', '/api/arkade/receive/sync');
      const synced = await fetchJson(syncUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cred_id_b64u: credIdB64u, client_public_key_33_hex: pkHex }),
      });
      const account = synced.account;
      const exactUsername = typeof account?.username === 'string' ? account.username.trim() : '';
      const exactLightningAddress = typeof account?.lightning_address === 'string' ? account.lightning_address.trim() : '';
      if (!exactUsername || !exactLightningAddress) {
        throw new Error('receive sync returned no registered Lightning username for this card credential');
      }
      if (!Array.isArray(synced.lightning)) throw new Error('receive sync returned no Lightning receive list');
      setUsername(exactUsername);
      setLightningAddress(exactLightningAddress);
      const receives = synced.lightning;
      const claimable = receives.filter((r: any) => r.status === 'claimable' && r.restore);
      setClaimableCount(claimable.length);
      if (claimable.length > 0) {
        const totalSats = claimable.reduce((sum: number, r: any) => sum + Number(r.restore.request.invoiceAmount), 0);
        setClaimStatus(`${claimable.length} incoming payment(s) waiting: ${totalSats} sats.`);
      } else {
        setClaimStatus('The server returned no claimable incoming payments.');
      }
      setLoaded(true);
    } catch (e: any) {
      setError(e.message || 'Failed to read card or fetch balance');
    } finally {
      setBusy(false);
    }
  }

  async function claimReceives() {
    setBusy(true); setError(''); setClaimStatus('Claiming — hold card on phone...');
    try {
      // Use the same NfcCardIdentity from sendFlow — it handles card NFC signing
      const identity = new NfcCardIdentity(config);
      await (identity as any).initialize();

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

      // Sync receives
      const syncUrl = aspInfoUrl.replace('/v4/arkade/info', '/api/arkade/receive/sync');
      const synced = await fetchJson(syncUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ cred_id_b64u: credIdB64u, client_public_key_33_hex: bytesToHex(identity.clientPk33) }),
      });
      if (!Array.isArray(synced.lightning)) throw new Error('receive sync returned no Lightning receive list');
      const receives = synced.lightning;
      const claimable = receives.filter((r: any) => r.status === 'claimable' && r.restore);

      if (claimable.length === 0) {
        setClaimStatus('No incoming payments to claim.');
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

      setClaimStatus(`Claimed ${claimed}/${claimable.length} (${totalSats} sats)`);

      // Refresh balance
      const { available, total } = parseBalance(await wallet.getBalance());
      setBalance(`${available} sats (total ${total})`);
      setClaimableCount(0);
    } catch (e: any) {
      setError(e.message || 'Claim failed');
      setClaimStatus('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Scroll>
      <View padding="lg" paddingBottom="xl" gap="lg">
        {loaded ? (
          <>
            <View chrome="canvas" radius="md" padding="xl" gap="md">
              <Text size="lg" emphasis>Wallet</Text>
              {username ? <Text size="sm" muted>{username}</Text> : null}
              {lightningAddress ? <Text size="sm" muted>{lightningAddress}</Text> : null}
              <Stack gap="xs">
                <Text size="xs" emphasis muted>Ark address</Text>
                <Text size="xs" flow="truncate" lines={1}>{arkAddress}</Text>
              </Stack>
              <Stack gap="xs">
                <Text size="xs" emphasis muted>Balance</Text>
                <Text size="xl" emphasis>{balance}</Text>
              </Stack>
            </View>

            <View chrome="canvas" radius="md" padding="xl" gap="md">
              <Text size="lg" emphasis>Card</Text>
              <Stack gap="xs">
                <Text size="xs" emphasis muted>Card MuSig2 pubkey</Text>
                <Text size="xs" flow="truncate" lines={1}>{cardPk}</Text>
              </Stack>
              <Stack gap="xs">
                <Text size="xs" emphasis muted>Registered</Text>
                <Text size="sm">{registered ? 'yes' : 'no'}</Text>
              </Stack>
            </View>

            <View chrome="canvas" radius="md" padding="xl" gap="md">
              <Text size="lg" emphasis>Arkade ASP</Text>
              <Stack gap="xs">
                <Text size="xs" emphasis muted>ASP server pubkey</Text>
                <Text size="xs" flow="truncate" lines={1}>{serverPk}</Text>
              </Stack>
            </View>

            {claimStatus ? <Text size="sm" emphasis muted align="center">{claimStatus}</Text> : null}
            {claimableCount > 0 ? (
              <Button variant="solid" size="lg" onPress={claimReceives} disabled={busy}>
                {busy ? 'Claiming…' : 'Claim incoming'}
              </Button>
            ) : null}
          </>
        ) : (
          <View chrome="canvas" radius="md" padding="xl" gap="md" align="center">
            <Text size="lg" emphasis>Card Profile</Text>
            <Text size="sm" muted>Tap the button below and hold your card on the phone to see your wallet balance, Ark address, and incoming payments.</Text>
          </View>
        )}

        {busy ? <ActivityIndicator style={{ alignSelf: 'center' }} /> : null}
        {error ? <Text size="sm" muted align="center">{error}</Text> : null}

        <Button variant="solid" size="lg" onPress={loadCard} disabled={busy}>
          {busy ? 'Reading card…' : loaded ? 'Refresh (tap card)' : 'Read card'}
        </Button>
      </View>
    </Scroll>
  );
}

function pubkeyHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
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
