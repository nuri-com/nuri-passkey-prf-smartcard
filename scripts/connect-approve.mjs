#!/usr/bin/env node
/**
 * Direct CLI Nuri Connect approver using a connected PC/SC Nuri Smartcard.
 *
 * Shortest path (zero browser, zero Chrome extension):
 *   1. Fetches the session from https://connect.nuri.com/api/wallet_session
 *   2. Calls host/webauthn_bridge.py directly over PC/SC (FIDO2 CTAP2 + PRF)
 *   3. Derives Nuri wallet / Agent Grant keys identically to connect.nuri.com
 *   4. Zeroizes PRF & private keys in memory and POSTs /api/wallet_sign_complete
 *
 * Usage:
 *   nuricard connect <approval_url_or_session_id> [--cred <cred_id_b64u>] [--dry-run] [--json]
 */

import { spawn } from "node:child_process";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bech32, bech32m } from "@scure/base";
import { HDKey } from "@scure/bip32";
import * as musig2 from "@scure/btc-signer/musig2.js";
import { Wallet, getAddress } from "ethers";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

export const DEFAULT_CONNECT_ORIGIN = "https://connect.nuri.com";
export const NURI_DERIVATION_VERSION = "nuri-expo-wallet-v1";
export const AGENT_DERIVATION_VERSION = "nuri-agent-wallet-v1";
export const AGENT_GRANT_REPLY_FORMAT = "nuri-agent-grant-reply-v1";

const WALLET_SALT = sha256(utf8("app:nuri.com|wallet|v1"));
const BITCOIN_INFO = utf8("app:nuri.com|wallet|v1|chain=bitcoin|fmt=taproot");
const ETHEREUM_INFO = utf8("app:nuri.com|wallet|v1|chain=ethereum|fmt=secp256k1");
const NOSTR_SALT = sha256(utf8("nuri-nostr-salt-v1"));
const NOSTR_INFO = utf8("nuri:nostr:sk:v1");
const AGENT_WALLET_SALT = sha256(utf8("app:nuri.com|agent-wallet|v1"));
const AGENT_REPLY_SALT = utf8("nuri-agent-grant-reply-v1");
const BIP86_PATH = "m/86'/0'/0'/0/0";
const ETH_PATH = "m/44'/60'/0'/0/0";
const MAX_AGENT_INDEX = 1_000_000;
const HEX64_RE = /^[0-9a-f]{64}$/;
const SECP256K1_N = secp256k1.Point.Fn.ORDER;

export function utf8(str) {
  return new TextEncoder().encode(String(str));
}

export function bytesToHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

export function hexToBytes(hex) {
  const clean = String(hex || "").replace(/^0x/, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error("invalid_hex");
  }
  return new Uint8Array(Buffer.from(clean, "hex"));
}

export function bytesToBase64Url(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function base64UrlToBytes(str) {
  let norm = String(str || "").replace(/-/g, "+").replace(/_/g, "/");
  while (norm.length % 4) norm += "=";
  return new Uint8Array(Buffer.from(norm, "base64"));
}

export function zeroize(bytes) {
  if (!bytes || !(bytes instanceof Uint8Array)) return;
  randomBytes(bytes.length).copy(bytes);
  bytes.fill(0);
}

// ---------------------------------------------------------------------------
// RFC draft-irtf-cfrg-xchacha: HChaCha20 + XChaCha20-Poly1305 (zero extra deps)
// ---------------------------------------------------------------------------
function rotl32(v, c) {
  return ((v << c) | (v >>> (32 - c))) >>> 0;
}

function quarterRound(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl32(s[b] ^ s[c], 7);
}

export function hchacha20(key32, nonce16) {
  if (key32.length !== 32 || nonce16.length !== 16) {
    throw new Error("hchacha20_invalid_input");
  }
  const kv = new DataView(key32.buffer, key32.byteOffset, 32);
  const nv = new DataView(nonce16.buffer, nonce16.byteOffset, 16);
  const s = new Uint32Array([
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    kv.getUint32(0, true), kv.getUint32(4, true), kv.getUint32(8, true), kv.getUint32(12, true),
    kv.getUint32(16, true), kv.getUint32(20, true), kv.getUint32(24, true), kv.getUint32(28, true),
    nv.getUint32(0, true), nv.getUint32(4, true), nv.getUint32(8, true), nv.getUint32(12, true),
  ]);
  for (let i = 0; i < 10; i++) {
    quarterRound(s, 0, 4, 8, 12);
    quarterRound(s, 1, 5, 9, 13);
    quarterRound(s, 2, 6, 10, 14);
    quarterRound(s, 3, 7, 11, 15);
    quarterRound(s, 0, 5, 10, 15);
    quarterRound(s, 1, 6, 11, 12);
    quarterRound(s, 2, 7, 8, 13);
    quarterRound(s, 3, 4, 9, 14);
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, s[0], true); ov.setUint32(4, s[1], true);
  ov.setUint32(8, s[2], true); ov.setUint32(12, s[3], true);
  ov.setUint32(16, s[12], true); ov.setUint32(20, s[13], true);
  ov.setUint32(24, s[14], true); ov.setUint32(28, s[15], true);
  return out;
}

export function xchacha20Poly1305Seal(key32, nonce24, plaintext, aad = new Uint8Array(0)) {
  if (key32.length !== 32 || nonce24.length !== 24) {
    throw new Error("xchacha20_invalid_input");
  }
  const subkey = hchacha20(key32, nonce24.subarray(0, 16));
  const ietfNonce = new Uint8Array(12);
  ietfNonce.set(nonce24.subarray(16, 24), 4);
  try {
    const cipher = createCipheriv("chacha20-poly1305", subkey, ietfNonce, { authTagLength: 16 });
    if (aad.length > 0) cipher.setAAD(aad);
    const enc = cipher.update(plaintext);
    const fin = cipher.final();
    const tag = cipher.getAuthTag();
    return new Uint8Array(Buffer.concat([enc, fin, tag]));
  } finally {
    zeroize(subkey);
  }
}

export function xchacha20Poly1305Open(key32, nonce24, ciphertextWithTag, aad = new Uint8Array(0)) {
  if (key32.length !== 32 || nonce24.length !== 24 || ciphertextWithTag.length < 16) {
    return null;
  }
  const subkey = hchacha20(key32, nonce24.subarray(0, 16));
  const ietfNonce = new Uint8Array(12);
  ietfNonce.set(nonce24.subarray(16, 24), 4);
  try {
    const body = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
    const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
    const decipher = createDecipheriv("chacha20-poly1305", subkey, ietfNonce, { authTagLength: 16 });
    if (aad.length > 0) decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const dec = decipher.update(body);
    const fin = decipher.final();
    return new Uint8Array(Buffer.concat([dec, fin]));
  } catch {
    return null;
  } finally {
    zeroize(subkey);
  }
}

// ---------------------------------------------------------------------------
// Exact Nuri Connect wallet & Agent Grant derivation (byte-identical to nuri-connect)
// ---------------------------------------------------------------------------
function bytesToBigInt(bytes) {
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return value;
}

// Matches nuri-connect/src/browser/wallet-compat.ts & src/shared/agent-grant.ts verbatim.
function taprootSingleSig(compressedPubkey33) {
  const internal = compressedPubkey33.slice(1);
  const tag = sha256(utf8("TapTweak"));
  const tweak = sha256(new Uint8Array([...tag, ...tag, ...internal]));
  const tweakScalar = bytesToBigInt(tweak) % SECP256K1_N;
  const point = secp256k1.Point.fromBytes(compressedPubkey33).add(
    secp256k1.Point.BASE.multiply(tweakScalar),
  );
  const xOnly = point.toBytes(true).slice(1);
  return {
    address: bech32m.encode("bc", [1, ...bech32m.toWords(xOnly)]),
    xOnly,
  };
}

function deriveNostrPrivateKey(bitcoinPrivateKey) {
  let candidate = hkdf(sha256, sha256(bitcoinPrivateKey), NOSTR_SALT, NOSTR_INFO, 32);
  for (let attempt = 0; attempt < 256; attempt++) {
    if (secp256k1.utils.isValidSecretKey(candidate)) return candidate;
    const next = sha256(candidate);
    zeroize(candidate);
    candidate = next;
  }
  zeroize(candidate);
  throw new Error("nostr_private_key_derivation_failed");
}

export function deriveNuriWallet(prf) {
  if (!(prf instanceof Uint8Array) || prf.byteLength < 32) {
    throw new Error("prf_invalid");
  }
  const bitcoinEntropy = hkdf(sha256, prf, WALLET_SALT, BITCOIN_INFO, 32);
  const ethereumEntropy = hkdf(sha256, prf, WALLET_SALT, ETHEREUM_INFO, 32);
  const bitcoinRoot = HDKey.fromMasterSeed(bitcoinEntropy);
  const ethereumRoot = HDKey.fromMasterSeed(ethereumEntropy);
  const bitcoinChild = bitcoinRoot.derive(BIP86_PATH);
  const ethereumChild = ethereumRoot.derive(ETH_PATH);
  try {
    if (!bitcoinChild.privateKey || !bitcoinChild.publicKey || !ethereumChild.privateKey) {
      throw new Error("wallet_derivation_failed");
    }
    const bitcoinPrivateKey = new Uint8Array(bitcoinChild.privateKey);
    const ethereumPrivateKey = new Uint8Array(ethereumChild.privateKey);
    const nostrPrivateKey = deriveNostrPrivateKey(bitcoinPrivateKey);
    const taproot = taprootSingleSig(bitcoinChild.publicKey);
    const nostrPubkey = schnorr.getPublicKey(nostrPrivateKey);
    const ethereumPubkey = secp256k1.getPublicKey(ethereumPrivateKey, false).slice(1);
    const ethereumAddress = getAddress(`0x${bytesToHex(keccak_256(ethereumPubkey).slice(-20))}`);
    const individualPubkey = musig2.IndividualPubkey(bitcoinPrivateKey);
    return {
      public: {
        derivation_version: NURI_DERIVATION_VERSION,
        bitcoin_address: taproot.address,
        bitcoin_xonly_pubkey_hex: bytesToHex(taproot.xOnly),
        client_public_key_33_hex: bytesToHex(individualPubkey),
        arkade_single_sig_xonly_pubkey_hex: bytesToHex(individualPubkey.slice(1)),
        eth_user_eoa: ethereumAddress,
        ethereum_public_key_hex: bytesToHex(ethereumPubkey),
        nostr_pubkey_hex: bytesToHex(nostrPubkey),
        nostr_npub: bech32.encode("npub", bech32.toWords(nostrPubkey)),
      },
      secrets: {
        bitcoin_private_key: bitcoinPrivateKey,
        ethereum_private_key: ethereumPrivateKey,
        nostr_private_key: nostrPrivateKey,
      },
    };
  } finally {
    bitcoinRoot.wipePrivateData();
    bitcoinChild.wipePrivateData();
    ethereumRoot.wipePrivateData();
    ethereumChild.wipePrivateData();
    zeroize(bitcoinEntropy);
    zeroize(ethereumEntropy);
  }
}

export function zeroizeNuriWallet(wallet) {
  if (!wallet?.secrets) return;
  zeroize(wallet.secrets.bitcoin_private_key);
  zeroize(wallet.secrets.ethereum_private_key);
  zeroize(wallet.secrets.nostr_private_key);
}

function assertValidAgentIndex(index) {
  const num = Number(index);
  if (!Number.isSafeInteger(num) || num < 0 || num > MAX_AGENT_INDEX) {
    throw new Error("agent_index_invalid");
  }
  return num;
}

export function deriveAgentWallet(prf, index = 0) {
  if (!(prf instanceof Uint8Array) || prf.byteLength < 32) {
    throw new Error("agent_prf_invalid");
  }
  const idx = assertValidAgentIndex(index);
  const ethEntropy = hkdf(
    sha256,
    prf,
    AGENT_WALLET_SALT,
    utf8(`app:nuri.com|agent-wallet|v1|chain=ethereum|fmt=secp256k1|index=${idx}`),
    32,
  );
  const btcEntropy = hkdf(
    sha256,
    prf,
    AGENT_WALLET_SALT,
    utf8(`app:nuri.com|agent-wallet|v1|chain=bitcoin|fmt=taproot|index=${idx}`),
    32,
  );
  const ethRoot = HDKey.fromMasterSeed(ethEntropy);
  const btcRoot = HDKey.fromMasterSeed(btcEntropy);
  const ethChild = ethRoot.derive(ETH_PATH);
  const btcChild = btcRoot.derive(BIP86_PATH);
  try {
    if (!ethChild.privateKey || !ethChild.publicKey || !btcChild.privateKey || !btcChild.publicKey) {
      throw new Error("agent_wallet_derivation_failed");
    }
    const agentEthPrivateKey = new Uint8Array(ethChild.privateKey);
    const agentBtcPrivateKey = new Uint8Array(btcChild.privateKey);
    const ethEoa = getAddress(new Wallet(`0x${bytesToHex(agentEthPrivateKey)}`).address);
    const ethPub33 = new Uint8Array(ethChild.publicKey);
    const btcPub33 = new Uint8Array(btcChild.publicKey);
    const btcXOnly = schnorr.getPublicKey(agentBtcPrivateKey);
    return {
      public: {
        derivation_version: AGENT_DERIVATION_VERSION,
        index: idx,
        agent_eth_eoa: ethEoa,
        agent_eth_public_key_33_hex: bytesToHex(ethPub33),
        agent_btc_public_key_33_hex: bytesToHex(btcPub33),
        agent_btc_xonly_pubkey_hex: bytesToHex(btcXOnly),
        agent_btc_taproot_address: taprootSingleSig(btcPub33).address,
      },
      secrets: {
        agent_eth_private_key: agentEthPrivateKey,
        agent_btc_private_key: agentBtcPrivateKey,
      },
    };
  } finally {
    zeroize(ethEntropy);
    zeroize(btcEntropy);
    ethRoot.wipePrivateData();
    btcRoot.wipePrivateData();
    ethChild.wipePrivateData();
    btcChild.wipePrivateData();
  }
}

export function validateAgentGrantPolicy(raw) {
  if (raw === undefined || raw === null) return {};
  if (typeof raw !== "object" || Array.isArray(raw)) throw new Error("agent_grant_policy_invalid");
  const policy = {};
  if (raw.max_per_tx_usdc !== undefined) {
    const t = String(raw.max_per_tx_usdc).trim();
    if (!/^(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{1,6})?$/.test(t)) throw new Error("max_per_tx_usdc_invalid");
    policy.max_per_tx_usdc = t;
  }
  if (raw.daily_limit_usdc !== undefined) {
    const t = String(raw.daily_limit_usdc).trim();
    if (!/^(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{1,6})?$/.test(t)) throw new Error("daily_limit_usdc_invalid");
    policy.daily_limit_usdc = t;
  }
  if (raw.max_per_tx_sats !== undefined) {
    const n = Number(raw.max_per_tx_sats);
    if (!Number.isSafeInteger(n) || n < 0 || n > 2_100_000_000_000_000) throw new Error("max_per_tx_sats_invalid");
    policy.max_per_tx_sats = n;
  }
  if (raw.daily_limit_sats !== undefined) {
    const n = Number(raw.daily_limit_sats);
    if (!Number.isSafeInteger(n) || n < 0 || n > 2_100_000_000_000_000) throw new Error("daily_limit_sats_invalid");
    policy.daily_limit_sats = n;
  }
  if (raw.expires_at !== undefined) {
    const exp = Number(raw.expires_at);
    if (!Number.isSafeInteger(exp) || exp <= 0) throw new Error("agent_grant_expires_at_invalid");
    policy.expires_at = exp;
  }
  if (raw.label !== undefined) {
    const label = String(raw.label).trim();
    if (!label || label.length > 120 || /[\r\n]/.test(label)) throw new Error("agent_grant_label_invalid");
    policy.label = label;
  }
  return policy;
}

export function validateAgentGrantPayload(payload) {
  const replyPubkey = String(payload?.reply_pubkey || "").toLowerCase();
  if (!HEX64_RE.test(replyPubkey)) throw new Error("reply_pubkey_invalid");
  secp256k1.Point.fromHex(`02${replyPubkey}`);
  const index = payload.index === undefined ? 0 : assertValidAgentIndex(payload.index);
  const policy = validateAgentGrantPolicy(payload.policy);
  return { reply_pubkey: replyPubkey, index, policy };
}

function grantReplyKey(sk, peerXOnlyHex, sessionId) {
  const shared = secp256k1.getSharedSecret(sk, hexToBytes(`02${peerXOnlyHex}`), true);
  const x = shared.slice(1);
  try {
    return hkdf(sha256, x, AGENT_REPLY_SALT, utf8(sessionId), 32);
  } finally {
    zeroize(x);
    zeroize(shared);
  }
}

function grantAad(sessionId, agentPublic, policy) {
  return utf8(
    JSON.stringify({
      format: AGENT_GRANT_REPLY_FORMAT,
      session_id: sessionId,
      index: agentPublic.index,
      agent_eth_eoa: agentPublic.agent_eth_eoa,
      agent_btc_public_key_33_hex: agentPublic.agent_btc_public_key_33_hex,
      policy,
    }),
  );
}

export function encryptAgentGrantReply({ prf, sessionId, request, ephemeralSk, nonce }) {
  const derived = deriveAgentWallet(prf, request.index);
  const ephSk = ephemeralSk ? new Uint8Array(ephemeralSk) : secp256k1.utils.randomSecretKey();
  const n24 = nonce ? new Uint8Array(nonce) : new Uint8Array(randomBytes(24));
  const key = grantReplyKey(ephSk, request.reply_pubkey, sessionId);
  const bundle = {
    format: AGENT_GRANT_REPLY_FORMAT,
    derivation_version: AGENT_DERIVATION_VERSION,
    index: derived.public.index,
    agent_eth_private_key_hex: bytesToHex(derived.secrets.agent_eth_private_key),
    agent_btc_private_key_hex: bytesToHex(derived.secrets.agent_btc_private_key),
    public: derived.public,
    policy: request.policy,
  };
  const plaintext = utf8(JSON.stringify(bundle));
  try {
    const ephemeralPubkey = bytesToHex(schnorr.getPublicKey(ephSk));
    const aad = grantAad(sessionId, derived.public, request.policy);
    const ciphertext = xchacha20Poly1305Seal(key, n24, plaintext, aad);
    return {
      ephemeral_pubkey: ephemeralPubkey,
      nonce_b64u: bytesToBase64Url(n24),
      ciphertext_b64u: bytesToBase64Url(ciphertext),
      agent_public: derived.public,
      policy: request.policy,
    };
  } finally {
    zeroize(derived.secrets.agent_eth_private_key);
    zeroize(derived.secrets.agent_btc_private_key);
    zeroize(ephSk);
    zeroize(key);
    zeroize(plaintext);
  }
}

export function decryptAgentGrantReply({ replySk, sessionId, reply }) {
  const key = grantReplyKey(replySk, reply.ephemeral_pubkey, sessionId);
  const aad = grantAad(sessionId, reply.agent_public, reply.policy);
  let pt = null;
  try {
    pt = xchacha20Poly1305Open(
      key,
      base64UrlToBytes(reply.nonce_b64u),
      base64UrlToBytes(reply.ciphertext_b64u),
      aad,
    );
    if (!pt) throw new Error("agent_grant_reply_invalid");
    return JSON.parse(new TextDecoder().decode(pt));
  } finally {
    zeroize(key);
    zeroize(pt);
  }
}

export function agentGrantProofMessage({ sessionId, replyPubkey, reply }) {
  const cipherDigest = bytesToHex(sha256(utf8(reply.ciphertext_b64u)));
  const policyJson = JSON.stringify(reply.policy);
  return [
    "Nuri agent wallet grant v1",
    `Session: ${sessionId}`,
    `Index: ${reply.agent_public.index}`,
    `Agent EVM EOA: ${reply.agent_public.agent_eth_eoa}`,
    `Agent BTC Pubkey: ${reply.agent_public.agent_btc_public_key_33_hex}`,
    `Reply Pubkey: ${replyPubkey.toLowerCase()}`,
    `Ephemeral Pubkey: ${reply.ephemeral_pubkey}`,
    `Policy: ${policyJson}`,
    `Ciphertext SHA-256: ${cipherDigest}`,
  ].join("\n");
}

export function walletConnectProofMessage({ sessionId, challengeB64u, rpId }) {
  return [
    "Nuri Wallet Connect",
    "",
    "Approve access to this public wallet.",
    `Session: ${sessionId}`,
    `Challenge: ${challengeB64u}`,
    `RP ID: ${rpId}`,
  ].join("\n");
}

export async function signWalletOperation(operation, payload, wallet) {
  const ethWallet = new Wallet(`0x${bytesToHex(wallet.secrets.ethereum_private_key)}`);
  if (operation === "ethereum_personal_sign" || operation === "wallet_connect") {
    const message = String(payload?.message || "");
    if (!message) throw new Error("message_required");
    return {
      operation,
      address: ethWallet.address,
      message,
      signature: await ethWallet.signMessage(message),
    };
  }
  if (operation === "ethereum_personal_sign_bundle") {
    const messages = Array.isArray(payload?.messages) ? payload.messages : [];
    if (messages.length < 1 || messages.length > 8) throw new Error("messages_required");
    const signatures = [];
    for (const msg of messages) {
      const m = String(msg || "");
      if (!m) throw new Error("bundle_message_invalid");
      signatures.push({ message: m, signature: await ethWallet.signMessage(m) });
    }
    return { operation, address: ethWallet.address, signatures };
  }
  if (operation === "ethereum_typed_data") {
    const typedData = payload?.typed_data || {};
    const { EIP712Domain: _ignored, ...types } = typedData.types || {};
    const signature = await ethWallet.signTypedData(typedData.domain || {}, types, typedData.message || {});
    return { operation, address: ethWallet.address, typed_data: typedData, signature };
  }
  if (operation === "ethereum_transaction") {
    const tx = payload?.transaction || {};
    const serialized_transaction = await ethWallet.signTransaction(tx);
    return { operation, address: ethWallet.address, serialized_transaction };
  }
  if (operation === "nostr_event") {
    const ev = payload?.event || {};
    const event = {
      kind: Number(ev.kind),
      pubkey: wallet.public.nostr_pubkey_hex,
      created_at: Number(ev.created_at),
      tags: Array.isArray(ev.tags) ? ev.tags : [],
      content: String(ev.content || ""),
    };
    const id = bytesToHex(
      sha256(utf8(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]))),
    );
    return {
      ...event,
      operation,
      id,
      sig: bytesToHex(schnorr.sign(hexToBytes(id), wallet.secrets.nostr_private_key)),
    };
  }
  throw new Error(`unsupported_wallet_operation: ${operation}`);
}

export function parseConnectInput(input, originOverride = null) {
  const raw = String(input || "").trim();
  if (!raw) throw new Error("approval_url_or_session_id_required");
  if (/^[0-9a-fA-F]{32,128}$/.test(raw)) {
    return {
      origin: (originOverride || DEFAULT_CONNECT_ORIGIN).replace(/\/+$/, ""),
      sessionId: raw,
    };
  }
  const url = new URL(raw);
  const origin = (originOverride || url.origin).replace(/\/+$/, "");
  if (!originOverride && origin !== DEFAULT_CONNECT_ORIGIN) {
    throw new Error(`untrusted_connect_origin: ${origin} (expected ${DEFAULT_CONNECT_ORIGIN})`);
  }
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length >= 2 && ["signature", "approve", "sign", "create"].includes(parts[0])) {
    return { origin, sessionId: decodeURIComponent(parts[1]) };
  }
  const qid = url.searchParams.get("session_id");
  if (qid) return { origin, sessionId: qid };
  throw new Error(`cannot_parse_session_id: ${raw}`);
}

export function defaultCardBridge(requestObj) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(
      resolve(ROOT, "scripts/run-card-python.sh"),
      [resolve(ROOT, "scripts/connect-card-webauthn.py")],
      {
        cwd: ROOT,
        stdio: ["pipe", "pipe", "inherit"],
        env: process.env,
      },
    );
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.on("error", rejectPromise);
    child.on("close", () => {
      const line = stdout.trim().split("\n").pop() || "";
      if (!line) {
        rejectPromise(new Error("card_bridge_empty_output"));
        return;
      }
      try {
        resolvePromise(JSON.parse(line));
      } catch (err) {
        rejectPromise(new Error(`card_bridge_bad_json: ${err.message}`));
      }
    });
    child.stdin.write(JSON.stringify(requestObj));
    child.stdin.end();
  });
}

async function fetchJson(fetchImpl, url, init) {
  const res = await fetchImpl(url, init);
  const text = await res.text();
  let parsed = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }
  if (!res.ok) {
    const err = new Error(parsed.error || `HTTP ${res.status}`);
    err.status = res.status;
    err.body = parsed;
    throw err;
  }
  return parsed;
}

export async function approveConnectSession({
  input,
  originOverride = null,
  credId = null,
  dryRun = false,
  cardBridge = defaultCardBridge,
  fetchImpl = globalThis.fetch,
  log = (msg) => process.stderr.write(`${msg}\n`),
}) {
  const { origin, sessionId } = parseConnectInput(input, originOverride);
  const session = await fetchJson(
    fetchImpl,
    `${origin}/api/wallet_session?session_id=${encodeURIComponent(sessionId)}`,
  );
  if (session.status !== "pending") {
    throw new Error(`session_not_pending: status=${session.status}`);
  }

  let operation = String(session.operation || (session.kind === "connect" ? "wallet_connect" : ""));
  let payload = session.payload && typeof session.payload === "object" ? session.payload : {};

  if (session.deferred_message_pending) {
    const prepared = await fetchJson(fetchImpl, `${origin}/api/wallet_sign_prepare`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ session_id: session.session_id }),
    });
    operation = String(prepared.operation || operation);
    payload = prepared.payload && typeof prepared.payload === "object" ? prepared.payload : payload;
  }

  // Print concise human-readable approval summary before touching card.
  log(`Session:   ${session.session_id} (${session.kind}/${operation})`);
  if (operation === "agent_grant") {
    const req = validateAgentGrantPayload(payload);
    const lims = [];
    if (req.policy.max_per_tx_usdc) lims.push(`<= ${req.policy.max_per_tx_usdc} USDC/tx`);
    if (req.policy.daily_limit_usdc) lims.push(`<= ${req.policy.daily_limit_usdc} USDC/day`);
    if (req.policy.max_per_tx_sats !== undefined) lims.push(`<= ${req.policy.max_per_tx_sats} sats/tx`);
    if (req.policy.daily_limit_sats !== undefined) lims.push(`<= ${req.policy.daily_limit_sats} sats/day`);
    log(`Action:    Authorize Nuri Agent Wallet (slot #${req.index}) ${lims.length ? `[${lims.join(", ")}]` : ""}`);
  } else if (typeof payload.message === "string" && payload.message) {
    log(`Message:   ${payload.message.slice(0, 160)}`);
  }

  const effectiveCredId = String(credId || session.cred_id_b64u || "").trim();
  const publicKey = {
    challenge: session.challenge_b64u,
    rpId: session.rp_id || "nuri.com",
    userVerification: "required",
    ...(effectiveCredId
      ? { allowCredentials: [{ type: "public-key", id: effectiveCredId }] }
      : {}),
    ...(session.prf_salt
      ? { extensions: { prf: { eval: { first: bytesToBase64Url(utf8(session.prf_salt)) } } } }
      : {}),
  };

  const bridgeRes = await cardBridge({
    kind: "get",
    params: { origin: DEFAULT_CONNECT_ORIGIN, publicKey },
    include_cred_pubkey: true,
  });
  if (!bridgeRes?.ok) {
    const err = new Error(`${bridgeRes?.code || "CARD_ERROR"}: ${bridgeRes?.error || "card failed"}`);
    err.code = bridgeRes?.code || "CARD_ERROR";
    err.extra = bridgeRes?.extra || {};
    throw err;
  }

  const cred = bridgeRes.response;
  const prfB64u = cred?.clientExtensionResults?.prf?.results?.first;
  if (!prfB64u) throw new Error("missing_assertion_prf");
  const prf = base64UrlToBytes(prfB64u);

  let wallet = null;
  let walletPublic = null;
  let completionBody = null;
  let result = null;
  try {
    wallet = deriveNuriWallet(prf);
    walletPublic = { ...wallet.public };
    if (session.expected_eoa && getAddress(session.expected_eoa) !== getAddress(walletPublic.eth_user_eoa)) {
      throw new Error(`expected_eoa_mismatch: card=${walletPublic.eth_user_eoa} expected=${session.expected_eoa}`);
    }

    if (session.kind === "connect") {
      result = await signWalletOperation(
        "wallet_connect",
        {
          message: walletConnectProofMessage({
            sessionId: session.session_id,
            challengeB64u: session.challenge_b64u,
            rpId: session.rp_id || "nuri.com",
          }),
        },
        wallet,
      );
    } else if (operation === "agent_grant") {
      const request = validateAgentGrantPayload(payload);
      const reply = encryptAgentGrantReply({ prf, sessionId: session.session_id, request });
      const proofMessage = agentGrantProofMessage({
        sessionId: session.session_id,
        replyPubkey: request.reply_pubkey,
        reply,
      });
      const proof = await signWalletOperation("ethereum_personal_sign", { message: proofMessage }, wallet);
      result = { ...reply, signature: proof.signature };
    } else {
      result = await signWalletOperation(operation, payload, wallet);
    }

    const credentialPubkeyB64u =
      session.credential_pubkey_b64u || bridgeRes.credential_pubkey_b64u || undefined;

    completionBody = {
      session_id: session.session_id,
      ...(credentialPubkeyB64u ? { credential_pubkey_b64u: credentialPubkeyB64u } : {}),
      wallet: walletPublic,
      result,
      cred_id_b64u: cred.rawId || cred.id,
      client_data_b64u: cred.response.clientDataJSON,
      auth_data_b64u: cred.response.authenticatorData,
      sig_b64u: cred.response.signature,
    };
  } finally {
    zeroizeNuriWallet(wallet);
    zeroize(prf);
  }

  if (dryRun) {
    return {
      ok: true,
      dry_run: true,
      session_id: session.session_id,
      operation,
      cred_id_b64u: completionBody.cred_id_b64u,
      has_credential_pubkey: Boolean(completionBody.credential_pubkey_b64u),
      wallet: walletPublic,
      ...(result?.agent_public ? { agent_public: result.agent_public } : {}),
    };
  }

  const approved = await fetchJson(fetchImpl, `${origin}/api/wallet_sign_complete`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(completionBody),
  });

  return {
    ok: true,
    status: approved.status || "approved",
    session_id: session.session_id,
    operation: approved.operation || operation,
    cred_id_b64u: completionBody.cred_id_b64u,
    wallet: walletPublic,
    ...(result?.agent_public ? { agent_public: result.agent_public } : {}),
  };
}

function parseCliArgs(argv) {
  const out = { input: null, credId: null, originOverride: null, dryRun: false, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--cred" && argv[i + 1]) out.credId = argv[++i];
    else if (a === "--origin" && argv[i + 1]) out.originOverride = argv[++i];
    else if (a === "--dry-run") out.dryRun = true;
    else if (a === "--json") out.json = true;
    else if (a === "-h" || a === "--help") out.help = true;
    else if (!a.startsWith("-") && !out.input) out.input = a;
  }
  return out;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = parseCliArgs(process.argv.slice(2));
  if (args.help || !args.input) {
    console.log("Usage: nuricard connect <approval_url_or_session_id> [--cred <id>] [--dry-run] [--json]");
    process.exit(args.help ? 0 : 1);
  }
  approveConnectSession(args)
    .then((res) => {
      if (args.json) {
        console.log(JSON.stringify(res, null, 2));
      } else {
        console.log(`Approved:  ${res.session_id} (${res.operation})${res.dry_run ? " [DRY RUN]" : ""}`);
        console.log(`Main EOA:  ${res.wallet.eth_user_eoa}`);
        console.log(`Main BTC:  ${res.wallet.bitcoin_address}`);
        if (res.agent_public) {
          console.log(`Agent EOA: ${res.agent_public.agent_eth_eoa} (slot #${res.agent_public.index})`);
          console.log(`Agent BTC: ${res.agent_public.agent_btc_public_key_33_hex}`);
        }
      }
    })
    .catch((err) => {
      console.error(`Error: ${err.message}`);
      if (err.code === "AMBIGUOUS_CREDENTIAL" && Array.isArray(err.extra?.credentials)) {
        console.error("Multiple credentials on card — re-run with --cred <id>:");
        for (const c of err.extra.credentials) {
          console.error(`  ${c.id}  ${c.name || c.displayName || ""}`);
        }
      }
      process.exit(1);
    });
}
