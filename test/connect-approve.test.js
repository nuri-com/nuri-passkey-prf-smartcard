import test from "node:test";
import assert from "node:assert/strict";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { verifyMessage } from "ethers";
import {
  agentGrantProofMessage,
  approveConnectSession,
  bytesToBase64Url,
  bytesToHex,
  decryptAgentGrantReply,
  deriveAgentWallet,
  deriveNuriWallet,
  encryptAgentGrantReply,
  hchacha20,
  hexToBytes,
  parseConnectInput,
  utf8,
  walletConnectProofMessage,
  xchacha20Poly1305Open,
  xchacha20Poly1305Seal,
} from "../scripts/connect-approve.mjs";

test("HChaCha20 matches RFC draft-irtf-cfrg-xchacha Section 2.2.1 test vector", () => {
  const key = hexToBytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  );
  const nonce = hexToBytes("000000090000004a0000000031415927");
  const expected =
    "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc";
  assert.equal(bytesToHex(hchacha20(key, nonce)), expected);
});

test("XChaCha20-Poly1305 matches RFC draft-irtf-cfrg-xchacha Section A.3.1 test vector", () => {
  const key = hexToBytes(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  );
  const nonce = hexToBytes("404142434445464748494a4b4c4d4e4f5051525354555657");
  const aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
  const plaintext = utf8(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  );
  const expectedCt =
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
    "21f9664c97637da9768812f615c68b13b52e";
  const expectedTag = "c0875924c1c7987947deafd8780acf49";

  const sealed = xchacha20Poly1305Seal(key, nonce, plaintext, aad);
  assert.equal(bytesToHex(sealed), expectedCt + expectedTag);

  const opened = xchacha20Poly1305Open(key, nonce, sealed, aad);
  assert.deepEqual(opened, plaintext);
  assert.equal(xchacha20Poly1305Open(key, nonce, sealed, utf8("wrong-aad")), null);
});

test("parseConnectInput accepts connect.nuri.com URLs and rejects untrusted origins", () => {
  const sid = "b90105daf20824bad492a7b68639391dcd080df8cf7bcb36b2628b2e758c45f4";
  assert.deepEqual(
    parseConnectInput(`https://connect.nuri.com/signature/${sid}`),
    { origin: "https://connect.nuri.com", sessionId: sid },
  );
  assert.deepEqual(parseConnectInput(sid), {
    origin: "https://connect.nuri.com",
    sessionId: sid,
  });
  assert.throws(
    () => parseConnectInput(`https://evil.example/signature/${sid}`),
    /untrusted_connect_origin/,
  );
});

test("deriveNuriWallet & deriveAgentWallet + E2EE agent_grant round-trip", () => {
  const prf = new Uint8Array(32).fill(0x42);
  const main = deriveNuriWallet(prf);
  assert.match(main.public.eth_user_eoa, /^0x[0-9a-fA-F]{40}$/);
  assert.match(main.public.bitcoin_address, /^bc1p[0-9a-z]{58}$/);
  assert.match(main.public.client_public_key_33_hex, /^0[23][0-9a-f]{64}$/);
  assert.match(main.public.nostr_npub, /^npub1[0-9a-z]+$/);

  const agent = deriveAgentWallet(prf, 0);
  assert.notEqual(agent.public.agent_eth_eoa, main.public.eth_user_eoa);
  assert.match(agent.public.agent_btc_taproot_address, /^bc1p[0-9a-z]{58}$/);

  const replySk = secp256k1.utils.randomSecretKey();
  const replyPubkey = bytesToHex(schnorr.getPublicKey(replySk));
  const sessionId = "a".repeat(64);
  const policy = { max_per_tx_usdc: "25", daily_limit_usdc: "100", max_per_tx_sats: 100000 };
  const reply = encryptAgentGrantReply({
    prf,
    sessionId,
    request: { reply_pubkey: replyPubkey, index: 0, policy },
  });
  const decrypted = decryptAgentGrantReply({ replySk, sessionId, reply });
  assert.equal(decrypted.public.agent_eth_eoa, agent.public.agent_eth_eoa);
  assert.equal(decrypted.agent_eth_private_key_hex, bytesToHex(agent.secrets.agent_eth_private_key));
  assert.equal(decrypted.agent_btc_private_key_hex, bytesToHex(agent.secrets.agent_btc_private_key));
});

test("approveConnectSession completes agent_grant end-to-end against mock connect.nuri.com + mock card", async () => {
  const prf = new Uint8Array(32).fill(0x19);
  const replySk = secp256k1.utils.randomSecretKey();
  const replyPubkey = bytesToHex(schnorr.getPublicKey(replySk));
  const sessionId = "c".repeat(64);
  const policy = { max_per_tx_usdc: "25", daily_limit_usdc: "100", max_per_tx_sats: 100000 };
  let postedBody = null;

  const fetchImpl = async (url, init) => {
    if (String(url).includes("/api/wallet_session")) {
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            status: "pending",
            session_id: sessionId,
            kind: "sign",
            challenge_b64u: "Y2hhbGxlbmdl",
            rp_id: "nuri.com",
            prf_salt: "nuri-prf-salt-v1",
            operation: "agent_grant",
            payload: { reply_pubkey: replyPubkey, index: 0, policy },
          }),
      };
    }
    if (String(url).endsWith("/api/wallet_sign_complete")) {
      postedBody = JSON.parse(init.body);
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ status: "approved", operation: "agent_grant" }),
      };
    }
    throw new Error(`unexpected url ${url}`);
  };

  const cardBridge = async (req) => {
    assert.equal(req.kind, "get");
    assert.equal(req.params.origin, "https://connect.nuri.com");
    assert.equal(req.params.publicKey.rpId, "nuri.com");
    assert.equal(
      req.params.publicKey.extensions.prf.eval.first,
      bytesToBase64Url(utf8("nuri-prf-salt-v1")),
    );
    return {
      ok: true,
      credential_pubkey_b64u: "mockSpkiPubkeyB64u",
      response: {
        id: "mockCredId",
        rawId: "mockCredId",
        response: {
          clientDataJSON: "mockClientData",
          authenticatorData: "mockAuthData",
          signature: "mockSig",
        },
        clientExtensionResults: {
          prf: { results: { first: bytesToBase64Url(prf) } },
        },
      },
    };
  };

  const res = await approveConnectSession({
    input: `https://connect.nuri.com/signature/${sessionId}`,
    cardBridge,
    fetchImpl,
    log: () => {},
  });

  assert.equal(res.ok, true);
  assert.equal(res.status, "approved");
  assert.equal(postedBody.session_id, sessionId);
  assert.equal(postedBody.cred_id_b64u, "mockCredId");
  assert.equal(postedBody.credential_pubkey_b64u, undefined);

  // Verify the main EOA signature over agentGrantProofMessage and E2EE bundle decryption.
  const expectedMsg = agentGrantProofMessage({
    sessionId,
    replyPubkey,
    reply: postedBody.result,
  });
  assert.equal(verifyMessage(expectedMsg, postedBody.result.signature), postedBody.wallet.eth_user_eoa);
  const bundle = decryptAgentGrantReply({ replySk, sessionId, reply: postedBody.result });
  assert.equal(bundle.public.agent_eth_eoa, res.agent_public.agent_eth_eoa);

  // Sanity check walletConnectProofMessage format.
  assert.match(
    walletConnectProofMessage({ sessionId, challengeB64u: "abc", rpId: "nuri.com" }),
    /Nuri Wallet Connect\n\nApprove access to this public wallet\./,
  );
});
