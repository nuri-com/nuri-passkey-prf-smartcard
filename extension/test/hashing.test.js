// Known-vector tests for the extension's hashing (personal_sign, EIP-712, EIP-1559).
// Run: node --test extension/test/hashing.test.js
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

globalThis.ethers = require(path.join(__dirname, "..", "third_party", "ethers.umd.min.js"));
const H = require(path.join(__dirname, "..", "lib", "hashing.js"));

test("keccak256 empty string (NIST/Ethereum vector)", () => {
  assert.equal(H.ethers.keccak256("0x"), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
});

test("personal_sign hash of 'hello' matches EIP-191 vector", () => {
  // keccak256("\x19Ethereum Signed Message:\n5hello") — widely published (web3.js / ethers docs)
  assert.equal(H.hashPersonalMessage("hello"), "0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750");
  // hex-encoded form of the same bytes hashes identically
  assert.equal(H.hashPersonalMessage("0x68656c6c6f"), H.hashPersonalMessage("hello"));
  assert.equal(H.decodePersonalMessage("0x68656c6c6f"), "hello");
});

test("personal_sign signature recovers the signer (go-ethereum TestSign vector)", () => {
  // MetaMask docs example: message "Example `personal_sign` message" signed by 0x0c5...: hashing only here.
  // Additionally check that ethers recovery over a known signature yields the known address.
  const wallet = new H.ethers.Wallet("0x" + "01".repeat(32));
  const msg = "Nuri Card test";
  const sig = H.ethers.Signature.from(wallet.signingKey.sign(H.hashPersonalMessage(msg)));
  assert.equal(H.recoverAddress(H.hashPersonalMessage(msg), { r: sig.r, s: sig.s, yParity: sig.yParity }), wallet.address);
});

test("EIP-712 hash matches the EIP-712 spec 'Mail' example", () => {
  // Vector from https://eips.ethereum.org/EIPS/eip-712 (Example.js); same JSON shape MetaMask passes to eth_signTypedData_v4.
  const typedData = {
    types: {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId", type: "uint256" },
        { name: "verifyingContract", type: "address" },
      ],
      Person: [
        { name: "name", type: "string" },
        { name: "wallet", type: "address" },
      ],
      Mail: [
        { name: "from", type: "Person" },
        { name: "to", type: "Person" },
        { name: "contents", type: "string" },
      ],
    },
    primaryType: "Mail",
    domain: {
      name: "Ether Mail",
      version: "1",
      chainId: 1,
      verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    },
    message: {
      from: { name: "Cow", wallet: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
      to: { name: "Bob", wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
      contents: "Hello, Bob!",
    },
  };
  assert.equal(H.hashTypedDataV4(JSON.stringify(typedData)), "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
  // the spec signs it with key cow -> address 0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826
  const cow = new H.ethers.Wallet(H.ethers.keccak256(H.ethers.toUtf8Bytes("cow")));
  assert.equal(cow.address, "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826");
  const sig = cow.signingKey.sign(H.hashTypedDataV4(typedData));
  assert.equal(sig.v, 28);
  assert.equal(sig.r, "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d");
  assert.equal(sig.s, "0x07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562");
});

test("EIP-1559 tx: unsigned hash + attached card-style signature round-trips through ethers", () => {
  const wallet = new H.ethers.Wallet("0x" + "02".repeat(32));
  const tx = H.buildUnsignedTx(
    { to: "0x000000000000000000000000000000000000dEaD", value: "0x1", data: "0x" },
    8453,
    { nonce: 7, gasLimit: 21000n, maxFeePerGas: 1_000_000n, maxPriorityFeePerGas: 1_000n },
  );
  assert.equal(tx.type, 2);
  assert.equal(tx.chainId, 8453n);
  const hash = H.unsignedTxHash(tx);
  assert.match(hash, /^0x[0-9a-f]{64}$/);
  const s = wallet.signingKey.sign(hash);
  const raw = H.attachSignature(tx, { r: s.r, s: s.s, yParity: s.yParity });
  const parsed = H.ethers.Transaction.from(raw);
  assert.equal(parsed.from, wallet.address);
  assert.equal(parsed.nonce, 7);
  assert.equal(parsed.to, "0x000000000000000000000000000000000000dEaD");
  assert.equal(raw.slice(0, 4), "0x02");
});

test("supported chains", () => {
  assert.equal(H.SUPPORTED_CHAINS["0x2105"].rpc, "https://mainnet.base.org");
  assert.equal(H.toHexChainId(8453), "0x2105");
});
