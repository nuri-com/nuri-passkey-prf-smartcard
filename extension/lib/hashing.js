// Hashing / encoding helpers for the Nuri Card extension.
// All keccak256, RLP and EIP-712 work is delegated to ethers v6 (vendor/ethers.umd.min.js).
// Loadable both in the MV3 service worker (importScripts) and in node (tests):
//   - browser: expects globalThis.ethers (loaded first via importScripts)
//   - node:    module.exports, expects globalThis.ethers set by the test before require
(function (root, factory) {
  const ethers = root.ethers || (typeof require === "function" ? require("../vendor/ethers.umd.min.js") : null);
  const api = factory(ethers);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.NuriHashing = api;
})(typeof globalThis !== "undefined" ? globalThis : self, function (ethers) {
  if (!ethers) throw new Error("ethers not loaded");

  const SUPPORTED_CHAINS = {
    "0x1": { chainId: 1, name: "Ethereum", rpc: "https://cloudflare-eth.com" },
    "0x2105": { chainId: 8453, name: "Base", rpc: "https://mainnet.base.org" },
  };

  function toHexChainId(n) {
    return "0x" + BigInt(n).toString(16);
  }

  // personal_sign payload can be hex bytes or a plain utf-8 string (EIP-191 "\x19Ethereum Signed Message:\n")
  function personalMessageBytes(data) {
    if (typeof data === "string" && ethers.isHexString(data)) return ethers.getBytes(data);
    if (typeof data === "string") return ethers.toUtf8Bytes(data);
    if (data instanceof Uint8Array || Array.isArray(data)) return Uint8Array.from(data);
    throw new Error("personal_sign: unsupported message type");
  }

  function decodePersonalMessage(data) {
    const bytes = personalMessageBytes(data);
    try {
      return ethers.toUtf8String(bytes);
    } catch {
      return ethers.hexlify(bytes);
    }
  }

  function hashPersonalMessage(data) {
    return ethers.hashMessage(personalMessageBytes(data));
  }

  // EIP-712 (eth_signTypedData_v4). Accepts the JSON string or object a dApp passes.
  function parseTypedData(input) {
    const td = typeof input === "string" ? JSON.parse(input) : input;
    if (!td || typeof td !== "object" || !td.types || !td.domain || td.message === undefined) {
      throw new Error("eth_signTypedData_v4: typed data must have types, domain, message");
    }
    const types = { ...td.types };
    delete types.EIP712Domain; // ethers derives the domain type from the domain object
    return { domain: td.domain, types, primaryType: td.primaryType, message: td.message };
  }

  function hashTypedDataV4(input) {
    const { domain, types, message } = parseTypedData(input);
    return ethers.TypedDataEncoder.hash(domain, types, message);
  }

  // EIP-1559 transaction assembly. `req` is the dApp's eth_sendTransaction object,
  // `filled` is what the extension fetched from the RPC (nonce, gas, fees).
  function buildUnsignedTx(req, chainId, filled) {
    const tx = new ethers.Transaction();
    tx.type = 2;
    tx.chainId = BigInt(chainId);
    if (req.to) tx.to = ethers.getAddress(req.to);
    tx.value = req.value ? BigInt(req.value) : 0n;
    tx.data = req.data || req.input || "0x";
    tx.nonce = Number(req.nonce ?? filled.nonce);
    tx.gasLimit = BigInt(req.gas ?? req.gasLimit ?? filled.gasLimit);
    tx.maxFeePerGas = BigInt(req.maxFeePerGas ?? filled.maxFeePerGas);
    tx.maxPriorityFeePerGas = BigInt(req.maxPriorityFeePerGas ?? filled.maxPriorityFeePerGas);
    if (req.accessList) tx.accessList = req.accessList;
    return tx;
  }

  function unsignedTxHash(tx) {
    return tx.unsignedHash;
  }

  // sig = {r, s, yParity} from the host
  function attachSignature(tx, sig) {
    const signed = tx.clone();
    signed.signature = ethers.Signature.from({ r: sig.r, s: sig.s, yParity: sig.yParity });
    return signed.serialized;
  }

  function recoverAddress(hash, sig) {
    return ethers.recoverAddress(hash, ethers.Signature.from({ r: sig.r, s: sig.s, yParity: sig.yParity }));
  }

  function compactSignature(sig) {
    return ethers.Signature.from({ r: sig.r, s: sig.s, yParity: sig.yParity }).serialized; // 65 bytes, v = 27/28
  }

  function formatEther(wei) {
    return ethers.formatEther(wei);
  }

  function txSummary(tx) {
    return {
      chainId: tx.chainId.toString(),
      to: tx.to || "(contract creation)",
      value: ethers.formatEther(tx.value) + " ETH",
      nonce: tx.nonce,
      gasLimit: tx.gasLimit.toString(),
      maxFeePerGas: ethers.formatUnits(tx.maxFeePerGas, "gwei") + " gwei",
      maxPriorityFeePerGas: ethers.formatUnits(tx.maxPriorityFeePerGas, "gwei") + " gwei",
      data: tx.data,
    };
  }

  return {
    ethers,
    SUPPORTED_CHAINS,
    toHexChainId,
    personalMessageBytes,
    decodePersonalMessage,
    hashPersonalMessage,
    parseTypedData,
    hashTypedDataV4,
    buildUnsignedTx,
    unsignedTxHash,
    attachSignature,
    recoverAddress,
    compactSignature,
    formatEther,
    txSummary,
    getAddress: (a) => ethers.getAddress(a),
  };
});
