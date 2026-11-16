const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const EXT = path.resolve(__dirname, '..');

function lib() {
  const sandbox = {};
  vm.createContext(sandbox);
  sandbox.self = sandbox;
  sandbox.NuriHashing = { ethers: require('../third_party/ethers.umd.min.js') };
  vm.runInContext(fs.readFileSync(path.join(EXT, 'lib/bitcoin.js'), 'utf8'), sandbox);
  return sandbox.NuriBitcoin;
}

// Real mainnet Arkade address from the repository README (receives to a card).
const ARK = 'ark1qzpq904am6clw3pgqwyh4p02708fy4xs0hcpwt7rwfdttuxsjameepfv6ed2mgaw4k2tdts49m4wkk3zqyrjv44sr2gcgxrm47gy7sqnlyjr3x';
const LN = 'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4js';

test('sats parsing is strict and round-trips through BTC formatting', () => {
  const B = lib();
  assert.equal(B.parseSats('0.00012'), 12000);
  assert.equal(B.parseSats('1'), 100000000);
  assert.equal(B.parseSats(' 21_000 '), 2100000000000);
  assert.equal(B.formatBtc(12000), '0.00012');
  assert.equal(B.formatBtc(100000000), '1');
  assert.equal(B.formatSats(4926), '4,926');
  for (const bad of ['', '0', '0.0', '1.123456789', 'abc', '-1', '1,5']) assert.throws(() => B.parseSats(bad), bad);
});

test('Arkade address validation checks the bech32m checksum, not just the prefix', () => {
  const B = lib();
  assert.equal(B.isArkAddress(ARK), true);
  assert.equal(B.isArkAddress(ARK.toUpperCase()), true);
  const mutated = ARK.slice(0, -1) + (ARK.endsWith('x') ? 'q' : 'x');
  assert.equal(B.isArkAddress(mutated), false);
  assert.equal(B.isArkAddress('ark1qqqqqq'), false);
  assert.equal(B.isArkAddress('tb1qxyz'), false);
  assert.equal(B.isArkAddress(''), false);
});

test('Lightning and username shapes', () => {
  const B = lib();
  assert.equal(B.isLightningInvoice(LN), true);
  assert.equal(B.isLightningInvoice(LN.toUpperCase()), true);
  assert.equal(B.isLightningInvoice('lnbc2500'), false);
  assert.equal(B.isLightningInvoice('lntb2500u1pp5xyz'), false, 'testnet is not accepted here');
  assert.equal(B.isNuriName('emino'), true);
  assert.equal(B.isNuriName('bad name'), false);
  assert.equal(B.isNuriName('-lead'), false);
});

test('a wrong ENS text key falls through to the next one; the matched key is reported', async () => {
  const B = lib();
  const resolver = {
    address: '0x0000000000000000000000000000000000000001',
    async getText(key) {
      if (key === 'ark') return '';
      if (key === 'arkade') return ARK;
      return '';
    },
    async getAddress() { throw new Error('no addr'); },
  };
  const E = require('../third_party/ethers.umd.min.js');
  const original = E.EnsResolver.fromName;
  E.EnsResolver.fromName = async () => resolver;
  try {
    const resolved = await B.resolveNuriName('emino.nuri.eth', 'https://rpc.test');
    assert.equal(resolved.address, ARK.toLowerCase());
    assert.equal(resolved.source, 'text:arkade');
    assert.equal(resolved.kind, 'ark');
  } finally { E.EnsResolver.fromName = original; }
});

test('unregistered or recordless names fail closed', async () => {
  const B = lib();
  const E = require('../third_party/ethers.umd.min.js');
  const original = E.EnsResolver.fromName;
  try {
    E.EnsResolver.fromName = async () => null;
    await assert.rejects(() => B.resolveNuriName('nobody', 'https://rpc.test'), /not registered/);
    E.EnsResolver.fromName = async () => ({ address: '0x00', async getText() { return ''; }, async getAddress() { return null; } });
    await assert.rejects(() => B.resolveNuriName('empty', 'https://rpc.test'), /no Arkade, Lightning or EVM/);
    E.EnsResolver.fromName = async () => ({ address: '0x00', async getText() { return 'not-an-address'; }, async getAddress() { return null; } });
    await assert.rejects(() => B.resolveNuriName('junk', 'https://rpc.test'), /no Arkade/);
  } finally { E.EnsResolver.fromName = original; }
});
