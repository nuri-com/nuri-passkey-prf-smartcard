import test from 'node:test';
import assert from 'node:assert/strict';
import { SoftwareCardSigner, localProof, deriveAddresses, CARD_COMPARISON_KEY } from '../scripts/arkade-card-e2e.mjs';
import { readFile } from 'node:fs/promises';

test('231-byte card math aggregates with software BIP327 counterparty, both aggregate parities', async () => {
  for (let i = 0; i < 16; i++) {
    const proof = await localProof(); assert.equal(proof.finalize_bytes, 231); assert.equal(proof.bip340_verified, true);
    assert.equal(proof.scope, 'LOCAL_SOFTWARE_COUNTERPARTY_NOT_LIVE_SERVER');
  }
});
test('FINALIZE burns nonces even on malformed request', async () => {
  const s = new SoftwareCardSigner(); await s.getNonces();
  await assert.rejects(s.finalize(new Uint8Array(97)), /231/);
  await assert.rejects(s.finalize(new Uint8Array(231)), /consumed/);
});
test('correct 3-leaf production recovery addresses match captured live-parameter vector', () => {
  const a = deriveAddresses(CARD_COMPARISON_KEY, { server_pubkey: '03ad4fbb3f767966998015316b840ffd13c70712d36356dfc92c2a58864773835b', nuri_server_csv: { type: 'seconds', value: 6674432 } }, { network: 'bitcoin', signerPubkey: '038202bebddeb1f7442803897a85eaf3ce9254d07df0172fc3725ab5f0d097779c', unilateralExitDelay: '605184', boardingExitDelay: '7776256' });
  assert.equal(a.ark_address, 'ark1qzpq904am6clw3pgqwyh4p02708fy4xs0hcpwt7rwfdttuxsjameestt87ajw7jzpul22tqrcg455q72ps04qqfgcq35gna6czkpx4wr3l6526');
  assert.equal(a.boarding_address, 'bc1pn0cjhhhxpp0vs7sud2qlnuuuxjv495flfzk95jdfxnuhxc8d8ggs9ps2v3');
  assert.equal(a.offchain_script, '5120c16b3fbb277a420f3ea52c03c22b4a03ca0c1f500128c023444fbac0ac1355c3');
});
test('receipt distinguishes live authorization denial from local signature proof', async () => {
  const r = JSON.parse(await readFile(new URL('../docs/proofs/w35-arkade-e2e.json', import.meta.url)));
  assert.equal(r.registration.readback_registered, true);
  assert.equal(r.live_sign.status, 403);
  assert.equal(r.live_tree_nonce.status, 403);
  assert.equal(r.local_card_semantics.bip340_verified, true);
  assert.equal(r.balances.software.offchain_sats, 0);
});
