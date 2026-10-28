// Offline cross-check: board.mjs commitmentRequests vs the real server verifier.
import { Transaction } from '@scure/btc-signer';
import { sdk, hex } from './deps.mjs';
import { boardingContext } from './board-core.mjs';
import { commitmentRequests } from './board.mjs';
import { CLIENT } from './core.mjs';
const { verifyArkadePsbtSignRequests } = await import(process.env.SRV_VERIFIER);

const info = await (await fetch(`https://arkade.nuri.com/v4/arkade/info?client_pk33=02b935bfc0d6d379243205d5c110732400cc8ae82e2fe94d6384963c7c9a62cae6&client_signer_pubkey=02b935bfc0d6d379243205d5c110732400cc8ae82e2fe94d6384963c7c9a62cae6&cred_id_b64u=SUulp_FdnSxmGnT_KExCDld8_Ibwt1NOw1AlLau0xsKs8th4iw0sXrvcwHjHAwidXkbJYxzhk1R3WB5gP1GQTY65PbDUpQq2G969WwHhf_23f6upE7cHbUa2a9iWy0HPMSX29OelLq5w4Qr62BVIPg`)).json();
const op = await (await fetch('https://arkade.computer/v1/info')).json();
const ctx = boardingContext(CLIENT, info, op);
const tx = new Transaction({ allowUnknownOutputs: true, allowUnknown: true });
// input 0: foreign key-path input (operator funding), input 1: our boarding input
tx.addInput({ txid: '11'.repeat(32), index: 0, witnessUtxo: { script: Buffer.from('5120' + '22'.repeat(32), 'hex'), amount: 100000n } });
tx.addInput({ txid: 'fdbd415e6f1048fced5c2ddd79d22ded6cd261f8cc68f07772fd62b6e55bb1d8', index: 0, witnessUtxo: { script: Buffer.from(ctx.script, 'hex'), amount: 7499n }, tapLeafScript: [ctx.leaf] });
tx.addOutput({ script: Buffer.from('5120' + '33'.repeat(32), 'hex'), amount: 107000n });
const reqs = commitmentRequests(tx, ctx).map(r => ({ kind: 'direct', input_index: r.input_index, msg32: r.msg32, client_pk33: CLIENT, ...(r.tweak32 ? { tweak32: r.tweak32 } : {}) }));
const psbt = Buffer.from(tx.toPSBT()).toString('base64');
const expected = verifyArkadePsbtSignRequests(psbt, { clientPk33: CLIENT, serverPk33: info.server_pubkey, signRequests: reqs });
console.log('OK server accepts', reqs.length, 'requests; expected', expected.length);
