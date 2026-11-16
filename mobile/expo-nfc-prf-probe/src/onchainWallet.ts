import { NETWORK, Script, p2tr } from '@scure/btc-signer';
import { secp256k1 } from '@noble/curves/secp256k1.js';

/** Same leaf and key aggregation output as Nuri's ArkadeOnchainAddress.js.
 * Inputs come from runtime card discovery and the live, validated CSV policy.
 */
export function deriveOnchainAddress(client: Uint8Array, aggregate: Uint8Array, csv: {type: 'seconds'|'blocks'; value: bigint}): string {
  if(client.length!==33 || (client[0]!==2 && client[0]!==3)) throw Error('Invalid client key');
  secp256k1.Point.fromBytes(client).assertValidity();
  const internal = aggregate.length===33 ? aggregate.slice(1) : aggregate;
  if(internal.length!==32) throw Error('Invalid aggregate key');
  const value=Number(csv.value);
  if(!Number.isSafeInteger(value)||value<=0) throw Error('Invalid CSV');
  let sequence:number;
  if(csv.type==='seconds'){
    if(value%512!==0||value/512>65535) throw Error('Invalid CSV seconds');
    sequence=(1<<22)|(value/512);
  } else if(csv.type==='blocks' && value<=65535) sequence=value;
  else throw Error('Invalid CSV blocks');
  const leaf={script:Script.encode([client.slice(1),'CHECKSIGVERIFY',sequence,'CHECKSEQUENCEVERIFY']),leafVersion:0xc0};
  const address=p2tr(internal,[leaf],NETWORK,true).address;
  if(!address) throw Error('Missing onchain address');
  return address;
}

export function validateUtxos(coins: unknown): {txid:string;vout:number;value:number;status:{confirmed:boolean}}[] {
 if(!Array.isArray(coins)) throw Error('Invalid onchain UTXO response');
 const unique=new Map<string,{txid:string;vout:number;value:number;status:{confirmed:boolean}}>();
 for(const coin of coins){
  if(!coin||!/^[0-9a-f]{64}$/.test(coin.txid)||!Number.isSafeInteger(coin.vout)||coin.vout<0||!Number.isSafeInteger(coin.value)||coin.value<0||typeof coin.status?.confirmed!=='boolean') throw Error('Malformed onchain UTXO');
  unique.set(`${coin.txid}:${coin.vout}`,coin);
 }
 return [...unique.values()];
}
