import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from 'typescript';
import { keyAggregate, keyAggExport, sortKeys } from '@scure/btc-signer/musig2.js';
const file=new URL('../src/.onchain-test.mjs',import.meta.url);
try{
 fs.writeFileSync(file,ts.transpileModule(fs.readFileSync('src/onchainWallet.ts','utf8'),{compilerOptions:{module:ts.ModuleKind.ES2022,target:ts.ScriptTarget.ES2022}}).outputText);
 const {deriveOnchainAddress,validateUtxos}=await import(file.href);
 const client=Uint8Array.from(Buffer.from('02b935bfc0d6d379243205d5c110732400cc8ae82e2fe94d6384963c7c9a62cae6','hex'));
 const server=Uint8Array.from(Buffer.from('031dbb179bb996bcd6dc9c9cfccd73c649f987c10c6016650b53789056ae641e29','hex'));
 const aggregate=keyAggExport(keyAggregate(sortKeys([client,server])));
 const address=deriveOnchainAddress(client,aggregate,{type:'seconds',value:6674432n});
 assert.equal(address,'bc1pxa43e00wl6a2qqfd7wu8xgmuz8vczauvmn0nt45zff2kuq9u4klsfrz0f5');
 assert.throws(()=>deriveOnchainAddress(client,aggregate,{type:'seconds',value:513n}));
 const coin=(i,value,confirmed)=>({txid:String(i).padStart(64,'0'),vout:0,value,status:{confirmed}});
 const coins=[coin(1,1337,true),coin(2,3333,false),coin(3,1337,false)];
 assert.equal(validateUtxos([...coins,coins[0]]).reduce((n,c)=>n+c.value,0),6007);
 assert.throws(()=>validateUtxos([{...coins[0],value:-1}]));
 console.log('PASS MuSig2+CSV onchain derivation matches exact card address; CSV validation; confirmed + unconfirmed 6,007 sats; outpoint deduplication; malformed UTXO rejection');
 if(process.argv.includes('--live')){
  const response=await fetch(`https://mempool.space/api/address/${address}/utxo`);
  assert.ok(response.ok);
  const utxos=validateUtxos(await response.json());
  console.log('LIVE '+JSON.stringify({address,utxos,total:utxos.reduce((n,c)=>n+c.value,0)}));
 }
}finally{fs.rmSync(file,{force:true});}
