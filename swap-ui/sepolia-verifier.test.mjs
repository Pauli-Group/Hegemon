import {test} from 'node:test';
import assert from 'node:assert/strict';
import {expectedEtherRuntime} from './ethereum-escrow.mjs';
import {SEPOLIA_GENESIS,verifySepoliaEscrow} from './sepolia-verifier.mjs';

test('checks Sepolia genesis and exact funded escrow without sending transactions',async()=>{
 const names=['hashlock','claimant','refundee','expiry'];
 const template={runtime:'00'.repeat(32*names.length),immutableReferences:Object.fromEntries(names.map((n,i)=>[n,[{start:i*32,length:32}]]))};
 const terms={kind:'eth',contract:'0x'+'3'.repeat(40),claimant:'0x'+'1'.repeat(40),refundee:'0x'+'2'.repeat(40),hashlock:'0x'+'a'.repeat(64),expiry:'10000',amount:'123'};
 const code=expectedEtherRuntime(template,terms),head={hash:'0x'+'b'.repeat(64),number:'0x5',timestamp:'0x64'},snapshot={hash:'0x'+'c'.repeat(64),number:'0x4',timestamp:'0x63'};
 for(const mode of ['ok','wrong-genesis','wrong-code','spent','lag']){
  let calls=[],lagged=false;const provider={request:async({method,params})=>{calls.push(method);
   if(method==='eth_chainId')return '0xaa36a7';
   if(method==='eth_blockNumber')return '0x5';
   if(method==='eth_getBlockByNumber')return params[0]==='0x0'?{hash:mode==='wrong-genesis'?'0x'+'0'.repeat(64):SEPOLIA_GENESIS}:params[0]==='latest'?head:snapshot;
   if(method==='eth_getCode'){if(mode==='lag'&&!lagged){lagged=true;throw Error('block not found');}return mode==='wrong-code'?'0x':code;}
   if(method==='eth_call')return '0x'+(mode==='spent'?'1':'0').padStart(64,'0');
   if(method==='eth_getBalance')return '0x7b';throw Error('unexpected '+method);
  }};
  if(mode==='ok'||mode==='lag'){const result=await verifySepoliaEscrow(provider,template,terms);assert.equal(result.blockNumber,'0x4');}
  else await assert.rejects(verifySepoliaEscrow(provider,template,terms),mode==='wrong-genesis'?/Sepolia/:mode==='wrong-code'?/bytecode/:/unspent/);
  assert.equal(calls.includes('eth_sendTransaction'),false);
 }
});

test('policy limits raise the remaining-time floor and the snapshot reports the head time',async()=>{
 const names=['hashlock','claimant','refundee','expiry'];
 const template={runtime:'00'.repeat(32*names.length),immutableReferences:Object.fromEntries(names.map((n,i)=>[n,[{start:i*32,length:32}]]))};
 const terms={kind:'eth',contract:'0x'+'3'.repeat(40),claimant:'0x'+'1'.repeat(40),refundee:'0x'+'2'.repeat(40),hashlock:'0x'+'a'.repeat(64),expiry:'10000',amount:'123'};
 const code=expectedEtherRuntime(template,terms),head={hash:'0x'+'b'.repeat(64),number:'0x5',timestamp:'0x64'},snapshot={hash:'0x'+'c'.repeat(64),number:'0x4',timestamp:'0x63'};
 const tags=[];const provider={request:async({method,params})=>{
  if(method==='eth_chainId')return '0xaa36a7';if(method==='eth_blockNumber')return '0x5';
  if(method==='eth_getBlockByNumber'){tags.push(params[0]);}if(method==='eth_getBlockByNumber')return params[0]==='0x0'?{hash:SEPOLIA_GENESIS}:params[0]==='latest'?head:snapshot;
  if(method==='eth_getCode')return code;if(method==='eth_call')return '0x'+'0'.padStart(64,'0');if(method==='eth_getBalance')return '0x7b';throw Error('unexpected '+method);
 }};
 assert.equal((await verifySepoliaEscrow(provider,template,terms,{minClaimWindowSeconds:9900})).headTimestamp,100);
 await assert.rejects(verifySepoliaEscrow(provider,template,terms,{minClaimWindowSeconds:9901}),/too close/);
 tags.length=0;await verifySepoliaEscrow(provider,template,terms,{confirmations:3});
 assert.ok(tags.includes('0x3')&&!tags.includes('0x4'),'three confirmations read the escrow at head minus two');
});
