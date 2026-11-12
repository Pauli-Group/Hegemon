import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {hegemonSessionReader,HEGEMON_GENESIS,HEGEMON_CHAIN_ID} from './session-hegemon-read.mjs';
import {toHex} from './cbor.mjs';

test('Hegemon companion reads pin the release, exact note and confirmation policy',async()=>{
 const release=JSON.parse(readFileSync(new URL('../config/testnet/0.11/release.json',import.meta.url),'utf8'));assert.equal(HEGEMON_GENESIS,release.genesis_hash);assert.equal(HEGEMON_CHAIN_ID,release.chain_id);
 const state={enabled:true,head:100,position:'9007199254740993',remaining:20},calls=[];
 const request=async(path,body)=>{calls.push({path,body});if(path.endsWith('/head'))return {network:'pre-mainnet',genesis:HEGEMON_GENESIS,chain_id:HEGEMON_CHAIN_ID,height:String(state.head)};
  if(path.endsWith('/address'))return {address:'shca1'+'q'.repeat(100)};
  if(path.endsWith('/verify'))return {verified:true,snapshot:{verified:true,position:state.position,created_height:'98',reference_height:'100',confirmations:'3',commitment:'cc'.repeat(56),action_id:body.action_id,refund_ready:body.refund_ready}};
  throw Error('Unexpected request');};
 const reader=hegemonSessionReader({request,enabled:()=>state.enabled}),terms={locked:state.position,claim:'shca1'+'p'.repeat(100),refund:'shca1'+'q'.repeat(100),hashlock:'aa'.repeat(32),timeout:'120',amount:'9007199254740993',action_id:'bb'.repeat(48)};
 assert.equal((await reader.head()).height,100);assert.match(await reader.address(),/^shca1/);
 assert.equal((await reader.escrow(terms,{confirmations:2,minBlocksToExpiry:3})).position,state.position);
 const sent=calls.find(item=>item.path.endsWith('/verify')).body;assert.equal(sent.amount,'9007199254740993');assert.equal(sent.locked,state.position);
 state.position='7';await assert.rejects(reader.escrow(terms,{confirmations:2,minBlocksToExpiry:3}),/did not verify/);state.position=terms.locked;
 state.head=118;await assert.rejects(reader.escrow(terms,{confirmations:2,minBlocksToExpiry:3}),/stale or inconsistent/);
 await assert.rejects(reader.escrow(terms,{confirmations:2,minBlocksToExpiry:1,refundReady:true}),/stale or inconsistent/);state.head=120;
 assert.equal((await reader.escrow(terms,{confirmations:2,minBlocksToExpiry:1,refundReady:true})).refundReady,true);
 state.enabled=false;await assert.rejects(reader.head(),/Connect the local/);
});
test('a released Hegemon secret is verified but is not mislabeled as an escrow claim',async()=>{
 const secret=new Uint8Array(32).fill(7),hashlock=toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',secret)));let value={state:'pending'};
 const reader=hegemonSessionReader({enabled:()=>true,request:async path=>path.endsWith('/head')?{network:'pre-mainnet',genesis:HEGEMON_GENESIS,chain_id:HEGEMON_CHAIN_ID,height:'103'}:value});
 assert.deepEqual(await reader.observe(hashlock,100),{state:'pending'});
 value={state:'secret-revealed',preimage:toHex(secret),action_id:'ab'.repeat(48),block_hash:'0x'+'cd'.repeat(32),block_height:'101',confirmations:3};
 assert.equal((await reader.observe(hashlock,100)).state,'secret-revealed');
 value={...value,preimage:'00'.repeat(32)};await assert.rejects(reader.observe(hashlock,100),/does not match/);
 value={...value,preimage:toHex(secret),confirmations:1};await assert.rejects(reader.observe(hashlock,100),/Invalid Hegemon/);
});
test('Hegemon note selection checks exact amounts, exclusions and fresh height',async()=>{
 let selection={inputs:['7'],total:'9007199254740995',synced_height:'99'};
 const reader=hegemonSessionReader({enabled:()=>true,request:async path=>path.endsWith('/head')?{network:'pre-mainnet',genesis:HEGEMON_GENESIS,chain_id:HEGEMON_CHAIN_ID,height:'100'}:selection});
 assert.deepEqual(await reader.select('9007199254740993','2',['8']),{inputs:['7'],total:'9007199254740995',syncedHeight:99});
 selection={...selection,inputs:['8']};await assert.rejects(reader.select('1','0',['8']),/Invalid/);
 selection={...selection,inputs:['7'],synced_height:'97'};await assert.rejects(reader.select('1','0'),/stale/);
 selection={...selection,synced_height:'99',total:'1'};await assert.rejects(reader.select('2','0'),/insufficient/);
});
test('Hegemon note lookup and action inclusion require bounded confirmed evidence',async()=>{
 let value={position:'9007199254740993',created_height:'98',synced_height:'100'};
 const reader=hegemonSessionReader({enabled:()=>true,request:async path=>path.endsWith('/head')?{network:'pre-mainnet',genesis:HEGEMON_GENESIS,chain_id:HEGEMON_CHAIN_ID,height:'100'}:value});
 assert.deepEqual(await reader.locate('aa'.repeat(56)),{position:'9007199254740993',createdHeight:98,syncedHeight:100});
 value={state:'pending',action_id:'cc'.repeat(48)};assert.deepEqual(await reader.inclusion('bb'.repeat(32)),{state:'pending',actionId:'cc'.repeat(48)});
 value={state:'confirmed',action_id:'cc'.repeat(48),block_hash:'0x'+'dd'.repeat(32),block_height:'98',confirmations:3};
 assert.equal((await reader.inclusion('bb'.repeat(32),'cc'.repeat(48))).blockHeight,98);
 assert.equal((await reader.inclusion('bb'.repeat(32))).actionId,'cc'.repeat(48));
 value={...value,confirmations:4};await assert.rejects(reader.inclusion('bb'.repeat(32),'cc'.repeat(48)),/stale/);
});
