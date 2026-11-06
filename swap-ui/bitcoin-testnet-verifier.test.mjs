import {test} from 'node:test';
import assert from 'node:assert/strict';
import {bitcoinWitnessScript,expectedBitcoinScript,verifyBitcoinTestnetEscrow,TESTNET4_GENESIS} from './bitcoin-testnet-verifier.mjs';

const terms={txid:'a'.repeat(64),vout:0,amount_sats:1500,hashlock:'33'.repeat(32),claimant_key:'034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa',refund_key:'02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27',refund_height:158927};
test('reconstructs the Core-compatible output and rejects changed or spent terms',async()=>{
 const output='0020b1825672591ed3e3defdf080b6758602562d87c52e137b08d4662f884ef18624';assert.equal(await expectedBitcoinScript(terms),output);
 const snapshot={genesis:TESTNET4_GENESIS,txid:terms.txid,vout:0,tip:158800,confirmed:true,confirmations:2,block_height:158799,block_hash:'b'.repeat(64),spent:false,amount_sats:1500,script:output};
 assert.equal((await verifyBitcoinTestnetEscrow(terms,async()=>snapshot)).confirmations,2);
 for(const [change,reason] of [[{spent:true},/spent/],[{amount_sats:1499},/match/],[{script:'0020'+'0'.repeat(64)},/match/],[{confirmations:1},/confirmations/],[{genesis:'0'.repeat(64)},/different network/]])await assert.rejects(verifyBitcoinTestnetEscrow(terms,async()=>({...snapshot,...change})),reason);
 const near={...terms,refund_height:158802};await assert.rejects(verifyBitcoinTestnetEscrow(near,async()=>({...snapshot,script:await expectedBitcoinScript(near)})),/too close/);
 await assert.rejects(expectedBitcoinScript({...terms,claimant_key:'02'+'f'.repeat(64)}),/public key/);
 await assert.rejects(expectedBitcoinScript({...terms,claimant_key:terms.refund_key}),/must differ/);
});

test('policy limits tighten the confirmation and refund-distance floors but never loosen them',async()=>{
 const output='0020b1825672591ed3e3defdf080b6758602562d87c52e137b08d4662f884ef18624';
 const snapshot={genesis:TESTNET4_GENESIS,txid:terms.txid,vout:0,tip:158800,confirmed:true,confirmations:2,block_height:158799,block_hash:'b'.repeat(64),spent:false,amount_sats:1500,script:output};
 const read=async()=>snapshot,distance=terms.refund_height-snapshot.tip;
 assert.equal((await verifyBitcoinTestnetEscrow(terms,read,{minBlocksToExpiry:distance})).tip,158800);
 await assert.rejects(verifyBitcoinTestnetEscrow(terms,read,{minBlocksToExpiry:distance+1}),/too close/);
 await assert.rejects(verifyBitcoinTestnetEscrow(terms,read,{confirmations:3}),/confirmations/);
 assert.equal((await verifyBitcoinTestnetEscrow(terms,read,{minBlocksToExpiry:1,confirmations:1})).tip,158800,'limits below the floors are ignored');
});

test('a refund may be verified after the refund height only when the caller says so, and the witness script hashes to the output',async()=>{
 const output='0020b1825672591ed3e3defdf080b6758602562d87c52e137b08d4662f884ef18624';
 const late={...terms,refund_height:158790},lateOutput=await expectedBitcoinScript(late);
 const snapshot={genesis:TESTNET4_GENESIS,txid:terms.txid,vout:0,tip:158800,confirmed:true,confirmations:2,block_height:158799,block_hash:'b'.repeat(64),spent:false,amount_sats:1500,script:lateOutput};
 await assert.rejects(verifyBitcoinTestnetEscrow(late,async()=>snapshot),/too close/);
 assert.equal((await verifyBitcoinTestnetEscrow(late,async()=>snapshot,{allowExpired:true})).tip,158800);
 await assert.rejects(verifyBitcoinTestnetEscrow(late,async()=>({...snapshot,spent:true}),{allowExpired:true}),/spent/);
 await assert.rejects(verifyBitcoinTestnetEscrow(late,async()=>({...snapshot,confirmations:1}),{allowExpired:true}),/confirmations/);
 const script=bitcoinWitnessScript(terms),bytes=Uint8Array.from(script.match(/../g),h=>parseInt(h,16));
 const digest=Buffer.from(await crypto.subtle.digest('SHA-256',bytes)).toString('hex');
 assert.equal('0020'+digest,output);
});
