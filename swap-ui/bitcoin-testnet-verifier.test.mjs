import {test} from 'node:test';
import assert from 'node:assert/strict';
import {expectedBitcoinScript,verifyBitcoinTestnetEscrow,TESTNET4_GENESIS} from './bitcoin-testnet-verifier.mjs';

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
