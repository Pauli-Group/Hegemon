import test from 'node:test';
import assert from 'node:assert/strict';
import {Address,TEST_NETWORK,Transaction,secp256k1} from './vendor/btc-signer.mjs';
import {prepareBitcoinPsbt} from './bitcoin-wallet.mjs';
import {encodePsbt} from './bitcoin-psbt.mjs';
import {validateBitcoinDraft} from './session-bitcoin-draft.mjs';

const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join(''),key=n=>new Uint8Array(32).fill(n),pub=n=>hex(secp256k1.getPublicKey(key(n),true));
const session='11'.repeat(32),role='owner',operation='fund',attemptId='22'.repeat(16),address=Address(TEST_NETWORK).encode({type:'wpkh',hash:new Uint8Array(20).fill(3)});
const terms={hashlock:'33'.repeat(32),claimant_key:pub(4),refund_key:pub(5),refund_height:'130000',amount_sats:'50000'};
async function sample(){
 const draft=await prepareBitcoinPsbt({op:operation,terms,address,feeRate:2,read:{utxos:async a=>({address:a,tip:129000,utxos:[{txid:'44'.repeat(32),vout:0,amount_sats:200000,confirmations:3}]})},verifyEscrow:async()=>{},journal:{begin:async()=>attemptId}});
 return {version:1,id:`${session}:${role}:${operation}`,session,role,side:'long',operation,attemptId,draft};
}
test('the exact unsigned Bitcoin draft can be saved for a later wallet handoff',async()=>{
 const record=await sample();assert.equal(validateBitcoinDraft(structuredClone(record),terms).draft.txid,record.draft.txid);
 assert.throws(()=>validateBitcoinDraft({...record,draft:{...record.draft,privateKey:'not permitted'}},terms),/Invalid saved Bitcoin draft/);
 assert.throws(()=>validateBitcoinDraft(record,{...terms,amount_sats:'50001'}),/does not match/);
 const altered=structuredClone(record);altered.draft.built.expect.maxFeeSats=999999999n;assert.throws(()=>validateBitcoinDraft(altered,terms),/Invalid Bitcoin draft contents/);
});
test('a signed PSBT is refused even when its transaction ID is unchanged',async()=>{
 const record=await sample(),tx=Transaction.fromPSBT(record.draft.built.psbt);
 tx.updateInput(0,{partialSig:[[secp256k1.getPublicKey(key(8),true),Uint8Array.from([0x30,1,1])]]});
 const signed=tx.toPSBT(),altered=structuredClone(record);altered.draft.built.psbt=signed;altered.draft.psbt=encodePsbt(signed);
 assert.throws(()=>validateBitcoinDraft(altered,terms),/signatures|PSBT|signature/i);
});
