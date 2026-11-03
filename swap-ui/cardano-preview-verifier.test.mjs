import {test} from 'node:test';
import assert from 'node:assert/strict';
import {parseCardanoAssets,PREVIEW_HTLC_ADDRESS,verifyCardanoPreviewEscrow} from './cardano-preview-verifier.mjs';

const txid='d00b896311757de703272676a851a5353ec63e02f48c2c550612009df6f4270f';
const hashlock='b710e3f9d78b3c0fd74964d63c8d6ac4fe13f290aaed172a0a7509712f7bbebb';
const claimant='88894379b235102cc2e55b1f95e8577b06e9896683a9d68495bf562f',refundee='c526918111bb0b514bdd60981690a056a82b0bd497acf8a28d302533',policy='0a396632a227e19f8aed123cc124ad75139de3c96b897e029c88d77e';
const terms={outref:txid+'#0',lovelace:'4000000',assets:policy+'.4e4654=1',hashlock,claimant,refundee,expiry_ms:1793670562000};
const raw='d8799f5820'+hashlock+'581c'+claimant+'581c'+refundee+'1b000001a19f18c0d0ff';
function snapshot(){return {network:'preview',magic:2,system_start:1666656000,slot:127013562,confirmations:2,output:{tx_hash:txid,tx_index:0,address:PREVIEW_HTLC_ADDRESS,value:'4000000',is_spent:false,asset_list:[{policy_id:policy,asset_name:'4e4654',quantity:'1'}],inline_datum:{bytes:raw,value:{constructor:0,fields:[{bytes:hashlock},{bytes:claimant},{bytes:refundee},{int:terms.expiry_ms}]}}}};}
test('matches a preview HTLC datum and exact native assets, and rejects mutations',async()=>{
 const s=snapshot();s.slot=(terms.expiry_ms/1000)-s.system_start-1000;
 assert.equal((await verifyCardanoPreviewEscrow(terms,async()=>s)).confirmations,2);
 const mutations=[['spent',x=>x.output.is_spent=true,/spent/],['wrong address',x=>x.output.address='bad',/validator/],['wrong asset',x=>x.output.asset_list[0].quantity='2',/assets/],['wrong datum bytes',x=>x.output.inline_datum.bytes=raw.replace(hashlock,'00'.repeat(32)),/datum/],['unconfirmed',x=>x.confirmations=1,/confirm/],['deadline',x=>x.slot+=500,/deadline/]];
 for(const [,mutate,reason] of mutations){const value=structuredClone(s);mutate(value);await assert.rejects(verifyCardanoPreviewEscrow(terms,async()=>value),reason);}
 assert.throws(()=>parseCardanoAssets(terms.assets+'\n'+terms.assets),/Invalid/);
});
