import test from 'node:test';
import assert from 'node:assert/strict';
import {validateHegemonRecovery,validateHegemonRecoveryAdvance} from './session-hegemon-recovery.mjs';

const blank=()=>({fund:[],claim:[],refund:[]}),empty=()=>({fund:null,claim:null,refund:null});
function prepared(){
 const record={version:4,terms:{legs:{long:{asset:{chain:'hegemon'}},short:{asset:{chain:'ethereum'}}}},actions:{long:blank(),short:blank()},hegemon:{long:empty(),short:empty()}};
 record.actions.long.fund.push({id:'11'.repeat(16),state:'prepared',txid:'22'.repeat(32)});
 record.hegemon.long.fund={candidate:'22'.repeat(32),handoff:'33'.repeat(16)+'.bin',actionId:null,blockHeight:null,commitment:null,position:null};
 return record;
}
test('Hegemon recovery binds candidate and handoff and advances append-only',()=>{
 const first=prepared();validateHegemonRecovery(first);
 const submitted=structuredClone(first);submitted.hegemon.long.fund.actionId='44'.repeat(48);validateHegemonRecovery(submitted);validateHegemonRecoveryAdvance(first,submitted);
 const confirmed=structuredClone(submitted);Object.assign(confirmed.hegemon.long.fund,{blockHeight:'100',commitment:'55'.repeat(56),position:'9007199254740993'});validateHegemonRecovery(confirmed);validateHegemonRecoveryAdvance(submitted,confirmed);
 for(const mutate of [r=>r.hegemon.long.fund.candidate='99'.repeat(32),r=>r.hegemon.long.fund.handoff='../secret',r=>r.hegemon.long.fund.position='01',r=>r.hegemon.long.fund.actionId=null,r=>r.hegemon.short.fund=structuredClone(r.hegemon.long.fund)]){
  const bad=structuredClone(confirmed);mutate(bad);assert.throws(()=>validateHegemonRecovery(bad));
 }
 const changed=structuredClone(confirmed);changed.hegemon.long.fund.position='8';validateHegemonRecovery(changed);assert.throws(()=>validateHegemonRecoveryAdvance(confirmed,changed));
 const cleared=structuredClone(confirmed);cleared.hegemon.long.fund=null;assert.throws(()=>validateHegemonRecoveryAdvance(confirmed,cleared));
});
