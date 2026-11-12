import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {ethereumWallet} from './test-wallets.mjs';
import {signEthereum} from './identity-flow.mjs';
import {deriveSessionId,sessionOfferDigest,buildParticipant,serializeParticipant,participantText} from './session-identity.mjs';
import {createProtocolKey} from './session-packets.mjs';
import {channelFingerprint} from './session-channel.mjs';
import {planSessionTerms} from './session-plan.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';
import {participantDraft,participantStatement,completeParticipant} from './session-participant.mjs';
import {HEGEMON_GENESIS,HEGEMON_CHAIN_ID} from './session-hegemon-read.mjs';
import {SEPOLIA_GENESIS} from './sepolia-verifier.mjs';
import {checkSessionRefund} from './session-refund.mjs';
import {createSessionRecovery,openSessionRecovery,updateSessionRecovery} from './session-recovery.mjs';

const config=JSON.parse(readFileSync(new URL('./chain-timing.json',import.meta.url),'utf8')),now=1800000000,id='11'.repeat(32),reservation='22'.repeat(32),channelKey='33'.repeat(32),hgnA='shca1'+'q'.repeat(100),hgnB='shca1'+'p'.repeat(100),ethA=ethereumWallet('03'.repeat(32)),ethB=ethereumWallet('04'.repeat(32));
async function fixture(){
 const session=await deriveSessionId(id,reservation),channelDigest=await channelFingerprint(session,channelKey),sessionExpires=now+30*86400,offer={id,visibility:'private',expires:now+3600,ownerPublicKey:'04'+'aa'.repeat(64),give:{chain:'hegemon',kind:'hgn',id:'',amount:'100000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'100000000000000'}},offerDigest=await sessionOfferDigest(offer);
 async function cert(role,hgn,eth){const key=await createProtocolKey(),statement=buildParticipant({session,offer:id,reservation,role,offerDigest,channelDigest,protocolKey:key.publicKey,addresses:{give:hgn,receive:eth.address},issued:now,expires:sessionExpires},offer),text=participantText(statement);return serializeParticipant(statement,[await signEthereum({request:async({params})=>eth.personalSign(params[0])},eth.address,text)]);}
 const ownerBlob=await cert('owner',hgnA,ethA),takerBlob=await cert('taker',hgnB,ethB),snapshot={version:2,offer,offerDigest,reservation,credential:'44'.repeat(32),channelKey,sessionExpires,terms:null,escrows:{long:null,short:null},secretEnvelope:null,ownerBlob,takerBlob,transport:{next:1,previous:null}};
 const state={wrong:false,height:10000},readers={hegemon:{head:async()=>({genesis:HEGEMON_GENESIS,chain_id:HEGEMON_CHAIN_ID,height:state.height}),escrow:async(fields,limits)=>({position:state.wrong?'9':fields.locked,actionId:fields.action_id,createdHeight:9998,commitment:'cc'.repeat(56),confirmations:limits.confirmations,height:state.height,refundReady:limits.refundReady===true})},ethereum:{provider:{request:async({method,params=[]})=>{if(method==='eth_chainId')return '0xaa36a7';if(method==='eth_getBlockByNumber')return params[0]==='0x0'?{hash:SEPOLIA_GENESIS}:{timestamp:'0x'+now.toString(16)};throw Error('Unexpected RPC');}}}};
 return {state,input:{session,role:'owner',snapshot,readers,config,passphrase:'disposable test passphrase',now,nowClock:()=>now},channelDigest};
}
test('Hegemon planning requires an explicit acknowledgement of address-proof limits',async()=>{
 const {input}=await fixture();await assert.rejects(planSessionTerms(input),/not independently proven/);
 const planned=await planSessionTerms({...input,allowUnverifiedHegemon:true});assert.equal(planned.terms.legs.long.network,'pre-mainnet');assert.ok(planned.terms.legs.long.expiry>10000);
 const {snapshot,session}=input,publicKey=(await createProtocolKey()).publicKey,empty={...snapshot,ownerBlob:null};
 await assert.rejects(participantDraft({session,role:'owner',snapshot:empty,publicKey,now}),/proof limitation/);
 const draft=await participantDraft({session,role:'owner',snapshot:empty,publicKey,now,allowUnverifiedHegemon:true}),statement=participantStatement(draft,{give:hgnA,receive:ethA.address}),text=participantText(statement),proof=await signEthereum({request:async({params})=>ethA.personalSign(params[0])},ethA.address,text);
 await assert.rejects(completeParticipant(draft,statement,[proof],now),/do not bind/);
 assert.ok(await completeParticipant(draft,statement,[proof],now,{allowUnverifiedHegemon:true}));
});
test('a Hegemon escrow must be locally verified against the agreed private note and action',async()=>{
 const {input,state,channelDigest}=await fixture(),planned=await planSessionTerms({...input,allowUnverifiedHegemon:true}),reference={chain:'hegemon',txid:'55'.repeat(32),action_id:'66'.repeat(48),position:'7',block_height:'9998'},s=input.snapshot;
 const args={terms:planned.terms,offer:s.offer,expectedOfferDigest:s.offerDigest,channelDigest,ownerBlob:s.ownerBlob,takerBlob:s.takerBlob,session:input.session,reservation,sessionExpires:s.sessionExpires,role:'initiator',references:{long:reference,short:null},purpose:'verify_first',readers:input.readers,config,now,nowClock:()=>now,templates:{}};
 await assert.rejects(verifySessionSnapshot(args),/not independently proven/);
 assert.equal((await verifySessionSnapshot({...args,allowUnverifiedHegemon:true})).escrows.long.position,'7');
 state.wrong=true;await assert.rejects(verifySessionSnapshot({...args,allowUnverifiedHegemon:true}),/did not verify the agreed note/);
});
test('a Hegemon refund requires a mature, locally verified note from the saved action',async()=>{
 const {input,state}=await fixture(),planned=await planSessionTerms({...input,allowUnverifiedHegemon:true}),reference={chain:'hegemon',txid:'55'.repeat(32),action_id:'66'.repeat(48),position:'7',block_height:'9998'},snapshot={terms:planned.terms,escrows:{long:reference,short:null}};
 await assert.rejects(checkSessionRefund({snapshot,role:'owner',readers:input.readers,config}),/refund height has not been reached/);
 state.height=planned.terms.legs.long.expiry;assert.equal((await checkSessionRefund({snapshot,role:'owner',readers:input.readers,config})).chain,'hegemon');
 state.wrong=true;await assert.rejects(checkSessionRefund({snapshot,role:'owner',readers:input.readers,config}),/did not verify/);
});
test('encrypted Hegemon recovery retains append-only candidate and refund-handoff references',async()=>{
 const {input}=await fixture(),planned=await planSessionTerms({...input,allowUnverifiedHegemon:true}),blank=()=>({fund:[],claim:[],refund:[]}),empty=()=>({fund:null,claim:null,refund:null});
 const snapshot={...input.snapshot,version:4,terms:planned.terms,secretEnvelope:planned.secretEnvelope,actions:{long:blank(),short:blank()},hegemon:{long:empty(),short:empty()}};
 const recovery=await createSessionRecovery({session:input.session,role:'owner',snapshot,passphrase:input.passphrase});
 const intent=structuredClone(snapshot);intent.actions.long.fund.push({id:'11'.repeat(16),state:'intent',txid:null});
 const intentBackup=await updateSessionRecovery(recovery.envelope,input.passphrase,intent);
 const prepared=structuredClone(intent);prepared.actions.long.fund[0]={...prepared.actions.long.fund[0],state:'prepared',txid:'55'.repeat(32)};
 prepared.hegemon.long.fund={candidate:'55'.repeat(32),handoff:'77'.repeat(16)+'.bin',actionId:null,blockHeight:null,commitment:null,position:null};
 const saved=await updateSessionRecovery(intentBackup,input.passphrase,prepared),restored=await openSessionRecovery(saved,input.passphrase);
 assert.deepEqual(restored.snapshot.hegemon,prepared.hegemon);assert.equal(JSON.stringify(saved).includes(prepared.hegemon.long.fund.handoff),false);
 const changed=structuredClone(prepared);changed.hegemon.long.fund.handoff='88'.repeat(16)+'.bin';
 await assert.rejects(updateSessionRecovery(saved,input.passphrase,changed),/Invalid saved Hegemon/);
});
