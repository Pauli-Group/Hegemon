/** Recoverable local Hegemon funding preparation. This does not submit the
 * candidate; the local companion requires separate terminal approval. */
import {canonical} from './identity.mjs';
import {getSession,updateSession,sessionBackupCurrent,sessionFundingPrerequisites} from './session-store.mjs';
import {participantCode} from './session-participant.mjs';
import {channelFingerprint} from './session-channel.mjs';
import {peerFundingAgreement} from './session-funding.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {legRequirements} from './timelock-policy.mjs';
import {listActions,beginAction,finishAction,uncertainAction,removeAction,reconcileUncertainAction} from './action-journal.mjs';
import {actionLock,actionArmed,consumeActionArm,resolveSessionAction,requireRecoveryReviewComplete,hasHegemonConsent} from './session-action.mjs';

const FEE='1000',HEX=/^[0-9a-f]{64}$/,HANDOFF=/^[0-9a-f]{32}\.bin$/;
const submissionKey=(session,role,id)=>`hegemon.swap.hegemon-submit:${session}:${role}:${id}`;
function controls({session,role,attemptId,outbox,readFrames,readers,storage,locks}){
 if(!HEX.test(session||'')||!['owner','taker'].includes(role)||!/^[0-9a-f]{32}$/.test(attemptId||'')||outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'||typeof readers?.hegemon?.select!=='function'||typeof readers.hegemon.action!=='function'||!storage||typeof locks?.request!=='function')throw Error('The Hegemon funding controls are unavailable.');
}
async function gate({record,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId,state}){
 const {session,role,snapshot}=record,side=role==='owner'?'long':'short',attempt=snapshot.actions?.[side]?.fund?.at(-1),transport=await outbox.inspect();
 requireRecoveryReviewComplete(session,role,storage);
 if(snapshot.version!==4||snapshot.terms?.legs[side].asset.chain!=='hegemon'||snapshot.terms.legs[side].asset.kind!=='hgn'||snapshot.escrows[side]!==null||attempt?.id!==attemptId||attempt.state!==state||!record.backupAcknowledged||!await sessionBackupCurrent(record)||transport.pending||transport.next!==snapshot.transport.next||transport.previous!==snapshot.transport.previous)throw Error('The swap or its recovery state changed. Refresh before funding.');
 if(typeof readers.hegemon.address!=='function'||await readers.hegemon.address()!==snapshot.terms.legs[side].refundee)throw Error('The local Hegemon companion has a different wallet. Reconnect the wallet for this swap.');
 if(storage.getItem(`hegemon.swap.peer-pin:${session}:${role}`)!==await participantCode(role==='owner'?snapshot.takerBlob:snapshot.ownerBlob))throw Error('Confirm the other participant’s verification code before funding.');
 const chains=new Set([snapshot.terms.legs.long.asset.chain,snapshot.terms.legs.short.asset.chain]);
 for(const action of await listActions()){
  if(action.id===journalId||!chains.has(action.chain))continue;
  const raw=action.request?.hashlock,related=raw===undefined||typeof raw==='string'&&raw.toLowerCase().replace(/^0x/,'')===snapshot.terms.hashlock;
  if(related&&(action.state==='pending'||action.state==='uncertain'||action.chain==='hegemon'&&action.operation==='lock'&&action.state==='completed'&&action.receipt?.submitted===true))throw Error('A related wallet action needs review before funding.');
 }
 await peerFundingAgreement(record,readFrames,clock());
 return verifySessionSnapshot({terms:snapshot.terms,offer:snapshot.offer,expectedOfferDigest:snapshot.offerDigest,channelDigest:await channelFingerprint(session,snapshot.channelKey),ownerBlob:snapshot.ownerBlob,takerBlob:snapshot.takerBlob,session,reservation:snapshot.reservation,sessionExpires:snapshot.sessionExpires,role:role==='owner'?'initiator':'responder',references:snapshot.escrows,purpose:role==='owner'?'fund_first':'fund_second',readers,config,now:clock(),templates,allowUnverifiedHegemon:hasHegemonConsent(session,role,storage)});
}

/** Select unreserved inputs and ask the companion to prove a lock only after
 * the user has backed up the intent. Save the exact candidate and handoff in
 * one browser transaction. A lost response is uncertain and never retried. */
export async function prepareHegemonSessionFund(options){
 const {session,role,attemptId,outbox,readFrames,readers,config,templates,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}=options;
 controls({session,role,attemptId,outbox,readFrames,readers,storage,locks});
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');
  let record=await getSession(session,role);if(!record)throw Error('The saved swap is unavailable.');
  record=await sessionFundingPrerequisites({session,role,revision:record.revision,outbox:await outbox.inspect(),actions:await listActions(),attemptId});
  const side=role==='owner'?'long':'short',original=canonical(record.snapshot.terms),terms=sessionAssetTerms(record.snapshot.terms,side).operationTerms;
  let journalId=null,asked=false;
  const check=async()=>{const latest=await getSession(session,role);if(!latest||canonical(latest.snapshot.terms)!==original||!asked&&!actionArmed(session,role,attemptId,storage))throw Error('The Hegemon funding state changed.');await gate({record:latest,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId,state:'intent'});};
  await check();
  // A distinct fee note must remain available for a later refund. Merely
  // selecting it here does not reserve it; the wallet rechecks on proving.
  const feeNote=await readers.hegemon.select('1','999',[]);
  if(feeNote.inputs.length!==1)throw Error('Keep one separate Hegemon note of at least 1000 atoms for the refund fee.');
  const selected=await readers.hegemon.select(terms.amount,FEE,feeNote.inputs);
  const request={operation:'lock',inputs:selected.inputs,claim:terms.claim,refund:terms.refund,hashlock:terms.hashlock,timeout:terms.timeout,amount:terms.amount,fee:FEE};
  await check();journalId=await beginAction('hegemon','lock',request);
  try{
   await check();consumeActionArm(session,role,attemptId,storage);asked=true;
   const result=await readers.hegemon.action(request);
   if(result?.operation!=='lock'||!HEX.test(result.attempt||'')||!HANDOFF.test(result.refund_handoff||'')||result.submitted!==false)throw Error('The local wallet returned an invalid lock result.');
   await finishAction(journalId,{submitted:false,attempt:result.attempt,refund_handoff:result.refund_handoff});
   const latest=await getSession(session,role),next=structuredClone(latest.snapshot),attempt=next.actions[side].fund.at(-1);
   if(canonical(next.terms)!==original||attempt?.id!==attemptId||attempt.state!=='intent'||next.hegemon[side].fund!==null)throw Error('The Hegemon funding record changed.');
   next.actions[side].fund[next.actions[side].fund.length-1]={id:attemptId,state:'prepared',txid:result.attempt};
   next.hegemon[side].fund={candidate:result.attempt,handoff:result.refund_handoff,actionId:null,blockHeight:null,commitment:null,position:null};
   const saved=await updateSession(session,role,latest.revision,next);
   storage.setItem(submissionKey(session,role,attemptId),'ready');
   return {candidate:result.attempt,handoff:result.refund_handoff,revision:saved.revision};
  }catch(error){
   if(asked){await uncertainAction(journalId);try{await resolveSessionAction({session,role,side,operation:'fund',id:attemptId,state:'uncertain'});}catch{/* The local journal still prevents an automatic retry. */}}
   else await removeAction(journalId);
   throw error;
  }
 });
}

/** Recheck both chains and submit only the saved candidate after a second,
 * explicit local approval. A missing response is never a reason to retry. */
export async function submitHegemonSessionFund(options){
 const {session,role,attemptId,outbox,readFrames,readers,config,templates,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}=options;
 controls({session,role,attemptId,outbox,readFrames,readers,storage,locks});
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');
  const record=await getSession(session,role);if(!record)throw Error('The saved swap is unavailable.');
  const side=role==='owner'?'long':'short',item=record.snapshot.hegemon?.[side]?.fund,key=submissionKey(session,role,attemptId),original=canonical(record.snapshot.terms);
  if(!item||item.actionId!==null||storage.getItem(key)!=='ready')throw Error('This Hegemon candidate needs manual review before submission.');
  let journalId=null,asked=false;
  const check=async()=>{
   const latest=await getSession(session,role),saved=latest?.snapshot.hegemon?.[side]?.fund;
   if(!latest||canonical(latest.snapshot.terms)!==original||canonical(saved)!==canonical(item)||!asked&&storage.getItem(key)!=='ready')throw Error('The Hegemon funding state changed.');
   await gate({record:latest,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId,state:'prepared'});
  };
  await check();journalId=await beginAction('hegemon','submit',{operation:'submit',attempt:item.candidate});
  try{
   await check();storage.removeItem(key);if(storage.getItem(key)!==null)throw Error('Could not secure the Hegemon submission.');asked=true;
   const result=await readers.hegemon.action({operation:'submit',attempt:item.candidate});
   if(result?.operation!=='submit'||result.attempt!==item.candidate||result.submitted!==true||!/^[0-9a-f]{96}$/.test(result.txid||''))throw Error('The local wallet returned an invalid submission result.');
   await finishAction(journalId,{submitted:true,confirmed:false,txid:result.txid,attempt:item.candidate});
   const latest=await getSession(session,role),next=structuredClone(latest.snapshot),saved=next.hegemon?.[side]?.fund,attempt=next.actions[side].fund.at(-1);
   if(canonical(next.terms)!==original||canonical(saved)!==canonical(item)||attempt?.id!==attemptId||attempt.state!=='prepared'||attempt.txid!==item.candidate)throw Error('The Hegemon funding record changed.');
   saved.actionId=result.txid;
   const updated=await updateSession(session,role,latest.revision,next);
   return {candidate:item.candidate,actionId:result.txid,revision:updated.revision};
  }catch(error){
   if(asked){await uncertainAction(journalId);try{await resolveSessionAction({session,role,side,operation:'fund',id:attemptId,state:'uncertain',txid:item.candidate});}catch{/* The local journal still prevents an automatic retry. */}}
   else await removeAction(journalId);
   throw error;
  }
 });
}

/** A refresh may inspect the saved candidate without prompting or sending a
 * transaction. An unknown response remains uncertain until the wallet and
 * canonical chain agree on the exact action and confirmation depth. */
export async function observeHegemonSessionFunding({session,role,attemptId,readers,storage=globalThis.localStorage,locks=globalThis.navigator?.locks}){
 if(!HEX.test(session||'')||!['owner','taker'].includes(role)||!/^[0-9a-f]{32}$/.test(attemptId||'')||typeof readers?.hegemon?.inclusion!=='function'||!storage||typeof locks?.request!=='function')throw Error('The Hegemon funding observer is unavailable.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');
  const record=await getSession(session,role),side=role==='owner'?'long':'short',item=record?.snapshot.hegemon?.[side]?.fund,attempt=record?.snapshot.actions?.[side]?.fund?.at(-1);
  if(!record||record.snapshot.version!==4||!record.backupAcknowledged||!await sessionBackupCurrent(record)||!item||attempt?.id!==attemptId||!['prepared','uncertain'].includes(attempt.state)||attempt.txid!==item.candidate)throw Error('Save and review the Hegemon recovery data before checking the lock.');
  if(item.blockHeight!==null)return {state:'confirmed',actionId:item.actionId,blockHeight:item.blockHeight,revision:record.revision};
  const observed=await readers.hegemon.inclusion(item.candidate,item.actionId);
  if(observed.state==='pending')return {state:'pending'};
  if(observed.state!=='confirmed'||!/^[0-9a-f]{96}$/.test(observed.actionId||'')||!Number.isSafeInteger(observed.blockHeight)||observed.blockHeight<1||observed.blockHeight>=2**48||item.actionId!==null&&item.actionId!==observed.actionId)throw Error('The Hegemon wallet could not verify the funding action.');
  const latest=await getSession(session,role);
  if(!latest||latest.revision!==record.revision||canonical(latest.snapshot.hegemon[side].fund)!==canonical(item))throw Error('The Hegemon funding record changed.');
  const next=structuredClone(latest.snapshot);next.hegemon[side].fund.actionId=observed.actionId;next.hegemon[side].fund.blockHeight=String(observed.blockHeight);
  const saved=await updateSession(session,role,latest.revision,next);
  return {state:'confirmed',actionId:observed.actionId,blockHeight:String(observed.blockHeight),revision:saved.revision};
 });
}

/** Import the encrypted local refund handoff with terminal approval, locate
 * its exact note, and verify it against the canonical lock. Importing the
 * same handoff again is idempotent in the wallet and sends no transaction. */
export async function importHegemonSessionRefundHandoff({session,role,attemptId,readers,config,storage=globalThis.localStorage,locks=globalThis.navigator?.locks}){
 if(!HEX.test(session||'')||!['owner','taker'].includes(role)||!/^[0-9a-f]{32}$/.test(attemptId||'')||!['inclusion','action','locate','head','escrow'].every(name=>typeof readers?.hegemon?.[name]==='function')||!storage||typeof locks?.request!=='function')throw Error('The Hegemon refund handoff is unavailable.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');requireRecoveryReviewComplete(session,role,storage);
  const record=await getSession(session,role),side=role==='owner'?'long':'short',snapshot=record?.snapshot,item=snapshot?.hegemon?.[side]?.fund,attempt=snapshot?.actions?.[side]?.fund?.at(-1);
  if(!record||snapshot.version!==4||!record.backupAcknowledged||!await sessionBackupCurrent(record)||snapshot.escrows[side]!==null||!item||item.blockHeight===null||item.actionId===null||item.commitment!==null||attempt?.id!==attemptId||!['prepared','uncertain'].includes(attempt.state)||attempt.txid!==item.candidate)throw Error('Save and review the confirmed Hegemon lock before importing its refund handoff.');
  if(typeof readers.hegemon.address!=='function'||await readers.hegemon.address()!==snapshot.terms.legs[side].refundee)throw Error('The local Hegemon companion has a different wallet. Reconnect the wallet for this swap.');
  const seen=await readers.hegemon.inclusion(item.candidate,item.actionId);
  if(seen.state!=='confirmed'||seen.actionId!==item.actionId||String(seen.blockHeight)!==item.blockHeight)throw Error('The Hegemon lock is no longer confirmed.');
  const imported=await readers.hegemon.action({operation:'import-refund-handoff',handoff:item.handoff,block_height:item.blockHeight});
  if(imported?.operation!=='import-refund-handoff'||imported.block_height!==item.blockHeight||!/^[0-9a-f]{112}$/.test(imported.commitment||''))throw Error('The local wallet did not return the imported Hegemon note.');
  const located=await readers.hegemon.locate(imported.commitment);
  if(String(located.createdHeight)!==item.blockHeight)throw Error('The imported Hegemon note has a different creation block.');
  const reference={chain:'hegemon',txid:item.candidate,action_id:item.actionId,position:located.position,block_height:item.blockHeight},fields=sessionAssetTerms(snapshot.terms,side,{reference}).operationTerms,head=await readers.hegemon.head(),refundReady=head.height>=snapshot.terms.legs[side].expiry;
  const confirmations=legRequirements(config,'hegemon').confirmations,verified=await readers.hegemon.escrow(fields,{confirmations,minBlocksToExpiry:1,refundReady});
  if(verified?.position!==reference.position||verified.actionId!==reference.action_id||verified.commitment!==imported.commitment||String(verified.createdHeight)!==reference.block_height||verified.refundReady!==refundReady||!Number.isSafeInteger(verified.confirmations)||verified.confirmations<confirmations)throw Error('The local wallet did not verify the imported Hegemon lock.');
  const latest=await getSession(session,role);if(!latest||latest.revision!==record.revision||canonical(latest.snapshot.hegemon[side].fund)!==canonical(item))throw Error('The Hegemon recovery record changed.');
  const next=structuredClone(latest.snapshot);next.hegemon[side].fund.commitment=imported.commitment;next.hegemon[side].fund.position=located.position;next.escrows[side]=reference;next.actions[side].fund[next.actions[side].fund.length-1]={id:attemptId,state:'submitted',txid:item.candidate};
  const saved=await updateSession(session,role,latest.revision,next);
  for(const action of await listActions())if(action.chain==='hegemon'&&action.operation==='submit'&&action.state==='uncertain'&&action.request.attempt===item.candidate)await reconcileUncertainAction(action.id,{submitted:true,confirmed:false,txid:item.actionId,attempt:item.candidate});
  return {reference,refundReady,revision:saved.revision};
 });
}
