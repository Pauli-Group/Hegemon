/** Hegemon claims and refunds: prove locally, back up the candidate, then
 * separately approve submission. Plaintext preimages never enter the relay. */
import {canonical} from './identity.mjs';
import {getSession,updateSession,sessionBackupCurrent} from './session-store.mjs';
import {participantCode} from './session-participant.mjs';
import {readPeerSessionPackets} from './session-coordination.mjs';
import {sessionTermsDigest} from './session-packets.mjs';
import {channelFingerprint} from './session-channel.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';
import {observeSessionLeg} from './session-observation.mjs';
import {checkSessionRefund} from './session-refund.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {listActions,beginAction,finishAction,uncertainAction,removeAction,reconcileUncertainAction} from './action-journal.mjs';
import {actionLock,actionArmed,consumeActionArm,resolveSessionAction,requireRecoveryReviewComplete,hasHegemonConsent} from './session-action.mjs';

const HEX=/^[0-9a-f]{64}$/,FEE='1000';
const sideFor=(role,operation)=>operation==='refund'?(role==='owner'?'long':'short'):(role==='owner'?'short':'long');
const keyFor=(session,role,id)=>`hegemon.swap.hegemon-submit:${session}:${role}:${id}`;
function controls({session,role,operation,attemptId,readers,storage,locks,outbox,readFrames}){
 if(!HEX.test(session||'')||!['owner','taker'].includes(role)||!['claim','refund'].includes(operation)||!/^[0-9a-f]{32}$/.test(attemptId||'')||typeof readers?.hegemon?.select!=='function'||typeof readers.hegemon.action!=='function'||!storage||typeof locks?.request!=='function'||operation==='claim'&&(outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'))throw Error('The Hegemon spend controls are unavailable.');
}
async function gate({record,operation,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId,state}){
 const {session,role,snapshot}=record,side=sideFor(role,operation),attempt=snapshot.actions?.[side]?.[operation]?.at(-1);
 requireRecoveryReviewComplete(session,role,storage);
 if(snapshot.version!==4||snapshot.terms?.legs[side].asset.chain!=='hegemon'||snapshot.terms.legs[side].asset.kind!=='hgn'||!snapshot.escrows[side]||attempt?.id!==attemptId||attempt.state!==state||!record.backupAcknowledged||!await sessionBackupCurrent(record))throw Error('The swap or its recovery state changed. Refresh before continuing.');
 const ownAddress=operation==='claim'?snapshot.terms.legs[side].claimant:snapshot.terms.legs[side].refundee;
 if(typeof readers.hegemon.address!=='function'||await readers.hegemon.address()!==ownAddress)throw Error('The local Hegemon companion has a different wallet. Reconnect the wallet for this swap.');
 const chains=new Set([snapshot.terms.legs.long.asset.chain,snapshot.terms.legs.short.asset.chain]),hash=snapshot.terms.hashlock;
 for(const action of await listActions()){
  if(action.id===journalId||!chains.has(action.chain))continue;
  const raw=action.request?.hashlock,related=raw===undefined||typeof raw==='string'&&raw.toLowerCase().replace(/^0x/,'')===hash;
  if(related&&(operation!=='refund'||action.chain==='hegemon'&&action.operation==='refund')&&(action.state==='pending'||action.state==='uncertain'||action.chain==='hegemon'&&action.operation===operation&&action.state==='completed'&&action.receipt?.submitted===true))throw Error('A related wallet action needs review before continuing.');
 }
 if(operation==='refund')return (await checkSessionRefund({snapshot,role,readers,config})).snapshot;
 const local=await outbox.inspect();
 if(local.pending||local.next!==snapshot.transport.next||local.previous!==snapshot.transport.previous)throw Error('Synchronize the signed message history before claiming.');
 if(storage.getItem(`hegemon.swap.peer-pin:${session}:${role}`)!==await participantCode(role==='owner'?snapshot.takerBlob:snapshot.ownerBlob))throw Error('Confirm the other participant’s verification code before claiming.');
 const peers=await readPeerSessionPackets({session,role,readFrames,now:clock()}),digest=await sessionTermsDigest(snapshot.terms),first=peers[0]?.body.payload,last=peers[1]?.body.payload;
 if(peers.length!==2||role==='owner'&&(first?.type!=='accept'||first.termsDigest!==digest)||role==='taker'&&(first?.type!=='proposal'||canonical(first.terms)!==canonical(snapshot.terms))||last?.type!=='escrow'||last.leg!==(role==='owner'?'short':'long')||last.termsDigest!==digest||canonical(last.reference)!==canonical(snapshot.escrows[last.leg]))throw Error('The signed escrow history does not match the saved swap.');
 const checked=await verifySessionSnapshot({terms:snapshot.terms,offer:snapshot.offer,expectedOfferDigest:snapshot.offerDigest,channelDigest:await channelFingerprint(session,snapshot.channelKey),ownerBlob:snapshot.ownerBlob,takerBlob:snapshot.takerBlob,session,reservation:snapshot.reservation,sessionExpires:snapshot.sessionExpires,role:role==='owner'?'initiator':'responder',references:snapshot.escrows,purpose:role==='owner'?'claim_short':'claim_long',readers,config,now:clock(),templates,allowUnverifiedHegemon:hasHegemonConsent(session,role,storage)});
 if(role==='taker'){
  const seen=await observeSessionLeg({snapshot,side:'short',readers,config});
  if(!['claimed','secret-revealed'].includes(seen.state)||!seen.enough)throw Error('The other person’s confirmed secret is not yet verified.');
 }
 return checked.escrows[side];
}

export async function prepareHegemonSessionSpend(options){
 const {session,role,operation,attemptId,outbox,readFrames,readers,config,templates,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}=options;
 controls({session,role,operation,attemptId,outbox,readFrames,readers,storage,locks});
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');const record=await getSession(session,role);if(!record)throw Error('The saved swap is unavailable.');
  const side=sideFor(role,operation),original=canonical(record.snapshot.terms),reference=canonical(record.snapshot.escrows[side]),fields=sessionAssetTerms(record.snapshot.terms,side,{reference:record.snapshot.escrows[side]}).operationTerms;
  let journalId=null,asked=false;
  const check=async()=>{const latest=await getSession(session,role);if(!latest||canonical(latest.snapshot.terms)!==original||canonical(latest.snapshot.escrows[side])!==reference||!asked&&!actionArmed(session,role,attemptId,storage))throw Error('The Hegemon spend state changed.');return gate({record:latest,operation,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId,state:'intent'});};
  await check();const fee=await readers.hegemon.select('1','999',[fields.locked]);if(fee.inputs.length!==1)throw Error('One separate Hegemon note of at least 1000 atoms is needed for the fee.');
  const request={operation,locked:fields.locked,fee_input:fee.inputs[0],recipient:operation==='claim'?fields.claim:fields.refund,fee:FEE};
  await check();journalId=await beginAction('hegemon',operation,request);
  try{
   await check();consumeActionArm(session,role,attemptId,storage);asked=true;
   const result=await readers.hegemon.action(request,operation==='claim'?{secretEnvelope:record.snapshot.secretEnvelope}:{});
   if(result?.operation!==operation||!HEX.test(result.attempt||'')||result.submitted!==false)throw Error('The local wallet returned an invalid spend candidate.');
   await finishAction(journalId,{submitted:false,attempt:result.attempt});
   const latest=await getSession(session,role),next=structuredClone(latest.snapshot),attempt=next.actions[side][operation].at(-1);
   if(canonical(next.terms)!==original||canonical(next.escrows[side])!==reference||attempt?.id!==attemptId||attempt.state!=='intent'||next.hegemon[side][operation]!==null)throw Error('The Hegemon spend record changed.');
   next.actions[side][operation][next.actions[side][operation].length-1]={id:attemptId,state:'prepared',txid:result.attempt};
   next.hegemon[side][operation]={candidate:result.attempt,handoff:null,actionId:null,blockHeight:null,commitment:null,position:null};
   const saved=await updateSession(session,role,latest.revision,next);storage.setItem(keyFor(session,role,attemptId),'ready');
   return {candidate:result.attempt,revision:saved.revision};
  }catch(error){if(asked){await uncertainAction(journalId);try{await resolveSessionAction({session,role,side,operation,id:attemptId,state:'uncertain'});}catch{}}else await removeAction(journalId);throw error;}
 });
}

export async function submitHegemonSessionSpend(options){
 const {session,role,operation,attemptId,outbox,readFrames,readers,config,templates,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}=options;
 controls({session,role,operation,attemptId,outbox,readFrames,readers,storage,locks});
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');const record=await getSession(session,role);if(!record)throw Error('The saved swap is unavailable.');
  const side=sideFor(role,operation),item=record.snapshot.hegemon?.[side]?.[operation],key=keyFor(session,role,attemptId),original=canonical(record.snapshot.terms),reference=canonical(record.snapshot.escrows[side]);
  if(!item||item.actionId!==null||storage.getItem(key)!=='ready')throw Error('This Hegemon candidate needs manual review before submission.');
  let journalId=null,asked=false;
  const check=async()=>{const latest=await getSession(session,role),saved=latest?.snapshot.hegemon?.[side]?.[operation];if(!latest||canonical(latest.snapshot.terms)!==original||canonical(latest.snapshot.escrows[side])!==reference||canonical(saved)!==canonical(item)||!asked&&storage.getItem(key)!=='ready')throw Error('The Hegemon spend state changed.');await gate({record:latest,operation,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId,state:'prepared'});};
  await check();journalId=await beginAction('hegemon','submit',{operation:'submit',attempt:item.candidate});
  try{
   await check();storage.removeItem(key);if(storage.getItem(key)!==null)throw Error('Could not secure the Hegemon submission.');asked=true;
   const result=await readers.hegemon.action({operation:'submit',attempt:item.candidate});
   if(result?.operation!=='submit'||result.attempt!==item.candidate||result.submitted!==true||!/^[0-9a-f]{96}$/.test(result.txid||''))throw Error('The local wallet returned an invalid submission result.');
   await finishAction(journalId,{submitted:true,confirmed:false,txid:result.txid,attempt:item.candidate});
   const latest=await getSession(session,role),next=structuredClone(latest.snapshot),saved=next.hegemon?.[side]?.[operation],attempt=next.actions[side][operation].at(-1);
   if(canonical(next.terms)!==original||canonical(next.escrows[side])!==reference||canonical(saved)!==canonical(item)||attempt?.id!==attemptId||attempt.state!=='prepared'||attempt.txid!==item.candidate)throw Error('The Hegemon spend record changed.');
   saved.actionId=result.txid;const updated=await updateSession(session,role,latest.revision,next);
   return {candidate:item.candidate,actionId:result.txid,revision:updated.revision};
  }catch(error){if(asked){await uncertainAction(journalId);try{await resolveSessionAction({session,role,side,operation,id:attemptId,state:'uncertain',txid:item.candidate});}catch{}}else await removeAction(journalId);throw error;}
 });
}

/** Only the exact wallet attempt and canonical action can complete a spend. */
export async function observeHegemonSessionSpend({session,role,operation,attemptId,readers,storage=globalThis.localStorage,locks=globalThis.navigator?.locks}){
 if(!HEX.test(session||'')||!['owner','taker'].includes(role)||!['claim','refund'].includes(operation)||!/^[0-9a-f]{32}$/.test(attemptId||'')||typeof readers?.hegemon?.inclusion!=='function'||!storage||typeof locks?.request!=='function')throw Error('The Hegemon spend observer is unavailable.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');
  const record=await getSession(session,role),side=sideFor(role,operation),item=record?.snapshot.hegemon?.[side]?.[operation],attempt=record?.snapshot.actions?.[side]?.[operation]?.at(-1);
  if(!record||record.snapshot.version!==4||!record.backupAcknowledged||!await sessionBackupCurrent(record)||!item||attempt?.id!==attemptId||!['prepared','uncertain'].includes(attempt.state)||attempt.txid!==item.candidate)throw Error('Save and review the Hegemon recovery data before checking the spend.');
  const observed=await readers.hegemon.inclusion(item.candidate,item.actionId);if(observed.state==='pending')return {state:'pending'};
  if(observed.state!=='confirmed'||!/^[0-9a-f]{96}$/.test(observed.actionId||'')||!Number.isSafeInteger(observed.blockHeight)||observed.blockHeight<1||observed.blockHeight>=2**48||item.actionId!==null&&item.actionId!==observed.actionId)throw Error('The Hegemon wallet could not verify the spend.');
  const latest=await getSession(session,role);if(!latest||latest.revision!==record.revision||canonical(latest.snapshot.hegemon[side][operation])!==canonical(item))throw Error('The Hegemon spend record changed.');
  const next=structuredClone(latest.snapshot);next.hegemon[side][operation].actionId=observed.actionId;next.hegemon[side][operation].blockHeight=String(observed.blockHeight);next.actions[side][operation][next.actions[side][operation].length-1]={id:attemptId,state:'submitted',txid:item.candidate};
  const saved=await updateSession(session,role,latest.revision,next);
  for(const action of await listActions())if(action.chain==='hegemon'&&action.operation==='submit'&&action.state==='uncertain'&&action.request.attempt===item.candidate)await reconcileUncertainAction(action.id,{submitted:true,confirmed:false,txid:observed.actionId,attempt:item.candidate});
  return {state:'confirmed',actionId:observed.actionId,blockHeight:String(observed.blockHeight),revision:saved.revision};
 });
}
