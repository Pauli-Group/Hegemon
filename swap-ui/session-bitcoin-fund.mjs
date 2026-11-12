/** Prepare, recover and explicitly broadcast a Bitcoin testnet4 funding PSBT.
 * The user's external wallet signs; no key or signature is stored here. */
import {canonical} from './identity.mjs';
import {getSession,sessionBackupCurrent,sessionFundingPrerequisites} from './session-store.mjs';
import {participantCode} from './session-participant.mjs';
import {channelFingerprint} from './session-channel.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';
import {peerFundingAgreement} from './session-funding.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {prepareBitcoinPsbt,finishBitcoinPsbt} from './bitcoin-wallet.mjs';
import {saveBitcoinDraft,loadBitcoinDraft} from './session-bitcoin-draft.mjs';
import {listActions,beginAction,finishAction,uncertainAction,removeAction} from './action-journal.mjs';
import {actionLock,actionArmed,consumeActionArm,resolveSessionAction,requireRecoveryReviewComplete,hasHegemonConsent} from './session-action.mjs';

const broadcastKey=(session,role,id)=>`hegemon.swap.bitcoin-broadcast:${session}:${role}:${id}`;
function controls({session,role,attemptId,outbox,readFrames,readers,storage,locks}){
 if(!/^[0-9a-f]{64}$/.test(session||'')||!['owner','taker'].includes(role)||!/^[0-9a-f]{32}$/.test(attemptId||'')||outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'||typeof readers?.bitcoin?.utxos!=='function'||typeof readers.bitcoin.broadcast!=='function'||!storage||typeof locks?.request!=='function')throw Error('The Bitcoin funding controls are unavailable.');
}
async function gate({record,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId=null,state}){
 const {session,role,snapshot}=record,side=role==='owner'?'long':'short',attempt=snapshot.actions?.[side]?.fund?.at(-1),local=await outbox.inspect();
 requireRecoveryReviewComplete(session,role,storage);
 if(snapshot.terms?.legs[side].asset.chain!=='bitcoin'||snapshot.terms.legs[side].asset.kind!=='btc'||snapshot.escrows[side]!==null||attempt?.id!==attemptId||attempt.state!==state||!record.backupAcknowledged||!await sessionBackupCurrent(record)||local.pending||local.next!==snapshot.transport.next||local.previous!==snapshot.transport.previous)throw Error('The swap or its recovery state changed. Refresh before funding.');
 if(storage.getItem(`hegemon.swap.peer-pin:${session}:${role}`)!==await participantCode(role==='owner'?snapshot.takerBlob:snapshot.ownerBlob))throw Error('Confirm the other participant’s verification code before funding.');
 for(const action of await listActions()){
  if(action.id===journalId)continue;
  if(![snapshot.terms.legs.long.asset.chain,snapshot.terms.legs.short.asset.chain].includes(action.chain))continue;
  const raw=action.request?.hashlock,related=raw===undefined||typeof raw==='string'&&raw.toLowerCase().replace(/^0x/,'')===snapshot.terms.hashlock;
  if(related&&(action.state==='pending'||action.state==='uncertain'||action.chain==='bitcoin'&&action.operation==='lock'&&action.state==='completed'&&action.receipt?.submitted===true))throw Error('A related wallet action needs review before funding.');
 }
 await peerFundingAgreement(record,readFrames,clock());
 return verifySessionSnapshot({terms:snapshot.terms,offer:snapshot.offer,expectedOfferDigest:snapshot.offerDigest,channelDigest:await channelFingerprint(session,snapshot.channelKey),ownerBlob:snapshot.ownerBlob,takerBlob:snapshot.takerBlob,session,reservation:snapshot.reservation,sessionExpires:snapshot.sessionExpires,role:role==='owner'?'initiator':'responder',references:snapshot.escrows,purpose:role==='owner'?'fund_first':'fund_second',readers,config,now:clock(),templates,allowUnverifiedHegemon:hasHegemonConsent(session,role,storage)});
}
function journalTracking(set){return {begin:async(...args)=>{const id=await beginAction(...args);set(id);return id;},finish:finishAction,uncertain:uncertainAction,remove:removeAction};}

/** Build and persist an unsigned PSBT. The returned value contains only the
 * transaction ID; do not hand the PSBT to a signer before backing up the new
 * prepared state. */
export async function prepareBitcoinSessionFund(options){
 const {session,role,attemptId,outbox,readFrames,readers,config,templates,address,feeRate,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}=options;
 controls({session,role,attemptId,outbox,readFrames,readers,storage,locks});
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');requireRecoveryReviewComplete(session,role,storage);
  let record=await getSession(session,role);if(!record)throw Error('The saved swap is unavailable.');
  record=await sessionFundingPrerequisites({session,role,revision:record.revision,outbox:await outbox.inspect(),actions:await listActions(),attemptId});
  const side=role==='owner'?'long':'short';if(!actionArmed(session,role,attemptId,storage))throw Error('This funding action needs manual review.');
  const original=canonical(record.snapshot.terms),agreed=sessionAssetTerms(record.snapshot.terms,side).operationTerms;let journalId=null,saved=false;
  const check=async()=>{const latest=await getSession(session,role);if(!latest||canonical(latest.snapshot.terms)!==original||!actionArmed(session,role,attemptId,storage))throw Error('The funding attempt changed.');await gate({record:latest,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId,state:'intent'});};
  await check();
  try{
   const draft=await prepareBitcoinPsbt({op:'fund',terms:agreed,address,feeRate,read:readers.bitcoin,verifyEscrow:async()=>{throw Error('Unexpected Bitcoin escrow read.');},journal:journalTracking(id=>{journalId=id;})});
   await check();await saveBitcoinDraft({session,role,side,operation:'fund',attemptId,draft,agreed});saved=true;
   consumeActionArm(session,role,attemptId,storage);
   const updated=await resolveSessionAction({session,role,side,operation:'fund',id:attemptId,state:'prepared',txid:draft.txid});
   storage.setItem(broadcastKey(session,role,attemptId),'ready');
   return {txid:draft.txid,revision:updated.revision};
  }catch(error){if(journalId&&!saved)await removeAction(journalId);throw error;}
 });
}

/** Read the exact checked draft only after the prepared state is backed up. */
export async function bitcoinSessionFundDraft(options){
 const {session,role,attemptId,outbox,readFrames,readers,config,templates,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}=options;
 controls({session,role,attemptId,outbox,readFrames,readers,storage,locks});
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');const record=await getSession(session,role);if(!record)throw Error('The saved swap is unavailable.');
  const side=role==='owner'?'long':'short',agreed=sessionAssetTerms(record.snapshot.terms,side).operationTerms,saved=await loadBitcoinDraft({session,role,operation:'fund',agreed});
  if(!saved||saved.attemptId!==attemptId||saved.side!==side||storage.getItem(broadcastKey(session,role,attemptId))!=='ready')throw Error('The Bitcoin draft needs manual review before continuing.');
  await gate({record,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId:saved.draft.journalId,state:'prepared'});
  return {psbt:saved.draft.psbt,txid:saved.draft.txid,fee:String(saved.draft.fee),lines:saved.draft.lines};
 });
}

/** The caller explicitly asks to broadcast a signed PSBT. The signed bytes are
 * checked against the saved unsigned transaction and are not persisted. */
export async function broadcastBitcoinSessionFund(options){
 const {session,role,attemptId,outbox,readFrames,readers,config,templates,signedPsbt,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}=options;
 controls({session,role,attemptId,outbox,readFrames,readers,storage,locks});
 if(typeof signedPsbt!=='string'||signedPsbt.length>200000)throw Error('Enter a signed Bitcoin PSBT.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');const record=await getSession(session,role);if(!record)throw Error('The saved swap is unavailable.');
  const side=role==='owner'?'long':'short',original=canonical(record.snapshot.terms),agreed=sessionAssetTerms(record.snapshot.terms,side).operationTerms,saved=await loadBitcoinDraft({session,role,operation:'fund',agreed}),key=broadcastKey(session,role,attemptId);
  if(!saved||saved.attemptId!==attemptId||saved.side!==side||storage.getItem(key)!=='ready')throw Error('The Bitcoin draft needs manual review before retrying.');
  let asked=false;
  const check=async()=>{const latest=await getSession(session,role);if(!latest||canonical(latest.snapshot.terms)!==original||!asked&&storage.getItem(key)!=='ready')throw Error('The Bitcoin funding state changed.');await gate({record:latest,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId:saved.draft.journalId,state:'prepared'});};
  await check();
  const read={...readers.bitcoin,broadcast:async tx=>{if(storage.getItem(key)!=='ready')throw Error('The Bitcoin broadcast needs manual review.');storage.removeItem(key);asked=true;return readers.bitcoin.broadcast(tx);}};
  try{
   const result=await finishBitcoinPsbt({session:saved.draft,signedPsbt,read,verifyEscrow:async()=>{throw Error('Unexpected Bitcoin escrow read.');},journal:{finish:finishAction,uncertain:uncertainAction,remove:removeAction},verifyBeforeBroadcast:check});
   if(result.state!=='submitted'||result.txid!==saved.draft.txid)throw Error('The Bitcoin broadcast did not return the prepared transaction.');
   const reference={chain:'bitcoin',txid:result.txid,vout:0},updated=await resolveSessionAction({session,role,side,operation:'fund',id:attemptId,state:'submitted',txid:result.txid,reference});
   return {reference,revision:updated.revision};
  }catch(error){if(asked)try{await resolveSessionAction({session,role,side,operation:'fund',id:attemptId,state:'uncertain',txid:saved.draft.txid});}catch{/* The action journal still blocks a retry. */}throw error;}
 });
}
