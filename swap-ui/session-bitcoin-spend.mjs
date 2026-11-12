/** Recoverable Bitcoin claim/refund PSBT handoff for a signed swap session. */
import {canonical} from './identity.mjs';
import {getSession,sessionBackupCurrent} from './session-store.mjs';
import {participantCode} from './session-participant.mjs';
import {readPeerSessionPackets} from './session-coordination.mjs';
import {sessionTermsDigest} from './session-packets.mjs';
import {channelFingerprint} from './session-channel.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';
import {observeSessionLeg} from './session-observation.mjs';
import {checkSessionRefund} from './session-refund.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {unlockRecovery} from './recovery.mjs';
import {toHex} from './cbor.mjs';
import {prepareBitcoinPsbt,finishBitcoinPsbt} from './bitcoin-wallet.mjs';
import {saveBitcoinDraft,loadBitcoinDraft} from './session-bitcoin-draft.mjs';
import {listActions,beginAction,finishAction,uncertainAction,removeAction} from './action-journal.mjs';
import {actionLock,actionArmed,consumeActionArm,resolveSessionAction,requireRecoveryReviewComplete,hasHegemonConsent} from './session-action.mjs';

const broadcastKey=(session,role,id)=>`hegemon.swap.bitcoin-broadcast:${session}:${role}:${id}`;
function controls({session,role,operation,attemptId,readers,storage,locks,outbox,readFrames}){
 if(!/^[0-9a-f]{64}$/.test(session||'')||!['owner','taker'].includes(role)||!['claim','refund'].includes(operation)||!/^[0-9a-f]{32}$/.test(attemptId||'')||typeof readers?.bitcoin?.utxos!=='function'||typeof readers.bitcoin.broadcast!=='function'||!storage||typeof locks?.request!=='function'||operation==='claim'&&(outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'))throw Error('The Bitcoin spend controls are unavailable.');
}
const sideFor=(role,operation)=>operation==='refund'?(role==='owner'?'long':'short'):(role==='owner'?'short':'long');
async function gate({record,operation,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId=null,state,secret=null}){
 const {session,role,snapshot}=record,side=sideFor(role,operation),attempt=snapshot.actions?.[side]?.[operation]?.at(-1);
 requireRecoveryReviewComplete(session,role,storage);
 if(snapshot.terms?.legs[side].asset.chain!=='bitcoin'||snapshot.terms.legs[side].asset.kind!=='btc'||!snapshot.escrows[side]||attempt?.id!==attemptId||attempt.state!==state||!record.backupAcknowledged||!await sessionBackupCurrent(record))throw Error('The swap or its recovery state changed. Refresh before continuing.');
 const hash=snapshot.terms.hashlock,chains=new Set([snapshot.terms.legs.long.asset.chain,snapshot.terms.legs.short.asset.chain]);
 for(const action of await listActions()){
  if(action.id===journalId||!chains.has(action.chain))continue;
  const raw=action.request?.hashlock,related=raw===undefined||typeof raw==='string'&&raw.toLowerCase().replace(/^0x/,'')===hash;
  if(related&&(operation!=='refund'||action.chain==='bitcoin'&&action.operation==='refund')&&(action.state==='pending'||action.state==='uncertain'||action.chain==='bitcoin'&&action.operation===operation&&action.state==='completed'&&action.receipt?.submitted===true))throw Error('A related wallet action needs review before continuing.');
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
  if(!['claimed','secret-revealed'].includes(seen.state)||!seen.enough||secret&&seen.preimage!==toHex(secret))throw Error('The other person’s confirmed secret is not yet verified.');
 }
 return checked.escrows[side];
}
function journalTracking(set){return {begin:async(...args)=>{const id=await beginAction(...args);set(id);return id;},finish:finishAction,uncertain:uncertainAction,remove:removeAction};}

/** Prepare and save the unsigned spend without returning it before backup. */
export async function prepareBitcoinSessionSpend(options){
 const {session,role,operation,attemptId,outbox,readFrames,readers,config,templates,address,feeRate,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}=options;
 controls({session,role,operation,attemptId,outbox,readFrames,readers,storage,locks});
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');const record=await getSession(session,role);if(!record)throw Error('The saved swap is unavailable.');
  const side=sideFor(role,operation),original=canonical(record.snapshot.terms),reference=canonical(record.snapshot.escrows[side]),agreed=sessionAssetTerms(record.snapshot.terms,side,{reference:record.snapshot.escrows[side]}).operationTerms;let journalId=null,saved=false;
  const check=async()=>{const latest=await getSession(session,role);if(!latest||canonical(latest.snapshot.terms)!==original||canonical(latest.snapshot.escrows[side])!==reference||!actionArmed(session,role,attemptId,storage))throw Error('The Bitcoin spend state changed.');return gate({record:latest,operation,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId,state:'intent'});};
  await check();
  try{const draft=await prepareBitcoinPsbt({op:operation,terms:agreed,address,feeRate,read:readers.bitcoin,verifyEscrow:check,journal:journalTracking(id=>{journalId=id;})});
   await check();await saveBitcoinDraft({session,role,side,operation,attemptId,draft,agreed});saved=true;consumeActionArm(session,role,attemptId,storage);
   const updated=await resolveSessionAction({session,role,side,operation,id:attemptId,state:'prepared',txid:draft.txid});storage.setItem(broadcastKey(session,role,attemptId),'ready');
   return {txid:draft.txid,revision:updated.revision};
  }catch(error){if(journalId&&!saved)await removeAction(journalId);throw error;}
 });
}

export async function bitcoinSessionSpendDraft(options){
 const {session,role,operation,attemptId,outbox,readFrames,readers,config,templates,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}=options;
 controls({session,role,operation,attemptId,outbox,readFrames,readers,storage,locks});
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');const record=await getSession(session,role);if(!record)throw Error('The saved swap is unavailable.');
  const side=sideFor(role,operation),agreed=sessionAssetTerms(record.snapshot.terms,side,{reference:record.snapshot.escrows[side]}).operationTerms,saved=await loadBitcoinDraft({session,role,operation,agreed});
  if(!saved||saved.attemptId!==attemptId||saved.side!==side||storage.getItem(broadcastKey(session,role,attemptId))!=='ready')throw Error('The Bitcoin draft needs manual review before continuing.');
  await gate({record,operation,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId:saved.draft.journalId,state:'prepared'});
  return {psbt:saved.draft.psbt,txid:saved.draft.txid,fee:String(saved.draft.fee),lines:saved.draft.lines};
 });
}

/** Check the signed PSBT and revalidate before broadcasting the public spend. */
export async function broadcastBitcoinSessionSpend(options){
 const {session,role,operation,attemptId,outbox,readFrames,readers,config,templates,signedPsbt,passphrase,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}=options;
 controls({session,role,operation,attemptId,outbox,readFrames,readers,storage,locks});
 if(typeof signedPsbt!=='string'||signedPsbt.length>200000)throw Error('Enter a signed Bitcoin PSBT.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');const record=await getSession(session,role);if(!record)throw Error('The saved swap is unavailable.');
  const side=sideFor(role,operation),original=canonical(record.snapshot.terms),reference=canonical(record.snapshot.escrows[side]),agreed=sessionAssetTerms(record.snapshot.terms,side,{reference:record.snapshot.escrows[side]}).operationTerms,saved=await loadBitcoinDraft({session,role,operation,agreed}),key=broadcastKey(session,role,attemptId);
  if(!saved||saved.attemptId!==attemptId||saved.side!==side||storage.getItem(key)!=='ready')throw Error('The Bitcoin draft needs manual review before retrying.');
  let asked=false,secret;
  const check=async()=>{const latest=await getSession(session,role);if(!latest||canonical(latest.snapshot.terms)!==original||canonical(latest.snapshot.escrows[side])!==reference||!asked&&storage.getItem(key)!=='ready')throw Error('The Bitcoin spend state changed.');return gate({record:latest,operation,attemptId,outbox,readFrames,readers,config,templates,storage,clock,journalId:saved.draft.journalId,state:'prepared',secret});};
  try{
   if(operation==='claim')secret=await unlockRecovery(record.snapshot.secretEnvelope,passphrase);
   await check();const read={...readers.bitcoin,broadcast:async tx=>{if(storage.getItem(key)!=='ready')throw Error('The Bitcoin broadcast needs manual review.');storage.removeItem(key);asked=true;return readers.bitcoin.broadcast(tx);}};
   const result=await finishBitcoinPsbt({session:saved.draft,signedPsbt,...(secret?{preimage:toHex(secret)}:{}),read,verifyEscrow:check,journal:{finish:finishAction,uncertain:uncertainAction,remove:removeAction},verifyBeforeBroadcast:check});
   if(result.state!=='submitted'||result.txid!==saved.draft.txid)throw Error('The Bitcoin broadcast did not return the prepared transaction.');
   const updated=await resolveSessionAction({session,role,side,operation,id:attemptId,state:'submitted',txid:result.txid});return {txid:result.txid,revision:updated.revision};
  }catch(error){if(asked)try{await resolveSessionAction({session,role,side,operation,id:attemptId,state:'uncertain',txid:saved.draft.txid});}catch{/* The action journal still blocks a retry. */}throw error;}
  finally{secret?.fill(0);}
 });
}
