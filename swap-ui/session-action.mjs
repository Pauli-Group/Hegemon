/** A wallet attempt is saved in the encrypted recovery state before any wallet
 * request. A one-use, browser-local arm is consumed immediately before opening
 * the wallet; restored backups cannot silently replay an uncertain attempt. */
import {getSession,updateSession,sessionFundingPrerequisites,sessionBackupCurrent} from './session-store.mjs';
import {listActions} from './action-journal.mjs';
import {toHex} from './cbor.mjs';
const ARM='hegemon.swap.action-arm:';
export const recoveryReviewKey=(session,role)=>`hegemon.swap.recovery-review:${session}:${role}`;
export const hegemonConsentKey=(session,role)=>`hegemon.swap.hegemon-consent:${session}:${role}`;
export const hasHegemonConsent=(session,role,storage=globalThis.localStorage)=>storage?.getItem(hegemonConsentKey(session,role))==='accepted';
export function requireRecoveryReviewComplete(session,role,storage=globalThis.localStorage){if(storage?.getItem(recoveryReviewKey(session,role))==='required')throw Error('Review your wallet activity after restoring this backup before continuing.');}
export const actionLock=(session,role)=>`hegemon.swap.action:${session}:${role}`;
const armKey=(session,role,id)=>`${ARM}${session}:${role}:${id}`;
export function actionArmed(session,role,id,storage=globalThis.localStorage){return storage?.getItem(armKey(session,role,id))==='ready';}
/** Call only while holding actionLock, immediately before requesting a wallet. */
export function consumeActionArm(session,role,id,storage=globalThis.localStorage){
 const key=armKey(session,role,id);if(storage?.getItem(key)!=='ready')throw Error('This wallet action needs manual review before retrying.');
 storage.removeItem(key);if(storage.getItem(key)!==null)throw Error('Could not secure the wallet action.');
}
/** Prepare one native funding attempt. No wallet is opened and no transaction
 * is sent. The caller must have checked peer agreement and live chain policy. */
export async function prepareFundingAttempt({session,role,outbox,storage=globalThis.localStorage,locks=globalThis.navigator?.locks}){
 if(!['owner','taker'].includes(role)||outbox?.session!==session||outbox?.role!==role||!storage||typeof locks?.request!=='function')throw Error('The wallet action controls are unavailable.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');
  requireRecoveryReviewComplete(session,role,storage);
  const record=await getSession(session,role);if(!record)throw Error('The saved swap session is unavailable.');
  await sessionFundingPrerequisites({session,role,revision:record.revision,outbox:await outbox.inspect(),actions:await listActions()});
  const side=role==='owner'?'long':'short',attempt={id:toHex(crypto.getRandomValues(new Uint8Array(16))),state:'intent',txid:null};
  const next=structuredClone(record.snapshot);next.actions[side].fund.push(attempt);
  const saved=await updateSession(session,role,record.revision,next);
  storage.setItem(armKey(session,role,attempt.id),'ready');
  if(!actionArmed(session,role,attempt.id,storage))throw Error('The wallet action could not be armed. Check recovery before retrying.');
  return {id:attempt.id,revision:saved.revision};
 });
}
/** Prepare a claim or refund after the caller checked the live chains. */
export async function prepareSpendAttempt({session,role,operation,outbox,storage=globalThis.localStorage,locks=globalThis.navigator?.locks}){
 if(!['owner','taker'].includes(role)||!['claim','refund'].includes(operation)||outbox?.session!==session||outbox?.role!==role||!storage||typeof locks?.request!=='function')throw Error('The wallet action controls are unavailable.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');
  requireRecoveryReviewComplete(session,role,storage);
  const record=await getSession(session,role);if(!record||![3,4].includes(record.snapshot.version)||!record.backupAcknowledged||!await sessionBackupCurrent(record))throw Error('Save the current recovery backup before continuing.');
  const state=await outbox.inspect(),snapshot=record.snapshot;
  if(operation!=='refund'&&(state.pending||state.next!==snapshot.transport.next||state.previous!==snapshot.transport.previous))throw Error('Synchronize and back up the signed message history first.');
  const own=role==='owner'?'long':'short',side=operation==='refund'?own:own==='long'?'short':'long';
  if(!snapshot.terms||!snapshot.escrows[side]||operation==='claim'&&(!snapshot.escrows[own]||!snapshot.secretEnvelope))throw Error('The saved escrow and secret recovery data are incomplete.');
  for(const leg of ['long','short'])for(const kind of ['fund','claim','refund'])for(const attempt of snapshot.actions[leg][kind]){
   if((operation!=='refund'||leg===side&&kind==='refund')&&['intent','prepared','uncertain'].includes(attempt.state))throw Error('A wallet action needs review before continuing.');
   if(leg===side&&kind===operation&&attempt.state==='submitted')throw Error('This wallet action was already submitted. Check its outcome.');
  }
  const chains=new Set([snapshot.terms.legs.long.asset.chain,snapshot.terms.legs.short.asset.chain]),hash=snapshot.terms.hashlock;
  for(const action of await listActions()){
   if(!chains.has(action.chain))continue;const raw=action.request?.hashlock,related=raw===undefined||typeof raw==='string'&&raw.toLowerCase().replace(/^0x/,'')===hash;
   if(related&&(operation!=='refund'||action.chain===snapshot.terms.legs[side].asset.chain&&action.operation==='refund')&&(action.state==='pending'||action.state==='uncertain'||action.chain===snapshot.terms.legs[side].asset.chain&&action.operation===operation&&action.state==='completed'&&action.receipt?.submitted===true))throw Error('A related wallet action needs review before continuing.');
  }
  const attempt={id:toHex(crypto.getRandomValues(new Uint8Array(16))),state:'intent',txid:null},next=structuredClone(snapshot);next.actions[side][operation].push(attempt);
  const saved=await updateSession(session,role,record.revision,next);storage.setItem(armKey(session,role,attempt.id),'ready');
  if(!actionArmed(session,role,attempt.id,storage))throw Error('The wallet action could not be armed. Check recovery before retrying.');
  return {id:attempt.id,side,revision:saved.revision};
 });
}
/** Resolve the current intent only; an uncertain or submitted attempt cannot
 * be rewritten to a decline or silently removed. */
export async function resolveSessionAction({session,role,side,operation,id,state,txid=null,reference=null}){
 if(!['owner','taker'].includes(role)||!['long','short'].includes(side)||!['fund','claim','refund'].includes(operation)||!['prepared','submitted','declined','uncertain'].includes(state))throw Error('Invalid wallet action resolution.');
 const record=await getSession(session,role);if(!record||![3,4].includes(record.snapshot.version))throw Error('The saved wallet action is unavailable.');
 const next=structuredClone(record.snapshot),attempts=next.actions[side][operation],last=attempts.at(-1);
 if(!last||last.id!==id||!(last.state==='intent'||last.state==='prepared'&&['submitted','uncertain'].includes(state)&&last.txid===txid))throw Error('The wallet action is no longer pending.');
 attempts[attempts.length-1]={id,state,txid};
 if(reference){if(operation!=='fund'||next.escrows[side]!==null)throw Error('The escrow reference cannot be replaced.');next.escrows[side]=reference;}
 return updateSession(session,role,record.revision,next);
}
