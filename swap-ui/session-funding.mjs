/** Fund one native-asset leg of a signed Cardano–Ethereum session. Wallet
 * approval remains explicit. A cross-tab action lock, recovery backup, action
 * journal, signed peer messages and fresh chain checks are all required. */
import {canonical} from './identity.mjs';
import {getSession,sessionFundingPrerequisites,sessionBackupCurrent} from './session-store.mjs';
import {readPeerSessionPackets} from './session-coordination.mjs';
import {sessionTermsDigest} from './session-packets.mjs';
import {participantCode} from './session-participant.mjs';
import {channelFingerprint} from './session-channel.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {cardanoWalletAction} from './cardano-wallet.mjs';
import {deploySepoliaEscrow} from './sepolia-actions.mjs';
import {listActions,beginAction,finishAction,uncertainAction,removeAction} from './action-journal.mjs';
import {actionLock,actionArmed,consumeActionArm,resolveSessionAction,requireRecoveryReviewComplete,hasHegemonConsent} from './session-action.mjs';

export async function peerFundingAgreement(record,readFrames,now){
 const {session,role,snapshot}=record,packets=await readPeerSessionPackets({session,role,readFrames,now}),digest=await sessionTermsDigest(snapshot.terms);
 if(role==='owner'){
  if(packets.length!==1||packets[0].body.payload.type!=='accept'||packets[0].body.payload.termsDigest!==digest)throw Error('The other participant has not accepted these terms.');
 }else{
  if(packets.length!==2||packets[0].body.payload.type!=='proposal'||canonical(packets[0].body.payload.terms)!==canonical(snapshot.terms)||packets[1].body.payload.type!=='escrow'||packets[1].body.payload.leg!=='long'||packets[1].body.payload.termsDigest!==digest||canonical(packets[1].body.payload.reference)!==canonical(snapshot.escrows.long))throw Error('The first escrow announcement does not match the agreed terms.');
 }
}

export async function fundSession({session,role,attemptId,outbox,readFrames,readers,config,templates,getEthereum,getCardano,confirm,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}){
 if(!['owner','taker'].includes(role)||outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'||typeof getEthereum!=='function'||typeof getCardano!=='function'||typeof confirm!=='function'||!storage||typeof locks?.request!=='function')throw Error('The session funding controls are unavailable.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap is already being funded in another tab.');
  requireRecoveryReviewComplete(session,role,storage);
  let current=await getSession(session,role);if(!current)throw Error('The saved swap session is unavailable.');
  const state=await outbox.inspect();
  current=await sessionFundingPrerequisites({session,role,revision:current.revision,outbox:state,actions:await listActions(),attemptId});
  const snapshot=current.snapshot,own=role==='owner'?'long':'short',asset=snapshot.terms.legs[own].asset;
  const attempt=snapshot.actions[own].fund.at(-1);
  if(!attempt||attempt.id!==attemptId||attempt.state!=='intent'||!actionArmed(session,role,attemptId,storage))throw Error('This funding attempt needs manual review before retrying.');
  if(!((asset.chain==='ethereum'&&asset.kind==='eth')||(asset.chain==='cardano'&&['ada','native'].includes(asset.kind))))throw Error('Guided funding for this token is not available yet.');
  const peerBlob=role==='owner'?snapshot.takerBlob:snapshot.ownerBlob,peerPin=storage.getItem(`hegemon.swap.peer-pin:${session}:${role}`);
  if(!peerPin||peerPin!==await participantCode(peerBlob))throw Error('Confirm the other participant’s verification code before funding.');
  const originalTerms=canonical(snapshot.terms),purpose=role==='owner'?'fund_first':'fund_second';let ownActionId=null,walletAsked=false;
  const gate=async()=>{
   const latest=await getSession(session,role),local=await outbox.inspect();
   const active=latest?.snapshot.actions?.[own]?.fund?.at(-1);
   if(!latest||canonical(latest.snapshot.terms)!==originalTerms||latest.snapshot.escrows[own]!==null||active?.id!==attemptId||active.state!=='intent'||!latest.backupAcknowledged||!await sessionBackupCurrent(latest)||local.pending||local.next!==latest.snapshot.transport.next||local.previous!==latest.snapshot.transport.previous||!walletAsked&&!actionArmed(session,role,attemptId,storage))throw Error('The swap or its recovery state changed. Refresh before funding.');
   if(storage.getItem(`hegemon.swap.peer-pin:${session}:${role}`)!==await participantCode(role==='owner'?latest.snapshot.takerBlob:latest.snapshot.ownerBlob))throw Error('The other participant’s verification code changed.');
   const chains=new Set([latest.snapshot.terms.legs.long.asset.chain,latest.snapshot.terms.legs.short.asset.chain]);
   for(const action of await listActions()){
    if(action.id===ownActionId||!chains.has(action.chain))continue;
    const raw=action.request?.hashlock,related=raw===undefined||typeof raw==='string'&&raw.toLowerCase().replace(/^0x/,'')===latest.snapshot.terms.hashlock;
    if(related&&(action.state==='pending'||action.state==='uncertain'||action.chain===asset.chain&&['lock','deploy'].includes(action.operation)&&action.state==='completed'&&action.receipt?.submitted===true))throw Error('A related wallet action needs review before funding.');
   }
   await peerFundingAgreement(latest,readFrames,clock());
   return verifySessionSnapshot({terms:latest.snapshot.terms,offer:latest.snapshot.offer,expectedOfferDigest:latest.snapshot.offerDigest,channelDigest:await channelFingerprint(session,latest.snapshot.channelKey),ownerBlob:latest.snapshot.ownerBlob,takerBlob:latest.snapshot.takerBlob,session,reservation:latest.snapshot.reservation,sessionExpires:latest.snapshot.sessionExpires,role:role==='owner'?'initiator':'responder',references:latest.snapshot.escrows,purpose,readers,config,now:clock(),templates,allowUnverifiedHegemon:hasHegemonConsent(session,role,storage)});
  };
  await gate();
  const fields=sessionAssetTerms(snapshot.terms,own).operationTerms;
  let txid,uncertain=false;
  try{if(asset.chain==='cardano'){
   const wallet=getCardano();if(!wallet)throw Error('Connect your Cardano testnet wallet first.');
   const check=async()=>{if(wallet!==getCardano())throw Error('The Cardano wallet changed.');await gate();};
   const guarded=new Proxy(wallet,{get(target,key){if(key==='signTx')return (...args)=>{if(target!==getCardano())throw Error('The Cardano wallet changed.');consumeActionArm(session,role,attemptId,storage);walletAsked=true;return target.signTx(...args);};const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;}});
   const journal={begin:async(...args)=>{ownActionId=await beginAction(...args);return ownActionId;},finish:finishAction,uncertain:uncertainAction,remove:removeAction};
   const result=await cardanoWalletAction({op:'fund',terms:fields,api:guarded,read:readers.cardano,verifyEscrow:async()=>{throw Error('No escrow should be read before funding.');},verifyBeforeSign:check,verifyBeforeSubmit:check,journal,confirm,budget:templates.cardanoBudget});
   if(!['submitted','uncertain'].includes(result.state)||typeof result.txid!=='string'||!/^[0-9a-f]{64}$/.test(result.txid))throw Error('Funding did not return a usable transaction ID. Check your wallet before retrying.');
   txid=result.txid;uncertain=result.state==='uncertain';
  }else{
   const provider=getEthereum();if(!provider)throw Error('Connect your Ethereum Sepolia wallet first.');
   if(!templates.ether)throw Error('The pinned Ethereum escrow template is unavailable.');
   if(!await confirm({op:'fund',lines:[`Lock ${asset.amount} wei on Ethereum Sepolia.`,`Refund deadline: ${new Date(snapshot.terms.legs[own].expiry*1000).toLocaleString()}.`]}))throw Error('Funding was declined before the wallet request.');
   const guarded={request:args=>{if(provider!==getEthereum())throw Error('The Ethereum wallet changed.');if(args.method==='eth_sendTransaction'){consumeActionArm(session,role,attemptId,storage);walletAsked=true;}return provider.request(args);}};
   const id=await beginAction('ethereum','deploy',fields);ownActionId=id;
   try{
    const result=await deploySepoliaEscrow(guarded,templates.ether,fields,{verify:gate});
    if(!result.submitted||typeof result.txid!=='string'||!/^0x[0-9a-f]{64}$/.test(result.txid))throw Error('The wallet returned no usable transaction ID.');
    txid=result.txid.slice(2);await finishAction(id,{submitted:true,confirmed:false,txid:result.txid});
   }catch(error){if(walletAsked)await uncertainAction(id);else await removeAction(id);throw error;}
  }}catch(error){
   if(walletAsked){try{await resolveSessionAction({session,role,side:own,operation:'fund',id:attemptId,state:error?.code==='declined'?'declined':'uncertain'});}catch{/* The action journal still blocks a retry. */}}
   throw error;
  }
  const reference=asset.chain==='cardano'?{chain:'cardano',txid,vout:0}:{chain:'ethereum',txid};
  try{
   const updated=await resolveSessionAction({session,role,side:own,operation:'fund',id:attemptId,state:uncertain?'uncertain':'submitted',txid,reference});
   return {reference,uncertain,revision:updated.revision};
  }catch(error){throw Error(`Funding may have been submitted (${txid}). Check the action journal and wallet before retrying. ${error.message}`);}
 });
}
