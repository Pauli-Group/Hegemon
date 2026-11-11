/** Explicit, journaled claim of an authenticated testnet swap. */
import {canonical} from './identity.mjs';
import {getSession,sessionBackupCurrent} from './session-store.mjs';
import {readPeerSessionPackets} from './session-coordination.mjs';
import {sessionTermsDigest} from './session-packets.mjs';
import {participantCode} from './session-participant.mjs';
import {channelFingerprint} from './session-channel.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';
import {observeSessionLeg} from './session-observation.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {unlockRecovery} from './recovery.mjs';
import {toHex} from './cbor.mjs';
import {actionSeconds,legRequirements} from './timelock-policy.mjs';
import {cardanoWalletAction} from './cardano-wallet.mjs';
import {claimSepoliaEscrow} from './sepolia-actions.mjs';
import {listActions,beginAction,finishAction,uncertainAction,removeAction} from './action-journal.mjs';
import {actionLock,actionArmed,consumeActionArm,resolveSessionAction,requireRecoveryReviewComplete} from './session-action.mjs';

export async function claimSession({session,role,attemptId,outbox,readFrames,readers,config,templates,getEthereum,getCardano,confirm,passphrase,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}){
 if(!['owner','taker'].includes(role)||outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'||typeof getEthereum!=='function'||typeof getCardano!=='function'||typeof confirm!=='function'||!storage||typeof locks?.request!=='function')throw Error('The claim controls are unavailable.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');
  requireRecoveryReviewComplete(session,role,storage);
  const record=await getSession(session,role);if(!record||record.snapshot.version!==3)throw Error('The saved swap is unavailable.');
  const snapshot=record.snapshot,side=role==='owner'?'short':'long',leg=snapshot.terms.legs[side],attempt=snapshot.actions[side].claim.at(-1);
  if(!attempt||attempt.id!==attemptId||attempt.state!=='intent'||!actionArmed(session,role,attemptId,storage))throw Error('This claim needs manual review before retrying.');
  const savedTerms=canonical(snapshot.terms),digest=await sessionTermsDigest(snapshot.terms);let ownJournal=null,walletAsked=false,secret;
  const gate=async()=>{
   const latest=await getSession(session,role),local=await outbox.inspect(),active=latest?.snapshot.actions?.[side]?.claim?.at(-1);
   if(!latest||canonical(latest.snapshot.terms)!==savedTerms||canonical(latest.snapshot.escrows)!==canonical(snapshot.escrows)||active?.id!==attemptId||active.state!=='intent'||!latest.backupAcknowledged||!await sessionBackupCurrent(latest)||local.pending||local.next!==latest.snapshot.transport.next||local.previous!==latest.snapshot.transport.previous||!walletAsked&&!actionArmed(session,role,attemptId,storage))throw Error('The swap or its recovery state changed. Refresh before claiming.');
   if(storage.getItem(`hegemon.swap.peer-pin:${session}:${role}`)!==await participantCode(role==='owner'?latest.snapshot.takerBlob:latest.snapshot.ownerBlob))throw Error('The other participant’s verification code changed.');
   const chains=new Set([snapshot.terms.legs.long.asset.chain,snapshot.terms.legs.short.asset.chain]);
   for(const action of await listActions()){
    if(action.id===ownJournal||!chains.has(action.chain))continue;
    const raw=action.request?.hashlock,related=raw===undefined||typeof raw==='string'&&raw.toLowerCase().replace(/^0x/,'')===snapshot.terms.hashlock;
    if(related&&(action.state==='pending'||action.state==='uncertain'||action.chain===leg.asset.chain&&action.operation==='claim'&&action.state==='completed'&&action.receipt?.submitted===true))throw Error('A related wallet action needs review before claiming.');
   }
   const peers=await readPeerSessionPackets({session,role,readFrames,now:clock()}),first=peers[0]?.body.payload,last=peers[1]?.body.payload;
   if(peers.length!==2||role==='owner'&&(first?.type!=='accept'||first.termsDigest!==digest)||role==='taker'&&(first?.type!=='proposal'||canonical(first.terms)!==savedTerms)||last?.type!=='escrow'||last.leg!==(role==='owner'?'short':'long')||last.termsDigest!==digest||canonical(last.reference)!==canonical(snapshot.escrows[last.leg]))throw Error('The signed escrow history does not match the saved swap.');
   const result=await verifySessionSnapshot({terms:latest.snapshot.terms,offer:latest.snapshot.offer,expectedOfferDigest:latest.snapshot.offerDigest,channelDigest:await channelFingerprint(session,latest.snapshot.channelKey),ownerBlob:latest.snapshot.ownerBlob,takerBlob:latest.snapshot.takerBlob,session,reservation:latest.snapshot.reservation,sessionExpires:latest.snapshot.sessionExpires,role:role==='owner'?'initiator':'responder',references:latest.snapshot.escrows,purpose:role==='owner'?'claim_short':'claim_long',readers,config,now:clock(),templates});
   if(role==='taker'){
    const seen=await observeSessionLeg({snapshot:latest.snapshot,side:'short',readers,config});
    if(seen.state!=='claimed'||!seen.enough||!secret||seen.preimage!==toHex(secret))throw Error('The other person’s confirmed claim and secret are not yet verified.');
   }
   return result;
  };
  try{
   secret=await unlockRecovery(snapshot.secretEnvelope,passphrase);if(snapshot.terms.hashlock!==toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',secret))))throw Error('The saved secret does not match these terms.');
   const verified=await gate();let txid,uncertain=false;
   if(leg.asset.chain==='cardano'){
    const wallet=getCardano();if(!wallet)throw Error('Connect your Cardano testnet wallet first.');
    const check=async()=>{if(wallet!==getCardano())throw Error('The Cardano wallet changed.');await gate();};
    const guarded=new Proxy(wallet,{get(target,key){if(key==='signTx')return (...args)=>{if(target!==getCardano())throw Error('The Cardano wallet changed.');consumeActionArm(session,role,attemptId,storage);walletAsked=true;return target.signTx(...args);};const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;}});
    const journal={begin:async(...args)=>{ownJournal=await beginAction(...args);return ownJournal;},finish:finishAction,uncertain:uncertainAction,remove:removeAction};
    const fields=sessionAssetTerms(snapshot.terms,side,{reference:snapshot.escrows[side]}).operationTerms;
    const result=await cardanoWalletAction({op:'claim',terms:fields,preimage:toHex(secret),api:guarded,read:readers.cardano,verifyEscrow:check,verifyBeforeSign:check,verifyBeforeSubmit:check,journal,confirm,budget:templates.cardanoBudget,cutoffSeconds:leg.expiry-actionSeconds(config.chains.cardano)});
    if(!['submitted','uncertain'].includes(result.state)||!/^[0-9a-f]{64}$/.test(result.txid||''))throw Error('Claim did not return a usable transaction ID.');
    txid=result.txid;uncertain=result.state==='uncertain';
   }else if(leg.asset.chain==='ethereum'){
    const provider=getEthereum();if(!provider)throw Error('Connect your Ethereum Sepolia wallet first.');
    const contract=verified.escrows[side].contract,fields=sessionAssetTerms(snapshot.terms,side,{reference:snapshot.escrows[side],contract}).operationTerms,template=fields.kind==='eth'?templates.ether:templates.token;
    if(!template)throw Error('The pinned Ethereum escrow template is unavailable.');
    if(!await confirm({op:'claim',lines:[`Claim the agreed asset from ${contract}.`,`This transaction reveals the swap secret on chain.`]}))throw Error('Claim was declined before the wallet request.');
    const guarded={request:args=>{if(provider!==getEthereum())throw Error('The Ethereum wallet changed.');if(args.method==='eth_sendTransaction'){consumeActionArm(session,role,attemptId,storage);walletAsked=true;}return provider.request(args);}};
    ownJournal=await beginAction('ethereum','claim',fields);
    try{const result=await claimSepoliaEscrow(guarded,template,fields,secret,{cutoffSeconds:actionSeconds(config.chains.ethereum),confirmations:legRequirements(config,'ethereum').confirmations,verify:gate});
     if(!result.submitted||!/^0x[0-9a-f]{64}$/.test(result.txid||''))throw Error('The wallet returned no usable transaction ID.');
     txid=result.txid.slice(2);await finishAction(ownJournal,{submitted:true,confirmed:false,txid:result.txid});
    }catch(error){if(walletAsked)await uncertainAction(ownJournal);else await removeAction(ownJournal);throw error;}
   }else throw Error('This chain is not supported for claims.');
   const updated=await resolveSessionAction({session,role,side,operation:'claim',id:attemptId,state:uncertain?'uncertain':'submitted',txid});
   return {txid,uncertain,revision:updated.revision};
  }catch(error){
   // The claim secret reaches the wallet even when it says it declined. The
   // other participant may be able to use it; never silently retry that claim.
   if(walletAsked)try{await resolveSessionAction({session,role,side,operation:'claim',id:attemptId,state:'uncertain'});}catch{/* The journal still blocks a retry. */}
   throw error;
  }finally{secret?.fill(0);}
 });
}
