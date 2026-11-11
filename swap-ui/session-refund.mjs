/** Refund a saved escrow without consulting the relay or the other chain. */
import {canonical} from './identity.mjs';
import {getSession,sessionBackupCurrent} from './session-store.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {ethereumContract} from './session-verify.mjs';
import {assertSepoliaIdentity} from './sepolia-verifier.mjs';
import {verifyCardanoPreviewEscrow} from './cardano-preview-verifier.mjs';
import {legRequirements} from './timelock-policy.mjs';
import {cardanoWalletAction} from './cardano-wallet.mjs';
import {refundSepoliaEscrow} from './sepolia-actions.mjs';
import {listActions,beginAction,finishAction,uncertainAction,removeAction} from './action-journal.mjs';
import {actionLock,actionArmed,consumeActionArm,resolveSessionAction,requireRecoveryReviewComplete} from './session-action.mjs';

/** Check the user's own saved reference and its refund deadline. Contract
 * contents are additionally checked by the wallet action before signing. */
export async function checkSessionRefund({snapshot,role,readers,config}){
 if(!snapshot?.terms||!['owner','taker'].includes(role))throw Error('The saved swap is unavailable.');
 const side=role==='owner'?'long':'short',leg=snapshot.terms.legs[side],ref=snapshot.escrows[side];
 if(!ref||ref.chain!==leg.asset.chain)throw Error('The saved escrow reference is unavailable.');
 if(ref.chain==='cardano'){
  const fields=sessionAssetTerms(snapshot.terms,side,{reference:ref}).operationTerms,params=await readers.cardano.params();
  if(params?.network!=='preview'||params.magic!==2||params.system_start!==1666656000||!Number.isSafeInteger(params.slot)||params.slot<0)throw Error('Cardano preview is unavailable.');
  if(params.system_start+params.slot<leg.expiry)throw Error('The Cardano refund deadline has not passed.');
  await verifyCardanoPreviewEscrow({...fields,expiry_ms:Number(fields.expiry_ms)},readers.cardano.escrow,{...legRequirements(config,'cardano'),allowExpired:true});
  return {side,fields,chain:'cardano'};
 }
 if(ref.chain==='ethereum'){
  const provider=readers?.ethereum?.provider;await assertSepoliaIdentity(provider);
  const head=await provider.request({method:'eth_getBlockByNumber',params:['latest',false]});
  if(!/^0x[0-9a-f]+$/i.test(head?.timestamp||'')||BigInt(head.timestamp)<BigInt(leg.expiry))throw Error('The Ethereum refund deadline has not passed.');
  const contract=await ethereumContract(provider,ref,leg);
  return {side,fields:sessionAssetTerms(snapshot.terms,side,{reference:ref,contract}).operationTerms,chain:'ethereum'};
 }
 throw Error('Refunds for this chain are unavailable.');
}

export async function refundSession({session,role,attemptId,readers,config,templates,getEthereum,getCardano,confirm,storage=globalThis.localStorage,locks=globalThis.navigator?.locks}){
 if(!['owner','taker'].includes(role)||typeof getEthereum!=='function'||typeof getCardano!=='function'||typeof confirm!=='function'||!storage||typeof locks?.request!=='function')throw Error('The refund controls are unavailable.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');
  requireRecoveryReviewComplete(session,role,storage);
  const record=await getSession(session,role);if(!record||record.snapshot.version!==3)throw Error('The saved swap is unavailable.');
  const snapshot=record.snapshot,side=role==='owner'?'long':'short',attempt=snapshot.actions[side].refund.at(-1);
  if(!attempt||attempt.id!==attemptId||attempt.state!=='intent'||!actionArmed(session,role,attemptId,storage))throw Error('This refund needs manual review before retrying.');
  const original=canonical(snapshot.terms),reference=canonical(snapshot.escrows[side]);let ownJournal=null,walletAsked=false;
  const gate=async()=>{
   const latest=await getSession(session,role),active=latest?.snapshot.actions?.[side]?.refund?.at(-1);
   if(!latest||canonical(latest.snapshot.terms)!==original||canonical(latest.snapshot.escrows[side])!==reference||active?.id!==attemptId||active.state!=='intent'||!latest.backupAcknowledged||!await sessionBackupCurrent(latest)||!walletAsked&&!actionArmed(session,role,attemptId,storage))throw Error('The refund or recovery state changed. Refresh before continuing.');
   const chain=latest.snapshot.terms.legs[side].asset.chain,hash=latest.snapshot.terms.hashlock;
   for(const action of await listActions()){
    if(action.id===ownJournal||action.chain!==chain||action.operation!=='refund')continue;
    const raw=action.request?.hashlock,related=raw===undefined||typeof raw==='string'&&raw.toLowerCase().replace(/^0x/,'')===hash;
    if(related&&(action.state==='pending'||action.state==='uncertain'||action.state==='completed'&&action.receipt?.submitted===true))throw Error('A related refund needs review before continuing.');
   }
   return checkSessionRefund({snapshot:latest.snapshot,role,readers,config});
  };
  const checked=await gate();let txid,uncertain=false;
  try{
   if(checked.chain==='cardano'){
    const wallet=getCardano();if(!wallet)throw Error('Connect your Cardano testnet wallet first.');
    const check=async()=>{if(wallet!==getCardano())throw Error('The Cardano wallet changed.');await gate();};
    const guarded=new Proxy(wallet,{get(target,key){if(key==='signTx')return (...args)=>{if(target!==getCardano())throw Error('The Cardano wallet changed.');consumeActionArm(session,role,attemptId,storage);walletAsked=true;return target.signTx(...args);};const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;}});
    const journal={begin:async(...args)=>{ownJournal=await beginAction(...args);return ownJournal;},finish:finishAction,uncertain:uncertainAction,remove:removeAction};
    const result=await cardanoWalletAction({op:'refund',terms:checked.fields,api:guarded,read:readers.cardano,verifyEscrow:check,verifyBeforeSign:check,verifyBeforeSubmit:check,journal,confirm,budget:templates.cardanoBudget});
    if(!['submitted','uncertain'].includes(result.state)||!/^[0-9a-f]{64}$/.test(result.txid||''))throw Error('The refund did not return a usable transaction ID.');
    txid=result.txid;uncertain=result.state==='uncertain';
   }else{
    const provider=getEthereum();if(!provider)throw Error('Connect your Ethereum Sepolia wallet first.');
    const template=checked.fields.kind==='eth'?templates.ether:templates.token;if(!template)throw Error('The pinned Ethereum escrow template is unavailable.');
    if(!await confirm({op:'refund',lines:[`Refund the agreed asset from ${checked.fields.contract} to your wallet.`]}))throw Error('Refund was declined before the wallet request.');
    const guarded={request:args=>{if(provider!==getEthereum())throw Error('The Ethereum wallet changed.');if(args.method==='eth_sendTransaction'){consumeActionArm(session,role,attemptId,storage);walletAsked=true;}return provider.request(args);}};
    ownJournal=await beginAction('ethereum','refund',checked.fields);
    try{const result=await refundSepoliaEscrow(guarded,template,checked.fields,{verify:gate});
     if(!result.submitted||!/^0x[0-9a-f]{64}$/.test(result.txid||''))throw Error('The wallet returned no usable transaction ID.');
     txid=result.txid.slice(2);await finishAction(ownJournal,{submitted:true,confirmed:false,txid:result.txid});
    }catch(error){if(walletAsked)await uncertainAction(ownJournal);else await removeAction(ownJournal);throw error;}
   }
   const updated=await resolveSessionAction({session,role,side,operation:'refund',id:attemptId,state:uncertain?'uncertain':'submitted',txid});
   return {txid,uncertain,revision:updated.revision};
  }catch(error){if(walletAsked)try{await resolveSessionAction({session,role,side,operation:'refund',id:attemptId,state:error?.code==='declined'?'declined':'uncertain'});}catch{/* The action journal still blocks a retry. */}throw error;}
 });
}
