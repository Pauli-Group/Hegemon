/** Recover a lost native funding reference from independently verified chain
 * data. This never signs, broadcasts, replaces terms, or consults the relay. */
import {canonical} from './identity.mjs';
import {getSession,updateSession,sessionBackupCurrent} from './session-store.mjs';
import {actionLock,actionArmed,requireRecoveryReviewComplete} from './session-action.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {ethereumContract} from './session-verify.mjs';
import {verifySepoliaEscrow} from './sepolia-verifier.mjs';
import {verifyCardanoPreviewEscrow} from './cardano-preview-verifier.mjs';
import {verifyBitcoinTestnetEscrow} from './bitcoin-testnet-verifier.mjs';
import {legRequirements} from './timelock-policy.mjs';

const HEX=/^[0-9a-f]{64}$/;
export async function recoverFundingReference({session,role,attemptId,txid,readers,config,templates,storage=globalThis.localStorage,locks=globalThis.navigator?.locks}){
 if(!HEX.test(session||'')||!['owner','taker'].includes(role)||!/^[0-9a-f]{32}$/.test(attemptId||'')||typeof txid!=='string'||!storage||typeof locks?.request!=='function')throw Error('The funding recovery controls are unavailable.');
 txid=txid.trim().toLowerCase().replace(/^0x/,'');if(!HEX.test(txid))throw Error('Enter a 64-character transaction ID from your wallet.');
 return locks.request(actionLock(session,role),{mode:'exclusive',ifAvailable:true},async lock=>{
  if(!lock)throw Error('This swap has a wallet action in another tab.');requireRecoveryReviewComplete(session,role,storage);
  const record=await getSession(session,role),side=role==='owner'?'long':'short',snapshot=record?.snapshot,attempt=snapshot?.actions?.[side]?.fund?.at(-1),leg=snapshot?.terms?.legs?.[side];
  if(!record||![3,4].includes(snapshot.version)||!record.backupAcknowledged||!await sessionBackupCurrent(record)||snapshot.escrows[side]!==null||attempt?.id!==attemptId||!['intent','prepared','uncertain'].includes(attempt.state)||attempt.state==='intent'&&actionArmed(session,role,attemptId,storage)||attempt.txid!==null&&attempt.txid!==txid)throw Error('This funding action is not eligible for recovery.');
  if(!leg||!['bitcoin','cardano','ethereum'].includes(leg.asset.chain)||leg.asset.chain==='ethereum'&&leg.asset.kind!=='eth'||leg.asset.chain==='cardano'&&leg.asset.kind!=='ada'||leg.asset.chain==='bitcoin'&&leg.asset.kind!=='btc')throw Error('Recovery for this asset is not available here.');
  const reference=leg.asset.chain==='ethereum'?{chain:'ethereum',txid}:{chain:leg.asset.chain,txid,vout:0},fields=sessionAssetTerms(snapshot.terms,side,{reference}).operationTerms,limits={...legRequirements(config,leg.asset.chain),allowExpired:true};
  if(leg.asset.chain==='bitcoin'){
   if(typeof readers?.bitcoin?.escrow!=='function')throw Error('Bitcoin testnet data is unavailable.');
   await verifyBitcoinTestnetEscrow({...fields,vout:Number(fields.vout),amount_sats:Number(fields.amount_sats),refund_height:Number(fields.refund_height)},readers.bitcoin.escrow,limits);
  }else if(leg.asset.chain==='cardano'){
   if(typeof readers?.cardano?.escrow!=='function')throw Error('Cardano preview data is unavailable.');
   await verifyCardanoPreviewEscrow({...fields,expiry_ms:Number(fields.expiry_ms)},readers.cardano.escrow,limits);
  }else{
   const provider=readers?.ethereum?.provider,contract=await ethereumContract(provider,reference,leg);
   if(!templates?.ether)throw Error('The pinned Ethereum escrow template is unavailable.');
   await verifySepoliaEscrow(provider,templates.ether,sessionAssetTerms(snapshot.terms,side,{reference,contract}).operationTerms,limits);
  }
  const latest=await getSession(session,role),active=latest?.snapshot.actions?.[side]?.fund?.at(-1);
  if(!latest||latest.revision!==record.revision||canonical(latest.snapshot.terms)!==canonical(snapshot.terms)||latest.snapshot.escrows[side]!==null||canonical(active)!==canonical(attempt))throw Error('The swap changed while checking the transaction.');
  const next=structuredClone(latest.snapshot);next.actions[side].fund[next.actions[side].fund.length-1]={id:attempt.id,state:'submitted',txid};next.escrows[side]=reference;
  const saved=await updateSession(session,role,latest.revision,next);
  // Leave wallet action journals untouched. An exact escrow alone does not
  // establish which of multiple interrupted wallet requests created it.
  return {reference,revision:saved.revision};
 });
}
