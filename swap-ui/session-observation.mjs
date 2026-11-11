/** Observe a saved session escrow without trusting relay messages as evidence
 * of a claim. A public preimage is accepted only after the spending data hashes
 * to the agreed hashlock and the configured confirmation depth is reached. */
import {validateSessionTerms,validateSessionReference} from './session-packets.mjs';
import {ethereumContract} from './session-verify.mjs';
import {assertSepoliaIdentity} from './sepolia-verifier.mjs';
import {observeBitcoin,observeCardano,observeEthereum} from './observers.mjs';
import {legRequirements} from './timelock-policy.mjs';

export async function observeSessionLeg({snapshot,side,readers,config}){
 if(!snapshot||!['long','short'].includes(side))throw Error('Invalid swap observation.');
 validateSessionTerms(snapshot.terms);
 const leg=snapshot.terms.legs[side],ref=snapshot.escrows?.[side];validateSessionReference(ref);
 if(ref.chain!==leg.asset.chain)throw Error('The escrow reference is on the wrong chain.');
 const confirmations=legRequirements(config,ref.chain).confirmations;
 if(ref.chain==='bitcoin'){
  if(typeof readers?.bitcoin?.spend!=='function')throw Error('The Bitcoin spend reader is unavailable.');
  return observeBitcoin({...sessionBitcoinTerms(snapshot.terms,side),txid:ref.txid,vout:ref.vout},readers.bitcoin.spend,{confirmations});
 }
 if(ref.chain==='cardano'){
  if(typeof readers?.cardano?.spend!=='function')throw Error('The Cardano spend reader is unavailable.');
  return observeCardano({hashlock:snapshot.terms.hashlock,outref:`${ref.txid}#${ref.vout}`},readers.cardano.spend,{confirmations});
 }
 if(ref.chain==='ethereum'){
  const provider=readers?.ethereum?.provider;
  if(!provider||typeof readers.ethereum.events!=='function')throw Error('The Ethereum event reader is unavailable.');
  await assertSepoliaIdentity(provider);
  const contract=await ethereumContract(provider,ref,leg);
  const result=await observeEthereum({hashlock:snapshot.terms.hashlock,contract},readers.ethereum.events,{confirmations});
  await assertSepoliaIdentity(provider);
  return result;
 }
 throw Error('This session cannot observe that chain.');
}

function sessionBitcoinTerms(terms,side){
 const leg=terms.legs[side];return {hashlock:terms.hashlock,claimant_key:leg.claimant,refund_key:leg.refundee,refund_height:leg.expiry};
}
