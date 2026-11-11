/** Read-only gates for a wallet-bound Cardano–Ethereum session. A caller must
 * repeat these checks immediately before each wallet request; a successful
 * snapshot cannot guarantee the future state of a chain or token issuer. */
import {checkFundingPolicy,checkSessionProposal,validateSessionReference} from './session-packets.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {legRequirements,legWindow,checkOrdered,actionSeconds} from './timelock-policy.mjs';
import {claimGate} from './swap-flow.mjs';
import {assertSepoliaIdentity,verifySepoliaEscrow} from './sepolia-verifier.mjs';
import {verifyCardanoPreviewEscrow} from './cardano-preview-verifier.mjs';
import {TESTNET4_GENESIS,verifyBitcoinTestnetEscrow} from './bitcoin-testnet-verifier.mjs';

const HEX_TX=/^0x[0-9a-f]{64}$/;
const HEX_ADDRESS=/^0x[0-9a-f]{40}$/;

export async function ethereumContract(provider,ref,leg){
 const hash='0x'+ref.txid;
 const [receipt,transaction]=await Promise.all([
  provider.request({method:'eth_getTransactionReceipt',params:[hash]}),
  provider.request({method:'eth_getTransactionByHash',params:[hash]}),
 ]);
 if(!receipt||!transaction||String(receipt.transactionHash).toLowerCase()!==hash||String(transaction.hash).toLowerCase()!==hash||receipt.status!=='0x1'||transaction.to!==null||String(transaction.from).toLowerCase()!==leg.refundee)throw Error('Ethereum escrow creation is not confirmed for the agreed funder.');
 const address=String(receipt.contractAddress||'').toLowerCase();
 if(!HEX_ADDRESS.test(address)||/^0x0{40}$/.test(address)||!HEX_TX.test(hash))throw Error('Ethereum escrow creation did not return a valid contract.');
 return address;
}

/** Authenticate the offer, both wallet-bound participants and the exact terms;
 * read both chain heads; validate the deadline policy; then independently verify
 * each requested escrow reference against the pinned contracts and current chain.
 * The purpose selects the required evidence: review terms, fund the first
 * leg, fund the second leg, or claim either leg. Claiming the long leg also
 * requires the caller to independently observe the short leg's confirmed
 * claim and match its preimage. This API does not authorize refunds. */
export async function verifySessionSnapshot({terms,offer,expectedOfferDigest,channelDigest,ownerBlob,takerBlob,session,reservation,sessionExpires,role,references,purpose,readers,config,now,templates,nowClock=()=>Math.floor(Date.now()/1000),
 verifyEthereum=verifySepoliaEscrow,verifyCardano=verifyCardanoPreviewEscrow,verifyBitcoin=verifyBitcoinTestnetEscrow}){
 const requirements={review:[],fund_first:[],fund_second:['long'],verify_first:['long'],verify_both:['long','short'],claim_short:['long','short'],claim_long:['long']};
 if(!['initiator','responder'].includes(role)||!Object.hasOwn(requirements,purpose)||!references||!Number.isSafeInteger(now)||typeof nowClock!=='function')throw Error('Invalid session verification request.');
 if((purpose==='fund_first'||purpose==='claim_short')&&role!=='initiator'||(purpose==='fund_second'||purpose==='claim_long')&&role!=='responder')throw Error('The requested action belongs to the other participant.');
 const required=requirements[purpose];
 const checked=await checkSessionProposal(terms,{offer,expectedOfferDigest,channelDigest,ownerBlob,takerBlob,session,reservation,sessionExpires,now});
 if(checked.unverifiedHegemon||!['bitcoin','cardano','ethereum'].includes(terms.legs.long.asset.chain)||!['bitcoin','cardano','ethereum'].includes(terms.legs.short.asset.chain))throw Error('This browser session cannot yet verify that chain.');
 // These participant statements are revalidated on every refresh. Do not
 // fund a swap if they or the relay session would expire before recovery is
 // possible after the longer refund deadline.
 const chains=new Set([terms.legs.long.asset.chain,terms.legs.short.asset.chain]),provider=readers?.ethereum?.provider,chainHeads={};
 if(chains.has('ethereum')){
  if(!provider)throw Error('The Ethereum reader is required.');await assertSepoliaIdentity(provider);
  const head=await provider.request({method:'eth_getBlockByNumber',params:['latest',false]});
  if(typeof head?.timestamp!=='string'||!/^0x[0-9a-f]+$/i.test(head.timestamp))throw Error('Ethereum chain head is unavailable.');
  const timestamp=Number(BigInt(head.timestamp));if(!Number.isSafeInteger(timestamp)||timestamp<1)throw Error('Ethereum chain head is invalid.');
  chainHeads.ethereum={timestamp,observedAt:now};
 }
 if(chains.has('cardano')){
  if(typeof readers?.cardano?.params!=='function'||typeof readers.cardano.escrow!=='function')throw Error('The Cardano reader is required.');
  const cardano=await readers.cardano.params();
  if(cardano?.network!=='preview'||cardano.magic!==2||cardano.system_start!==1666656000||!Number.isSafeInteger(cardano.slot)||cardano.slot<0||!Number.isSafeInteger(cardano.system_start+cardano.slot))throw Error('The Cardano chain head is unavailable or invalid.');
  chainHeads.cardano={timestamp:cardano.system_start+cardano.slot,observedAt:now};
 }
 if(chains.has('bitcoin')){
  if(typeof readers?.bitcoin?.head!=='function'||typeof readers.bitcoin.escrow!=='function')throw Error('The Bitcoin reader is required.');
  const bitcoin=await readers.bitcoin.head();
  if(bitcoin?.genesis!==TESTNET4_GENESIS||!Number.isSafeInteger(bitcoin.tip)||bitcoin.tip<0)throw Error('The Bitcoin testnet4 head is unavailable or invalid.');
  chainHeads.bitcoin={height:bitcoin.tip,observedAt:now};
 }
 const heads={long:chainHeads[terms.legs.long.asset.chain],short:chainHeads[terms.legs.short.asset.chain]};
 const windows=['long','short'].map(side=>legWindow(config,{chain:terms.legs[side].asset.chain,expiry:terms.legs[side].expiry},heads[side],now));
 const identityFloor=now+Math.max(...windows.map(window=>window.lockUpperBound))+86400;
 if(!Number.isSafeInteger(identityFloor))throw Error('Invalid swap recovery deadline.');
 if((purpose==='fund_first'||purpose==='fund_second')&&(sessionExpires<=identityFloor||checked.owner.statement.expires<=identityFloor||checked.taker.statement.expires<=identityFloor))throw Error('The session or participant statements expire too soon for swap recovery.');
 if(purpose!=='claim_long')checkFundingPolicy(terms,{role,heads,config,now});
 const escrows={long:null,short:null};
 for(const side of required){
  const ref=references[side];validateSessionReference(ref);
  const leg=terms.legs[side],chain=leg.asset.chain;
  if(ref.chain!==chain)throw Error('The '+side+' escrow reference is for the wrong chain.');
  const limits=purpose==='claim_long'?(chain==='bitcoin'?{confirmations:legRequirements(config,chain).confirmations,minBlocksFloor:0}:{confirmations:legRequirements(config,chain).confirmations,minClaimWindowSeconds:actionSeconds(config.chains[chain]),remainingFloorSeconds:1}):legRequirements(config,chain);
  if(chain==='bitcoin'){
   const fields=sessionAssetTerms(terms,side,{reference:ref}).operationTerms;
   escrows[side]=await verifyBitcoin({...fields,vout:Number(fields.vout),amount_sats:Number(fields.amount_sats),refund_height:Number(fields.refund_height)},readers.bitcoin.escrow,limits);
  }else if(chain==='cardano'){
   const fields=sessionAssetTerms(terms,side,{reference:ref}).operationTerms;
   escrows[side]=await verifyCardano({...fields,expiry_ms:Number(fields.expiry_ms)},readers.cardano.escrow,limits);
  }else{
   const contract=await ethereumContract(provider,ref,leg);
   const fields=sessionAssetTerms(terms,side,{reference:ref,contract}).operationTerms;
   const template=fields.kind==='eth'?templates?.ether:templates?.token;
   if(!template)throw Error('The pinned Ethereum escrow template is unavailable.');
   escrows[side]=await verifyEthereum(provider,template,fields,limits);
  }
 }
 if(chains.has('ethereum'))await assertSepoliaIdentity(provider);
 const finished=nowClock();
 if(!Number.isSafeInteger(finished)||finished<now)throw Error('The local clock changed during verification.');
 await checkSessionProposal(terms,{offer,expectedOfferDigest,channelDigest,ownerBlob,takerBlob,session,reservation,sessionExpires,now:finished});
 const policy=purpose==='claim_long'?null:checkFundingPolicy(terms,{role,heads,config,now:finished});
 if(purpose==='claim_short'||purpose==='claim_long'){
  const policyTerms={legs:{long:{chain:terms.legs.long.asset.chain,expiry:terms.legs.long.expiry},short:{chain:terms.legs.short.asset.chain,expiry:terms.legs.short.expiry}}};
  if(purpose==='claim_long'){
   // The short deadline may have passed after the secret became public, but
   // the long-chain observation must still be fresh and consistent with the
   // local clock. A stale head could otherwise overstate the claim window.
   const freshness=checkOrdered(config,{long:policyTerms.legs.long,short:policyTerms.legs.short,heads,now:finished});
   if(freshness.reasons.some(r=>r.detail?.role==='long'&&['bad-input','head-stale','clock-drift'].includes(r.code)))throw Error('The long-chain head is not fresh enough to claim.');
  }
  const gate=claimGate(role,policyTerms,heads,config,finished);
  if(!gate.ok)throw Error('The claim is outside the safe window: '+gate.reasons.join(', '));
 }
 return {termsDigest:checked.termsDigest,heads,policy,escrows};
}
