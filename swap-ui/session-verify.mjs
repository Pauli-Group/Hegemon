/** Read-only gates for a wallet-bound Cardano–Ethereum session. A caller must
 * repeat these checks immediately before each wallet request; a successful
 * snapshot cannot guarantee the future state of a chain or token issuer. */
import {checkFundingPolicy,checkSessionProposal,validateSessionReference} from './session-packets.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {legRequirements} from './timelock-policy.mjs';
import {claimGate} from './swap-flow.mjs';
import {assertSepoliaIdentity,verifySepoliaEscrow} from './sepolia-verifier.mjs';
import {verifyCardanoPreviewEscrow} from './cardano-preview-verifier.mjs';

const HEX_TX=/^0x[0-9a-f]{64}$/;
const HEX_ADDRESS=/^0x[0-9a-f]{40}$/;

async function ethereumContract(provider,ref,leg){
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
 * leg, fund the second leg, or reveal the secret to claim the short leg. This
 * API does not yet authorize the responder's claim or a refund. */
export async function verifySessionSnapshot({terms,offer,expectedOfferDigest,channelDigest,ownerBlob,takerBlob,session,reservation,sessionExpires,role,references,purpose,readers,config,now,templates,nowClock=()=>Math.floor(Date.now()/1000),
 verifyEthereum=verifySepoliaEscrow,verifyCardano=verifyCardanoPreviewEscrow}){
 const requirements={review:[],fund_first:[],fund_second:['long'],claim_short:['long','short']};
 if(!['initiator','responder'].includes(role)||!Object.hasOwn(requirements,purpose)||!references||!Number.isSafeInteger(now)||typeof nowClock!=='function')throw Error('Invalid session verification request.');
 if((purpose==='fund_first'||purpose==='claim_short')&&role!=='initiator'||purpose==='fund_second'&&role!=='responder')throw Error('The requested action belongs to the other participant.');
 const required=requirements[purpose];
 const checked=await checkSessionProposal(terms,{offer,expectedOfferDigest,channelDigest,ownerBlob,takerBlob,session,reservation,sessionExpires,now});
 if(checked.unverifiedHegemon||!['cardano','ethereum'].includes(terms.legs.long.asset.chain)||!['cardano','ethereum'].includes(terms.legs.short.asset.chain))throw Error('This browser session supports Cardano and Ethereum only.');
 // These participant statements are revalidated on every refresh. Do not
 // fund a swap if they or the relay session would expire before recovery is
 // possible after the longer refund deadline.
 const identityFloor=Math.max(terms.legs.long.expiry,terms.legs.short.expiry)+86400;
 if(!Number.isSafeInteger(identityFloor))throw Error('Invalid swap recovery deadline.');
 if((purpose==='fund_first'||purpose==='fund_second')&&(sessionExpires<=identityFloor||checked.owner.statement.expires<=identityFloor||checked.taker.statement.expires<=identityFloor))throw Error('The session or participant statements expire too soon for swap recovery.');
 if(!readers?.ethereum?.provider||typeof readers.cardano?.params!=='function'||typeof readers.cardano?.escrow!=='function')throw Error('Both chain readers are required.');
 const provider=readers.ethereum.provider;
 await assertSepoliaIdentity(provider);
 const [ethereum,cardano]=await Promise.all([
  provider.request({method:'eth_getBlockByNumber',params:['latest',false]}),readers.cardano.params(),
 ]);
 if(!ethereum||typeof ethereum.timestamp!=='string'||!/^0x[0-9a-f]+$/i.test(ethereum.timestamp))throw Error('Ethereum chain head is unavailable.');
 const timestamp=Number(BigInt(ethereum.timestamp));
 if(!Number.isSafeInteger(timestamp)||timestamp<1||cardano?.network!=='preview'||cardano.magic!==2||cardano.system_start!==1666656000||!Number.isSafeInteger(cardano.slot)||cardano.slot<0||!Number.isSafeInteger(cardano.system_start+cardano.slot))throw Error('A testnet chain head is unavailable or invalid.');
 const chainHeads={ethereum:{timestamp,observedAt:now},cardano:{timestamp:cardano.system_start+cardano.slot,observedAt:now}};
 const heads={long:chainHeads[terms.legs.long.asset.chain],short:chainHeads[terms.legs.short.asset.chain]};
 checkFundingPolicy(terms,{role,heads,config,now});
 const escrows={long:null,short:null};
 for(const side of required){
  const ref=references[side];validateSessionReference(ref);
  const leg=terms.legs[side],chain=leg.asset.chain;
  if(ref.chain!==chain)throw Error('The '+side+' escrow reference is for the wrong chain.');
  const limits=legRequirements(config,chain);
  if(chain==='cardano'){
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
 await assertSepoliaIdentity(provider);
 const finished=nowClock();
 if(!Number.isSafeInteger(finished)||finished<now)throw Error('The local clock changed during verification.');
 await checkSessionProposal(terms,{offer,expectedOfferDigest,channelDigest,ownerBlob,takerBlob,session,reservation,sessionExpires,now:finished});
 const policy=checkFundingPolicy(terms,{role,heads,config,now:finished});
 if(purpose==='claim_short'){
  const policyTerms={legs:{long:{chain:terms.legs.long.asset.chain,expiry:terms.legs.long.expiry},short:{chain:terms.legs.short.asset.chain,expiry:terms.legs.short.expiry}}};
  const gate=claimGate(role,policyTerms,heads,config,finished);
  if(!gate.ok)throw Error('The claim is outside the safe window: '+gate.reasons.join(', '));
 }
 return {termsDigest:checked.termsDigest,heads,policy,escrows};
}
