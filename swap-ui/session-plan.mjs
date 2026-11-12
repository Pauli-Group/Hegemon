/** Create a proposed Cardano–Ethereum session from authenticated wallet
 * identities and fresh chain heads. The secret is created encrypted and never
 * leaves this browser. The caller must persist and back it up before funding. */
import {channelFingerprint} from './session-channel.mjs';
import {verifyParticipant,checkSessionAsset} from './session-identity.mjs';
import {checkSessionProposal,checkFundingPolicy} from './session-packets.mjs';
import {validateSessionSnapshot} from './session-recovery.mjs';
import {createRecovery} from './recovery.mjs';
import {planWithMargin} from './swap-flow.mjs';
import {assertSepoliaIdentity} from './sepolia-verifier.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {minimumEscrowLovelace} from './cardano-tx.mjs';
import {TESTNET4_GENESIS} from './bitcoin-testnet-verifier.mjs';
import {HEGEMON_GENESIS,HEGEMON_CHAIN_ID} from './session-hegemon-read.mjs';

export async function planSessionTerms({session,role,snapshot,readers,config,passphrase,cardanoDeposit,now,allowUnverifiedHegemon=false,nowClock=()=>Math.floor(Date.now()/1000)}){
 await validateSessionSnapshot(snapshot,session);
 if(role!=='owner'||![2,3,4].includes(snapshot.version)||snapshot.terms!==null||snapshot.secretEnvelope!==null||!snapshot.ownerBlob||!snapshot.takerBlob||!Number.isSafeInteger(now)||typeof nowClock!=='function')throw Error('The session is not ready to plan a new swap.');
 const offer=snapshot.offer,assets={give:checkSessionAsset(offer.give),receive:checkSessionAsset(offer.receive)};
 if(assets.give.chain===assets.receive.chain||![assets.give.chain,assets.receive.chain].every(chain=>['hegemon','bitcoin','ethereum','cardano'].includes(chain)))throw Error('The guided planner cannot plan that pair.');
 const channelDigest=await channelFingerprint(session,snapshot.channelKey),expected={session,offer:offer.id,reservation:snapshot.reservation,offerDigest:snapshot.offerDigest,channelDigest,assets,sessionExpires:snapshot.sessionExpires};
 const [owner,taker]=await Promise.all([verifyParticipant(snapshot.ownerBlob,{...expected,role:'owner'},now),verifyParticipant(snapshot.takerBlob,{...expected,role:'taker'},now)]);
 if(owner.statement.protocolKey===taker.statement.protocolKey)throw Error('The participants must use separate session keys.');
 if((owner.unverified.length||taker.unverified.length)&&allowUnverifiedHegemon!==true)throw Error('A Hegemon address is bound to the other wallet signature but is not independently proven. Explicitly review that limitation first.');
 const chains=new Set([assets.give.chain,assets.receive.chain]),provider=readers?.ethereum?.provider,headsByChain={};let cardano=null;
 if(chains.has('ethereum')){
  if(!provider)throw Error('The Ethereum reader is required.');await assertSepoliaIdentity(provider);
  const ethereum=await provider.request({method:'eth_getBlockByNumber',params:['latest',false]});
  if(typeof ethereum?.timestamp!=='string'||!/^0x[0-9a-f]+$/i.test(ethereum.timestamp))throw Error('The Ethereum chain head is unavailable.');
  const time=Number(BigInt(ethereum.timestamp));if(!Number.isSafeInteger(time)||time<1)throw Error('The Ethereum chain head is invalid.');headsByChain.ethereum={timestamp:time,observedAt:now};
 }
 if(chains.has('cardano')){
  if(typeof readers?.cardano?.params!=='function')throw Error('The Cardano reader is required.');cardano=await readers.cardano.params();
  if(cardano?.network!=='preview'||cardano.magic!==2||cardano.system_start!==1666656000||!Number.isSafeInteger(cardano.slot)||cardano.slot<0||!Number.isSafeInteger(cardano.system_start+cardano.slot))throw Error('The Cardano chain head is unavailable or invalid.');
  headsByChain.cardano={timestamp:cardano.system_start+cardano.slot,observedAt:now};
 }
 if(chains.has('bitcoin')){
  if(typeof readers?.bitcoin?.head!=='function')throw Error('The Bitcoin reader is required.');const bitcoin=await readers.bitcoin.head();
  if(bitcoin?.genesis!==TESTNET4_GENESIS||!Number.isSafeInteger(bitcoin.tip)||bitcoin.tip<0)throw Error('The Bitcoin testnet4 head is unavailable or invalid.');headsByChain.bitcoin={height:bitcoin.tip,observedAt:now};
 }
 if(chains.has('hegemon')){
  if(typeof readers?.hegemon?.head!=='function')throw Error('The local Hegemon swap companion is required.');const hgn=await readers.hegemon.head();
  if(hgn?.genesis!==HEGEMON_GENESIS||hgn.chain_id!==HEGEMON_CHAIN_ID||!Number.isSafeInteger(hgn.height)||hgn.height<1||hgn.height>=2**48)throw Error('The Hegemon pre-mainnet head is unavailable or invalid.');headsByChain.hegemon={height:hgn.height,observedAt:now};
 }
 const heads={long:headsByChain[assets.give.chain],short:headsByChain[assets.receive.chain]};
 const plan=planWithMargin(config,assets.give.chain,assets.receive.chain,heads,now);
 const secretEnvelope=await createRecovery(passphrase);
 const network={hegemon:'pre-mainnet',bitcoin:'testnet4',ethereum:'sepolia',cardano:'preview'};
 const makeLeg=(asset,side,expiry)=>({asset,network:network[asset.chain],refundee:side==='long'?owner.statement.addresses.give:taker.statement.addresses.receive,claimant:side==='long'?taker.statement.addresses.give:owner.statement.addresses.receive,expiry,...(asset.chain==='cardano'&&asset.kind==='native'?{lovelace:cardanoDeposit}:{})});
 const terms={version:2,hashlock:secretEnvelope.hashlock,legs:{long:makeLeg(assets.give,'long',plan.long.expiry),short:makeLeg(assets.receive,'short',plan.short.expiry)}};
 const checked=await checkSessionProposal(terms,{offer,expectedOfferDigest:snapshot.offerDigest,channelDigest,ownerBlob:snapshot.ownerBlob,takerBlob:snapshot.takerBlob,session,reservation:snapshot.reservation,sessionExpires:snapshot.sessionExpires,now});
 let minimum=null;
 if(chains.has('cardano')){const cardSide=assets.give.chain==='cardano'?'long':'short',fields=sessionAssetTerms(terms,cardSide).operationTerms;
  minimum=minimumEscrowLovelace(fields,cardano);if(BigInt(fields.lovelace)<minimum)throw Error('The Cardano escrow needs at least '+minimum+' lovelace, including its inline datum.');}
 if(chains.has('bitcoin'))sessionAssetTerms(terms,assets.give.chain==='bitcoin'?'long':'short');
 if(chains.has('hegemon'))sessionAssetTerms(terms,assets.give.chain==='hegemon'?'long':'short');
 if(chains.has('ethereum'))await assertSepoliaIdentity(provider);
 const finished=nowClock();if(!Number.isSafeInteger(finished)||finished<now)throw Error('The local clock changed during planning.');
 const policy=checkFundingPolicy(terms,{role:'initiator',heads,config,now:finished});
 const recoveryFloor=now+Math.max(plan.verdict.metrics.longLockUpperSeconds,plan.verdict.metrics.shortLockUpperSeconds)+86400;
 if(!Number.isSafeInteger(recoveryFloor)||snapshot.sessionExpires<=recoveryFloor||owner.statement.expires<=recoveryFloor||taker.statement.expires<=recoveryFloor)throw Error('The session or participant statements expire too soon for swap recovery.');
 return {terms,secretEnvelope,termsDigest:checked.termsDigest,heads,policy,minimumCardanoLovelace:minimum===null?null:minimum.toString()};
}
