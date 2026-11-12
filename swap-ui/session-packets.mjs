/** Signed, ordered coordination packets for an accepted swap.
 *
 * A protocol key must first be authenticated by verifyParticipant() against locally saved offer and wallet proofs. A
 * packet is not evidence that funds exist: callers must independently check both chains before requesting any wallet
 * signature. These functions do not send packets or execute transactions. Never put a preimage in a packet. */
import {canonical} from './identity.mjs';
import {checkSessionAddress,checkSessionAsset,sessionOfferDigest,verifyParticipant} from './session-identity.mjs';
import {fromHex,toHex} from './cbor.mjs';
import {checkOrdered,proveBlocks} from './timelock-policy.mjs';

const PREFIX='hegemon.swap.session-packet.v1\n',KIND='hegemon.swap.session-packet';
const HEX64=/^[0-9a-f]{64}$/;
const ORDER=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const NETWORK={bitcoin:'testnet4',ethereum:'sepolia',cardano:'preview',hegemon:'pre-mainnet'};
const enc=new TextEncoder();
const keys=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const fail=message=>{throw Error(message);};
const positive=v=>typeof v==='string'&&/^[1-9][0-9]{0,77}$/.test(v)&&BigInt(v)<(1n<<256n);
async function sha256(text){return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(text))));}
function uint(bytes){return BigInt('0x'+toHex(bytes));}
function write32(value){return fromHex(value.toString(16).padStart(64,'0'));}

/** Generate an independent, non-extractable signing key for protocol packets, never a wallet key. */
export async function createProtocolKey(){
 const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 return {privateKey:pair.privateKey,publicKey:toHex(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)))};
}

/** Version 2 terms carry exact asset identifiers and decimal integer strings on both legs. */
export function validateSessionTerms(terms){
 if(!keys(terms,['version','hashlock','legs'])||terms.version!==2||typeof terms.hashlock!=='string'||!HEX64.test(terms.hashlock)||!keys(terms.legs,['long','short']))fail('Invalid session terms.');
 for(const name of ['long','short']){
  const leg=terms.legs[name];
  if(!leg||typeof leg!=='object'||Array.isArray(leg))fail('Invalid '+name+' leg.');
  const cardanoToken=leg.asset?.chain==='cardano'&&leg.asset?.kind==='native';
  if(!keys(leg,['asset','network','claimant','refundee','expiry',...(cardanoToken?['lovelace']:[])]))fail('Invalid '+name+' leg fields.');
  const normalized=checkSessionAsset(leg.asset);
  if(canonical(normalized)!==canonical(leg.asset))fail('The '+name+' asset identifier is not canonical.');
  if(leg.network!==NETWORK[leg.asset.chain])fail('The '+name+' leg is on the wrong test network.');
  checkSessionAddress(leg.asset.chain,leg.claimant);checkSessionAddress(leg.asset.chain,leg.refundee);
  if(leg.claimant===leg.refundee||!Number.isSafeInteger(leg.expiry)||leg.expiry<1)fail('Invalid '+name+' participants or deadline.');
  if(cardanoToken&&(!positive(leg.lovelace)||BigInt(leg.lovelace)>=(1n<<64n)))fail('Invalid Cardano token deposit.');
 }
 const {long,short}=terms.legs;
 if(long.asset.chain===short.asset.chain&&(long.refundee!==short.claimant||short.refundee!==long.claimant))fail('Same-chain participants do not match.');
 return terms;
}
export async function sessionTermsDigest(terms){validateSessionTerms(terms);return sha256('hegemon.swap.session-terms.v2\n'+canonical(terms));}

/** Match a proposal to locally saved offer details and both independently wallet-verified participants.
 * This authenticates terms, not on-chain escrows; Hegemon addresses are explicitly returned as unverified. */
export async function checkSessionProposal(terms,{offer,expectedOfferDigest,channelDigest,ownerBlob,takerBlob,session,reservation,sessionExpires,now}){
 validateSessionTerms(terms);
 const digest=await sessionOfferDigest(offer),assets={give:offer.give,receive:offer.receive};
 if(typeof expectedOfferDigest!=='string'||!HEX64.test(expectedOfferDigest)||digest!==expectedOfferDigest)fail('The saved offer does not match the pinned offer digest.');
 const common={session,offer:offer.id,reservation,offerDigest:digest,channelDigest,assets,sessionExpires};
 const [owner,taker]=await Promise.all([verifyParticipant(ownerBlob,{...common,role:'owner'},now),verifyParticipant(takerBlob,{...common,role:'taker'},now)]);
 if(owner.statement.protocolKey===taker.statement.protocolKey)fail('Participants cannot share a protocol signing key.');
 const {long,short}=terms.legs;
 if(canonical(long.asset)!==canonical(checkSessionAsset(offer.give))||canonical(short.asset)!==canonical(checkSessionAsset(offer.receive)))fail('The proposed assets do not match the saved offer.');
 if(long.refundee!==owner.statement.addresses.give||long.claimant!==taker.statement.addresses.give||short.claimant!==owner.statement.addresses.receive||short.refundee!==taker.statement.addresses.receive)fail('The proposed recipients do not match the wallet-signed participants.');
 return {termsDigest:await sessionTermsDigest(terms),owner,taker,unverifiedHegemon:[...owner.unverified,...taker.unverified].length>0};
}

/** Recheck deadline policy on fresh chain heads immediately before a funding approval. */
export function checkFundingPolicy(terms,{role,heads,config,now}){
 validateSessionTerms(terms);
 if(!['initiator','responder'].includes(role)||!heads||heads.long==null||heads.short==null)fail('Fresh chain heads are required.');
 const ordered={long:{chain:terms.legs.long.asset.chain,expiry:terms.legs.long.expiry},short:{chain:terms.legs.short.asset.chain,expiry:terms.legs.short.expiry},heads,now};
 const result=checkOrdered(config,ordered);
 if(!result.ok)fail('The swap deadlines are not safe: '+result.reasons.map(reason=>reason.code).join(', '));
 for(const name of role==='initiator'?['long','short']:['short']){
  const leg=ordered[name],chain=config.chains[leg.chain],head=heads[name];
  if(chain.kind==='height'&&chain.minLockBlocks){
   const need=head.height+chain.minLockBlocks+chain.providerLagBlocks+proveBlocks(chain)+1;
   if(!Number.isSafeInteger(need)||leg.expiry<need)fail('The '+name+' lock no longer has enough time to be created.');
  }
 }
 return result;
}

export function validateSessionReference(value){
 if(!value||!['bitcoin','ethereum','cardano','hegemon'].includes(value.chain))fail('Invalid escrow reference.');
 if(value.chain==='hegemon'){
  // A wallet's local candidate is 32 bytes; the public action ID is 48 bytes,
  // and a private note is identified separately by its u64 position. None of
  // these alone proves that the note contains the agreed HTLC terms.
  if(!keys(value,['chain','txid','action_id','position','block_height'])||typeof value.txid!=='string'||!HEX64.test(value.txid)||typeof value.action_id!=='string'||!/^[0-9a-f]{96}$/.test(value.action_id)||typeof value.position!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(value.position)||BigInt(value.position)>=1n<<64n||typeof value.block_height!=='string'||!/^[1-9][0-9]{0,14}$/.test(value.block_height)||BigInt(value.block_height)>=1n<<48n)fail('Invalid Hegemon escrow reference.');
  return;
 }
 const utxo=['bitcoin','cardano'].includes(value.chain);
 if(!keys(value,['chain','txid',...(utxo?['vout']:[])])||typeof value.txid!=='string'||!HEX64.test(value.txid)||utxo&&(!Number.isSafeInteger(value.vout)||value.vout<0||value.vout>0xffffffff))fail('Invalid escrow reference.');
}
function payload(value){
 if(!value||typeof value!=='object'||Array.isArray(value))fail('Invalid coordination payload.');
 if(value.type==='proposal'){
  if(!keys(value,['type','terms']))fail('Invalid proposal packet.');validateSessionTerms(value.terms);
 }else if(value.type==='accept'){
  if(!keys(value,['type','termsDigest'])||typeof value.termsDigest!=='string'||!HEX64.test(value.termsDigest))fail('Invalid acceptance packet.');
 }else if(value.type==='escrow'){
  if(!keys(value,['type','termsDigest','leg','reference'])||typeof value.termsDigest!=='string'||!HEX64.test(value.termsDigest)||!['long','short'].includes(value.leg))fail('Invalid escrow packet.');validateSessionReference(value.reference);
 }else if(value.type==='cancel'){
  if(!keys(value,['type','reason'])||!['cancelled','unavailable','unsafe'].includes(value.reason))fail('Invalid cancellation packet.');
 }else fail('Unknown coordination packet.');
 return value;
}
function packetBody(value){
 if(!keys(value,['version','kind','session','role','sequence','previous','payload'])||value.version!==1||value.kind!==KIND||typeof value.session!=='string'||!HEX64.test(value.session)||!['owner','taker'].includes(value.role)||!Number.isSafeInteger(value.sequence)||value.sequence<1||value.sequence>256)fail('Invalid coordination packet.');
 if(value.sequence===1?value.previous!==null:typeof value.previous!=='string'||!HEX64.test(value.previous))fail('Invalid packet history.');
 payload(value.payload);return value;
}
function lowSignature(bytes){
 if(bytes.length!==64)fail('Invalid protocol signature.');
 const r=uint(bytes.slice(0,32)),s=uint(bytes.slice(32));
 if(r<=0n||r>=ORDER||s<=0n||s>=ORDER)fail('Invalid protocol signature.');
 const out=new Uint8Array(64);out.set(write32(r));out.set(write32(s>ORDER/2n?ORDER-s:s),32);return out;
}

/** The packet's history digest excludes its signature, preventing ECDSA signature malleability from changing history. */
export async function packetDigest(body){packetBody(body);return sha256(PREFIX+canonical(body));}
export async function signPacket(privateKey,{session,role,sequence,previous,payload:content}){
 const body=packetBody({version:1,kind:KIND,session,role,sequence,previous,payload:content});
 if(!privateKey||privateKey.type!=='private'||privateKey.algorithm?.name!=='ECDSA'||privateKey.algorithm?.namedCurve!=='P-256'||privateKey.extractable)fail('Invalid local protocol key.');
 const signature=lowSignature(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,enc.encode(PREFIX+canonical(body)))));
 return {body,signature:toHex(signature)};
}

/** Verify the peer's certified protocol key, exact next sequence and previous digest; never infer the key from the packet. */
export async function verifyPacket(packet,{session,role,sequence,previous,publicKey}){
 if(!keys(packet,['body','signature'])||typeof packet.signature!=='string'||!/^[0-9a-f]{128}$/.test(packet.signature))fail('Invalid signed packet.');
 const body=packetBody(packet.body);
 if(body.session!==session||body.role!==role||body.sequence!==sequence||body.previous!==previous)fail('Packet is for a different session, role, or sequence.');
 if(typeof publicKey!=='string'||!/^04[0-9a-f]{128}$/.test(publicKey))fail('A verified peer protocol key is required.');
 const signature=fromHex(packet.signature),s=uint(signature.slice(32)),r=uint(signature.slice(0,32));
 if(r<=0n||r>=ORDER||s<=0n||s>ORDER/2n)fail('Non-canonical protocol signature.');
 let key;try{key=await crypto.subtle.importKey('raw',fromHex(publicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);}catch{fail('Invalid peer protocol key.');}
 const ok=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,signature,enc.encode(PREFIX+canonical(body)));
 if(!ok)fail('Protocol packet signature does not verify.');
 return {body,digest:await packetDigest(body)};
}
