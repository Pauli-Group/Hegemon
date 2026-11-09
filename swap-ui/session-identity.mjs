/** Wallet-bound identities for an accepted swap session.
 *
 * This module only verifies statements and produces the text wallets sign. It does not establish a swap, authorize a
 * transaction, or prove control of a Hegemon address. Callers must compare the offer digest with the offer they saved
 * independently, and must validate both escrows and the deadline policy before spending. */
import {canonical} from './identity.mjs';
import {compressedKey, verifyProof} from './identity-proofs.mjs';
import {assetInfo, validateAssetId} from './offer-draft.mjs';
import {fromHex, toHex} from './cbor.mjs';

const PREFIX='hegemon.swap.session-participant.v1\n';
const KIND='hegemon.swap.session-participant';
const MAX_LIFETIME=180*86400, MAX_BLOB=20000;
const HEX64=/^[0-9a-f]{64}$/;
const HGN=/^shca1[023456789acdefghjklmnpqrstuvwxyz]{1,3000}$/;
const keys=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const fail=message=>{throw Error(message);};
const enc=new TextEncoder();
async function sha256(text){return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(text))));}

/** The relay session ID is public. It is not a credential. */
export async function deriveSessionId(offerId,reservationId){
 if(typeof offerId!=='string'||typeof reservationId!=='string'||!HEX64.test(offerId)||!HEX64.test(reservationId))fail('Invalid offer or reservation.');
 return sha256('hegemon.swap.session.v1:'+offerId+':'+reservationId);
}

/** Validate and canonicalize an offer asset; amounts remain integer strings, without floating-point conversion. */
export function checkSessionAsset(asset){
 if(!keys(asset,['chain','kind','id','amount'])||typeof asset.chain!=='string'||typeof asset.kind!=='string'||typeof asset.id!=='string'||typeof asset.amount!=='string')fail('Invalid offer asset.');
 const type=asset.chain+':'+asset.kind;
 assetInfo(type);
 const id=validateAssetId(type,asset.id).toLowerCase();
 if(asset.id.trim()!==asset.id)fail('Asset identifier must not contain surrounding whitespace.');
 if(!/^[1-9][0-9]{0,77}$/.test(asset.amount)||BigInt(asset.amount)>=(1n<<256n))fail('Invalid asset amount.');
 if(asset.kind==='erc721'&&asset.amount!=='1')fail('An ERC-721 offer needs one NFT.');
 if(asset.chain==='cardano'&&asset.kind==='native'&&BigInt(asset.amount)>=(1n<<63n))fail('Invalid Cardano asset amount.');
 return {...asset,id};
}

/** Bind the immutable offer that a participant actually saw. Store this digest before accepting relay updates. */
export async function sessionOfferDigest(offer){
 if(!offer||typeof offer.id!=='string'||!HEX64.test(offer.id)||!['public','private'].includes(offer.visibility)||!Number.isSafeInteger(offer.expires)||offer.expires<1||typeof offer.ownerPublicKey!=='string'||!/^04[0-9a-f]{128}$/.test(offer.ownerPublicKey))fail('Invalid session offer.');
 const fixed={id:offer.id,visibility:offer.visibility,give:checkSessionAsset(offer.give),receive:checkSessionAsset(offer.receive),expires:offer.expires,ownerPublicKey:offer.ownerPublicKey};
 return sha256('hegemon.swap.session-offer.v1\n'+canonical(fixed));
}

export function checkSessionAddress(chain,address){
 if(typeof address!=='string')fail('Invalid participant address.');
 if(chain==='ethereum'){if(!/^0x[0-9a-f]{40}$/.test(address)||/^0x0{40}$/.test(address))fail('Invalid Ethereum participant address.');}
 else if(chain==='cardano'){if(!/^[0-9a-f]{56}$/.test(address))fail('Invalid Cardano participant address.');}
 else if(chain==='bitcoin'){if(!/^(02|03)[0-9a-f]{64}$/.test(address))fail('Invalid Bitcoin participant key.');compressedKey(address);}
 else if(chain==='hegemon'){if(!HGN.test(address))fail('Invalid Hegemon participant address.');}
 else fail('Unsupported participant chain.');
}

function shape(statement,assets){
 if(!keys(statement,['version','kind','session','offer','reservation','role','offerDigest','channelDigest','protocolKey','addresses','issued','expires'])||statement.version!==1||statement.kind!==KIND)fail('Invalid participant statement.');
 for(const name of ['session','offer','reservation','offerDigest','channelDigest'])if(typeof statement[name]!=='string'||!HEX64.test(statement[name]))fail('Invalid participant binding.');
 if(!['owner','taker'].includes(statement.role)||typeof statement.protocolKey!=='string'||!/^04[0-9a-f]{128}$/.test(statement.protocolKey))fail('Invalid participant key.');
 if(!keys(statement.addresses,['give','receive']))fail('Invalid participant addresses.');
 if(!Number.isSafeInteger(statement.issued)||!Number.isSafeInteger(statement.expires)||statement.issued<1||statement.expires<=statement.issued||statement.expires-statement.issued>MAX_LIFETIME)fail('Invalid participant statement lifetime.');
 if(!assets||!assets.give||!assets.receive)fail('Offer assets are required.');
 for(const side of ['give','receive']){checkSessionAsset(assets[side]);checkSessionAddress(assets[side].chain,statement.addresses[side]);}
 return statement;
}

export function buildParticipant({session,offer,reservation,role,offerDigest,channelDigest,protocolKey,addresses,issued,expires},assets){
 return shape({version:1,kind:KIND,session,offer,reservation,role,offerDigest,channelDigest,protocolKey,addresses,issued,expires},assets);
}
export function participantText(statement){return PREFIX+canonical(statement);}
export function serializeParticipant(statement,proofs){
 const blob=JSON.stringify({statement,proofs});if(blob.length>MAX_BLOB)fail('Participant statement is too large.');return blob;
}

/** Verify wallet signatures over the entire statement, including the protocol key and the locally saved offer digest.
 * The returned `unverified` list names Hegemon legs: another chain's signature binds their address to this statement,
 * but Hegemon wallet control is not proven. A Hegemon-only identity cannot be authenticated with the current wallets. */
export async function verifyParticipant(blob,expected,now){
 if(typeof blob!=='string'||blob.length>MAX_BLOB||!Number.isSafeInteger(now))fail('Invalid participant statement.');
 let item;try{item=JSON.parse(blob);}catch{fail('Invalid participant statement.');}
 if(!keys(item,['statement','proofs'])||!Array.isArray(item.proofs)||item.proofs.length<1||item.proofs.length>4)fail('Invalid participant proofs.');
 const st=shape(item.statement,expected?.assets);
 if(st.session!==expected.session||st.offer!==expected.offer||st.reservation!==expected.reservation||st.role!==expected.role||st.offerDigest!==expected.offerDigest||st.channelDigest!==expected.channelDigest)fail('Participant statement does not match this session, offer, or channel.');
 if(st.session!==await deriveSessionId(st.offer,st.reservation))fail('Participant statement has a different session identifier.');
 if(st.issued>now+300||st.expires<=now||!Number.isSafeInteger(expected.sessionExpires)||st.expires>expected.sessionExpires)fail('Participant statement is expired or outside the session lifetime.');
 try{await crypto.subtle.importKey('raw',fromHex(st.protocolKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);}catch{fail('Invalid participant protocol key.');}
 const verified=[],seen=new Set(),text=participantText(st);
 for(const proof of item.proofs){
  if(!proof||typeof proof!=='object'||Array.isArray(proof)||JSON.stringify(proof).length>12000)fail('Invalid participant proof.');
  const result=verifyProof(proof,text),id=result.chain+':'+result.signer;
  if(seen.has(id))fail('Duplicate participant proof.');seen.add(id);
  if(!['give','receive'].some(side=>expected.assets[side].chain===result.chain&&st.addresses[side]===result.signer))fail('Proof does not name a participant address.');
  verified.push(result);
 }
 const proven={};
 for(const side of ['give','receive']){
  const chain=expected.assets[side].chain;
  proven[side]=chain!=='hegemon'&&verified.some(item=>item.chain===chain&&item.signer===st.addresses[side]);
  if(chain!=='hegemon'&&!proven[side])fail('A participant address is missing its wallet proof.');
 }
 if(!verified.length)fail('No supported wallet proof binds this participant.');
 return {statement:st,proven,unverified:['give','receive'].filter(side=>!proven[side]),proofs:verified};
}
