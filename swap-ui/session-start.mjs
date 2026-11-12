/** Start a recoverable, confidential session for an already-reserved offer.
 * The offer digest must have been pinned when the user reviewed the offer.
 * Only the owner may accept the reservation and close the listing. No wallet
 * signature or blockchain transaction is requested here. */
import {deriveSessionId,sessionOfferDigest} from './session-identity.mjs';
import {createChannelHandshake,openChannelHandshake} from './session-channel.mjs';
import {parsePublicSession} from './public-inbox.mjs';
import {createSessionRecovery} from './session-recovery.mjs';
import {getSession,addSession} from './session-store.mjs';
import {sessionOutbox} from './session-outbox.mjs';
import {canonical} from './identity.mjs';

const HEX=/^[0-9a-f]{64}$/;
const fail=message=>{throw Error(message);};
function fixedOffer(offer){return {id:offer.id,visibility:offer.visibility,give:offer.give,receive:offer.receive,expires:offer.expires,ownerPublicKey:offer.ownerPublicKey};}
function auth(credential){return {authorization:'Bearer '+credential};}

/** Fetch every page; relay-provided rows remain untrusted until verified. */
export async function readSessionFrames({session,credential,api}){
 if(!HEX.test(session)||!HEX.test(credential)||typeof api!=='function')fail('Invalid session history request.');
 let after=0;const frames=[];
 for(let page=0;page<6;page++){
  const value=await api(`/swap-sessions/${session}/packets?after=${after}`,{headers:auth(credential)});
  if(!value||!Array.isArray(value.packets)||value.packets.length>100)fail('Invalid session history response.');
  for(const row of value.packets){
   if(!row||!Number.isSafeInteger(row.id)||row.id<=after||!['owner','taker'].includes(row.sender)||!Number.isSafeInteger(row.sequence)||row.sequence<1||row.sequence>256||typeof row.ciphertext!=='string'||row.ciphertext.length>12000)fail('Invalid session history response.');
   after=row.id;frames.push(row);if(frames.length>512)fail('The session has too many packets.');
  }
  if(value.packets.length<100)return frames;
 }
 fail('The session history is incomplete.');
}

/** `api` returns parsed JSON or throws. Private provisional data stays in this
 * browser. `inboxPrivateKey` loads the maker's non-extractable local inbox key. */
export async function sessionStarter({role,offer,reservation,credential,pinnedOfferDigest,api,inboxPrivateKey,storage=globalThis.localStorage,locks=globalThis.navigator?.locks,clock=()=>Math.floor(Date.now()/1000)}){
 if(!['owner','taker'].includes(role)||![reservation,credential,pinnedOfferDigest].every(value=>typeof value==='string'&&HEX.test(value))||typeof api!=='function'||!storage||typeof storage.removeItem!=='function'||typeof locks?.request!=='function'||typeof clock!=='function')fail('Invalid session setup.');
 const fixed=fixedOffer(offer),offerDigest=await sessionOfferDigest(fixed);
 if(offerDigest!==pinnedOfferDigest)fail('The offer changed since you reviewed it. Do not start the swap.');
 if(!['bitcoin','cardano','ethereum'].includes(fixed.give.chain)||!['bitcoin','cardano','ethereum'].includes(fixed.receive.chain)||fixed.give.chain===fixed.receive.chain)fail('This guided session cannot yet support that pair.');
 const session=await deriveSessionId(fixed.id,reservation),key=`hegemon.swap.session-start.v1:${session}:${role}`;
 const lock=fn=>locks.request(key,{mode:'exclusive'},fn);
 const initial={version:1,session,role,offer:fixed,offerDigest,reservation,credential,sessionExpires:null,channelKey:null,handshake:null};
 function read(){
  const raw=storage.getItem(key);if(raw===null)return null;
  let item;try{item=JSON.parse(raw);}catch{fail('Saved session setup is invalid.');}
  if(!item||Object.keys(item).sort().join(',')!==Object.keys(initial).sort().join(',')||item.version!==1||item.session!==session||item.role!==role||item.offerDigest!==offerDigest||item.reservation!==reservation||item.credential!==credential||canonical(item.offer)!==canonical(fixed)||!(item.sessionExpires===null||Number.isSafeInteger(item.sessionExpires)&&item.sessionExpires>0)||!(item.channelKey===null||typeof item.channelKey==='string'&&HEX.test(item.channelKey))||!(item.handshake===null||typeof item.handshake==='string'&&parsePublicSession(item.handshake)))fail('Saved session setup is invalid.');
  if((item.channelKey===null)!==(item.handshake===null))fail('Saved session setup is incomplete.');
  if(item.handshake){const parsed=parsePublicSession(item.handshake);if(parsed.offer!==fixed.id||parsed.reservation!==reservation)fail('Saved session setup names a different offer.');}
  return item;
 }
 function save(item){storage.setItem(key,JSON.stringify(item));}
 const outbox=sessionOutbox({session,role,storage,locks,send:frame=>api(`/swap-sessions/${session}/packets`,{method:'POST',headers:auth(credential),body:JSON.stringify(frame)})});
 async function sessionInfo(){
  let value;
  if(role==='owner'){
   try{value=await api(`/offers/${fixed.id}/session`,{method:'POST',headers:auth(credential),body:JSON.stringify({reservationId:reservation})});}
   catch(error){try{value=await api(`/swap-sessions/${session}`,{headers:auth(credential)});}catch{throw error;}}
  }else value=await api(`/swap-sessions/${session}`,{headers:auth(credential)});
  if(!value||value.id!==session||value.offerId!==fixed.id||value.reservationId!==reservation||!Number.isSafeInteger(value.expires)||value.expires<=clock()||await sessionOfferDigest(fixedOffer(value.offer))!==offerDigest)fail('The relay returned a different or expired session.');
  return value;
 }
 async function channel(item){
  if(role==='taker'){
   if(!item.handshake){const value=await createChannelHandshake({session,offer:fixed.id,reservation,ownerPublicKey:fixed.ownerPublicKey});item={...item,channelKey:value.key,handshake:value.handshake};save(item);}
   let state=await outbox.inspect();
   if(state.pending){await outbox.retry();state=await outbox.inspect();}
   if(state.next===1){await outbox.enqueue(({sequence,previous})=>{if(sequence!==1||previous!==null)fail('The session message order changed.');return {ciphertext:item.handshake,previousAfter:null};});state=await outbox.inspect();}
   if(state.pending||state.next!==2||state.previous!==null)fail('The session message order changed.');
   const rows=await readSessionFrames({session,credential,api}),matches=rows.filter(row=>row.sender==='taker'&&row.sequence===1);
   if(matches.length!==1||matches[0].ciphertext!==item.handshake)fail('The relay did not retain the channel handshake.');
   return item;
  }
  const rows=await readSessionFrames({session,credential,api}),matches=rows.filter(row=>row.sender==='taker'&&row.sequence===1);
  if(!matches.length){if(item.handshake)fail('The relay omitted the saved channel handshake.');return null;}
  if(item.handshake){if(matches.length!==1||matches[0].ciphertext!==item.handshake)fail('The relay changed the saved channel handshake.');return item;}
  if(matches.length!==1||typeof inboxPrivateKey!=='function')fail('The other participant\'s channel setup is invalid.');
  const value=await openChannelHandshake({session,offer:fixed.id,reservation,ownerPublicKey:fixed.ownerPublicKey,privateInboxKey:await inboxPrivateKey(fixed.ownerPublicKey),handshake:matches[0].ciphertext});
  item={...item,channelKey:value.key,handshake:matches[0].ciphertext};save(item);return item;
 }
 return Object.freeze({session,role,outbox,
  /** Without a passphrase this checks the relay and returns the next setup
   * state. With one, it creates and durably saves the encrypted backup. */
  advance(passphrase){return lock(async()=>{
   const existing=await getSession(session,role);
   if(existing){if(existing.snapshot.offerDigest!==offerDigest||existing.snapshot.reservation!==reservation||existing.snapshot.credential!==credential)fail('The saved session belongs to different offer terms.');return {stage:'ready',session,revision:existing.revision,envelope:existing.envelope};}
   let item=read();if(!item){item=initial;save(item);} // Before a request that could close the offer.
   const info=await sessionInfo();
   if(item.sessionExpires!==null&&item.sessionExpires!==info.expires)fail('The session expiry changed.');
   if(item.sessionExpires===null){item={...item,sessionExpires:info.expires};save(item);}
   item=await channel(item);if(!item)return {stage:'waiting-for-other',session};
   if(passphrase===undefined)return {stage:'backup-required',session};
   const state=await outbox.inspect();if(state.pending||state.previous!==null||state.next!==(role==='owner'?1:2))fail('The session message order changed.');
   const blank=()=>({fund:[],claim:[],refund:[]});
   const hegemon=[fixed.give.chain,fixed.receive.chain].includes('hegemon'),emptyHegemon=()=>({fund:null,claim:null,refund:null});
   const snapshot={version:hegemon?4:3,offer:fixed,offerDigest,reservation,credential,channelKey:item.channelKey,sessionExpires:info.expires,terms:null,escrows:{long:null,short:null},secretEnvelope:null,ownerBlob:null,takerBlob:null,transport:{next:state.next,previous:null},actions:{long:blank(),short:blank()},...(hegemon?{hegemon:{long:emptyHegemon(),short:emptyHegemon()}}:{})};
   const recovery=await createSessionRecovery({session,role,snapshot,passphrase});
   const record=await addSession(recovery.envelope,passphrase);
   storage.removeItem(key);
   return {stage:'ready',session,revision:record.revision,envelope:record.envelope};
  });},
 });
}
