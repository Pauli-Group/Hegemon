/** Safe, idempotent local coordination helpers. They never request wallet
 * signatures or submit blockchain transactions. The caller supplies an
 * authenticated relay reader and a durable outbox for the selected session. */
import {channelFingerprint,sealParticipantFrame,openParticipantFrame,sealPacketFrame,openPacketFrame} from './session-channel.mjs';
import {replayOwnFrames} from './session-replay.mjs';
import {getSession,updateSession,sessionBackupCurrent} from './session-store.mjs';
import {verifyParticipant} from './session-identity.mjs';
import {checkSessionProposal,sessionTermsDigest,signPacket,packetDigest} from './session-packets.mjs';
import {canonical} from './identity.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';

async function load(session,role){
 const record=await getSession(session,role);
 if(!record||![2,3,4].includes(record.snapshot.version))throw Error('A recoverable swap session is required.');
 return record;
}
function sameTransport(saved,current){return saved.next===current.next&&saved.previous===current.previous;}

/** Re-read and authenticate the sender's complete history before advancing its
 * backed-up high-water mark. A relay acknowledgement alone is not enough. */
export async function syncSessionTransport({session,role,outbox,readFrames,now}){
 if(outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'||!Number.isSafeInteger(now))throw Error('The matching session outbox and history reader are required.');
 const record=await load(session,role),local=await outbox.inspect();
 if(local.pending)throw Error('Retry the pending session message first.');
 const frames=await readFrames({session,credential:record.snapshot.credential});
 const replay=await replayOwnFrames({session,role,snapshot:record.snapshot,publicKey:record.publicKey,frames,now});
 if(replay.next!==local.next||replay.previous!==local.previous)throw Error('The relay and local session history do not match.');
 const field=role==='owner'?'ownerBlob':'takerBlob';
 const snapshot={...record.snapshot,transport:{next:local.next,previous:local.previous},[field]:record.snapshot[field]??replay.ownBlob};
 return updateSession(session,role,record.revision,snapshot);
}

/** Publish the participant statement already saved in the local snapshot.
 * Its exact encrypted frame is committed to the outbox before the POST. */
export async function publishSessionParticipant({session,role,outbox,readFrames,now}){
 if(outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'||!Number.isSafeInteger(now))throw Error('The matching session outbox and history reader are required.');
 const record=await load(session,role),snapshot=record.snapshot,field=role==='owner'?'ownerBlob':'takerBlob',blob=snapshot[field];
 if(!blob)throw Error('Prepare and save both wallet proofs first.');
 const before=await outbox.inspect();
 if(before.pending||!sameTransport(snapshot.transport,before))throw Error('Synchronize the local session history first.');
 const expectedSequence=role==='owner'?1:2;
 if(before.next!==expectedSequence||before.previous!==null)throw Error('This participant statement was already sent or the channel is not ready.');
 const channelDigest=await channelFingerprint(session,snapshot.channelKey);
 const expected={session,role,offer:snapshot.offer.id,reservation:snapshot.reservation,offerDigest:snapshot.offerDigest,channelDigest,assets:{give:snapshot.offer.give,receive:snapshot.offer.receive},sessionExpires:snapshot.sessionExpires};
 const participant=await verifyParticipant(blob,expected,now);
 if(participant.statement.protocolKey!==record.publicKey)throw Error('The wallet proofs name a different protocol key.');
 await outbox.enqueue(async({sequence,previous})=>{
  if(sequence!==expectedSequence||previous!==null)throw Error('The session changed in another tab. Refresh before continuing.');
  const ciphertext=await sealParticipantFrame(snapshot.channelKey,{session,role,sequence},blob,expected,now);
  return {ciphertext,previousAfter:null};
 });
 return syncSessionTransport({session,role,outbox,readFrames,now});
}

/** A lost response retries the saved ciphertext only; reconciliation is still
 * required before the user can create another message or fund an escrow. */
export async function retrySessionMessage({session,role,outbox,readFrames,now}){
 if(outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'||!Number.isSafeInteger(now))throw Error('The matching session outbox and history reader are required.');
 await outbox.retry();
 return syncSessionTransport({session,role,outbox,readFrames,now});
}

/** Decrypt and authenticate the other participant's complete ordered packet
 * history against the immutable wallet proofs stored in this browser. */
export async function readPeerSessionPackets({session,role,readFrames,now}){
 if(typeof readFrames!=='function'||!Number.isSafeInteger(now))throw Error('A session history reader is required.');
 const record=await load(session,role),snapshot=record.snapshot,peer=role==='owner'?'taker':'owner',certSequence=peer==='owner'?1:2,peerBlob=peer==='owner'?snapshot.ownerBlob:snapshot.takerBlob;
 if(!peerBlob)throw Error('The other participant’s wallet proofs are not saved.');
 const frames=await readFrames({session,credential:snapshot.credential});
 if(!Array.isArray(frames)||frames.length>512)throw Error('Invalid session history.');
 const own=frames.filter(frame=>frame?.sender===peer).sort((a,b)=>a.sequence-b.sequence);
 for(let i=0;i<own.length;i++)if(own[i].sequence!==i+1)throw Error('The other participant’s message history is incomplete.');
 if(own.length<certSequence)throw Error('The other participant’s signed details are unavailable.');
 const channelDigest=await channelFingerprint(session,snapshot.channelKey),expected={session,role:peer,offer:snapshot.offer.id,reservation:snapshot.reservation,offerDigest:snapshot.offerDigest,channelDigest,assets:{give:snapshot.offer.give,receive:snapshot.offer.receive},sessionExpires:snapshot.sessionExpires};
 const cert=await openParticipantFrame(snapshot.channelKey,{session,role:peer,sequence:certSequence},own[certSequence-1].ciphertext,expected,now);
 if(canonical(JSON.parse(peerBlob))!==canonical(JSON.parse(cert.blob)))throw Error('The other participant’s signed details changed.');
 let previous=null,sequence=0;const packets=[];
 for(let i=certSequence;i<own.length;i++){
  const opened=await openPacketFrame(snapshot.channelKey,{session,role:peer,sequence:i+1},own[i].ciphertext,{session,role:peer,sequence:++sequence,previous,publicKey:cert.statement.protocolKey});
  previous=opened.digest;packets.push(opened);
 }
 return packets;
}

/** Publish the first proposal or its acceptance. Both parties' wallet proofs,
 * exact terms, current backup and the peer's proposal (for acceptance) must
 * already be saved. Escrow announcements and cancellation are separate steps. */
export async function publishSessionAgreement({session,role,outbox,readFrames,now,allowUnverifiedHegemon=false}){
 if(outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'||!Number.isSafeInteger(now))throw Error('The matching session outbox and history reader are required.');
 const record=await load(session,role),snapshot=record.snapshot;
 if(!record.backupAcknowledged||!await sessionBackupCurrent(record)||!snapshot.terms||!snapshot.ownerBlob||!snapshot.takerBlob)throw Error('Save the current recovery backup and both participants before continuing.');
 const channelDigest=await channelFingerprint(session,snapshot.channelKey);
 const checked=await checkSessionProposal(snapshot.terms,{offer:snapshot.offer,expectedOfferDigest:snapshot.offerDigest,channelDigest,ownerBlob:snapshot.ownerBlob,takerBlob:snapshot.takerBlob,session,reservation:snapshot.reservation,sessionExpires:snapshot.sessionExpires,now});
 if(checked.unverifiedHegemon&&allowUnverifiedHegemon!==true)throw Error('Review the Hegemon address proof limitation before continuing.');
 const state=await outbox.inspect(),expectedSequence=role==='owner'?2:3;
 if(state.pending||!sameTransport(snapshot.transport,state)||state.next!==expectedSequence||state.previous!==null)throw Error('Synchronize the session history before agreeing.');
 if(role==='taker'){
  const peer=await readPeerSessionPackets({session,role,readFrames,now});
  if(peer.length!==1||peer[0].body.payload.type!=='proposal'||canonical(peer[0].body.payload.terms)!==canonical(snapshot.terms))throw Error('The other participant’s signed proposal does not match these terms.');
 }
 const payload=role==='owner'?{type:'proposal',terms:snapshot.terms}:{type:'accept',termsDigest:await sessionTermsDigest(snapshot.terms)};
 await outbox.enqueue(async({sequence,previous})=>{
  if(sequence!==expectedSequence||previous!==null)throw Error('The session changed in another tab. Refresh before continuing.');
  const packet=await signPacket(record.privateKey,{session,role,sequence:1,previous,payload});
  const context={session,role,sequence},expected={session,role,sequence:1,previous,publicKey:record.publicKey};
  return {ciphertext:await sealPacketFrame(snapshot.channelKey,context,packet,expected),previousAfter:await packetDigest(packet.body)};
 });
 return syncSessionTransport({session,role,outbox,readFrames,now});
}

/** Announce only an independently verified, confirmed escrow. The local
 * reference and the updated recovery backup must already be durable. */
export async function publishSessionEscrow({session,role,outbox,readFrames,now,readers,config,templates,allowUnverifiedHegemon=false}){
 if(outbox?.session!==session||outbox?.role!==role||typeof readFrames!=='function'||!Number.isSafeInteger(now))throw Error('The matching session outbox and history reader are required.');
 const record=await load(session,role),snapshot=record.snapshot,own=role==='owner'?'long':'short',expectedSequence=role==='owner'?3:4;
 if(!record.backupAcknowledged||!await sessionBackupCurrent(record)||!snapshot.terms||!snapshot.escrows[own])throw Error('Save the current escrow reference in your recovery backup first.');
 const local=await outbox.inspect();
 if(local.pending||!sameTransport(snapshot.transport,local)||local.next!==expectedSequence||local.previous===null)throw Error('Synchronize the signed message history before continuing.');
 const peer=await readPeerSessionPackets({session,role,readFrames,now}),digest=await sessionTermsDigest(snapshot.terms);
 if(role==='owner'){
  if(peer.length!==1||peer[0].body.payload.type!=='accept'||peer[0].body.payload.termsDigest!==digest)throw Error('The other participant has not accepted these terms.');
 }else{
  if(peer.length!==2||peer[0].body.payload.type!=='proposal'||canonical(peer[0].body.payload.terms)!==canonical(snapshot.terms)||peer[1].body.payload.type!=='escrow'||peer[1].body.payload.leg!=='long'||peer[1].body.payload.termsDigest!==digest||canonical(peer[1].body.payload.reference)!==canonical(snapshot.escrows.long))throw Error('The first escrow announcement does not match the agreed terms.');
 }
 await verifySessionSnapshot({terms:snapshot.terms,offer:snapshot.offer,expectedOfferDigest:snapshot.offerDigest,channelDigest:await channelFingerprint(session,snapshot.channelKey),ownerBlob:snapshot.ownerBlob,takerBlob:snapshot.takerBlob,session,reservation:snapshot.reservation,sessionExpires:snapshot.sessionExpires,role:role==='owner'?'initiator':'responder',references:snapshot.escrows,purpose:role==='owner'?'verify_first':'verify_both',readers,config,now,templates,allowUnverifiedHegemon});
 const payload={type:'escrow',termsDigest:digest,leg:own,reference:snapshot.escrows[own]};
 await outbox.enqueue(async({sequence,previous})=>{
  if(sequence!==expectedSequence||previous!==local.previous)throw Error('The session changed in another tab. Refresh before continuing.');
  const packet=await signPacket(record.privateKey,{session,role,sequence:2,previous,payload});
  return {ciphertext:await sealPacketFrame(snapshot.channelKey,{session,role,sequence},packet,{session,role,sequence:2,previous,publicKey:record.publicKey}),previousAfter:await packetDigest(packet.body)};
 });
 return syncSessionTransport({session,role,outbox,readFrames,now});
}
