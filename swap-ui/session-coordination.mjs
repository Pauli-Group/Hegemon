/** Safe, idempotent local coordination helpers. They never request wallet
 * signatures or submit blockchain transactions. The caller supplies an
 * authenticated relay reader and a durable outbox for the selected session. */
import {channelFingerprint,sealParticipantFrame} from './session-channel.mjs';
import {replayOwnFrames} from './session-replay.mjs';
import {getSession,updateSession} from './session-store.mjs';
import {verifyParticipant} from './session-identity.mjs';

async function load(session,role){
 const record=await getSession(session,role);
 if(!record||record.snapshot.version!==2)throw Error('A recoverable swap session is required.');
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
