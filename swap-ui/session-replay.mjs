/** Reconstruct one participant's sent packet history after restoring a backup.
 * The relay is untrusted: a participant frame is checked against both wallet
 * signatures and the locally saved offer/channel, and every following frame
 * must carry the certified protocol key and exact signed hash chain. Missing
 * or altered history never establishes a usable next sequence. */
import {channelFingerprint,openParticipantFrame,openPacketFrame} from './session-channel.mjs';
import {parsePublicSession} from './public-inbox.mjs';
import {validateSessionSnapshot} from './session-recovery.mjs';
import {canonical} from './identity.mjs';

const fail=message=>{throw Error(message);};
export async function replayOwnFrames({session,role,snapshot,publicKey,frames,now}){
 if(!['owner','taker'].includes(role)||!Array.isArray(frames)||frames.length>512||frames.some(row=>!row||!['owner','taker'].includes(row.sender)||!Number.isSafeInteger(row.sequence)||row.sequence<1||row.sequence>256||typeof row.ciphertext!=='string')||!Number.isSafeInteger(now)||typeof publicKey!=='string'||!/^04[0-9a-f]{128}$/.test(publicKey))fail('Invalid session history.');
 await validateSessionSnapshot(snapshot,session);
 if(snapshot.version!==2)fail('This older backup has no authenticated packet history; recover manually.');
 const own=frames.filter(row=>row?.sender===role).slice().sort((a,b)=>a.sequence-b.sequence);
 if(own.length>256)fail('Invalid session history.');
 for(let i=0;i<own.length;i++)if(!Number.isSafeInteger(own[i].sequence)||own[i].sequence!==i+1||typeof own[i].ciphertext!=='string')fail('Session packet history is incomplete or duplicated.');
 const {offer,reservation,offerDigest,channelKey,sessionExpires}=snapshot;
 let index=0,previous=null,packetSequence=0,ownBlob=null;
 const history=new Map([[1,null]]);
 if(role==='taker'&&own.length){
  const handshake=parsePublicSession(own[0].ciphertext);
  if(!handshake||handshake.offer!==offer.id||handshake.reservation!==reservation)fail('The saved channel handshake is invalid.');
  index=1;
  history.set(index+1,previous);
 }
 if(own.length>index){
  const channelDigest=await channelFingerprint(session,channelKey),ctx={session,role,sequence:index+1};
  const expected={session,role,offer:offer.id,reservation,offerDigest,channelDigest,assets:{give:offer.give,receive:offer.receive},sessionExpires};
  const participant=await openParticipantFrame(channelKey,ctx,own[index].ciphertext,expected,now);
  if(participant.statement.protocolKey!==publicKey)fail('The saved participant signing key does not match.');
  ownBlob=participant.blob;
  const saved=role==='owner'?snapshot.ownerBlob:snapshot.takerBlob;
  if(saved!==null){let a,b;try{a=JSON.parse(saved);b=JSON.parse(ownBlob);}catch{fail('The saved participant statement is invalid.');}if(canonical(a)!==canonical(b))fail('The participant statement differs from the recovery backup.');}
  index++;
  history.set(index+1,previous);
 }
 const certificateSequence=role==='owner'?1:2;
 if(!ownBlob&&(role==='owner'?snapshot.ownerBlob:snapshot.takerBlob)!==null&&snapshot.transport.next>certificateSequence)fail('The relay is missing the saved participant statement.');
 for(;index<own.length;index++){
  const ctx={session,role,sequence:index+1};
  const packet=await openPacketFrame(channelKey,ctx,own[index].ciphertext,{session,role,sequence:++packetSequence,previous,publicKey});
  previous=packet.digest;
  history.set(index+2,previous);
 }
 const savedHistory=snapshot.transport;
 if(!history.has(savedHistory.next)||history.get(savedHistory.next)!==savedHistory.previous)fail('The relay omitted or changed packet history recorded in the backup.');
 return {next:own.length+1,previous,packetSequence,ownBlob};
}
