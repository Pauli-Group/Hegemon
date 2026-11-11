/** Confidential transport for wallet-bound coordination statements and signed packets.
 *
 * A new channel key is generated independently of the offer link, then encrypted to the offer maker's inbox key. Both
 * participants must bind its digest in their wallet-signed participant statements before trusting messages. Callers must
 * durably save the channel key and the exact outgoing ciphertext before POST so a lost response never creates a different
 * packet at the same transport sequence. This module never signs or submits a blockchain transaction. */
import {newMessageKey} from './crypto.mjs';
import {openPublicSession,parsePublicSession,sealPublicSession} from './public-inbox.mjs';
import {deriveSessionId,verifyParticipant} from './session-identity.mjs';
import {verifyPacket} from './session-packets.mjs';
import {fromHex,toHex} from './cbor.mjs';

const HEX64=/^[0-9a-f]{64}$/,PREFIX='hegemon.swap.session-channel.v1';
const enc=new TextEncoder(),dec=new TextDecoder('utf-8',{fatal:true});
const keys=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const fail=message=>{throw Error(message);};
const encode64=bytes=>btoa(Array.from(bytes,byte=>String.fromCharCode(byte)).join(''));
function context(value){
 if(!keys(value,['session','role','sequence'])||typeof value.session!=='string'||!HEX64.test(value.session)||!['owner','taker'].includes(value.role)||!Number.isSafeInteger(value.sequence)||value.sequence<1||value.sequence>256)fail('Invalid channel context.');
 return value;
}
function additionalData(ctx,type){context(ctx);return enc.encode([PREFIX,ctx.session,ctx.role,String(ctx.sequence),type].join('\n'));}
async function aes(key,usage){
 if(typeof key!=='string'||!HEX64.test(key))fail('Invalid channel key.');
 const bytes=fromHex(key);try{return await crypto.subtle.importKey('raw',bytes,'AES-GCM',false,[usage]);}finally{bytes.fill(0);}
}
export async function channelFingerprint(session,key){
 if(typeof session!=='string'||!HEX64.test(session)||typeof key!=='string'||!HEX64.test(key))fail('Invalid channel binding.');
 return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(PREFIX+'\n'+session+'\n'+key))));
}

/** The taker creates one independent key. Retain and retry these exact bytes if posting is uncertain. */
export async function createChannelHandshake({session,offer,reservation,ownerPublicKey}){
 if(session!==await deriveSessionId(offer,reservation))fail('The channel is for a different session.');
 const key=newMessageKey(),handshake=await sealPublicSession(ownerPublicKey,offer,reservation,key);
 return {key,handshake,channelDigest:await channelFingerprint(session,key)};
}
/** The maker opens a taker's handshake only with its locally stored inbox private key. */
export async function openChannelHandshake({session,offer,reservation,ownerPublicKey,privateInboxKey,handshake}){
 if(session!==await deriveSessionId(offer,reservation))fail('The channel is for a different session.');
 const parsed=parsePublicSession(handshake);
 if(!parsed||parsed.offer!==offer||parsed.reservation!==reservation)fail('Invalid channel handshake.');
 const key=await openPublicSession(privateInboxKey,ownerPublicKey,offer,reservation,handshake);
 return {key,channelDigest:await channelFingerprint(session,key)};
}

async function seal(key,ctx,type,value){
 const plain=enc.encode(JSON.stringify({version:1,type,value}));
 if(plain.length>8900)fail('The coordination message is too large.');
 const iv=crypto.getRandomValues(new Uint8Array(12));
 try{
  const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:additionalData(ctx,type)},await aes(key,'encrypt'),plain));
  const bytes=new Uint8Array(iv.length+encrypted.length);bytes.set(iv);bytes.set(encrypted,iv.length);
  const encoded=encode64(bytes);if(encoded.length>12000)fail('The encrypted coordination message is too large.');return encoded;
 }finally{plain.fill(0);iv.fill(0);}
}
async function open(key,ctx,type,encoded){
 if(typeof encoded!=='string'||encoded.length>12000||encoded.length%4||!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))fail('Invalid encrypted coordination message.');
 let bytes;try{bytes=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));}catch{fail('Invalid encrypted coordination message.');}
 if(bytes.length<28||encode64(bytes)!==encoded)fail('Invalid encrypted coordination message.');
 let plain;
 try{plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(0,12),additionalData:additionalData(ctx,type)},await aes(key,'decrypt'),bytes.slice(12)));}
 catch{fail('Could not authenticate the coordination message.');}
 try{
  let value;try{value=JSON.parse(dec.decode(plain));}catch{fail('Invalid coordination message.');}
  if(!keys(value,['version','type','value'])||value.version!==1||value.type!==type)fail('Invalid coordination message.');
  return value.value;
 }finally{plain.fill(0);bytes.fill(0);}
}

/** Participant statements are wallet-verified before they are encrypted or accepted. */
export async function sealParticipantFrame(key,ctx,blob,expected,now){
 const participant=await verifyParticipant(blob,expected,now);
 if(participant.statement.session!==ctx.session||participant.statement.role!==ctx.role||participant.statement.channelDigest!==await channelFingerprint(ctx.session,key))fail('Participant does not bind this channel.');
 return seal(key,ctx,'participant',blob);
}
export async function openParticipantFrame(key,ctx,ciphertext,expected,now){
 const blob=await open(key,ctx,'participant',ciphertext),participant=await verifyParticipant(blob,expected,now);
 if(participant.statement.session!==ctx.session||participant.statement.role!==ctx.role||participant.statement.channelDigest!==await channelFingerprint(ctx.session,key))fail('Participant does not bind this channel.');
 return {...participant,blob};
}

/** Signed packets are verified against the sender's already wallet-certified protocol key before use. */
export async function sealPacketFrame(key,ctx,packet,expected){
 if(expected.session!==ctx.session||expected.role!==ctx.role)fail('Packet does not bind this channel.');
 await verifyPacket(packet,expected);
 return seal(key,ctx,'packet',packet);
}
export async function openPacketFrame(key,ctx,ciphertext,expected){
 if(expected.session!==ctx.session||expected.role!==ctx.role)fail('Packet does not bind this channel.');
 return verifyPacket(await open(key,ctx,'packet',ciphertext),expected);
}
