import test from 'node:test';
import assert from 'node:assert/strict';
import {makeInboxKeyPair} from './public-inbox.mjs';
import {bitcoinProof,signEthereum} from './identity-flow.mjs';
import {bitcoinMessageWallet,ethereumWallet} from './test-wallets.mjs';
import {buildParticipant,deriveSessionId,participantText,serializeParticipant,sessionOfferDigest} from './session-identity.mjs';
import {createProtocolKey,signPacket} from './session-packets.mjs';
import {channelFingerprint,createChannelHandshake,openChannelHandshake,openPacketFrame,openParticipantFrame,sealPacketFrame,sealParticipantFrame} from './session-channel.mjs';

const now=1800000000,offerId='11'.repeat(32),reservation='22'.repeat(32),btc=bitcoinMessageWallet('01'.repeat(32)),eth=ethereumWallet('02'.repeat(32));
async function setup(){
 const inbox=await makeInboxKeyPair(),session=await deriveSessionId(offerId,reservation);
 const offer={id:offerId,visibility:'private',expires:now+3600,ownerPublicKey:inbox.publicKey,
  give:{chain:'bitcoin',kind:'btc',id:'',amount:'1000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'2000'}};
 const taker=await createChannelHandshake({session,offer:offerId,reservation,ownerPublicKey:inbox.publicKey});
 const owner=await openChannelHandshake({session,offer:offerId,reservation,ownerPublicKey:inbox.publicKey,privateInboxKey:inbox.privateKey,handshake:taker.handshake});
 const key=await createProtocolKey(),digest=await sessionOfferDigest(offer),assets={give:offer.give,receive:offer.receive};
 const statement=buildParticipant({session,offer:offerId,reservation,role:'taker',offerDigest:digest,channelDigest:taker.channelDigest,protocolKey:key.publicKey,addresses:{give:btc.publicKey,receive:eth.address},issued:now,expires:now+7200},assets);
 const text=participantText(statement),provider={request:async({params})=>eth.personalSign(params[0])};
 const blob=serializeParticipant(statement,[bitcoinProof('bip137',btc.sign(text),text),await signEthereum(provider,eth.address,text)]);
 const expected={session,offer:offerId,reservation,role:'taker',offerDigest:digest,channelDigest:taker.channelDigest,assets,sessionExpires:now+10000};
 return {inbox,session,offer,taker,owner,key,blob,expected};
}

test('an independent session key is exchanged only through the maker inbox',async()=>{
 const x=await setup();assert.equal(x.owner.key,x.taker.key);assert.equal(x.owner.channelDigest,x.taker.channelDigest);
 assert.equal(x.taker.channelDigest,await channelFingerprint(x.session,x.taker.key));
 const other=await makeInboxKeyPair();
 await assert.rejects(openChannelHandshake({session:x.session,offer:offerId,reservation,ownerPublicKey:x.inbox.publicKey,privateInboxKey:other.privateKey,handshake:x.taker.handshake}),/authenticate/i);
 await assert.rejects(openChannelHandshake({session:'ff'.repeat(32),offer:offerId,reservation,ownerPublicKey:x.inbox.publicKey,privateInboxKey:x.inbox.privateKey,handshake:x.taker.handshake}),/different session/);
 const bad=x.taker.handshake.slice(0,-4)+'AAAA';
 await assert.rejects(openChannelHandshake({session:x.session,offer:offerId,reservation,ownerPublicKey:x.inbox.publicKey,privateInboxKey:x.inbox.privateKey,handshake:bad}),/handshake|authenticate/i);
});

test('participant frames require valid wallet proofs and bind the session key and transport sequence',async()=>{
 const x=await setup(),ctx={session:x.session,role:'taker',sequence:2};
 const ciphertext=await sealParticipantFrame(x.taker.key,ctx,x.blob,x.expected,now);
 const decoded=await openParticipantFrame(x.owner.key,ctx,ciphertext,x.expected,now);
 assert.equal(decoded.statement.protocolKey,x.key.publicKey);assert.deepEqual(decoded.proven,{give:true,receive:true});
 assert.equal(Buffer.from(ciphertext,'base64').includes(Buffer.from(btc.publicKey)),false);
 await assert.rejects(openParticipantFrame('ff'.repeat(32),ctx,ciphertext,x.expected,now),/authenticate/);
 await assert.rejects(openParticipantFrame(x.owner.key,{...ctx,sequence:3},ciphertext,x.expected,now),/authenticate/);
 await assert.rejects(openParticipantFrame(x.owner.key,{...ctx,role:'owner'},ciphertext,x.expected,now),/authenticate/);
 await assert.rejects(openParticipantFrame(x.owner.key,ctx,ciphertext,{...x.expected,offerDigest:'ff'.repeat(32)},now),/does not match/);
 const tampered=ciphertext.slice(0,-4)+(ciphertext.endsWith('AAAA')?'BBBB':'AAAA');
 await assert.rejects(openParticipantFrame(x.owner.key,ctx,tampered,x.expected,now),/authenticate|invalid encrypted/i);
});

test('only authenticated signed packets can be exchanged; a link key cannot decrypt them',async()=>{
 const x=await setup(),ctx={session:x.session,role:'taker',sequence:3};
 const packet=await signPacket(x.key.privateKey,{session:x.session,role:'taker',sequence:1,previous:null,payload:{type:'accept',termsDigest:'ab'.repeat(32)}});
 const expected={session:x.session,role:'taker',sequence:1,previous:null,publicKey:x.key.publicKey};
 const ciphertext=await sealPacketFrame(x.taker.key,ctx,packet,expected),opened=await openPacketFrame(x.owner.key,ctx,ciphertext,expected);
 assert.deepEqual(opened.body.payload,{type:'accept',termsDigest:'ab'.repeat(32)});
 await assert.rejects(openPacketFrame('ee'.repeat(32),ctx,ciphertext,expected),/authenticate/);
 await assert.rejects(openPacketFrame(x.owner.key,ctx,ciphertext,{...expected,sequence:2}),/different session, role, or sequence/);
 await assert.rejects(sealPacketFrame(x.taker.key,{...ctx,role:'owner'},packet,expected),/bind this channel/);
});
