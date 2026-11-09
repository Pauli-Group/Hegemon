import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import worker from './cloudflare/worker.mjs';
import {makeInboxKeyPair} from '../swap-ui/public-inbox.mjs';
import {bitcoinProof,signEthereum} from '../swap-ui/identity-flow.mjs';
import {bitcoinMessageWallet,ethereumWallet} from '../swap-ui/test-wallets.mjs';
import {buildParticipant,deriveSessionId,participantText,serializeParticipant,sessionOfferDigest} from '../swap-ui/session-identity.mjs';
import {checkFundingPolicy,checkSessionProposal,createProtocolKey,sessionTermsDigest,signPacket} from '../swap-ui/session-packets.mjs';
import {createChannelHandshake,openChannelHandshake,openPacketFrame,openParticipantFrame,sealPacketFrame,sealParticipantFrame} from '../swap-ui/session-channel.mjs';
import {validateTiming} from '../swap-ui/timelock-policy.mjs';

function database(){
 const raw=new DatabaseSync(':memory:');raw.exec(readFileSync(new URL('./cloudflare/schema.sql',import.meta.url),'utf8'));
 return {raw,async batch(statements){raw.exec('BEGIN');try{const out=[];for(const s of statements)out.push(await s.run());raw.exec('COMMIT');return out;}catch(e){raw.exec('ROLLBACK');throw e;}},
  prepare(sql){const q=raw.prepare(sql);let values=[];return {bind(...v){values=v;return this;},async first(){return q.get(...values)??null;},async all(){return {results:q.all(...values)};},async run(){return q.run(...values);}};}};
}
function client(db){const env={DB:db,ASSETS:{fetch:async()=>new Response('board')}};return async(path,{method='GET',token,data}={})=>{
 const headers={'CF-Connecting-IP':'192.0.2.42',origin:'https://swap.example'};if(token)headers.authorization='Bearer '+token;if(data)headers['content-type']='application/json';
 const response=await worker.fetch(new Request('https://swap.example'+path,{method,headers,...(data?{body:JSON.stringify(data)}:{})}),env);
 return [response.status,await response.json()];};}
async function person({session,offer,reservation,role,key,channelDigest,btc,eth,now}){
 const digest=await sessionOfferDigest(offer),assets={give:offer.give,receive:offer.receive};
 const statement=buildParticipant({session,offer:offer.id,reservation,role,offerDigest:digest,channelDigest,protocolKey:key.publicKey,addresses:{give:btc.publicKey,receive:eth.address},issued:now,expires:now+7200},assets);
 const text=participantText(statement),provider={request:async({method,params})=>{assert.equal(method,'personal_sign');return eth.personalSign(params[0]);}};
 return serializeParticipant(statement,[bitcoinProof('bip137',btc.sign(text),text),await signEthereum(provider,eth.address,text)]);
}

test('two parties exchange wallet-bound swap terms and references without chat or transactions',async()=>{
 const db=database(),call=client(db),ownerBtc=bitcoinMessageWallet('01'.repeat(32)),ownerEth=ethereumWallet('02'.repeat(32)),takerBtc=bitcoinMessageWallet('03'.repeat(32)),takerEth=ethereumWallet('04'.repeat(32));
 try{
  const now=Math.floor(Date.now()/1000),inbox=await makeInboxKeyPair(),give={chain:'bitcoin',kind:'btc',id:'',amount:'100000'},receive={chain:'ethereum',kind:'eth',id:'',amount:'1000000000000000000'};
  const [posted,owner]=await call('/offers',{method:'POST',data:{visibility:'public',expires:now+3600,give,receive,ownerPublicKey:inbox.publicKey}});assert.equal(posted,201);
  const [reserved,taker]=await call(`/offers/${owner.id}/reserve`,{method:'POST'});assert.equal(reserved,201);
  const [opened,session]=await call(`/offers/${owner.id}/session`,{method:'POST',token:owner.ownerToken,data:{reservationId:taker.reservationId}});assert.equal(opened,201);
  assert.equal(session.id,await deriveSessionId(owner.id,taker.reservationId));
  const path=`/swap-sessions/${session.id}/packets`,send=(token,sequence,ciphertext)=>call(path,{method:'POST',token,data:{sequence,ciphertext}});
  const hand=await createChannelHandshake({session:session.id,offer:owner.id,reservation:taker.reservationId,ownerPublicKey:inbox.publicKey});
  assert.equal((await send(taker.reservationToken,1,hand.handshake))[0],201);
  assert.equal((await send(taker.reservationToken,1,hand.handshake))[0],200,'retry uses the saved ciphertext');
  const ownerReceived=(await call(path,{token:owner.ownerToken}))[1].packets[0];
  const openedHand=await openChannelHandshake({session:session.id,offer:owner.id,reservation:taker.reservationId,ownerPublicKey:inbox.publicKey,privateInboxKey:inbox.privateKey,handshake:ownerReceived.ciphertext});
  assert.equal(openedHand.channelDigest,hand.channelDigest);
  const ownerKey=await createProtocolKey(),takerKey=await createProtocolKey(),offer=session.offer,digest=await sessionOfferDigest(offer),assets={give,receive};
  const ownerBlob=await person({session:session.id,offer,reservation:taker.reservationId,role:'owner',key:ownerKey,channelDigest:hand.channelDigest,btc:ownerBtc,eth:ownerEth,now});
  const takerBlob=await person({session:session.id,offer,reservation:taker.reservationId,role:'taker',key:takerKey,channelDigest:hand.channelDigest,btc:takerBtc,eth:takerEth,now});
  const base={session:session.id,offer:owner.id,reservation:taker.reservationId,offerDigest:digest,channelDigest:hand.channelDigest,assets,sessionExpires:session.expires};
  const ownerCtx={session:session.id,role:'owner',sequence:1},takerCtx={session:session.id,role:'taker',sequence:2};
  const ownerCert=await sealParticipantFrame(openedHand.key,ownerCtx,ownerBlob,{...base,role:'owner'},now);
  const takerCert=await sealParticipantFrame(hand.key,takerCtx,takerBlob,{...base,role:'taker'},now);
  assert.equal((await send(owner.ownerToken,1,ownerCert))[0],201);assert.equal((await send(taker.reservationToken,2,takerCert))[0],201);
  const all=(await call(path,{token:owner.ownerToken}))[1].packets;
  const ownerVerified=await openParticipantFrame(hand.key,ownerCtx,all.find(p=>p.sender==='owner').ciphertext,{...base,role:'owner'},now);
  const takerVerified=await openParticipantFrame(openedHand.key,takerCtx,all.find(p=>p.sender==='taker'&&p.sequence===2).ciphertext,{...base,role:'taker'},now);
  assert.equal(ownerVerified.statement.protocolKey,ownerKey.publicKey);assert.equal(takerVerified.statement.protocolKey,takerKey.publicKey);
  await assert.rejects(openParticipantFrame(hand.key,{...ownerCtx,role:'taker'},ownerCert,{...base,role:'owner'},now),/authenticate/);
  const terms={version:2,hashlock:'ab'.repeat(32),legs:{
   long:{asset:give,network:'testnet4',refundee:ownerBtc.publicKey,claimant:takerBtc.publicKey,expiry:150337},
   short:{asset:receive,network:'sepolia',refundee:takerEth.address,claimant:ownerEth.address,expiry:1800013951}}};
  const syntheticNow=1800000000,config=validateTiming(JSON.parse(readFileSync(new URL('../swap-ui/chain-timing.json',import.meta.url),'utf8')));
  const heads={long:{height:150000,observedAt:syntheticNow},short:{timestamp:syntheticNow-5,observedAt:syntheticNow}};
  const proposal=await signPacket(ownerKey.privateKey,{session:session.id,role:'owner',sequence:1,previous:null,payload:{type:'proposal',terms}});
  const ownerPacket={session:session.id,role:'owner',sequence:1,previous:null,publicKey:ownerVerified.statement.protocolKey},proposalCtx={session:session.id,role:'owner',sequence:2};
  const encryptedProposal=await sealPacketFrame(openedHand.key,proposalCtx,proposal,ownerPacket);assert.equal((await send(owner.ownerToken,2,encryptedProposal))[0],201);
  const acceptedProposal=await openPacketFrame(hand.key,proposalCtx,encryptedProposal,ownerPacket);
  const checked=await checkSessionProposal(acceptedProposal.body.payload.terms,{offer,expectedOfferDigest:digest,channelDigest:hand.channelDigest,ownerBlob,takerBlob,session:session.id,reservation:taker.reservationId,sessionExpires:session.expires,now});
  assert.equal(checkFundingPolicy(terms,{role:'initiator',heads,config,now:syntheticNow}).ok,true);
  const accept=await signPacket(takerKey.privateKey,{session:session.id,role:'taker',sequence:1,previous:null,payload:{type:'accept',termsDigest:checked.termsDigest}});
  const takerPacket={session:session.id,role:'taker',sequence:1,previous:null,publicKey:takerVerified.statement.protocolKey},acceptCtx={session:session.id,role:'taker',sequence:3};
  const encryptedAccept=await sealPacketFrame(hand.key,acceptCtx,accept,takerPacket);assert.equal((await send(taker.reservationToken,3,encryptedAccept))[0],201);
  assert.equal((await openPacketFrame(openedHand.key,acceptCtx,encryptedAccept,takerPacket)).body.payload.termsDigest,await sessionTermsDigest(terms));
  const escrow=await signPacket(ownerKey.privateKey,{session:session.id,role:'owner',sequence:2,previous:acceptedProposal.digest,payload:{type:'escrow',termsDigest:checked.termsDigest,leg:'long',reference:{chain:'bitcoin',txid:'44'.repeat(32),vout:0}}});
  const escrowCtx={session:session.id,role:'owner',sequence:3},nextOwnerPacket={...ownerPacket,sequence:2,previous:acceptedProposal.digest};
  const encryptedEscrow=await sealPacketFrame(openedHand.key,escrowCtx,escrow,nextOwnerPacket);assert.equal((await send(owner.ownerToken,3,encryptedEscrow))[0],201);
  assert.equal((await openPacketFrame(hand.key,escrowCtx,encryptedEscrow,nextOwnerPacket)).body.payload.reference.txid,'44'.repeat(32));
  db.raw.prepare('UPDATE offers SET expires=0,reservation_expires=0 WHERE id=?').run(owner.id);
  assert.equal((await call(`/swap-sessions/${session.id}`,{token:taker.reservationToken}))[0],200);
  assert.equal((await call(path,{token:taker.reservationToken}))[1].packets.length,6);
 }finally{db.raw.close();}
});
