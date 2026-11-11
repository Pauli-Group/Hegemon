import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import worker from './cloudflare/worker.mjs';
import {makeInboxKeyPair} from '../swap-ui/public-inbox.mjs';
import {bitcoinProof,signEthereum,signCardano} from '../swap-ui/identity-flow.mjs';
import {bitcoinMessageWallet,ethereumWallet,cardanoWallet} from '../swap-ui/test-wallets.mjs';
import {buildParticipant,deriveSessionId,participantText,serializeParticipant,sessionOfferDigest} from '../swap-ui/session-identity.mjs';
import {checkFundingPolicy,checkSessionProposal,createProtocolKey,sessionTermsDigest,signPacket} from '../swap-ui/session-packets.mjs';
import {createChannelHandshake,openChannelHandshake,openPacketFrame,openParticipantFrame,sealPacketFrame,sealParticipantFrame} from '../swap-ui/session-channel.mjs';
import {sessionOutbox} from '../swap-ui/session-outbox.mjs';
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
  const rows=new Map(),storage={getItem:key=>rows.get(key)??null,setItem:(key,value)=>rows.set(key,value)},locks={request:(_key,_options,fn)=>fn()};
  let loseResponse=true;
  const outbox=sessionOutbox({session:session.id,role:'taker',storage,locks,send:async frame=>{
   const [status,result]=await send(taker.reservationToken,frame.sequence,frame.ciphertext);
   assert.ok(status===201||status===200);
   if(loseResponse){loseResponse=false;throw Error('response lost after acceptance');}
   return result;
  }});
  await assert.rejects(outbox.enqueue(({sequence,previous})=>{assert.equal(sequence,1);assert.equal(previous,null);return {ciphertext:hand.handshake,previousAfter:null};}),/response lost/);
  assert.equal((await outbox.retry()).duplicate,true,'retry after a lost response uses the saved ciphertext');
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
  const openedEscrow=await openPacketFrame(hand.key,escrowCtx,encryptedEscrow,nextOwnerPacket);
  assert.equal(openedEscrow.body.payload.reference.txid,'44'.repeat(32));
  const cleanOffer={id:offer.id,visibility:offer.visibility,give:offer.give,receive:offer.receive,expires:offer.expires,ownerPublicKey:offer.ownerPublicKey};
  const snapshot={version:2,offer:cleanOffer,offerDigest:digest,reservation:taker.reservationId,credential:owner.ownerToken,channelKey:openedHand.key,sessionExpires:session.expires,terms,escrows:{long:{chain:'bitcoin',txid:'44'.repeat(32),vout:0},short:null},secretEnvelope:null,ownerBlob,takerBlob,transport:{next:4,previous:openedEscrow.digest}};
  const frames=(await call(path,{token:owner.ownerToken}))[1].packets;
  const freshRows=new Map(),freshStorage={getItem:key=>freshRows.get(key)??null,setItem:(key,value)=>freshRows.set(key,value)};
  const restored=sessionOutbox({session:session.id,role:'owner',storage:freshStorage,locks,send:async frame=>{
   const [status,result]=await send(owner.ownerToken,frame.sequence,frame.ciphertext);assert.ok(status===201||status===200);return result;
  }});
  await assert.rejects(restored.restore({snapshot,publicKey:ownerKey.publicKey,frames:frames.filter(frame=>!(frame.sender==='owner'&&frame.sequence===3)),now}),/omitted or changed/);
  const recovered=await restored.restore({snapshot,publicKey:ownerKey.publicKey,frames,now});
  assert.equal(recovered.next,4);assert.equal(recovered.previous,openedEscrow.digest);assert.equal(recovered.packetSequence,2);
  await restored.enqueue(async({sequence,previous})=>{
   assert.equal(sequence,4);assert.equal(previous,openedEscrow.digest);
   const packet=await signPacket(ownerKey.privateKey,{session:session.id,role:'owner',sequence:3,previous,payload:{type:'cancel',reason:'unavailable'}});
   const expected={session:session.id,role:'owner',sequence:3,previous,publicKey:ownerKey.publicKey};
   const ciphertext=await sealPacketFrame(openedHand.key,{session:session.id,role:'owner',sequence},packet,expected);
   const result=await openPacketFrame(hand.key,{session:session.id,role:'owner',sequence},ciphertext,expected);
   return {ciphertext,previousAfter:result.digest};
  });
  db.raw.prepare('UPDATE offers SET expires=0,reservation_expires=0 WHERE id=?').run(owner.id);
  assert.equal((await call(`/swap-sessions/${session.id}`,{token:taker.reservationToken}))[0],200);
  assert.equal((await call(path,{token:taker.reservationToken}))[1].packets.length,7);
 }finally{db.raw.close();}
});

test('Cardano and Ethereum participants bind the exact offer, channel and terms to both wallets', async () => {
 const db=database(), call=client(db);
 try {
  const now=Math.floor(Date.now()/1000), inbox=await makeInboxKeyPair();
  const ada={chain:'cardano',kind:'ada',id:'',amount:'5000000'};
  const eth={chain:'ethereum',kind:'eth',id:'',amount:'100000000000000000'};
  const [created,owner]=await call('/offers',{method:'POST',data:{visibility:'private',expires:now+3600,give:ada,receive:eth,ownerPublicKey:inbox.publicKey}});
  assert.equal(created,201);
  const [reserved,taker]=await call(`/offers/${owner.id}/reserve`,{method:'POST'});assert.equal(reserved,201);
  const [opened,session]=await call(`/offers/${owner.id}/session`,{method:'POST',token:owner.ownerToken,data:{reservationId:taker.reservationId}});assert.equal(opened,201);
  const path=`/swap-sessions/${session.id}/packets`;
  const send=(token,sequence,ciphertext)=>call(path,{method:'POST',token,data:{sequence,ciphertext}});
  const channel=await createChannelHandshake({session:session.id,offer:owner.id,reservation:taker.reservationId,ownerPublicKey:inbox.publicKey});
  assert.equal((await send(taker.reservationToken,1,channel.handshake))[0],201);
  const openedChannel=await openChannelHandshake({session:session.id,offer:owner.id,reservation:taker.reservationId,ownerPublicKey:inbox.publicKey,privateInboxKey:inbox.privateKey,handshake:channel.handshake});
  assert.equal(openedChannel.channelDigest,channel.channelDigest);
  const offer=session.offer,digest=await sessionOfferDigest(offer),assets={give:ada,receive:eth};
  const ownerAda=cardanoWallet('11'.repeat(32)),ownerEth=ethereumWallet('12'.repeat(32));
  const takerAda=cardanoWallet('13'.repeat(32)),takerEth=ethereumWallet('14'.repeat(32));
  const ownerKey=await createProtocolKey(),takerKey=await createProtocolKey();
  async function certificate(role,key,cardano,ethereum){
   const statement=buildParticipant({session:session.id,offer:owner.id,reservation:taker.reservationId,role,offerDigest:digest,channelDigest:channel.channelDigest,protocolKey:key.publicKey,addresses:{give:cardano.keyHash,receive:ethereum.address},issued:now,expires:now+3600},assets);
   const text=participantText(statement);
   const cardanoApi={getUsedAddresses:async()=>[cardano.addressHex],signData:async(address,payload)=>cardano.signData(address,payload)};
   const provider={request:async({method,params})=>{assert.equal(method,'personal_sign');return ethereum.personalSign(params[0]);}};
   return serializeParticipant(statement,[await signCardano(cardanoApi,text),await signEthereum(provider,ethereum.address,text)]);
  }
  const ownerBlob=await certificate('owner',ownerKey,ownerAda,ownerEth),takerBlob=await certificate('taker',takerKey,takerAda,takerEth);
  const expected={session:session.id,offer:owner.id,reservation:taker.reservationId,offerDigest:digest,channelDigest:channel.channelDigest,assets,sessionExpires:session.expires};
  const ownerCtx={session:session.id,role:'owner',sequence:1},takerCtx={session:session.id,role:'taker',sequence:2};
  const ownerFrame=await sealParticipantFrame(channel.key,ownerCtx,ownerBlob,{...expected,role:'owner'},now);
  const takerFrame=await sealParticipantFrame(channel.key,takerCtx,takerBlob,{...expected,role:'taker'},now);
  assert.equal((await send(owner.ownerToken,1,ownerFrame))[0],201);
  assert.equal((await send(taker.reservationToken,2,takerFrame))[0],201);
  const ownerVerified=await openParticipantFrame(channel.key,ownerCtx,ownerFrame,{...expected,role:'owner'},now);
  const takerVerified=await openParticipantFrame(channel.key,takerCtx,takerFrame,{...expected,role:'taker'},now);
  assert.deepEqual(ownerVerified.proven,{give:true,receive:true});assert.deepEqual(takerVerified.proven,{give:true,receive:true});
  const terms={version:2,hashlock:'ab'.repeat(32),legs:{
   long:{asset:ada,network:'preview',refundee:ownerAda.keyHash,claimant:takerAda.keyHash,expiry:now+86400},
   short:{asset:eth,network:'sepolia',refundee:takerEth.address,claimant:ownerEth.address,expiry:now+43200}}};
  const proposal=await signPacket(ownerKey.privateKey,{session:session.id,role:'owner',sequence:1,previous:null,payload:{type:'proposal',terms}});
  const proposalContext={session:session.id,role:'owner',sequence:2};
  const expectedPacket={session:session.id,role:'owner',sequence:1,previous:null,publicKey:ownerVerified.statement.protocolKey};
  const proposalFrame=await sealPacketFrame(channel.key,proposalContext,proposal,expectedPacket);
  assert.equal((await send(owner.ownerToken,2,proposalFrame))[0],201);
  const checkedPacket=await openPacketFrame(channel.key,proposalContext,proposalFrame,expectedPacket);
  const checked=await checkSessionProposal(checkedPacket.body.payload.terms,{offer,expectedOfferDigest:digest,channelDigest:channel.channelDigest,ownerBlob,takerBlob,session:session.id,reservation:taker.reservationId,sessionExpires:session.expires,now});
  assert.equal(checked.termsDigest,await sessionTermsDigest(terms));
  const altered=structuredClone(terms);altered.legs.short.asset.amount='1';
  await assert.rejects(checkSessionProposal(altered,{offer,expectedOfferDigest:digest,channelDigest:channel.channelDigest,ownerBlob,takerBlob,session:session.id,reservation:taker.reservationId,sessionExpires:session.expires,now}),/assets do not match/);
  await assert.rejects(openPacketFrame(channel.key,{...proposalContext,sequence:3},proposalFrame,expectedPacket),/authenticate/);
 } finally { db.raw.close(); }
});
