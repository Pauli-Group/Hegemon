import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {bitcoinProof,signEthereum} from './identity-flow.mjs';
import {bitcoinMessageWallet,ethereumWallet} from './test-wallets.mjs';
import {buildParticipant,deriveSessionId,participantText,serializeParticipant,sessionOfferDigest} from './session-identity.mjs';
import {checkFundingPolicy,checkSessionProposal,createProtocolKey,packetDigest,sessionTermsDigest,signPacket,validateSessionTerms,verifyPacket} from './session-packets.mjs';
import {validateTiming} from './timelock-policy.mjs';

const now=1800000000,offerId='11'.repeat(32),reservation='22'.repeat(32);
const config=validateTiming(JSON.parse(readFileSync(new URL('./chain-timing.json',import.meta.url))));
const heads={long:{height:150000,observedAt:now},short:{timestamp:now-5,observedAt:now}};
const makerBtc=bitcoinMessageWallet('01'.repeat(32)),makerEth=ethereumWallet('02'.repeat(32));
const takerBtc=bitcoinMessageWallet('03'.repeat(32)),takerEth=ethereumWallet('04'.repeat(32));
const offer={id:offerId,visibility:'public',expires:now+3600,ownerPublicKey:'04'+'aa'.repeat(64),
 give:{chain:'bitcoin',kind:'btc',id:'',amount:'100000'},receive:{chain:'ethereum',kind:'erc20',id:'0x'+'ab'.repeat(20),amount:'100000000000000000000000'}};
async function setup(){
 const session=await deriveSessionId(offerId,reservation),digest=await sessionOfferDigest(offer),channelDigest='44'.repeat(32),ownerKey=await createProtocolKey(),takerKey=await createProtocolKey();
 const assets={give:offer.give,receive:offer.receive};
 async function person(role,key,btc,eth){
  const statement=buildParticipant({session,offer:offerId,reservation,role,offerDigest:digest,channelDigest,protocolKey:key.publicKey,addresses:{give:btc.publicKey,receive:eth.address},issued:now,expires:now+7200},assets);
  const text=participantText(statement),provider={request:async({method,params})=>{assert.equal(method,'personal_sign');return eth.personalSign(params[0]);}};
  return serializeParticipant(statement,[bitcoinProof('bip137',btc.sign(text),text),await signEthereum(provider,eth.address,text)]);
 }
 const ownerBlob=await person('owner',ownerKey,makerBtc,makerEth),takerBlob=await person('taker',takerKey,takerBtc,takerEth);
 const terms={version:2,hashlock:'ab'.repeat(32),legs:{
  long:{asset:offer.give,network:'testnet4',refundee:makerBtc.publicKey,claimant:takerBtc.publicKey,expiry:150337},
  short:{asset:offer.receive,network:'sepolia',refundee:takerEth.address,claimant:makerEth.address,expiry:1800013951},
 }};
 return {session,ownerKey,takerKey,ownerBlob,takerBlob,terms,expected:{offer,expectedOfferDigest:digest,channelDigest,ownerBlob,takerBlob,session,reservation,sessionExpires:now+10000,now}};
}

test('wallet-bound participants and exact large token quantities agree on one proposal',async()=>{
 const {terms,expected,ownerKey,takerKey}=await setup(),result=await checkSessionProposal(terms,expected);
 assert.equal(result.termsDigest,await sessionTermsDigest(terms));assert.equal(result.unverifiedHegemon,false);
 assert.equal(result.owner.statement.protocolKey,ownerKey.publicKey);assert.equal(result.taker.statement.protocolKey,takerKey.publicKey);
 assert.equal(checkFundingPolicy(terms,{role:'initiator',heads,config,now}).ok,true);
 assert.equal(checkFundingPolicy(terms,{role:'responder',heads,config,now}).ok,true);
 const wrong=structuredClone(terms);wrong.legs.short.asset.amount='100000000000000000000001';
 await assert.rejects(checkSessionProposal(wrong,expected),/assets do not match/);
 await assert.rejects(checkSessionProposal(terms,{...expected,expectedOfferDigest:'ff'.repeat(32)}),/pinned offer digest/);
 const altered=structuredClone(terms);altered.legs.long.claimant=makerBtc.publicKey;
 assert.throws(()=>validateSessionTerms(altered),/participants/);
 const changed=structuredClone(terms);changed.legs.short.refundee='0x'+'33'.repeat(20);
 await assert.rejects(checkSessionProposal(changed,expected),/recipients do not match/);
 const expired=structuredClone(terms);expired.legs.short.expiry=now+10;
 assert.throws(()=>checkFundingPolicy(expired,{role:'initiator',heads,config,now}),/not safe/);
 assert.throws(()=>checkFundingPolicy(terms,{role:'initiator',heads:{...heads,long:null},config,now}),/chain heads/);
});

test('signed packets bind the certified key, session, role, exact sequence and history',async()=>{
 const {session,ownerKey,takerKey,terms}=await setup();
 assert.equal(ownerKey.privateKey.extractable,false);
 const first=await signPacket(ownerKey.privateKey,{session,role:'owner',sequence:1,previous:null,payload:{type:'proposal',terms}});
 const expected={session,role:'owner',sequence:1,previous:null,publicKey:ownerKey.publicKey};
 const checked=await verifyPacket(first,expected);assert.equal(checked.digest,await packetDigest(first.body));
 for(const change of [
  e=>({...e,session:'ff'.repeat(32)}),e=>({...e,role:'taker'}),e=>({...e,sequence:2}),e=>({...e,previous:'ff'.repeat(32)}),
 ])await assert.rejects(verifyPacket(first,change(expected)),/different session, role, or sequence/);
 await assert.rejects(verifyPacket(first,{...expected,publicKey:takerKey.publicKey}),/does not verify/);
 const tampered=structuredClone(first);tampered.body.payload.terms.legs.short.asset.amount='2';
 await assert.rejects(verifyPacket(tampered,expected),/does not verify/);
 const second=await signPacket(ownerKey.privateKey,{session,role:'owner',sequence:2,previous:checked.digest,payload:{type:'escrow',termsDigest:await sessionTermsDigest(terms),leg:'long',reference:{chain:'bitcoin',txid:'44'.repeat(32),vout:0}}});
 assert.equal((await verifyPacket(second,{...expected,sequence:2,previous:checked.digest})).body.payload.leg,'long');
 await assert.rejects(verifyPacket(second,{...expected,sequence:2,previous:'00'.repeat(32)}),/different session, role, or sequence/);
});

test('packets reject private secrets, invalid references and noncanonical signatures',async()=>{
 const {session,ownerKey,terms}=await setup();
 await assert.rejects(signPacket(ownerKey.privateKey,{session,role:'owner',sequence:1,previous:null,payload:{type:'proposal',terms,preimage:'ff'.repeat(32)}}),/Invalid proposal/);
 const embedded=structuredClone(terms);embedded.legs.long.secret='ff'.repeat(32);
 await assert.rejects(signPacket(ownerKey.privateKey,{session,role:'owner',sequence:1,previous:null,payload:{type:'proposal',terms:embedded}}),/Invalid long leg fields/);
 await assert.rejects(signPacket(ownerKey.privateKey,{session,role:'owner',sequence:1,previous:null,payload:{type:'escrow',termsDigest:'aa'.repeat(32),leg:'long',reference:{chain:'bitcoin',txid:'44'.repeat(32)}}}),/reference/);
 const signed=await signPacket(ownerKey.privateKey,{session,role:'owner',sequence:1,previous:null,payload:{type:'cancel',reason:'cancelled'}});
 const order=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),s=BigInt('0x'+signed.signature.slice(64));
 const high={...signed,signature:signed.signature.slice(0,64)+(order-s).toString(16).padStart(64,'0')};
 await assert.rejects(verifyPacket(high,{session,role:'owner',sequence:1,previous:null,publicKey:ownerKey.publicKey}),/Non-canonical/);
});

test('funding checks include Hegemon proving and minimum lock windows',async()=>{
 const {terms}=await setup();
 terms.legs.long={asset:{chain:'hegemon',kind:'hgn',id:'',amount:'1000'},network:'pre-mainnet',refundee:'shca1'+'q'.repeat(200),claimant:'shca1'+'p'.repeat(200),expiry:151011};
 terms.legs.short.expiry=1800010826;
 const stricter=structuredClone(config);stricter.chains.hegemon.minLockBlocks=2000;
 assert.throws(()=>checkFundingPolicy(terms,{role:'initiator',heads,config:stricter,now}),/long lock no longer has enough time/);
 assert.equal(checkFundingPolicy(terms,{role:'responder',heads,config:stricter,now}).ok,true,'the already-funded long lock is not checked as a new lock');
});

test('terms identify Cardano native assets and Ethereum NFTs without rounding or omitting their deposit',async()=>{
 const {terms}=await setup();
 terms.legs.long={asset:{chain:'cardano',kind:'native',id:'ab'.repeat(28)+'.00ff',amount:'9223372036854775807'},network:'preview',claimant:'11'.repeat(28),refundee:'22'.repeat(28),expiry:1800100000,lovelace:'2000000'};
 terms.legs.short.asset={chain:'ethereum',kind:'erc721',id:'0x'+'12'.repeat(20)+':999999999999999999999999999999999999',amount:'1'};
 assert.equal(validateSessionTerms(terms),terms);
 const missing=structuredClone(terms);delete missing.legs.long.lovelace;assert.throws(()=>validateSessionTerms(missing),/leg fields/);
 const bad=structuredClone(terms);bad.legs.short.asset.amount='2';assert.throws(()=>validateSessionTerms(bad),/one NFT/);
 const many=structuredClone(terms);many.legs.short.asset.kind='erc1155';many.legs.short.asset.amount='999999999999999999999999';assert.equal(validateSessionTerms(many),many);
});
