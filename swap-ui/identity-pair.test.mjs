import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyIdentity} from './identity.mjs';
import {comparePair,checkIdentities,legParticipants} from './pair-check.mjs';
import {checkPublicPair} from './public-pair.mjs';

const vectors=JSON.parse(readFileSync(new URL('../config/swap/identity-vectors.json',import.meta.url),'utf8'));
const pair=vectors.pairs[0];
const hashlock='a'.repeat(64);
const identities=async()=>({owner:await verifyIdentity(pair.owner.blob,pair.owner.expected,pair.owner.now),taker:await verifyIdentity(pair.taker.blob,pair.taker.expected,pair.taker.now)});
const offer={id:pair.owner.expected.offer,give:{chain:'bitcoin',kind:'btc',id:'',amount:'1000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'5'}};
function legs(ids,change={}){
 const {owner,taker}=ids;
 return {
  give:{chain:'bitcoin',terms:{amount_sats:'1000',hashlock,claimant_key:taker.addresses.give,refund_key:owner.addresses.give,txid:'1'.repeat(64),vout:0,...change.give}},
  receive:{chain:'ethereum',terms:{kind:'eth',amount:'5',hashlock:'0x'+hashlock,claimant:owner.addresses.receive.toUpperCase().replace('0X','0x'),refundee:taker.addresses.receive,contract:'0x'+'2'.repeat(40),...change.receive}}
 };
}

test('escrows that name exactly the signed identities pass, and the result says what was and was not proven',async()=>{
 const ids=await identities(),{give,receive}=legs(ids);
 const result=comparePair(offer,give,receive,undefined,ids);
 assert.deepEqual(result.identities.matched,['give','receive']);assert.deepEqual(result.identities.unverified,[]);
 assert.equal(result.identities.owner.code,ids.owner.code);assert.equal(result.identities.taker.code,ids.taker.code);
 // Each participant proved only its Bitcoin address; the Ethereum addresses are asserted.
 assert.deepEqual(result.identities.unproven.sort(),['owner.receive','taker.receive']);
});

test('every escrow address that differs from a signed identity fails the pair check',async()=>{
 const ids=await identities(),otherKey='03'+'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',otherAddress='0x'+'ee'.repeat(20);
 const cases=[
  ['give claimant',{give:{claimant_key:otherKey}},/give escrow claimant/],
  ['give refund',{give:{refund_key:otherKey}},/give escrow refund/],
  ['receive claimant',{receive:{claimant:otherAddress}},/receive escrow claimant/],
  ['receive refundee',{receive:{refundee:otherAddress}},/receive escrow refund/],
  ['swapped roles',{give:{claimant_key:ids.owner.addresses.give,refund_key:ids.taker.addresses.give}},/give escrow claimant/]
 ];
 for(const [name,change,pattern] of cases){const {give,receive}=legs(ids,change);assert.throws(()=>comparePair(offer,give,receive,undefined,ids),pattern,name);}
});

test('statements for another offer, another chain or the wrong role are refused; missing identities are refused',async()=>{
 const ids=await identities(),{give,receive}=legs(ids);
 assert.throws(()=>comparePair({...offer,id:'ff'.repeat(32)},give,receive,undefined,ids),/different offer/);
 assert.throws(()=>comparePair(offer,{...give,chain:'cardano'},receive,undefined,ids),/./);
 assert.throws(()=>comparePair(offer,give,receive,undefined,{owner:ids.owner}),/both participants/);
 assert.throws(()=>comparePair(offer,give,receive,undefined,{owner:ids.taker,taker:ids.owner}),/both participants/);
 const chain=structuredClone(ids);chain.owner.statement.legs.give.chain='ethereum';
 assert.throws(()=>checkIdentities(offer,give,receive,chain),/different give chain/);
});

test('a local Hegemon leg must name the local identities and is still unverified',async()=>{
 const ids=await identities(),{receive}=legs(ids);
 const swapped=structuredClone(ids);
 for(const who of [swapped.owner,swapped.taker])who.statement.legs.give.chain='hegemon';
 swapped.owner.addresses.give='local:'+'aa'.repeat(16);swapped.taker.addresses.give='local:'+'bb'.repeat(16);
 const hgnOffer={...offer,give:{chain:'hegemon',kind:'hgn',id:'',amount:'1000'}};
 const leg=(claimant,refundee)=>({chain:'hegemon',terms:{amount:'1000',locked:'x',timeout:5,hashlock,claimant,refundee}});
 const result=checkIdentities(hgnOffer,leg('bb'.repeat(16),'aa'.repeat(16)),receive,swapped);
 assert.deepEqual(result.unverified,['give']);assert.deepEqual(result.localOnly,['give']);assert.deepEqual(result.matched,['receive']);
 assert.throws(()=>checkIdentities(hgnOffer,leg('ee'.repeat(16),'aa'.repeat(16)),receive,swapped),/local Hegemon identities/);
 assert.throws(()=>checkIdentities(hgnOffer,leg('bb'.repeat(16),'ee'.repeat(16)),receive,swapped),/local Hegemon identities/);
});

test('a Hegemon leg is reported unverified and never matched',async()=>{
 const ids=await identities(),{receive}=legs(ids);
 const swapped=structuredClone(ids);
 for(const who of [swapped.owner,swapped.taker])who.statement.legs.give.chain='hegemon';
 swapped.owner.addresses.give='pending';swapped.taker.addresses.give='pending';
 const result=checkIdentities({...offer,give:{chain:'hegemon',kind:'hgn',id:'',amount:'1000'}},{chain:'hegemon',terms:{amount:'1000',locked:'x',timeout:5,hashlock}},receive,swapped);
 assert.deepEqual(result.unverified,['give']);assert.deepEqual(result.matched,['receive']);
 assert.equal(legParticipants({chain:'hegemon',terms:{}}),null);
 assert.throws(()=>legParticipants({chain:'dogecoin',terms:{}}),/Unsupported/);
});

test('cardano participants come from the claimant and refundee key hashes',()=>{
 assert.deepEqual(legParticipants({chain:'cardano',terms:{claimant:'AA'.repeat(28),refundee:'bb'.repeat(28)}}),{claimant:'aa'.repeat(28),refundee:'bb'.repeat(28)});
});

test('checkPublicPair passes the identities through and fails before any chain read when they differ',async()=>{
 const ids=await identities(),{give,receive}=legs(ids,{receive:{claimant:'0x'+'ee'.repeat(20)}});
 let reads=0;
 await assert.rejects(()=>checkPublicPair(offer,give,receive,async()=>{reads++;return {};},undefined,ids),/receive escrow claimant/);
 assert.equal(reads,0);
 const good=legs(ids),result=await checkPublicPair(offer,good.give,good.receive,async leg=>({chain:leg.chain,snapshot:{}}),undefined,ids);
 assert.deepEqual(result.identities.matched,['give','receive']);
});
