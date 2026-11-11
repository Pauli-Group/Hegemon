import test from 'node:test';
import assert from 'node:assert/strict';
import {pinOffer,readOfferPin} from './offer-pin.mjs';
function memory(){const rows=new Map();return {getItem:key=>rows.get(key)??null,setItem:(key,value)=>rows.set(key,value)};}
const offer={id:'11'.repeat(32),visibility:'private',expires:1800003600,ownerPublicKey:'04'+'aa'.repeat(64),give:{chain:'cardano',kind:'ada',id:'',amount:'5000000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'100000000000000000'},reservationId:'22'.repeat(32)};
test('pins exact offer terms while allowing reservation metadata to change',async()=>{
 const store=memory(),saved=await pinOffer(offer,store);
 assert.equal(saved.offer.reservationId,undefined);assert.deepEqual(await readOfferPin(offer.id,store),saved);
 assert.equal((await pinOffer({...offer,reservationId:'33'.repeat(32)},store)).digest,saved.digest);
 await assert.rejects(pinOffer({...offer,give:{...offer.give,amount:'1'}},store),/offer changed/);
 await assert.rejects(pinOffer({...offer,ownerPublicKey:'04'+'bb'.repeat(64)},store),/offer changed/);
});
test('malformed saved pins fail closed',async()=>{
 const store=memory();store.setItem('hegemon.swap.pinned-offer:'+offer.id,'{bad');
 await assert.rejects(readOfferPin(offer.id,store),/saved offer is invalid/);
});
