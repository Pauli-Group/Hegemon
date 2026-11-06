import {test} from 'node:test';
import assert from 'node:assert/strict';
import {comparePair,matchesOfferAsset} from './pair-check.mjs';
const digest='a'.repeat(64),policy='b'.repeat(56),contract='0x'+'1'.repeat(40),token='0x'+'2'.repeat(40);
test('pair comparison binds exact assets, amounts, hashlocks and distinct escrows',()=>{
 const offer={give:{chain:'ethereum',kind:'erc721',id:token+':42',amount:'1'},receive:{chain:'cardano',kind:'native',id:policy+'.00',amount:'9007199254740993'}};
 const give={chain:'ethereum',terms:{contract,kind:'1',token,tokenId:'42',amount:'1',hashlock:'0x'+digest}};
 const receive={chain:'cardano',terms:{outref:'c'.repeat(64)+'#0',hashlock:digest,expected_value:{lovelace:'10000000',[policy]:{'00':'9007199254740993'}}}};
 assert.equal(comparePair(offer,give,receive).hashlock,digest);
 assert.throws(()=>comparePair(offer,{...give,terms:{...give.terms,tokenId:'43'}},receive),/assets or amounts/);
 assert.throws(()=>comparePair(offer,give,{...receive,terms:{...receive.terms,hashlock:'d'.repeat(64)}}),/hashlocks/);
 assert.equal(matchesOfferAsset(offer.receive,{...receive,terms:{...receive.terms,expected_value:{...receive.terms.expected_value,[policy]:{'00':'9007199254740993','01':'1'}}}}),false);
 const sameOffer={give:offer.give,receive:offer.give};assert.throws(()=>comparePair(sameOffer,give,give),/different escrows/);
});
test('asset matching covers every supported chain and token kind with exact units',()=>{
 const cases=[
  [{chain:'ethereum',kind:'eth',id:'',amount:'4'},{chain:'ethereum',terms:{kind:'eth',amount:'4'}}],
  [{chain:'ethereum',kind:'erc20',id:token,amount:'5'},{chain:'ethereum',terms:{kind:'0',token,amount:'5'}}],
  [{chain:'ethereum',kind:'erc1155',id:token+':42',amount:'6'},{chain:'ethereum',terms:{kind:'2',token,tokenId:'42',amount:'6'}}],
  [{chain:'bitcoin',kind:'btc',id:'',amount:'7'},{chain:'bitcoin',terms:{amount_sats:'7'}}],
  [{chain:'hegemon',kind:'hgn',id:'',amount:'8'},{chain:'hegemon',terms:{amount:'8'}}],
  [{chain:'cardano',kind:'ada',id:'',amount:'9'},{chain:'cardano',terms:{expected_value:{lovelace:'9'}}}],
 ];
 for(const [asset,leg] of cases){assert.equal(matchesOfferAsset(asset,leg),true,asset.chain+' '+asset.kind);assert.equal(matchesOfferAsset({...asset,amount:'10'},leg),false);}
 const [ada,leg]=cases.at(-1);assert.equal(matchesOfferAsset(ada,{...leg,terms:{expected_value:{lovelace:'9',[policy]:{'':'1'}}}}),false);
});

import {readFileSync} from 'node:fs';
import {planTimeouts} from './timelock-policy.mjs';
import {policyLeg,policyHead,judgeTiming,TimingError} from './pair-check.mjs';
const timingConfig=JSON.parse(readFileSync(new URL('../config/swap/chain-timing.json',import.meta.url),'utf8'));
test('timing policy rejects pairs whose deadlines leave too little time between legs',()=>{
 const now=1_793_935_000,offer={give:{chain:'ethereum',kind:'eth',id:'',amount:'4'},receive:{chain:'cardano',kind:'ada',id:'',amount:'9'}};
 const heads={long:{observedAt:now,timestamp:now-10},short:{observedAt:now,timestamp:now-10}};
 const plan=planTimeouts(timingConfig,{longChain:'ethereum',shortChain:'cardano',heads,now});
 const make=(longExpiry,shortExpiry)=>[{chain:'ethereum',terms:{kind:'eth',amount:'4',hashlock:'0x'+digest,contract,expiry:String(longExpiry)}},{chain:'cardano',terms:{outref:'c'.repeat(64)+'#0',hashlock:digest,expected_value:{lovelace:'9'},expiry_ms:shortExpiry*1000}}];
 const timing={config:timingConfig,now,heads:{give:{observedAt:now,timestamp:now-10},receive:{observedAt:now,timestamp:now-10}}};
 const [give,receive]=make(plan.long.expiry,plan.short.expiry);
 const ok=comparePair(offer,give,receive,timing);assert.equal(ok.timing.ok,true);assert.equal(ok.timing.long,'give');
 const [tooTight]=make(plan.long.expiry-3600,plan.short.expiry);
 assert.throws(()=>comparePair(offer,tooTight,receive,timing),error=>error instanceof TimingError&&error.verdict.reasons.some(r=>r.code==='insufficient-gap')&&/Unsafe deadlines/.test(error.message));
 // Roles are not needed: the same pair swapped between give and receive is judged the same way.
 const swappedOffer={give:offer.receive,receive:offer.give},swappedTiming={...timing,heads:{give:timing.heads.receive,receive:timing.heads.give}};
 assert.equal(comparePair(swappedOffer,receive,give,swappedTiming).timing.long,'receive');
 assert.equal(comparePair(offer,give,receive).timing,undefined,'without timing the comparison stays point-in-time only');
});
test('timing inputs come straight from verifier snapshots and terms',()=>{
 assert.deepEqual(policyLeg({chain:'bitcoin',terms:{refund_height:'159000'}}),{chain:'bitcoin',expiry:159000});
 assert.deepEqual(policyLeg({chain:'cardano',terms:{expiry_ms:1793935000000}}),{chain:'cardano',expiry:1793935000});
 assert.throws(()=>policyLeg({chain:'cardano',terms:{expiry_ms:1793935000500}}),/whole number of seconds/);
 assert.deepEqual(policyHead('bitcoin',{tip:7},5),{observedAt:5,height:7});
 assert.deepEqual(policyHead('ethereum',{headTimestamp:9},5),{observedAt:5,timestamp:9});
 assert.throws(()=>judgeTiming({chain:'bitcoin',terms:{refund_height:1}},{chain:'ethereum',terms:{expiry:'1'}},{}),/required/);
});
