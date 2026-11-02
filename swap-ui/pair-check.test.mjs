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
