import {test} from 'node:test';
import assert from 'node:assert/strict';
import {cardanoOfferValue,checkPublicPair} from './public-pair.mjs';

test('matches both assets and hashlocks before checking either chain',async()=>{
 const hash='a'.repeat(64),policy='b'.repeat(56),token='0x'+'c'.repeat(40);
 const offer={give:{chain:'ethereum',kind:'erc20',id:token,amount:'25'},receive:{chain:'cardano',kind:'native',id:policy+'.00',amount:'7'}};
 const give={chain:'ethereum',terms:{kind:'0',token,amount:'25',hashlock:'0x'+hash,contract:'0x'+'d'.repeat(40)}};
 const receive={chain:'cardano',terms:{outref:'e'.repeat(64)+'#0',hashlock:hash,expected_value:cardanoOfferValue('4000000',policy+'.00=7')}};
 let calls=[];const check=async leg=>{calls.push(leg.chain);return {chain:leg.chain,snapshot:{confirmations:2}};};
 const result=await checkPublicPair(offer,give,receive,check);assert.equal(result.hashlock,hash);assert.deepEqual(calls,['ethereum','cardano']);
 calls=[];await assert.rejects(checkPublicPair(offer,give,{...receive,terms:{...receive.terms,hashlock:'f'.repeat(64)}},check),/hashlocks/);assert.deepEqual(calls,[]);
 calls=[];await assert.rejects(checkPublicPair(offer,give,{...receive,terms:{...receive.terms,expected_value:cardanoOfferValue('4000000',policy+'.00=8')}},check),/assets or amounts/);assert.deepEqual(calls,[]);
 await assert.rejects(checkPublicPair(offer,give,receive,async leg=>{if(leg.chain==='cardano')throw Error('provider unavailable');return {chain:leg.chain};}),/provider unavailable/);
});
