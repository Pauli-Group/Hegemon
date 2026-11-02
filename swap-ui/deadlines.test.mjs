import {test} from 'node:test';
import assert from 'node:assert/strict';
import {validateWatch,evaluateWatch} from './deadlines.mjs';
test('deadline watch binds genesis and keeps large integer values exact',()=>{
 const w={chain:'hegemon',label:'Example',genesis:'a'.repeat(64),deadline:'9007199254741000',warning:'5'};
 assert.equal(evaluateWatch(w,{genesis:w.genesis,current:'9007199254740990'}).state,'watching');
 assert.equal(evaluateWatch(w,{genesis:w.genesis,current:'9007199254740997'}).state,'near');
 assert.equal(evaluateWatch(w,{genesis:w.genesis,current:'9007199254741000'}).state,'expired');
 assert.throws(()=>evaluateWatch(w,{genesis:'b'.repeat(64),current:'9007199254740990'}),/different genesis/);
 assert.throws(()=>validateWatch({...w,deadline:'18446744073709551616'}));
});
