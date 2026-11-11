import test from 'node:test';
import assert from 'node:assert/strict';
import {sessionOutbox} from './session-outbox.mjs';

function harness(send){
 const rows=new Map(),storage={getItem:key=>rows.get(key)??null,setItem:(key,value)=>rows.set(key,value)};
 let tail=Promise.resolve();const locks={request:(_key,_options,fn)=>{const result=tail.then(fn);tail=result.catch(()=>{});return result;}};
 const session='11'.repeat(32),role='owner';
 return {rows,storage,locks,make:()=>sessionOutbox({session,role,send,storage,locks})};
}

test('lost acknowledgement retries the exact persisted encrypted frame before sending another',async()=>{
 let accepted=null,calls=0,store;
 const h=harness(async frame=>{
  calls++;
  const stored=JSON.parse([...store.values()][0]);
  assert.deepEqual(stored.pending,frame,'the packet must be durable before network activity');
  if(!accepted){accepted=frame;throw Error('response lost');}
  assert.deepEqual(frame,accepted,'retry must be byte-identical');
  return {id:7,duplicate:true};
 });store=h.rows;
 const out=h.make();await assert.rejects(out.enqueue(()=> 'YWJj'),/response lost/);
 assert.deepEqual(await out.inspect(),{next:1,pending:true});
 await assert.rejects(out.enqueue(()=> 'ZGVm'),/Retry the saved/);
 assert.deepEqual(await h.make().retry(),{id:7,duplicate:true,sequence:1});
 assert.deepEqual(await out.inspect(),{next:2,pending:false});assert.equal(calls,2);
});

test('concurrent tabs are serialized and distinct packets get consecutive sequences',async()=>{
 const calls=[],allocated=[],h=harness(async frame=>{calls.push(frame);return {id:calls.length,duplicate:false};});
 await Promise.all([h.make().enqueue(sequence=>{allocated.push(sequence);return 'YWJj';}),h.make().enqueue(sequence=>{allocated.push(sequence);return 'ZGVm';})]);
 assert.deepEqual(allocated,[1,2],'each ciphertext must be built with its actual locked sequence');
 assert.deepEqual(calls,[{sequence:1,ciphertext:'YWJj'},{sequence:2,ciphertext:'ZGVm'}]);
 assert.deepEqual(await h.make().inspect(),{next:3,pending:false});
});

test('storage failures and malformed acknowledgements fail closed',async()=>{
 let sent=0;const h=harness(async()=>{sent++;return {id:1};});
 await assert.rejects(h.make().enqueue(()=> 'YWJj'),/did not confirm/);assert.equal(sent,1);
 assert.deepEqual(await h.make().inspect(),{next:1,pending:true});
 h.storage.setItem([...h.rows.keys()][0],'{bad');
 await assert.rejects(h.make().retry(),/outbox is invalid/);assert.equal(sent,1);
 const noSave=harness(async()=>{sent++;return {id:2,duplicate:false};});noSave.storage.setItem=()=>{throw Error('quota');};
 await assert.rejects(noSave.make().enqueue(()=> 'YWJj'),/quota/);assert.equal(sent,1,'a packet must not be sent if it cannot be saved');
});
