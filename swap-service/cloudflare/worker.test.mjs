import {test} from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import worker from './worker.mjs';

function database(){
  const db=new DatabaseSync(':memory:');db.exec(readFileSync(new URL('./schema.sql',import.meta.url),'utf8'));
  return {raw:db,async batch(statements){for(const s of statements)await s.run();},prepare(sql){const q=db.prepare(sql);let values=[];return {bind(...v){values=v;return this;},async first(){return q.get(...values)??null;},async all(){return {results:q.all(...values)};},async run(){return q.run(...values);}};}};
}
function client(db){
  const env={DB:db,ASSETS:{fetch:async()=>new Response('board')}};
  return async(path,{method='GET',token,data,ip='192.0.2.8',origin='https://swap.example'}={})=>{
    const headers={'CF-Connecting-IP':ip,origin};if(token)headers.authorization='Bearer '+token;if(data)headers['content-type']='application/json';
    const r=await worker.fetch(new Request('https://swap.example'+path,{method,headers,...(data?{body:JSON.stringify(data)}:{})}),env);
    return [r.status,await r.json()];
  };
}
const offer=()=>({visibility:'public',expires:Math.floor(Date.now()/1000)+600,give:{chain:'bitcoin',kind:'btc',id:'',amount:'1000'},receive:{chain:'ethereum',kind:'erc721',id:'0x'+'a'.repeat(40)+':1',amount:'1'},ownerPublicKey:'04'+'a'.repeat(128)});

test('offers, exclusive reservations, authorization and session replacement',async()=>{
  const db=database(),call=client(db);const [created,a]=await call('/offers',{method:'POST',data:offer()});assert.equal(created,201);
  const results=await Promise.all(Array.from({length:8},()=>call('/offers/'+a.id+'/reserve',{method:'POST'})));
  assert.equal(results.filter(([s])=>s===201).length,1);assert.equal(results.filter(([s])=>s===409).length,7);
  const b=results.find(([s])=>s===201)[1];
  assert.equal((await call('/offers/'+a.id+'/messages',{method:'POST',token:b.reservationToken,data:{ciphertext:'YWJj',reservationId:b.reservationId}}))[0],201);
  assert.equal((await call('/offers/'+a.id+'/messages',{token:a.ownerToken}))[1].messages.length,1);
  assert.equal((await call('/offers/'+a.id+'/messages',{method:'POST',token:a.ownerToken,data:{ciphertext:'YWJj',reservationId:'0'.repeat(64)}}))[0],409);
  db.raw.prepare('UPDATE offers SET reservation_expires=0 WHERE id=?').run(a.id);
  const [status,c]=await call('/offers/'+a.id+'/reserve',{method:'POST'});assert.equal(status,201);
  assert.equal((await call('/offers/'+a.id+'/messages',{token:b.reservationToken}))[0],401);
  assert.deepEqual((await call('/offers/'+a.id+'/messages',{token:a.ownerToken}))[1].messages,[]);
  assert.equal((await call('/offers/'+a.id+'/messages',{method:'POST',token:a.ownerToken,data:{ciphertext:'YWJj',reservationId:b.reservationId}}))[0],409);
  assert.equal((await call('/offers/'+a.id+'/messages',{method:'POST',token:c.reservationToken,data:{ciphertext:'ZGVm',reservationId:c.reservationId}}))[0],201);
  assert.equal((await call('/offers/'+a.id+'/close',{method:'POST',token:c.reservationToken}))[0],403);
  assert.equal((await call('/offers/'+a.id+'/close',{method:'POST',token:a.ownerToken}))[0],200);
  assert.equal((await call('/offers'))[1].offers.length,0);db.raw.close();
});

test('rejects invalid tokens, cross-origin actions, oversized bodies and excessive traffic',async()=>{
  const db=database(),call=client(db);const bad=offer();bad.receive.amount='2';assert.equal((await call('/offers',{method:'POST',data:bad}))[0],400);
  assert.equal((await call('/offers',{method:'POST',data:offer(),origin:'https://other.example'}))[0],403);
  assert.equal((await call('/offers',{method:'POST',data:{padding:'x'.repeat(17000)}}))[0],400);
  const [ok,a]=await call('/offers',{method:'POST',data:offer()});assert.equal(ok,201);
  assert.equal((await call('/offers/'+a.id+'/messages',{token:'0'.repeat(64)}))[0],401);
  let status;for(let i=0;i<45;i++)[status]=await call('/offers/'+a.id+'/reserve',{method:'POST',ip:'192.0.2.9'});
  assert.equal(status,429);db.raw.close();
});
