import {test} from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {once} from 'node:events';
import worker from './cloudflare/worker.mjs';

const schema=readFileSync(new URL('./cloudflare/schema.sql',import.meta.url),'utf8');
const migration=readFileSync(new URL('./cloudflare/migrations/0003_swap_sessions.sql',import.meta.url),'utf8');
const terms=()=>({visibility:'public',expires:Math.floor(Date.now()/1000)+3600,
  give:{chain:'bitcoin',kind:'btc',id:'',amount:'1000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'500'},ownerPublicKey:'04'+'a'.repeat(128)});
function wrap(db){return {async batch(statements){db.exec('BEGIN');try{const results=[];for(const s of statements)results.push(await s.run());db.exec('COMMIT');return results;}catch(e){db.exec('ROLLBACK');throw e;}},prepare(sql){const q=db.prepare(sql);let values=[];return {bind(...v){values=v;return this;},async first(){return q.get(...values)??null;},async all(){return {results:q.all(...values)};},async run(){return q.run(...values);}};}};}
function workerHarness(){
  const raw=new DatabaseSync(':memory:');raw.exec(schema);const env={DB:wrap(raw),ASSETS:{fetch:async()=>new Response('board')}};
  return {raw,async call(path,{method='GET',token,data}={}){
    const headers={'CF-Connecting-IP':'192.0.2.41',origin:'https://swap.example'};if(token)headers.authorization='Bearer '+token;if(data)headers['content-type']='application/json';
    const res=await worker.fetch(new Request('https://swap.example'+path,{method,headers,...(data?{body:JSON.stringify(data)}:{})}),env);
    return [res.status,await res.json()];
  },async expire(id){raw.prepare('UPDATE offers SET expires=0,reservation_expires=0 WHERE id=?').run(id);},async forgetListing(id){raw.prepare('DELETE FROM offers WHERE id=?').run(id);},async close(){raw.close();}};
}
async function localHarness(){
  const dir=await mkdtemp(join(tmpdir(),'swap-session-')),probe=createServer().listen(0,'127.0.0.1');await once(probe,'listening');const port=probe.address().port;await new Promise(done=>probe.close(done));
  const path=join(dir,'offers.sqlite'),base=`http://127.0.0.1:${port}`;
  const child=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:path,SWAP_PORT:String(port)},stdio:'ignore'});
  let ready=false;
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok){ready=true;break;}}catch{}await new Promise(done=>setTimeout(done,50));}
  if(!ready){child.kill('SIGTERM');throw Error('local relay did not start');}
  return {async call(url,{method='GET',token,data}={}){const headers={};if(token)headers.authorization='Bearer '+token;if(data)headers['content-type']='application/json';
    const res=await fetch(base+url,{method,headers,...(data?{body:JSON.stringify(data)}:{})});return [res.status,await res.json()];},
    async expire(id){const db=new DatabaseSync(path);db.prepare('UPDATE offers SET expires=0 WHERE id=?').run(id);db.prepare('UPDATE reservations SET expires=0 WHERE offer_id=?').run(id);db.close();},
    async forgetListing(id){const db=new DatabaseSync(path);db.prepare('DELETE FROM messages WHERE offer_id=?').run(id);db.prepare('DELETE FROM reservations WHERE offer_id=?').run(id);db.prepare('DELETE FROM offers WHERE id=?').run(id);db.close();},
    async close(){child.kill('SIGTERM');await once(child,'exit');await rm(dir,{recursive:true,force:true});}};
}

async function exercise(h){
  const call=h.call;
  const [created,owner]=await call('/offers',{method:'POST',data:terms()});assert.equal(created,201);
  const [reserved,taker]=await call(`/offers/${owner.id}/reserve`,{method:'POST'});assert.equal(reserved,201);
  const start=`/offers/${owner.id}/session`,body={reservationId:taker.reservationId};
  assert.equal((await call(start,{method:'POST',token:taker.reservationToken,data:body}))[0],403,'only the offer maker can start a session');
  assert.equal((await call(start,{method:'POST',token:owner.ownerToken,data:{reservationId:'0'.repeat(64)}}))[0],409);
  const [opened,session]=await call(start,{method:'POST',token:owner.ownerToken,data:body});assert.equal(opened,201);
  assert.equal(session.id,createHash('sha256').update(`hegemon.swap.session.v1:${owner.id}:${taker.reservationId}`).digest('hex'));
  assert.equal(session.expires-session.created,180*86400);
  const [repeat,repeated]=await call(start,{method:'POST',token:owner.ownerToken,data:body});assert.equal(repeat,200);assert.deepEqual(repeated,session);
  assert.equal((await call('/offers'))[1].offers.length,0,'a matched offer is no longer on the public board');
  const path=`/swap-sessions/${session.id}`;
  assert.equal((await call(path,{token:'0'.repeat(64)}))[0],401);
  assert.deepEqual((await call(path,{token:owner.ownerToken}))[1],session);
  assert.deepEqual((await call(path,{token:taker.reservationToken}))[1],session);
  const packets=path+'/packets',a={sequence:1,ciphertext:'YWJj'},b={sequence:1,ciphertext:'ZGVm'};
  const concurrent=await Promise.all(Array.from({length:4},()=>call(packets,{method:'POST',token:taker.reservationToken,data:a})));
  assert.equal(concurrent.filter(([status])=>status===201).length,1);
  assert.equal(concurrent.filter(([status,result])=>status===200&&result.duplicate).length,3);
  assert.equal((await call(packets,{method:'POST',token:taker.reservationToken,data:b}))[0],409,'a sequence cannot be overwritten');
  assert.equal((await call(packets,{method:'POST',token:taker.reservationToken,data:{sequence:3,ciphertext:'YWJj'}}))[0],409,'packets cannot skip a sequence');
  assert.equal((await call(packets,{method:'POST',token:owner.ownerToken,data:{...a,secret:'not allowed'}}))[0],400);
  assert.equal((await call(packets,{method:'POST',token:owner.ownerToken,data:{sequence:257,ciphertext:'YWJj'}}))[0],400);
  assert.equal((await call(packets,{method:'POST',token:owner.ownerToken,data:b}))[0],201,'each role has its own sequence');
  const [read,list]=await call(packets,{token:owner.ownerToken});assert.equal(read,200);assert.equal(list.packets.length,2);
  assert.deepEqual(list.packets.map(({sender,sequence})=>({sender,sequence})),[{sender:'taker',sequence:1},{sender:'owner',sequence:1}]);
  assert.equal((await call(packets+'?after='+list.packets[0].id,{token:taker.reservationToken}))[1].packets.length,1);
  assert.equal((await call(packets+'?after=-1',{token:taker.reservationToken}))[0],400);
  await h.expire(owner.id);
  assert.equal((await call(path,{token:taker.reservationToken}))[0],200,'the accepted session outlives the listing and reservation');
  assert.equal((await call(packets,{method:'POST',token:taker.reservationToken,data:{sequence:2,ciphertext:'aGk='}}))[0],201);
  await h.forgetListing(owner.id);
  assert.equal((await call(path,{token:owner.ownerToken}))[0],200,'cleanup of the listing cannot delete the session');
  assert.equal((await call(packets,{token:taker.reservationToken}))[1].packets.length,3);
}

test('hosted Worker preserves a matched session and rejects conflicting or replayed packets',async()=>{const h=workerHarness();try{await exercise(h);}finally{await h.close();}});
test('local relay preserves the same session and packet semantics',async()=>{const h=await localHarness();try{await exercise(h);}finally{await h.close();}});
test('session migration is additive and can be applied repeatedly',()=>{
  const db=new DatabaseSync(':memory:');try{
    db.exec("CREATE TABLE offers(id TEXT PRIMARY KEY, offer TEXT); INSERT INTO offers VALUES('old','kept');");
    db.exec(migration);db.exec(migration);
    assert.equal(db.prepare('SELECT offer FROM offers WHERE id=?').get('old').offer,'kept');
    const tables=db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(row=>row.name);
    assert.ok(tables.includes('swap_sessions')&&tables.includes('swap_packets'));
  }finally{db.close();}
});
