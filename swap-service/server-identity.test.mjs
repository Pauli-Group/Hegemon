import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {DatabaseSync} from 'node:sqlite';
import {makeInboxKeyPair,inboxFingerprint} from '../swap-ui/public-inbox.mjs';

async function availablePort(){const server=createServer();server.listen(0,'127.0.0.1');await once(server,'listening');const port=server.address().port;await new Promise(done=>server.close(done));return port;}
async function relay(dir){
  const port=await availablePort(),base=`http://127.0.0.1:${port}`;
  const child=spawn(globalThis.process.execPath,[resolve('swap-service/server.ts')],{env:{...globalThis.process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(port)},stdio:['ignore','pipe','pipe']});
  let error='';child.stderr.on('data',data=>error+=data);
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(done=>setTimeout(done,30));if(i===99)throw Error('relay did not start: '+error);}
  const call=async(path,{method='GET',data,token}={})=>{const headers={};if(data)headers['content-type']='application/json';if(token)headers.authorization='Bearer '+token;const res=await fetch(base+path,{method,headers,body:data?JSON.stringify(data):undefined});return [res.status,await res.json()];};
  return {call,stop:async()=>{if(child.exitCode===null){child.kill('SIGTERM');await once(child,'exit');}}};
}
const blob=({id,role,reservation='',inbox})=>JSON.stringify({statement:{version:1,kind:'hegemon.swap.identity',role,offer:id,reservation,inbox,legs:{},nonce:'a'.repeat(32),issued:1,expires:2},proofs:[{chain:'bitcoin',scheme:'bip137',signer:'02'+'a'.repeat(64),signature:'AAAA'}]});

test('the local relay stores signed identity statements once and clears the taker identity with the reservation',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'swap-identity-')),{call,stop}=await relay(dir);
  try{
    const inbox=await makeInboxKeyPair(),fingerprint=await inboxFingerprint(inbox.publicKey);
    const terms={give:{chain:'bitcoin',kind:'btc',id:'',amount:'50'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'100'},visibility:'public',expires:Math.floor(Date.now()/1000)+3600,ownerPublicKey:inbox.publicKey};
    const [,a]=await call('/offers',{method:'POST',data:terms});
    const post=(token,data)=>call('/offers/'+a.id+'/identity',{method:'POST',token,data});
    const owner=blob({id:a.id,role:'owner',inbox:fingerprint});
    assert.equal((await post(undefined,{identity:owner}))[0],401);
    assert.equal((await post(a.ownerToken,{identity:blob({id:a.id,role:'owner',inbox:'e'.repeat(64)})}))[0],400);
    assert.equal((await post(a.ownerToken,{identity:owner}))[0],201);
    assert.equal((await post(a.ownerToken,{identity:owner}))[0],409);
    assert.equal((await call('/offers/'+a.id))[1].ownerIdentity,owner);
    const [,b]=await call('/offers/'+a.id+'/reserve',{method:'POST'});
    const taker=blob({id:a.id,role:'taker',reservation:b.reservationId,inbox:'c'.repeat(64)});
    assert.equal((await post(a.ownerToken,{identity:taker,reservationId:b.reservationId}))[0],400);
    assert.equal((await post(b.reservationToken,{identity:taker,reservationId:'0'.repeat(64)}))[0],400);
    assert.equal((await post(b.reservationToken,{identity:taker,reservationId:b.reservationId}))[0],201);
    assert.equal((await post(b.reservationToken,{identity:taker,reservationId:b.reservationId}))[0],409);
    assert.equal((await call('/offers/'+a.id))[1].reservationIdentity,taker);
    const db=new DatabaseSync(join(dir,'offers.db'));db.prepare('UPDATE reservations SET expires=0 WHERE offer_id=?').run(a.id);db.close();
    assert.equal((await call('/offers/'+a.id))[1].reservationIdentity,undefined);
    const [,c]=await call('/offers/'+a.id+'/reserve',{method:'POST'});
    assert.equal((await call('/offers/'+a.id))[1].reservationIdentity,undefined);
    assert.equal((await post(b.reservationToken,{identity:taker,reservationId:b.reservationId}))[0],401);
    assert.equal((await post(c.reservationToken,{identity:blob({id:a.id,role:'taker',reservation:c.reservationId,inbox:'d'.repeat(64)}),reservationId:c.reservationId}))[0],201);
  }finally{await stop();await rm(dir,{recursive:true,force:true});}
});

test('the local relay upgrades a pre-P5 database additively and keeps its offers',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'swap-identity-old-'));
  const old=new DatabaseSync(join(dir,'offers.db'));
  old.exec(`CREATE TABLE offers (id TEXT PRIMARY KEY, owner_hash TEXT NOT NULL, public INTEGER NOT NULL, offer TEXT NOT NULL, expires INTEGER NOT NULL, closed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE reservations (offer_id TEXT PRIMARY KEY REFERENCES offers(id), token_hash TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, offer_id TEXT NOT NULL REFERENCES offers(id), sender TEXT NOT NULL, payload TEXT NOT NULL, created INTEGER NOT NULL);`);
  const id='1'.repeat(64);
  old.prepare('INSERT INTO offers(id,owner_hash,public,offer,expires) VALUES(?,?,?,?,?)').run(id,'h',1,JSON.stringify({give:{chain:'bitcoin',kind:'btc',id:'',amount:'1'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'2'}}),Math.floor(Date.now()/1000)+600);
  old.close();
  const {call,stop}=await relay(dir);
  try{
    const [status,offer]=await call('/offers/'+id);assert.equal(status,200);assert.equal(offer.ownerIdentity,undefined);
    await stop();
    const db=new DatabaseSync(join(dir,'offers.db'));
    assert.ok(db.prepare('PRAGMA table_info(offers)').all().some(c=>c.name==='owner_identity'));assert.ok(db.prepare('PRAGMA table_info(reservations)').all().some(c=>c.name==='identity'));
    assert.equal(db.prepare('SELECT count(*) AS n FROM offers').get().n,1);db.close();
  }finally{await stop();await rm(dir,{recursive:true,force:true});}
});
