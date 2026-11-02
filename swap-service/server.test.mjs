import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {newMessageKey,encryptMessage,decryptMessage} from '../swap-ui/crypto.mjs';
import {makeInboxKeyPair} from '../swap-ui/public-inbox.mjs';

async function availablePort() {
  const server=createServer();server.listen(0,'127.0.0.1');await once(server,'listening');
  const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;
}
test('private and public offers, exclusive reservations, authenticated relay and persistence',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'swap-relay-'));
  const port=await availablePort(); const base=`http://127.0.0.1:${port}`;
  let process;
  async function start() {
    process=spawn(globalThis.process.execPath,[resolve('swap-service/server.ts')],{env:{...globalThis.process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(port)},stdio:['ignore','pipe','pipe']});
    let error='';process.stderr.on('data',data=>error+=data);
    for(let i=0;i<100;i++) {try {if((await fetch(base+'/health')).ok) return;}catch{} await new Promise(resolve=>setTimeout(resolve,30));}
    throw Error('relay did not start: '+error);
  }
  async function stop() {if(process.exitCode===null){process.kill('SIGTERM');await once(process,'exit');}}
  async function call(path,{method='GET',data,token}={}) {
    const headers={}; if(data) headers['content-type']='application/json'; if(token) headers.authorization='Bearer '+token;
    const res=await fetch(base+path,{method,headers,body:data?JSON.stringify(data):undefined});return [res.status,await res.json()];
  }
  try {
    await start();
    const page=await fetch(base+'/');assert.equal(page.status,200);assert.match(await page.text(),/Offers and reservations do not lock assets/);
    assert.match(page.headers.get('content-security-policy'),/frame-ancestors 'none'/);
    assert.equal((await fetch(base+'/app.js')).status,200);
    assert.match((await fetch(base+'/crypto.mjs')).headers.get('content-type'),/javascript/);
    const terms={give:{chain:'ethereum',kind:'erc20',id:'0x1234567890123456789012345678901234567890',amount:'100'},receive:{chain:'bitcoin',kind:'btc',id:'',amount:'50'},visibility:'private',expires:Math.floor(Date.now()/1000)+3600};
    let [status,priv]=await call('/offers',{method:'POST',data:terms});assert.equal(status,201);
    const [pubStatus,pub]=await call('/offers',{method:'POST',data:{...terms,visibility:'public'}});assert.equal(pubStatus,201);
    let [,listing]=await call('/offers');assert.deepEqual(listing.offers.map(x=>x.id),[pub.id]);
    const inbox=await makeInboxKeyPair(),[inboxStatus,inboxOffer]=await call('/offers',{method:'POST',data:{...terms,visibility:'public',ownerPublicKey:inbox.publicKey}});assert.equal(inboxStatus,201);
    const [inboxReserve,inboxReservation]=await call('/offers/'+inboxOffer.id+'/reserve',{method:'POST'});assert.equal(inboxReserve,201);assert.match(inboxReservation.reservationId,/^[0-9a-f]{64}$/);
    const [,inboxRead]=await call('/offers/'+inboxOffer.id);assert.equal(inboxRead.ownerPublicKey,inbox.publicKey);assert.equal(inboxRead.reservationId,inboxReservation.reservationId);
    assert.equal((await call('/offers/'+inboxOffer.id+'/messages',{method:'POST',token:inboxOffer.ownerToken,data:{ciphertext:'YWJj'}}))[0],400);
    assert.equal((await call('/offers/'+inboxOffer.id+'/messages',{method:'POST',token:inboxOffer.ownerToken,data:{ciphertext:'YWJj',reservationId:'0'.repeat(64)}}))[0],409);
    assert.equal((await call('/offers/'+inboxOffer.id+'/messages',{method:'POST',token:inboxReservation.reservationToken,data:{ciphertext:'YWJj',reservationId:inboxReservation.reservationId}}))[0],201);
    assert.equal((await call('/offers',{method:'POST',data:{...terms,ownerPublicKey:'invalid'}}))[0],400);
    assert.equal((await call('/offers/'+priv.id))[0],200);
    assert.equal((await call('/offers',{method:'POST',data:{...terms,secret:'do not accept'}}))[0],400);
    assert.equal((await call('/offers',{method:'POST',data:{...terms,give:{chain:'ethereum',kind:'erc721',id:'0x1234567890123456789012345678901234567890:1',amount:'2'}}}))[0],400);
    const [reserved,reservation]=await call('/offers/'+priv.id+'/reserve',{method:'POST'});assert.equal(reserved,201);
    assert.equal((await call('/offers/'+priv.id+'/reserve',{method:'POST'}))[0],409);
    assert.equal((await call('/offers/'+priv.id+'/messages'))[0],401);
    const key=newMessageKey(), ciphertext=await encryptMessage(key,priv.id,'hello');
    assert.equal((await call('/offers/'+priv.id+'/messages',{method:'POST',token:reservation.reservationToken,data:{ciphertext}}))[0],201);
    const [,messages]=await call('/offers/'+priv.id+'/messages',{token:priv.ownerToken});assert.equal(await decryptMessage(key,priv.id,messages.messages[0].ciphertext),'hello');
    assert.equal((await call('/offers/'+priv.id+'/close',{method:'POST',token:reservation.reservationToken}))[0],403);
    assert.equal((await call('/offers/'+priv.id+'/close',{method:'POST',token:priv.ownerToken}))[0],200);
    await stop();await start();
    const [,inboxAfter]=await call('/offers/'+inboxOffer.id);assert.equal(inboxAfter.reservationId,inboxReservation.reservationId);assert.equal(inboxAfter.ownerPublicKey,inbox.publicKey);
    const [,after]=await call('/offers/'+priv.id+'/messages',{token:priv.ownerToken});assert.equal(after.messages.length,1);
    assert.equal((await call('/offers/'+priv.id+'/reserve',{method:'POST'}))[0],409);
  } finally {await stop();await rm(dir,{recursive:true,force:true});}
});
