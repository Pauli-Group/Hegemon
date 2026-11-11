import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
async function port(){const server=createServer();server.listen(0,'127.0.0.1');await once(server,'listening');const p=server.address().port;await new Promise(r=>server.close(r));return p;}

test('both browsers start a pinned session, retry a lost handshake and recover on refresh',{timeout:90000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-session-start-')),p=await port(),base=`http://127.0.0.1:${p}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(p)},stdio:'ignore'});
 let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const owner=await browser.newContext(),taker=await browser.newContext(),a=await owner.newPage(),b=await taker.newPage();
  await Promise.all([a.goto(base),b.goto(base)]);
  const ownerPublicKey=await a.evaluate(async()=>(await import('/public-inbox.mjs')).createInbox());
  const expires=Math.floor(Date.now()/1000)+3600,give={chain:'cardano',kind:'ada',id:'',amount:'5000000'},receive={chain:'ethereum',kind:'eth',id:'',amount:'100000000000000000'};
  const created=await (await fetch(base+'/offers',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({visibility:'private',expires,give,receive,ownerPublicKey})})).json();
  const reserved=await (await fetch(base+'/offers/'+created.id+'/reserve',{method:'POST'})).json();
  const offer={id:created.id,visibility:'private',expires,give,receive,ownerPublicKey};
  const setup=async(page,role,credential,loseResponse)=>page.evaluate(async({role,credential,loseResponse,offer,reservation})=>{
   const {sessionStarter}=await import('/session-start.mjs'),{sessionOfferDigest}=await import('/session-identity.mjs'),{inboxPrivateKey}=await import('/public-inbox.mjs');
   const pinnedOfferDigest=await sessionOfferDigest(offer);let lose=loseResponse;
   const api=async(path,options={})=>{
    const response=await fetch(path,{...options,headers:{...(options.body?{'content-type':'application/json'}:{}),...options.headers}}),value=await response.json();
    if(!response.ok)throw Error(value.error||'request failed');
    if(lose&&path.includes('/packets')&&options.method==='POST'){lose=false;throw Error('response lost after acceptance');}
    return value;
   };
   window.testStarter=await sessionStarter({role,offer,reservation,credential,pinnedOfferDigest,api,inboxPrivateKey});
   return window.testStarter.session;
  },{role,credential,loseResponse,offer,reservation:reserved.reservationId});
  const [ownerId,takerId]=await Promise.all([setup(a,'owner',created.ownerToken,false),setup(b,'taker',reserved.reservationToken,true)]);
  assert.equal(ownerId,takerId);
  assert.equal((await a.evaluate(()=>window.testStarter.advance())).stage,'waiting-for-other');
  assert.match(await b.evaluate(async()=>{try{await window.testStarter.advance();return 'unexpected';}catch(e){return e.message;}}),/response lost/);
  assert.equal((await windowEval(a)).stage,'backup-required');
  assert.equal((await windowEval(b)).stage,'backup-required');
  const [aReady,bReady]=await Promise.all([a.evaluate(()=>window.testStarter.advance('owner disposable passphrase')),b.evaluate(()=>window.testStarter.advance('taker disposable passphrase'))]);
  assert.equal(aReady.stage,'ready');assert.equal(bReady.stage,'ready');
  const get=async(page,role)=>page.evaluate(async({session,role})=>{const {getSession}=await import('/session-store.mjs');const record=await getSession(session,role);return {key:record.snapshot.channelKey,next:record.snapshot.transport.next,ack:record.backupAcknowledged,publicKey:record.publicKey};},{session:ownerId,role});
  const ownerState=await get(a,'owner'),takerState=await get(b,'taker');
  assert.equal(ownerState.key,takerState.key);assert.equal(ownerState.next,1);assert.equal(takerState.next,2);assert.equal(ownerState.ack,false);assert.equal(takerState.ack,false);assert.notEqual(ownerState.publicKey,takerState.publicKey);
  await a.reload();await setup(a,'owner',created.ownerToken,false);
  assert.equal((await a.evaluate(()=>window.testStarter.advance())).stage,'ready');
  const altered={...offer,give:{...offer.give,amount:'1'}};
  const refused=await a.evaluate(async({offer,altered,reservation,credential})=>{const {sessionStarter}=await import('/session-start.mjs'),{sessionOfferDigest}=await import('/session-identity.mjs');try{await sessionStarter({role:'owner',offer:altered,reservation,credential,pinnedOfferDigest:await sessionOfferDigest(offer),api:async()=>{throw Error('should not call');}});return false;}catch(e){return /offer changed/.test(e.message);}},{offer,altered,reservation:reserved.reservationId,credential:created.ownerToken});
  assert.equal(refused,true,'changed offer terms are rejected before a relay request');
 }finally{await browser?.close();server.kill('SIGTERM');await Promise.race([once(server,'exit'),new Promise(r=>setTimeout(r,2000))]);await rm(dir,{recursive:true,force:true});}
});
async function windowEval(page){return page.evaluate(()=>window.testStarter.advance());}
