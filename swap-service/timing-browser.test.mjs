import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {chromium} from 'playwright-core';

async function port(){const s=createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const n=s.address().port;await new Promise(r=>s.close(r));return n;}

test('served page loads the timing policy and comparePair rejects an insufficient gap in a real browser',{timeout:60000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'timing-browser-')),n=await port(),base=`http://127.0.0.1:${n}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(n)},stdio:'ignore'});let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
  const page=await (await browser.newContext()).newPage(),errors=[];
  page.on('pageerror',error=>errors.push(error.message));page.on('response',response=>{if(response.status()>=400&&!response.url().endsWith('/favicon.ico'))errors.push(response.status()+' '+response.url());});
  await page.goto(base);await page.waitForLoadState('networkidle');
  assert.deepEqual(errors,[],'the page and its modules load without errors');
  assert.equal(await page.locator('#public-pair-timing').count(),1);
  const outcome=await page.evaluate(async()=>{
   const [{comparePair,TimingError},{planTimeouts}]=await Promise.all([import('/pair-check.mjs'),import('/timelock-policy.mjs')]);
   const config=await (await fetch('/chain-timing.json')).json(),now=1_793_935_000,digest='a'.repeat(64);
   const heads={long:{observedAt:now,timestamp:now-10},short:{observedAt:now,timestamp:now-10}};
   const plan=planTimeouts(config,{longChain:'ethereum',shortChain:'cardano',heads,now});
   const offer={give:{chain:'ethereum',kind:'eth',id:'',amount:'4'},receive:{chain:'cardano',kind:'ada',id:'',amount:'9'}};
   const leg=(longExpiry)=>[{chain:'ethereum',terms:{kind:'eth',amount:'4',hashlock:'0x'+digest,contract:'0x'+'1'.repeat(40),expiry:String(longExpiry)}},{chain:'cardano',terms:{outref:'c'.repeat(64)+'#0',hashlock:digest,expected_value:{lovelace:'9'},expiry_ms:plan.short.expiry*1000}}];
   const timing={config,now,heads:{give:heads.long,receive:heads.short}};
   const [give,receive]=leg(plan.long.expiry),[tight]=leg(plan.long.expiry-3600);
   const accepted=comparePair(offer,give,receive,timing).timing.ok;
   let rejected=null;try{comparePair(offer,tight,receive,timing);}catch(error){rejected={timing:error instanceof TimingError,codes:error.verdict.reasons.map(r=>r.code)};}
   return {accepted,rejected};
  });
  assert.equal(outcome.accepted,true);
  assert.deepEqual(outcome.rejected,{timing:true,codes:['insufficient-gap']});
 }finally{if(browser)await browser.close();server.kill('SIGTERM');await once(server,'exit').catch(()=>{});await rm(dir,{recursive:true,force:true});}
});
