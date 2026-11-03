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
test('Sepolia deployment requests one wallet transaction and journals the result',{timeout:60000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'sepolia-browser-')),n=await port(),base=`http://127.0.0.1:${n}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(n)},stdio:'ignore'});let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});const context=await browser.newContext();
  await context.addInitScript(()=>{window.sent=[];window.ethereum={request:async({method,params=[]})=>{
   if(method==='eth_requestAccounts'||method==='eth_accounts')return ['0x'+'1'.repeat(40)];if(method==='eth_chainId')return '0xaa36a7';
   if(method==='eth_getBlockByNumber')return params[0]==='0x0'?{hash:'0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9'}:{hash:'0x'+'b'.repeat(64),number:'0x10',timestamp:'0x64'};
   if(method==='eth_sendTransaction'){window.sent.push(params[0]);return '0x'+'9'.repeat(64);}throw Error('unexpected '+method);
  }};});
  const p=await context.newPage();await p.goto(base);await p.evaluate(()=>document.getElementById('sepolia-action-section').hidden=false);await p.getByRole('button',{name:'Connect Ethereum wallet'}).click();
  const terms={amount:'100',hashlock:'0x'+'a'.repeat(64),claimant:'0x'+'2'.repeat(40),refundee:'0x'+'1'.repeat(40),expiry:'5000'};
  for(const [k,v] of Object.entries(terms))await p.locator(`#sepolia-action-form [name="${k}"]`).fill(v);
  await p.getByRole('button',{name:'Deploy Sepolia escrow'}).click();await p.getByText('Transaction submitted. Check its receipt and confirmations.').waitFor();
  const sent=await p.evaluate(()=>window.sent);assert.equal(sent.length,1);assert.equal(sent[0].value,'0x64');
  await p.getByRole('button',{name:'Export action records'}).click();await p.waitForFunction(()=>{try{return JSON.parse(document.getElementById('action-journal-text').value).records.some(x=>x.operation==='deploy'&&x.state==='completed');}catch{return false;}});
 }finally{if(browser)await browser.close();server.kill('SIGTERM');await once(server,'exit').catch(()=>{});await rm(dir,{recursive:true,force:true});}
});
