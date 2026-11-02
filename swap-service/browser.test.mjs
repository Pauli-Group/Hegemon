import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';

async function port(){const s=createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const n=s.address().port;await new Promise(r=>s.close(r));return n;}
test('two browser sessions create a private offer and exchange encrypted messages',{timeout:60000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-browser-'));const n=await port(), base=`http://127.0.0.1:${n}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(n)},stdio:'ignore'});
 let browser;
 try {
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const owner=await browser.newContext(),taker=await browser.newContext();
  await owner.addInitScript(()=>{
    window.walletCalls=[];
    window.ethereum={request:async ({method})=>{window.walletCalls.push(method);if(method==='eth_requestAccounts')return ['0x1234567890123456789012345678901234567890'];if(method==='eth_chainId')return '0x7a69';throw Error('unexpected wallet request');}};
    window.cardano={fixture:{name:'Fixture wallet',enable:async()=>{window.walletCalls.push('cardano.enable');return {getNetworkId:async()=>0};}}};
  });
  const first=await owner.newPage(),second=await taker.newPage();
  await first.goto(base);await first.locator('[name="give-amount"]').fill('100');
  assert.deepEqual(await first.evaluate(()=>window.walletCalls),[]);
  await first.getByRole('button',{name:'Connect Ethereum wallet'}).click();await first.getByText('Ethereum connected:',{exact:false}).waitFor();
  await first.locator('#cardano-wallet').selectOption('fixture');await first.getByRole('button',{name:'Connect Cardano wallet'}).click();await first.getByText('Cardano connected:',{exact:false}).waitFor();
  assert.deepEqual(await first.evaluate(()=>window.walletCalls),['eth_requestAccounts','eth_chainId','cardano.enable']);
  await first.locator('[name="receive-type"]').selectOption('bitcoin:btc');await first.locator('[name="receive-amount"]').fill('50');
  await first.getByRole('button',{name:'Create offer'}).click();
  await first.locator('#share-link').waitFor({state:'visible'});const link=await first.locator('#share-link').inputValue();
  assert.match(link,/#([a-f0-9]{64})\.([a-f0-9]{64})$/);
  await second.goto(link);await second.getByRole('button',{name:'Reserve offer'}).click();
  await second.getByText('No funds have been locked.',{exact:false}).waitFor();
  await second.locator('#chat-form input').fill('hello from taker');await second.getByRole('button',{name:'Send encrypted message'}).click();
  await second.getByText('taker: hello from taker').waitFor();
  await first.getByRole('button',{name:'Refresh messages'}).click();await first.getByText('taker: hello from taker').waitFor();
  await first.locator('#chat-form input').fill('hello from owner');await first.getByRole('button',{name:'Send encrypted message'}).click();
  await second.getByRole('button',{name:'Refresh messages'}).click();await second.getByText('owner: hello from owner').waitFor();
  await owner.close();await taker.close();
 } finally {
  if(browser)await browser.close();
  if(server.exitCode===null){server.kill('SIGTERM');await once(server,'exit');}
  await rm(dir,{recursive:true,force:true});
 }
});
