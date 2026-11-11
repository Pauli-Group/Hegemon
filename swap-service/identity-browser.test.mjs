/* Two real browser sessions against the real local relay. A relay stub (Playwright routes) then plays a hostile relay that
 * substitutes the owner's inbox key, the owner's whole identity, and the taker's identity: every substitution must be
 * detected by the other party's page, and the conversation must stop. A fresh browser profile restores the inbox key.
 * Wallets are test signers held by this test (no value); the page only ever sees a wallet interface. */
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {ethereumWallet,ethereumProviderSource,bitcoinMessageWallet,cardanoWallet} from '../swap-ui/test-wallets.mjs';
import {draftStatement,statementText,signEthereum,bitcoinProof,addProof,publishable} from '../swap-ui/identity-flow.mjs';
import {inboxFingerprint} from '../swap-ui/public-inbox.mjs';

async function port(){const s=createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const n=s.address().port;await new Promise(r=>s.close(r));return n;}
const hex=bytes=>[...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,'0')).join('');
async function attackerKey(){const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);return hex(await crypto.subtle.exportKey('raw',pair.publicKey));}

const owner={eth:ethereumWallet('11'.repeat(32)),btc:bitcoinMessageWallet('21'.repeat(32))};
const taker={eth:ethereumWallet('12'.repeat(32)),btc:bitcoinMessageWallet('22'.repeat(32))};
const attacker={eth:ethereumWallet('13'.repeat(32)),btc:bitcoinMessageWallet('23'.repeat(32))};

/** A statement signed by the attacker's own wallets, valid on its face for this offer (and reservation) and role. */
async function forgedIdentity({offer,role,reservation,inbox}){
 const statement=draftStatement({role,offer,reservation,inbox,addresses:{give:attacker.btc.publicKey,receive:attacker.eth.address},now:Math.floor(Date.now()/1000)}),text=statementText(statement);
 let proofs=addProof(statement,[],bitcoinProof('bip137',attacker.btc.sign(text),text));
 proofs=addProof(statement,proofs,await signEthereum({request:async({params})=>attacker.eth.personalSign(params[0])},attacker.eth.address,text));
 return publishable(statement,proofs);
}

async function session(browser,wallet){
 const context=await browser.newContext();
 await context.exposeFunction('__personalSign',hexMessage=>wallet.eth.personalSign(hexMessage));
 await context.addInitScript(`window.ethereum=${ethereumProviderSource(wallet.eth.address)};`);
 return context;
}
/** Fill both addresses, sign with both wallets and publish. Returns the identity code shown by the page. */
async function publishIdentity(page,wallet){
 await page.locator('#identity-form').waitFor({state:'visible'});
 await page.locator('#identity-legs input[name="give"]').fill(wallet.btc.publicKey);
 await page.getByRole('button',{name:'Use connected Ethereum account'}).click();
 await page.getByRole('button',{name:'Prepare statement'}).click();
 await page.locator('#identity-text').waitFor({state:'visible'});
 const text=await page.locator('#identity-text').textContent();
 await page.locator('#identity-bitcoin-scheme').selectOption('bip137');
 await page.locator('#identity-bitcoin-signature').fill(wallet.btc.sign(text));
 await page.getByRole('button',{name:'Add Bitcoin signature'}).click();
 await page.getByRole('button',{name:'Sign with Ethereum wallet'}).click();
 await page.waitForFunction(()=>document.querySelectorAll('#identity-proofs li').length===2);
 await page.getByRole('button',{name:'Publish signed identity'}).click();
 await page.locator('#identity-status').getByText('Published.',{exact:false}).waitFor();
}
const peerText=page=>page.locator('#identity-peer').textContent();

test('a hostile relay cannot substitute an inbox key or an identity without the other page detecting it',{timeout:240000},async()=>{
 // SWAP_BASE=http://127.0.0.1:8799 runs the same test against `wrangler dev --local` (the Worker and D1 in the Workers runtime).
 const dir=await mkdtemp(join(tmpdir(),'swap-identity-'));const external=process.env.SWAP_BASE,n=external?0:await port(),base=external||`http://127.0.0.1:${n}`;
 const server=external?{exitCode:0}:spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(n)},stdio:'ignore'});
 let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const ownerContext=await session(browser,owner),takerContext=await session(browser,taker);
  const first=await ownerContext.newPage(),second=await takerContext.newPage();
  const pageErrors=[];for(const page of [first,second])page.on('pageerror',error=>pageErrors.push(error.message));

  // ---- the owner creates a public offer with a backed-up inbox key and publishes a signed identity
  await first.goto(base);
  await first.getByRole('button',{name:'Connect Ethereum wallet'}).click();await first.getByText('Ethereum connected:',{exact:false}).waitFor();
  await first.locator('[name="give-type"]').selectOption('bitcoin:btc');await first.locator('[name="give-amount"]').fill('1000');
  await first.locator('[name="receive-type"]').selectOption('ethereum:eth');await first.locator('[name="receive-amount"]').fill('5000');
  await first.locator('#offer-form [name="visibility"]').selectOption('public');
  const backupPhrase='correct horse battery staple',wrongPhrase='wrong horse battery staple';
  await first.locator('#offer-form [name="backup-passphrase"]').fill(backupPhrase);
  await first.getByRole('button',{name:'Create offer'}).click();
  await first.locator('#share-link').waitFor({state:'visible'});
  const backup=await first.locator('#inbox-backup-text').inputValue();assert.match(backup,/"type":"inbox-key"/);assert.ok(!backup.includes(backupPhrase));
  const shared=await first.locator('#share-link').inputValue(),id=shared.split('#')[1].split('.')[0];
  await publishIdentity(first,owner);
  await first.locator('#identity-peer').getByText('Owner identity verified',{exact:false}).waitFor();
  const link=await first.locator('#identity-link').inputValue();assert.match(link,/#[0-9a-f]{64}\.[0-9a-f]{64}\.[0-9a-f]{16}$/);
  const ownerCode=link.split('.')[2];

  // ---- the taker follows the link with the owner's code, reserves and publishes an identity of their own
  await second.goto(link);
  await second.getByRole('button',{name:'Connect Ethereum wallet'}).click();await second.getByText('Ethereum connected:',{exact:false}).waitFor();
  await second.locator('#identity-peer').getByText('matches the pinned code',{exact:false}).waitFor();
  await second.getByRole('button',{name:'Reserve offer'}).click();await second.getByText('No funds have been locked.',{exact:false}).waitFor();
  await second.locator('#chat-form input').fill('hello');await second.getByRole('button',{name:'Send encrypted message'}).click();await second.getByText('taker: hello').waitFor();
  await publishIdentity(second,taker);
  await first.getByRole('button',{name:'Refresh messages'}).click();
  await first.locator('#identity-peer').getByText('Taker identity verified',{exact:false}).waitFor();
  assert.match(await peerText(first),/Give leg: bitcoin 0[23][0-9a-f]{64} \(proven by wallet signature\)/);
  assert.equal(await first.locator('#chat-form button').isDisabled(),false);

  // ---- substitution 1: the relay swaps the owner's inbox key for its own. The signed statement names the real key.
  const attackerPub=await attackerKey();
  const offerRoute='**/offers/'+id;
  await second.route(offerRoute,async route=>{if(route.request().method()!=='GET')return route.continue();const response=await route.fetch(),value=await response.json();value.ownerPublicKey=attackerPub;return route.fulfill({response,json:value});});
  await second.getByRole('button',{name:'Refresh messages'}).click();
  await second.locator('#identity-peer').getByText('FAILED',{exact:false}).waitFor();
  assert.match(await peerText(second),/inbox/i);
  assert.equal(await second.locator('#chat-form button').isDisabled(),true);
  await second.unrouteAll({behavior:'wait'});

  // ---- substitution 2: the relay fabricates a whole owner identity, validly signed, under its own inbox key. The pin catches it.
  const offerBody=await (await fetch(base+'/offers/'+id)).json();
  const fakeOwner=await forgedIdentity({offer:offerBody,role:'owner',reservation:'',inbox:await inboxFingerprint(attackerPub)});
  await second.route(offerRoute,async route=>{if(route.request().method()!=='GET')return route.continue();const response=await route.fetch(),value=await response.json();value.ownerPublicKey=attackerPub;value.ownerIdentity=fakeOwner;return route.fulfill({response,json:value});});
  await second.getByRole('button',{name:'Refresh messages'}).click();
  await second.locator('#identity-peer').getByText('FAILED',{exact:false}).waitFor();
  assert.equal(await second.locator('#chat-form button').isDisabled(),true);
  assert.match(await peerText(second),new RegExp(ownerCode.slice(0,4)+'|pinned|code','i'));
  await second.unrouteAll({behavior:'wait'});
  await second.getByRole('button',{name:'Refresh messages'}).click();
  await second.locator('#identity-peer').getByText('matches the pinned code',{exact:false}).waitFor();
  assert.equal(await second.locator('#chat-form button').isDisabled(),false);

  // ---- substitution 3: the relay shows the owner a forged taker identity for the live reservation (and a replay of a real one).
  const live=await (await fetch(base+'/offers/'+id)).json();
  const fakeTaker=await forgedIdentity({offer:offerBody,role:'taker',reservation:live.reservationId,inbox:hex(crypto.getRandomValues(new Uint8Array(32)))});
  await first.route(offerRoute,async route=>{if(route.request().method()!=='GET')return route.continue();const response=await route.fetch(),value=await response.json();value.reservationIdentity=fakeTaker;return route.fulfill({response,json:value});});
  await first.getByRole('button',{name:'Refresh messages'}).click();
  await first.locator('#identity-peer').getByText('FAILED',{exact:false}).waitFor();
  assert.equal(await first.locator('#chat-form button').isDisabled(),true);
  await first.unrouteAll({behavior:'wait'});
  // The owner's own genuine statement presented as the taker's: wrong role and wrong reservation.
  const ownerGenuine=(await (await fetch(base+'/offers/'+id)).json()).ownerIdentity;
  await first.route(offerRoute,async route=>{if(route.request().method()!=='GET')return route.continue();const response=await route.fetch(),value=await response.json();value.reservationIdentity=ownerGenuine;return route.fulfill({response,json:value});});
  await first.getByRole('button',{name:'Refresh messages'}).click();
  await first.locator('#identity-peer').getByText('FAILED',{exact:false}).waitFor();
  await first.unrouteAll({behavior:'wait'});
  await first.getByRole('button',{name:'Refresh messages'}).click();
  await first.locator('#identity-peer').getByText('Taker identity verified',{exact:false}).waitFor();

  // ---- a viewer with no code and no earlier visit has nothing to compare with: the page says so rather than claiming safety
  const stranger=await (await browser.newContext()).newPage();
  await stranger.goto(base+'/#'+id);
  await stranger.locator('#identity-peer').getByText('first seen here; confirm the code',{exact:false}).waitFor();
  assert.match(await peerText(stranger),new RegExp(ownerCode));

  // ---- a fresh browser profile restores the owner's inbox key from the encrypted backup
  const fresh=await (await browser.newContext()).newPage();
  const stored=publicKey=>fresh.evaluate(async key=>{try{const k=await (await import('/public-inbox.mjs')).inboxPrivateKey(key);return {ok:true,extractable:k.extractable,type:k.type};}catch(e){return {ok:false,error:e.message};}},publicKey);
  const ownerPublicKey=offerBody.ownerPublicKey;
  await fresh.goto(base);
  assert.equal((await stored(ownerPublicKey)).ok,false);
  const restore=async(text,phrase)=>{await fresh.locator('#restore-form [name="backup"]').fill(text);await fresh.locator('#restore-form [name="passphrase"]').fill(phrase);await fresh.getByRole('button',{name:'Restore inbox key'}).click();
   await fresh.waitForFunction(()=>document.getElementById('restore-result').textContent!==''&&!document.querySelector('#restore-form button').disabled);return fresh.locator('#restore-result').textContent();};
  // corrupted, wrong passphrase and a swapped public key all fail closed and store nothing
  const envelope=JSON.parse(backup),corrupted=structuredClone(envelope);corrupted.ciphertext=(corrupted.ciphertext[0]==='0'?'1':'0')+corrupted.ciphertext.slice(1);
  assert.match(await restore(JSON.stringify(corrupted),backupPhrase),/Could not unlock|altered|invalid/i);
  assert.match(await restore(backup,wrongPhrase),/Could not unlock/i);
  assert.match(await restore(backup.slice(0,-3),backupPhrase),/./);
  assert.equal((await stored(ownerPublicKey)).ok,false);
  const swapped=structuredClone(envelope);swapped.publicKey=attackerPub;
  assert.match(await restore(JSON.stringify(swapped),backupPhrase),/Could not unlock|altered|invalid|match/i);
  assert.equal((await stored(attackerPub)).ok,false);
  // the real backup restores, as a non-extractable key, and a repeat changes nothing
  assert.match(await restore(backup,backupPhrase),/Inbox key restored\. Fingerprint [0-9a-f]{64}/);
  assert.deepEqual(await stored(ownerPublicKey),{ok:true,extractable:false,type:'private'});
  assert.match(await restore(backup,backupPhrase),/already holds that inbox key/);
  // a different key already stored under the same public key is never overwritten
  const clash=await (await browser.newContext()).newPage();await clash.goto(base);
  await clash.evaluate(async key=>{const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
   const db=await new Promise((resolve,reject)=>{const r=indexedDB.open('hegemon.local.offer-inbox.v1',1);r.onupgradeneeded=()=>r.result.createObjectStore('keys',{keyPath:'publicKey'});r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
   await new Promise((resolve,reject)=>{const tx=db.transaction('keys','readwrite');tx.objectStore('keys').add({publicKey:key,privateKey:pair.privateKey});tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);});db.close();},ownerPublicKey);
  await clash.locator('#restore-form [name="backup"]').fill(backup);await clash.locator('#restore-form [name="passphrase"]').fill(backupPhrase);await clash.getByRole('button',{name:'Restore inbox key'}).click();
  await clash.locator('#restore-result').getByText('A different inbox key is already stored',{exact:false}).waitFor();
  assert.deepEqual(pageErrors,[]);
 }finally{
  if(browser)await browser.close();
  if(server.exitCode===null){server.kill('SIGTERM');await once(server,'exit');}
  await rm(dir,{recursive:true,force:true});
 }
});

test('the browser refuses to run a served module or entry script that differs from the manifest',{timeout:120000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-integrity-'));const n=await port(),base=`http://127.0.0.1:${n}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(n)},stdio:'ignore'});
 let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const loaded=async(tamper)=>{
   const context=await browser.newContext(),page=await context.newPage(),errors=[];
   page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error'&&!m.location().url.endsWith('/favicon.ico'))errors.push(m.text());});
   if(tamper)await page.route('**/'+tamper,async route=>{const response=await route.fetch(),body=await response.text();return route.fulfill({response,body:body+'\n// altered by a hostile host\n'});});
   await page.goto(base);await page.waitForLoadState('load');await new Promise(r=>setTimeout(r,500));
   const options=await page.evaluate(()=>document.querySelector('[name="give-type"]').options.length);
   await context.close();return {options,errors};
  };
  const clean=await loaded(null);assert.equal(clean.options,8);assert.deepEqual(clean.errors,[]);
  for(const file of ['pair-check.mjs','identity.mjs','vendor/hash.mjs','app.js']){
   const result=await loaded(file);
   assert.equal(result.options,0,file+' altered: the application must not start');
   assert.ok(result.errors.length>0,file+' altered: the browser must report a failure');
  }
 }finally{
  if(browser)await browser.close();
  if(server.exitCode===null){server.kill('SIGTERM');await once(server,'exit');}
  await rm(dir,{recursive:true,force:true});
 }
});

test('connected Cardano and Ethereum wallets supply empty identity fields without signing or overwriting edits',{timeout:90000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-autofill-')),n=await port(),base=`http://127.0.0.1:${n}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(n)},stdio:'ignore'});
 let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const context=await browser.newContext(),eth=ethereumWallet('16'.repeat(32)),ada=cardanoWallet('17'.repeat(32));
  await context.exposeFunction('__testEthereumSign',payload=>eth.personalSign(payload));
  await context.exposeFunction('__testCardanoSign',(address,payload)=>ada.signData(address,payload));
  await context.addInitScript(({address,cardanoAddress})=>{
   window.walletApprovals=0;
   window.ethereum={request:async({method,params})=>{if(method==='eth_requestAccounts'||method==='eth_accounts')return [address];if(method==='eth_chainId')return '0xaa36a7';if(method==='personal_sign'){window.walletApprovals++;return window.__testEthereumSign(params[0]);}throw Error('Unexpected wallet request');},on(){}};
   window.cardano={test:{name:'Test wallet',enable:async()=>({getNetworkId:async()=>0,getUsedAddresses:async()=>[cardanoAddress],signData:async(a,p)=>{window.walletApprovals++;return window.__testCardanoSign(a,p);}})}};
  },{address:eth.address,cardanoAddress:ada.addressHex});
  const page=await context.newPage();await page.goto(base);
  await page.locator('#connect-ethereum').click();await page.locator('#wallet-status').getByText('Ethereum connected',{exact:false}).waitFor();
  await page.locator('#cardano-wallet').selectOption('test');await page.locator('#connect-cardano').click();await page.locator('#wallet-status').getByText('Cardano connected',{exact:false}).waitFor();
  await page.locator('#offer-form [name="give-type"]').selectOption('cardano:ada');
  await page.locator('#offer-form [name="give-amount"]').fill('5000000');
  await page.locator('#offer-form [name="receive-type"]').selectOption('ethereum:eth');
  await page.locator('#offer-form [name="receive-amount"]').fill('100000000000000000');
  await page.locator('#offer-form button[type="submit"]').click();
  await page.locator('#identity-form').waitFor({state:'visible'});
  await page.waitForFunction(({key,address})=>document.querySelector('#identity-legs [name="give"]').value===key&&document.querySelector('#identity-legs [name="receive"]').value===address,{key:ada.keyHash,address:eth.address});
  await page.locator('#identity-legs [name="receive"]').fill('0x'+'aa'.repeat(20));
  await page.locator('#connect-ethereum').click();
  assert.equal(await page.locator('#identity-legs [name="receive"]').inputValue(),'0x'+'aa'.repeat(20),'an explicit edit must not be overwritten');
  assert.equal(await page.evaluate(()=>window.walletApprovals),0,'autofill must never request a signature or transaction');
  await page.locator('#identity-legs [name="receive"]').fill(eth.address);
  await page.locator('#journey-mode').click();
  await page.evaluate(()=>window.dispatchEvent(new Event('hashchange')));
  await page.locator('#journey-identity-next').evaluate(button=>button.click()); // Exercise the retained legacy identity screen.
  await page.locator('#identity-prepare').click();
  await page.locator('#identity-sign-cardano').waitFor({state:'visible'});
  assert.equal(await page.locator('#identity-sign-ethereum').isVisible(),false,'only the next wallet signature is shown');
  await page.locator('#identity-sign-cardano').click();
  await page.locator('#identity-sign-ethereum').waitFor({state:'visible'});
  assert.equal(await page.locator('#identity-sign-cardano').isVisible(),false);
  assert.equal(await page.locator('#identity-publish').isVisible(),false,'both wallet proofs are required in guided view');
  await page.locator('#identity-sign-ethereum').click();
  await page.locator('#identity-publish').waitFor({state:'visible'});
  assert.equal(await page.evaluate(()=>window.walletApprovals),2);
  await page.locator('#identity-publish').click();
  await page.locator('#identity-status').getByText('Published.',{exact:false}).waitFor();
  await page.locator('.journey-swap-status').getByText('Waiting for someone to reserve').waitFor();
 }finally{await browser?.close();server.kill('SIGTERM');await Promise.race([once(server,'exit'),new Promise(r=>setTimeout(r,2000))]);await rm(dir,{recursive:true,force:true});}
});
