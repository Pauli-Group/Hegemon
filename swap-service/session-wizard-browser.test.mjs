import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {cardanoWallet,ethereumWallet} from '../swap-ui/test-wallets.mjs';
import {SEPOLIA_GENESIS} from '../swap-ui/sepolia-verifier.mjs';
import {HOSTED_CSP} from './cloudflare/client-policy.mjs';
import {softwareWallet,rowOf} from './tools/cardano-bridge.mjs';
import * as ct from '../swap-ui/cardano-tx.mjs';
import {decode,fromHex,toHex} from '../swap-ui/cbor.mjs';
import {PREVIEW_HTLC_ADDRESS} from '../swap-ui/cardano-preview-verifier.mjs';
import {expectedEtherRuntime} from '../swap-ui/ethereum-escrow.mjs';
const TEST_TOKEN='ab'.repeat(28)+'.cd';
async function port(){const s=createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const p=s.address().port;await new Promise(r=>s.close(r));return p;}
async function participant(browser,base,html,seed,cardanoParams,etherTemplate,network){
 const context=await browser.newContext(),cardano=cardanoWallet(seed.repeat(32)),ethereum=ethereumWallet((Number(seed)+1).toString(16).padStart(2,'0').repeat(32));
 const seedBytes=new Uint8Array(32).fill(parseInt(seed,16)),address=ct.toBech32(fromHex(cardano.addressHex));
 const utxos=[{ref:seed.repeat(32)+'#0',address,lovelace:50000000,assets:{[TEST_TOKEN]:100}},{ref:(Number(seed)+1).toString(16).padStart(2,'0').repeat(32)+'#0',address,lovelace:6000000,assets:{}}];
 const wallet=softwareWallet({seed:seedBytes,address,utxos,collateral:[utxos[1].ref],onSubmit:hex=>{
  const tx=ct.inspectTx(fromHex(hex)),txid=toHex(tx.bodyHash),output=tx.outputs[0];
  if(output.datum?.bytes){const datum=decode(output.datum.bytes),fields=datum.value;
   network.cardano.set(txid+'#0',{tx_hash:txid,tx_index:0,address:PREVIEW_HTLC_ADDRESS,value:output.value.lovelace.toString(),asset_list:Object.entries(output.value.assets).map(([name,quantity])=>({policy_id:name.split('.')[0],asset_name:name.split('.')[1],quantity:String(quantity)})),is_spent:false,inline_datum:{bytes:toHex(output.datum.bytes),value:{constructor:0,fields:[{bytes:toHex(fields[0])},{bytes:toHex(fields[1])},{bytes:toHex(fields[2])},{int:Number(fields[3])}]}}});
  }else{
   const input=tx.inputs.map(item=>`${item.txid}#${item.index}`).find(ref=>network.cardano.has(ref));
   if(!input)throw Error('Test claim did not spend a known Cardano escrow.');network.cardano.get(input).is_spent=true;network.cardanoSpends.set(input,{txid,hex});
  }
 }});
 await context.route(base+'/',route=>route.fulfill({status:200,body:html,headers:{'content-type':'text/html; charset=utf-8','content-security-policy':HOSTED_CSP}}));
 await context.route('**/cardano-preview/params',route=>route.fulfill({json:{...cardanoParams,slot:Math.floor(Date.now()/1000)-1666656000+network.elapsed}}));
 await context.route('**/cardano-preview/utxos?*',route=>{const refs=new URL(route.request().url()).searchParams.get('refs').split(',');const rows=new Map(utxos.map(item=>[item.ref,rowOf(item)]));return route.fulfill({json:{...cardanoParams,slot:Math.floor(Date.now()/1000)-1666656000+network.elapsed,outputs:refs.map(ref=>rows.get(ref)||network.cardano.get(ref)||null)}});});
 await context.route('**/cardano-preview/escrow?*',route=>{const outref=new URL(route.request().url()).searchParams.get('outref');return route.fulfill({json:{network:'preview',magic:2,system_start:1666656000,slot:Math.floor(Date.now()/1000)-1666656000+network.elapsed,confirmations:3,output:network.cardano.get(outref)||null}});});
 await context.route('**/cardano-preview/spend?*',route=>{const outref=new URL(route.request().url()).searchParams.get('outref'),spend=network.cardanoSpends.get(outref);return route.fulfill({json:spend?{network:'preview',outref,spent:true,indexed:true,spender:spend.txid,cbor:spend.hex,confirmations:3}:{network:'preview',outref,spent:false}});});
 await context.route('**/sepolia/escrow-events?*',route=>{const contract=new URL(route.request().url()).searchParams.get('contract'),evm=network.ethereum;return route.fulfill({json:{chain_id:11155111,contract,deployed:true,spent:!!(evm?.secret||evm?.refunded),events:evm?.secret?[{kind:'claimed',data:'0x'+evm.secret,tx_hash:evm.claimTx,confirmations:3}]:evm?.refunded?[{kind:'refunded',tx_hash:evm.claimTx,confirmations:3}]:[]}});});
 const ethRead=({method,params=[]})=>{
  const timestamp='0x'+(Math.floor(Date.now()/1000)+network.elapsed).toString(16),head={timestamp,number:'0x64',hash:'0x'+'aa'.repeat(32)},evm=network.ethereum;
  let result=null;
  if(method==='eth_chainId')result='0xaa36a7';
  else if(method==='eth_getBlockByNumber')result=params[0]==='0x0'?{hash:SEPOLIA_GENESIS}:params[0]==='latest'?head:{...head,number:params[0],hash:'0x'+'bb'.repeat(32)};
  else if(method==='eth_blockNumber')result='0x64';
  else if(method==='eth_getTransactionReceipt'&&evm)result={transactionHash:evm.txid,status:'0x1',contractAddress:evm.contract};
  else if(method==='eth_getTransactionByHash'&&evm)result={hash:evm.txid,to:null,from:evm.fields.refundee};
  else if(method==='eth_getCode'&&evm)result=expectedEtherRuntime(etherTemplate,evm.fields);
  else if(method==='eth_call'&&evm)result='0x'+(params[0].data==='0x7ab71b7a'&&evm.secret?'1':'0').padStart(64,'0');
  else if(method==='eth_getBalance'&&evm)result='0x'+BigInt(evm.fields.amount).toString(16);
  if(result===null)throw Error('Unexpected test RPC '+method);return result;
 };
 await context.route('**/sepolia/rpc',route=>{try{return route.fulfill({json:{result:ethRead(route.request().postDataJSON())}});}catch{return route.fulfill({status:400,json:{error:'Unexpected test RPC'}});}});
 await context.exposeFunction('__testAdaSign',(address,payload)=>cardano.signData(address,payload));
 await context.exposeFunction('__testEthSign',payload=>ethereum.personalSign(payload));
 await context.exposeFunction('__testEthRead',ethRead);
 await context.exposeFunction('__testEthSend',tx=>{if(tx.to){if(tx.data.slice(0,10)==='0xbd66528a')network.ethereum.secret=tx.data.slice(10);else if(tx.data==='0x590e1ae3')network.ethereum.refunded=true;else throw Error('Unexpected test spend');network.ethereum.claimTx='0x'+'88'.repeat(32);return network.ethereum.claimTx;}
  const tail=tx.data.slice(-192),fields={hashlock:'0x'+tail.slice(0,64),claimant:'0x'+tail.slice(88,128),expiry:BigInt('0x'+tail.slice(128,192)).toString(),refundee:tx.from.toLowerCase(),amount:BigInt(tx.value).toString()};const txid='0x'+'66'.repeat(32),contract='0x'+'77'.repeat(20);network.ethereum={txid,contract,fields};return txid;});
 await context.exposeFunction('__testAdaWallet',(method,args)=>wallet[method](...args));
 await context.addInitScript(({adaAddress,ethAddress,genesis})=>{
  window.signatures=Number(sessionStorage.getItem('test.signatures')||0);window.transactions=Number(sessionStorage.getItem('test.transactions')||0);
  window.ethereum={request:async({method,params=[]})=>{if(method==='eth_requestAccounts'||method==='eth_accounts')return [ethAddress];if(method==='personal_sign'){sessionStorage.setItem('test.signatures',String(++window.signatures));return window.__testEthSign(params[0]);}if(method==='eth_sendTransaction'){sessionStorage.setItem('test.transactions',String(++window.transactions));return window.__testEthSend(params[0]);}return window.__testEthRead({method,params});},on(){}};
  window.cardano={test:{name:'Test wallet',enable:async()=>({getNetworkId:async()=>0,getUsedAddresses:async()=>[adaAddress],getUnusedAddresses:async()=>[],getUtxos:(...a)=>window.__testAdaWallet('getUtxos',a),getCollateral:(...a)=>window.__testAdaWallet('getCollateral',a),getChangeAddress:(...a)=>window.__testAdaWallet('getChangeAddress',a),signTx:(...a)=>{sessionStorage.setItem('test.transactions',String(++window.transactions));return window.__testAdaWallet('signTx',a);},submitTx:(...a)=>window.__testAdaWallet('submitTx',a),signData:async(a,p)=>{sessionStorage.setItem('test.signatures',String(++window.signatures));return window.__testAdaSign(a,p);}})}};
 },{adaAddress:cardano.addressHex,ethAddress:ethereum.address,genesis:SEPOLIA_GENESIS});
 return {context,page:await context.newPage()};
}
async function createOffer(page,native=false,reverse=false){
 await page.getByRole('button',{name:/Create an offer/}).click();
 await page.locator('#journey-give-type').selectOption(reverse?'ethereum:eth':native?'cardano:native':'cardano:ada');if(native)await page.locator('#journey-give-id').fill(TEST_TOKEN);await page.locator('#journey-next').click();
 await page.locator('#journey-give-amount').fill(reverse?'0.1':'5');await page.locator('#journey-next').click();
 await page.locator('#journey-receive-type').selectOption(reverse?'cardano:ada':'ethereum:eth');await page.locator('#journey-next').click();
 await page.locator('#journey-receive-amount').fill(reverse?'5':'0.1');await page.locator('#journey-next').click();
 await page.locator('[name="journey-visibility"][value="private"]').check();await page.locator('#journey-next').click();
 await page.locator('#journey-lifetime').selectOption('86400');await page.locator('#journey-next').click();
 await page.locator('[name="journey-backup"][value="no"]').check();await page.locator('#journey-next').click();
 await page.locator('#journey-publish').click();await page.locator('#journey-created').waitFor({state:'visible'});
 return page.locator('#journey-share-link').inputValue();
}
async function initialBackup(page,phrase){
 const panel=page.locator('#session-wizard');
 await panel.getByText('Protect your swap recovery').waitFor();
 await panel.getByLabel('Backup passphrase',{exact:true}).fill(phrase);await panel.getByLabel('Repeat passphrase').fill(phrase);
 await panel.getByRole('button',{name:'Create recovery backup'}).click();await panel.getByText('Save your encrypted recovery backup').waitFor();
 assert.ok((await panel.locator('textarea').inputValue()).length>100);
 await panel.getByRole('button',{name:'I saved the backup'}).click();
}
async function signParticipant(page,phrase,reverse=false){
 const panel=page.locator('#session-wizard');
 await panel.getByRole('button',{name:'Connect Ethereum wallet'}).click();
 await page.waitForFunction(()=>['Connect your Cardano wallet','Update your recovery backup'].includes(document.querySelector('#session-wizard h3')?.textContent));
 if(await panel.getByText('Update your recovery backup').isVisible())await updateBackup(page,phrase);
 await panel.getByLabel('Cardano wallet').selectOption('test');await panel.getByRole('button',{name:'Connect Cardano wallet'}).click();
 await panel.getByRole('button',{name:reverse?'Sign with Ethereum':'Sign with Cardano'}).click();
 await panel.getByRole('button',{name:reverse?'Sign with Cardano':'Sign with Ethereum'}).click();
 await panel.getByText('Update your recovery backup').waitFor();
}
async function updateBackup(page,phrase){
 const panel=page.locator('#session-wizard');await panel.getByText('Update your recovery backup').waitFor();
 await panel.getByLabel('Backup passphrase').fill(phrase);await panel.getByRole('button',{name:'Update recovery backup'}).click();
 await panel.getByText('Save your encrypted recovery backup').waitFor();const backup=await panel.locator('textarea').inputValue();await panel.getByRole('button',{name:'I saved the backup'}).click();return backup;
}
async function refundAfterRelayFailure(person,phrase,network,chain){
 const page=person.page,panel=page.locator('#session-wizard');network.elapsed=20*86400;
 await person.context.route('**/swap-sessions/**',route=>route.fulfill({status:503,json:{error:'test relay outage'}}));
 await page.reload();
 await panel.getByRole('button',{name:'Refund options'}).click();
 await panel.getByText('Prepare your refund').waitFor();
 await panel.getByRole('button',{name:'Prepare refund'}).click();await updateBackup(page,phrase);
 if(chain==='cardano'){await panel.getByLabel('Cardano wallet').selectOption('test');await panel.getByRole('button',{name:'Connect Cardano wallet'}).click();}
 else await panel.getByRole('button',{name:'Connect Ethereum wallet'}).click();
 await panel.getByRole('button',{name:'Review refund transaction'}).click();await panel.getByText('Review the wallet transaction').waitFor();
 assert.equal(await page.evaluate(()=>window.transactions),1,'refund must wait for explicit local approval');
 await panel.getByRole('button',{name:'Approve and open wallet'}).click();await updateBackup(page,phrase);
 await panel.getByText('Refund confirmed').waitFor();assert.equal(await page.evaluate(()=>window.transactions),2);
}

for(const scenario of ['claim','reverse','cardano-token','refund-cardano','refund-ethereum'])test(`guided session: ${scenario} with refresh and explicit wallet approval`,{timeout:120000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-wizard-')),p=await port(),base=`http://127.0.0.1:${p}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(p)},stdio:'ignore'});
 let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  const html=await readFile('swap-ui/hosted.html'),cardanoParams=JSON.parse(await readFile('swap-ui/fixtures/cardano-preview-params.json','utf8')),etherTemplate=JSON.parse(await readFile('swap-ui/ether-escrow-template.json','utf8'));browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const network={cardano:new Map(),cardanoSpends:new Map(),ethereum:null,elapsed:0},owner=await participant(browser,base,html,'11',cardanoParams,etherTemplate,network),taker=await participant(browser,base,html,'21',cardanoParams,etherTemplate,network),a=owner.page,b=taker.page;
  const reverse=scenario==='reverse';await a.goto(base);const link=await createOffer(a,scenario==='cardano-token',reverse);await a.locator('#journey-see-offer').click();
  await b.goto(link);await b.locator('#selected').waitFor({state:'visible'});await b.locator('#reserve').click();await b.getByText('No funds have been locked.',{exact:false}).last().waitFor();
  await b.locator('#journey-session-next').click();await b.locator('#session-wizard').getByRole('button',{name:'Join swap'}).click();
  await b.locator('#session-wizard').getByText('Waiting for the maker or unable to access the session').waitFor();
  await a.reload();await a.locator('#journey-session-next').click();await a.locator('#session-wizard').getByRole('button',{name:'Accept and start'}).click();
  await a.locator('#session-wizard').getByText('Waiting for their session setup').waitFor();
  await b.reload();await b.locator('#session-wizard').waitFor({state:'visible'});
  await initialBackup(b,'taker disposable passphrase');
  await a.reload();await a.locator('#session-wizard').waitFor({state:'visible'});await initialBackup(a,'owner disposable passphrase');
  await signParticipant(a,'owner disposable passphrase',reverse);await updateBackup(a,'owner disposable passphrase');
  await a.locator('#session-wizard').getByText('Waiting for their signed details').waitFor();
  await signParticipant(b,'taker disposable passphrase',reverse);await updateBackup(b,'taker disposable passphrase');
  await b.locator('#session-wizard').getByText('Confirm the other person’s code').waitFor();
  const takerText=await b.locator('#session-wizard-content').innerText(),takerCode=takerText.match(/Your code: ([0-9a-f]{16})/)[1],ownerCode=takerText.match(/Their code shown here: ([0-9a-f]{16})/)[1];
  await b.locator('#session-wizard').getByLabel('Code they gave you').fill(ownerCode);await b.locator('#session-wizard').getByRole('button',{name:'Confirm code'}).click();
  await b.locator('#session-wizard').getByText('Waiting for the proposed swap terms').waitFor();
  await a.reload();await updateBackup(a,'owner disposable passphrase');
  await a.locator('#session-wizard').getByText('Confirm the other person’s code').waitFor();
  const ownerText=await a.locator('#session-wizard-content').innerText();assert.match(ownerText,new RegExp('Your code: '+ownerCode));
  await a.locator('#session-wizard').getByLabel('Code they gave you').fill(takerCode);await a.locator('#session-wizard').getByRole('button',{name:'Confirm code'}).click();
  await a.locator('#session-wizard').getByText('Prepare the swap terms').waitFor();
  await a.locator('#session-wizard').getByLabel('Recovery passphrase').fill('owner disposable passphrase');
  await a.locator('#session-wizard').getByRole('button',{name:'Prepare terms'}).click();
  await updateBackup(a,'owner disposable passphrase');
  await a.locator('#session-wizard').getByText('Review and send the terms').waitFor();
  await a.locator('#session-wizard').getByRole('button',{name:'Send these terms'}).click();
  await updateBackup(a,'owner disposable passphrase');
  await a.locator('#session-wizard').getByText('Waiting for their acceptance').waitFor();
  await b.reload();await updateBackup(b,'taker disposable passphrase');
  await b.locator('#session-wizard').getByText('Review and accept the terms').waitFor();
  await b.locator('#session-wizard').getByRole('button',{name:'Accept these terms'}).click();
  await updateBackup(b,'taker disposable passphrase');
  await b.locator('#session-wizard').getByText('Waiting for the first lock').waitFor();
  await a.reload();await a.locator('#session-wizard').getByText('Prepare your funding action').waitFor();
  await a.locator('#session-wizard').getByRole('button',{name:'Prepare funding'}).click();await updateBackup(a,'owner disposable passphrase');
  if(reverse)await a.locator('#session-wizard').getByRole('button',{name:'Connect Ethereum wallet'}).click();
  else{await a.locator('#session-wizard').getByText('Connect your Cardano wallet').waitFor();await a.locator('#session-wizard').getByLabel('Cardano wallet').selectOption('test');await a.locator('#session-wizard').getByRole('button',{name:'Connect Cardano wallet'}).click();}
  await a.locator('#session-wizard').getByText('Lock your side of the swap').waitFor();
  await a.locator('#session-wizard').getByRole('button',{name:'Review funding transaction'}).click();
  await a.locator('#session-wizard').getByText('Review the wallet transaction').waitFor();
  assert.equal(await a.evaluate(()=>window.transactions),0,'the wallet must not sign before the local review is approved');
  await a.locator('#session-wizard').getByRole('button',{name:'Approve and open wallet'}).click();
  await updateBackup(a,'owner disposable passphrase');
  const ownerBackup=await updateBackup(a,'owner disposable passphrase');
  await a.locator('#session-wizard').getByText('Waiting for their lock').waitFor();
  if(scenario==='claim'){
   const restored=await participant(browser,base,html,'11',cardanoParams,etherTemplate,network),p=restored.page;
   await p.goto(base);await p.locator('#session-restore-open').click();await p.locator('#session-restore-data').fill(ownerBackup);await p.locator('#session-restore-passphrase').fill('owner disposable passphrase');await p.locator('#session-restore-submit').click();
   await p.locator('#session-wizard').getByText('Save your encrypted recovery backup').waitFor();await p.locator('#session-wizard').getByRole('button',{name:'I saved the backup'}).click();
   await p.locator('#session-wizard').getByText('Review your wallet activity').waitFor();await p.locator('#session-wizard').getByRole('button',{name:'I checked my wallets'}).click();
   await p.locator('#session-wizard').getByText('Confirm the other person’s code').waitFor();await p.locator('#session-wizard').getByLabel('Code they gave you').fill(takerCode);await p.locator('#session-wizard').getByRole('button',{name:'Confirm code'}).click();
   await p.locator('#session-wizard').getByText('Waiting for their lock').waitFor();assert.equal(await p.evaluate(()=>window.transactions),0,'restoring must never request a wallet transaction');await restored.context.close();
  }
  if(scenario==='refund-cardano'){await refundAfterRelayFailure(owner,'owner disposable passphrase',network,'cardano');return;}
  await b.reload();await updateBackup(b,'taker disposable passphrase');
  await b.locator('#session-wizard').getByText('Prepare your funding action').waitFor();
  await b.locator('#session-wizard').getByRole('button',{name:'Prepare funding'}).click();await updateBackup(b,'taker disposable passphrase');
  if(reverse){await b.locator('#session-wizard').getByLabel('Cardano wallet').selectOption('test');await b.locator('#session-wizard').getByRole('button',{name:'Connect Cardano wallet'}).click();}
  else{await b.locator('#session-wizard').getByText('Connect your Ethereum wallet').waitFor();await b.locator('#session-wizard').getByRole('button',{name:'Connect Ethereum wallet'}).click();}
  await b.locator('#session-wizard').getByText('Lock your side of the swap').waitFor();
  await b.locator('#session-wizard').getByRole('button',{name:'Review funding transaction'}).click();
  await b.locator('#session-wizard').getByText('Review the wallet transaction').waitFor();
  assert.equal(await b.evaluate(()=>window.transactions),0,'Ethereum funding must wait for the local review');
  await b.locator('#session-wizard').getByRole('button',{name:'Approve and open wallet'}).click();
  await updateBackup(b,'taker disposable passphrase');await updateBackup(b,'taker disposable passphrase');
  await b.locator('#session-wizard').getByText('Waiting for their claim').waitFor();
  if(scenario==='refund-ethereum'){await refundAfterRelayFailure(taker,'taker disposable passphrase',network,'ethereum');return;}
  await a.reload();await updateBackup(a,'owner disposable passphrase');
  await a.locator('#session-wizard').getByText('Prepare your claim').waitFor();
  await a.locator('#session-wizard').getByRole('button',{name:'Prepare claim'}).click();await updateBackup(a,'owner disposable passphrase');
  if(reverse){await a.locator('#session-wizard').getByLabel('Cardano wallet').selectOption('test');await a.locator('#session-wizard').getByRole('button',{name:'Connect Cardano wallet'}).click();}
  else await a.locator('#session-wizard').getByRole('button',{name:'Connect Ethereum wallet'}).click();
  await a.locator('#session-wizard').getByLabel('Recovery passphrase').fill('owner disposable passphrase');
  await a.locator('#session-wizard').getByRole('button',{name:'Review claim transaction'}).click();
  await a.locator('#session-wizard').getByText('Review the wallet transaction').waitFor();
  assert.equal(await a.evaluate(()=>window.transactions),1,'the claim must wait for explicit local approval');
  await a.locator('#session-wizard').getByRole('button',{name:'Approve and open wallet'}).click();await updateBackup(a,'owner disposable passphrase');
  await a.locator('#session-wizard').getByText('Your claim is confirmed').waitFor();
  await b.reload();await b.locator('#session-wizard').getByText('Save the claim recovery data').waitFor();
  await b.locator('#session-wizard').getByLabel('Recovery passphrase').fill('taker disposable passphrase');
  await b.locator('#session-wizard').getByRole('button',{name:'Protect claim recovery'}).click();await updateBackup(b,'taker disposable passphrase');
  await b.locator('#session-wizard').getByRole('button',{name:'Prepare claim'}).click();await updateBackup(b,'taker disposable passphrase');
  if(reverse)await b.locator('#session-wizard').getByRole('button',{name:'Connect Ethereum wallet'}).click();
  else{await b.locator('#session-wizard').getByLabel('Cardano wallet').selectOption('test');await b.locator('#session-wizard').getByRole('button',{name:'Connect Cardano wallet'}).click();}
  await b.locator('#session-wizard').getByLabel('Recovery passphrase').fill('taker disposable passphrase');await b.locator('#session-wizard').getByRole('button',{name:'Review claim transaction'}).click();
  await b.locator('#session-wizard').getByText('Review the wallet transaction').waitFor();
  assert.equal(await b.evaluate(()=>window.transactions),1,'the claim must wait for explicit local approval');
  await b.locator('#session-wizard').getByRole('button',{name:'Approve and open wallet'}).click();await updateBackup(b,'taker disposable passphrase');
  await b.locator('#session-wizard').getByText('Swap complete').waitFor();
  assert.equal(await a.evaluate(()=>window.signatures),2);assert.equal(await b.evaluate(()=>window.signatures),2);
  assert.equal(await a.evaluate(()=>window.transactions),2);assert.equal(await b.evaluate(()=>window.transactions),2);
 }finally{await browser?.close();server.kill('SIGTERM');await Promise.race([once(server,'exit'),new Promise(r=>setTimeout(r,2000))]);await rm(dir,{recursive:true,force:true});}
});
