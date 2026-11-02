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
  const companionRequests=[];let failBitcoinAction=false;
  await first.route('http://127.0.0.1:8788/**',async route=>{
    const request=route.request(),headers={'access-control-allow-origin':base,'access-control-allow-methods':'GET, POST, OPTIONS','access-control-allow-headers':'authorization, content-type','content-type':'application/json'};
    if(request.method()==='OPTIONS')return route.fulfill({status:204,headers});
    companionRequests.push({url:request.url(),authorization:request.headers().authorization,body:request.postDataJSON()});
    if(request.url().endsWith('/bitcoin/action')&&failBitcoinAction)return route.fulfill({status:503,headers,body:JSON.stringify({error:'Fixture action response lost.'})});
    const payload=request.url().endsWith('/health')?{status:'ok',capabilities:['bitcoin-regtest-verify','bitcoin-regtest-actions','cardano-local-verify','cardano-local-actions','hegemon-local-verify','hegemon-local-actions']}:(request.url().endsWith('/bitcoin/head')?{genesis:'b'.repeat(64),height:'150'}:request.url().endsWith('/bitcoin/action')?{completed:true,result:{operation:'lock',txid:'a'.repeat(64),submitted:true,confirmed:false}}:request.url().endsWith('/cardano/action')?{completed:true,result:{operation:'lock',txid:'b'.repeat(64),submitted:true,confirmed:false}}:request.url().endsWith('/cardano/verify')?{verified:true,snapshot:{confirmations:null,tip_block:8}}:request.url().endsWith('/hegemon/verify')?{verified:true,snapshot:{verified:true,confirmations:'2',reference_height:'101'}}:request.url().endsWith('/hegemon/action')?{completed:true,result:{operation:'claim',attempt:'a'.repeat(64),submitted:false}}:{verified:true,snapshot:{confirmations:2,block_height:101}});
    return route.fulfill({status:200,headers,body:JSON.stringify(payload)});
  });
  await first.locator('#companion-token').fill('a'.repeat(64));await first.getByRole('button',{name:'Connect local companion'}).click();await first.getByText('Local companion connected with experimental Hegemon actions enabled.').waitFor();
  const bitcoinTerms={txid:'a'.repeat(64),vout:'0',amount_sats:'100000',genesis_hash:'b'.repeat(64),hashlock:'c'.repeat(64),claimant_key:'02'+'d'.repeat(64),refund_key:'03'+'e'.repeat(64),refund_height:'200'};
  for(const [name,value] of Object.entries(bitcoinTerms))await first.locator(`#bitcoin-form [name="${name}"]`).fill(value);
  await first.getByRole('button',{name:'Verify Bitcoin escrow'}).click();await first.getByText('Verified unspent with 2 confirmations',{exact:false}).waitFor();
  assert.equal(companionRequests.length,2);assert.equal(companionRequests[1].body.amount_sats,100000);
  const policy='a'.repeat(56),cardanoTerms={outref:'1'.repeat(64)+'#0',lovelace:'10000000',genesis_sha256:'2'.repeat(64),hashlock:'3'.repeat(64),claimant:'4'.repeat(56),refundee:'5'.repeat(56),expiry_ms:'1800000000000',assets:policy+'.00=9007199254740993'};
  for(const [name,value] of Object.entries(cardanoTerms))await first.locator(`#cardano-form [name="${name}"]`).fill(value);
  await first.getByRole('button',{name:'Verify Cardano escrow'}).click();await first.getByText('Confirmation depth is unknown.',{exact:false}).waitFor();
  assert.equal(companionRequests[2].body.expected_value[policy]['00'],'9007199254740993');
  const hegemonTerms={locked:'0',claim:'shca1fixture',refund:'shca1fixture',hashlock:'3'.repeat(64),timeout:'9007199254740993',amount:'100000',min_confirmations:'2',min_remaining_blocks:'2'};
  for(const [name,value] of Object.entries(hegemonTerms))await first.locator(`#hegemon-form [name="${name}"]`).fill(value);
  await first.getByRole('button',{name:'Verify Hegemon escrow'}).click();await first.getByText('Verified unspent with 2 confirmations at local height 101.').waitFor();
  assert.equal(companionRequests[3].body.timeout,'9007199254740993');
  await first.locator('#hegemon-action-form [name="operation"]').selectOption('claim');
  for(const [name,value] of Object.entries({locked:'0',fee_input:'1',recipient:'shca1'+'q'.repeat(100),fee:'1'}))await first.locator(`#hegemon-action-form [name="${name}"]`).fill(value);
  await first.getByRole('button',{name:'Request local action'}).click();await first.getByText('Local action completed.',{exact:false}).waitFor();
  assert.deepEqual(Object.keys(companionRequests[4].body).sort(),['fee','fee_input','locked','operation','recipient']);
  for(const [name,value] of Object.entries({hashlock:'c'.repeat(64),claimant_key:'02'+'d'.repeat(64),refund_key:'03'+'e'.repeat(64),refund_height:'200',amount_sats:'100000'}))await first.locator(`#bitcoin-action-form [name="${name}"]`).fill(value);
  await first.getByRole('button',{name:'Request Bitcoin action'}).click();await first.getByText('Bitcoin transaction submitted.',{exact:false}).waitFor();
  assert.deepEqual(Object.keys(companionRequests[5].body).sort(),['amount_sats','claimant_key','hashlock','operation','refund_height','refund_key']);
  failBitcoinAction=true;await first.getByRole('button',{name:'Request Bitcoin action'}).click();await first.getByText('Fixture action response lost.').waitFor();failBitcoinAction=false;
  for(const [name,value] of Object.entries({lovelace:'10000000',assets:policy+'.00=9007199254740993',inputs:'1'.repeat(64)+'#0',hashlock:'3'.repeat(64),claimant:'4'.repeat(56),refundee:'5'.repeat(56),expiry_ms:'1800000000000'}))await first.locator(`#cardano-action-form [name="${name}"]`).fill(value);
  await first.getByRole('button',{name:'Request Cardano action'}).click();await first.getByText('Cardano transaction submitted.',{exact:false}).waitFor();
  assert.equal(companionRequests[7].body.expected_value[policy]['00'],'9007199254740993');assert.deepEqual(companionRequests[7].body.inputs,['1'.repeat(64)+'#0']);
  await first.getByRole('button',{name:'Export action records'}).click();await first.getByText('Action records ready to copy and store privately.').waitFor();const journalText=await first.locator('#action-journal-text').inputValue(),journal=JSON.parse(journalText);
  assert.equal(journal.records.length,4);assert.equal(journal.records.filter(item=>item.state==='uncertain').length,1);assert.equal(journal.records.filter(item=>item.state==='completed').length,3);
  assert.equal(journal.records.some(item=>Object.hasOwn(item.request,'secret')||Object.hasOwn(item.request,'passphrase')),false);
  await second.goto(base);await second.locator('#action-journal-text').fill(journalText);await second.getByRole('button',{name:'Import action records'}).click();await second.getByText('Action records imported.',{exact:false}).waitFor();
  const conflict=structuredClone(journal);conflict.records[0].created+=1;await second.locator('#action-journal-text').fill(JSON.stringify(conflict));await second.getByRole('button',{name:'Import action records'}).click();await second.getByText('Conflicting action records; neither was overwritten.').waitFor();
  const secretField=structuredClone(journal);secretField.records[0].request.secret='f'.repeat(64);await second.locator('#action-journal-text').fill(JSON.stringify(secretField));await second.getByRole('button',{name:'Import action records'}).click();await second.locator('#action-journal-status').getByText(/Invalid .* action/).waitFor();
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
  const sent=[];first.on('request',request=>{const body=request.postData();if(body)sent.push(body);});
  const backupPhrase='separate test backup passphrase';
  const third=await owner.newPage();await third.goto(base);
  const concurrentTerms={operation:'lock',hashlock:'c'.repeat(64),claimant_key:'02'+'d'.repeat(64),refund_key:'03'+'e'.repeat(64),refund_height:'200',amount_sats:'100000'};
  const pending=await Promise.all([first.evaluate(async terms=>(await import('/action-journal.mjs')).beginAction('bitcoin','lock',terms),concurrentTerms),third.evaluate(async terms=>(await import('/action-journal.mjs')).beginAction('bitcoin','lock',terms),concurrentTerms)]);
  assert.notEqual(pending[0],pending[1]);await first.getByRole('button',{name:'Export action records'}).click();await first.waitForFunction(()=>{try{return JSON.parse(document.getElementById('action-journal-text').value).records.length===6;}catch{return false;}});assert.equal(JSON.parse(await first.locator('#action-journal-text').inputValue()).records.length,6);
  await first.locator('#vault-create [name="label"]').fill('Local test secret');
  await first.locator('#vault-create [name="passphrase"]').fill(backupPhrase);await first.locator('#vault-create [name="confirm"]').fill(backupPhrase);
  await third.locator('#vault-create [name="label"]').fill('Second local secret');await third.locator('#vault-create [name="passphrase"]').fill(backupPhrase);await third.locator('#vault-create [name="confirm"]').fill(backupPhrase);
  await Promise.all([first.getByRole('button',{name:'Create encrypted secret'}).click(),third.getByRole('button',{name:'Create encrypted secret'}).click()]);
  await first.getByText('Encrypted secret created.',{exact:false}).waitFor();await third.getByText('Encrypted secret created.',{exact:false}).waitFor();
  const backup=await first.locator('#vault-backup').inputValue(),parsed=JSON.parse(backup);
  assert.match(parsed.envelope.hashlock,/^[0-9a-f]{64}$/);assert.equal(parsed.envelope.ciphertext.length,96);
  assert.equal(sent.some(body=>body.includes(backupPhrase)||body.includes(parsed.envelope.ciphertext)),false);
  const stored=await first.evaluate(()=>new Promise((resolve,reject)=>{const request=indexedDB.open('hegemon.local.encrypted-secrets.v2',1);request.onerror=()=>reject(request.error);request.onsuccess=()=>{const db=request.result,query=db.transaction('encrypted-secrets','readonly').objectStore('encrypted-secrets').getAll();query.onerror=()=>reject(query.error);query.onsuccess=()=>{db.close();resolve(JSON.stringify(query.result));};};}));assert.ok(!stored.includes(backupPhrase));assert.equal(JSON.parse(stored).length,2);
  await second.locator('#vault-backup').fill(backup);await second.getByRole('button',{name:'Import encrypted backup'}).click();
  await second.locator('#vault-unlock').fill(backupPhrase);await second.getByRole('button',{name:'Test unlock'}).click();await second.getByText('Backup unlocked and hashlock verified.').waitFor();
  const migration=await browser.newContext(),legacy=await migration.newPage();await legacy.goto(base);
  await legacy.evaluate(value=>localStorage.setItem('hegemon.local.encrypted-secrets.v1',JSON.stringify([value])),parsed);
  await legacy.reload();await legacy.getByText('Local test secret · hashlock '+parsed.envelope.hashlock).waitFor();
  assert.equal(await legacy.evaluate(()=>localStorage.getItem('hegemon.local.encrypted-secrets.v1')),null);
  await legacy.evaluate(value=>localStorage.setItem('hegemon.local.encrypted-secrets.v1',JSON.stringify([value])),parsed);
  await legacy.reload();await legacy.getByText('Local test secret · hashlock '+parsed.envelope.hashlock).waitFor();
  assert.equal(await legacy.evaluate(()=>localStorage.getItem('hegemon.local.encrypted-secrets.v1')),null);
  await legacy.evaluate(value=>{const changed=structuredClone(value);const c=changed.envelope.ciphertext;changed.envelope.ciphertext=c.slice(0,-1)+(c.endsWith('0')?'1':'0');localStorage.setItem('hegemon.local.encrypted-secrets.v1',JSON.stringify([changed]));},parsed);
  await legacy.reload();await legacy.getByText('Conflicting encrypted backups; neither was overwritten.').waitFor();
  assert.notEqual(await legacy.evaluate(()=>localStorage.getItem('hegemon.local.encrypted-secrets.v1')),null);
  await migration.close();
  await first.evaluate(()=>new Promise((resolve,reject)=>{const open=indexedDB.open('hegemon.local.action-journal.v1',1);open.onerror=()=>reject(open.error);open.onsuccess=()=>{const db=open.result,tx=db.transaction('actions','readwrite');tx.objectStore('actions').add({id:'0'.repeat(32)});tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);};}));
  const beforeCorrupt=companionRequests.length;await first.getByRole('button',{name:'Request Bitcoin action'}).click();await first.locator('#bitcoin-action-status').getByText('Invalid saved action journal.').waitFor();assert.equal(companionRequests.length,beforeCorrupt);
  await first.evaluate(()=>new Promise((resolve,reject)=>{const open=indexedDB.open('hegemon.local.action-journal.v1',1);open.onerror=()=>reject(open.error);open.onsuccess=()=>{const db=open.result,tx=db.transaction('actions','readwrite');tx.objectStore('actions').delete('0'.repeat(32));tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);};}));
  const watch={label:'Watch BTC',chain:'bitcoin',deadline:'200',warning:'60',genesis:'b'.repeat(64)};
  for(const [name,value] of Object.entries(watch)){const element=first.locator(`#watch-form [name="${name}"]`);if(name==='chain')await element.selectOption(value);else await element.fill(value);}
  await first.getByRole('button',{name:'Add deadline'}).click();await first.getByText('Watch BTC · bitcoin · near · 50 blocks remaining at last reported tip').waitFor();
  await first.reload();await first.getByText('Watch BTC · bitcoin · unavailable: Connect the configured local companion.').waitFor();
  await first.evaluate(()=>localStorage.setItem('hegemon.local.encrypted-secrets.v1','corrupt'));
  await first.reload();await first.getByText('Saved encrypted backups are invalid; they were not overwritten.').waitFor();
  await first.locator('#vault-create [name="label"]').fill('Another');await first.locator('#vault-create [name="passphrase"]').fill(backupPhrase);await first.locator('#vault-create [name="confirm"]').fill(backupPhrase);
  await first.getByRole('button',{name:'Create encrypted secret'}).click();
  await first.getByText('Saved encrypted backups are invalid; they were not overwritten.').waitFor();
  assert.equal(await first.evaluate(()=>localStorage.getItem('hegemon.local.encrypted-secrets.v1')),'corrupt');
  await owner.close();await taker.close();
 } finally {
  if(browser)await browser.close();
  if(server.exitCode===null){server.kill('SIGTERM');await once(server,'exit');}
  await rm(dir,{recursive:true,force:true});
 }
});

test('browser verifies real local Ethereum token escrow and rejects changed terms',{timeout:60000},async()=>{
 const {readFile}=await import('node:fs/promises');const {createHash}=await import('node:crypto');
 const dir=await mkdtemp(join(tmpdir(),'swap-verify-'));const serverPort=await port(),rpcPort=await port();
 const base=`http://127.0.0.1:${serverPort}`,rpcUrl=`http://127.0.0.1:${rpcPort}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(serverPort)},stdio:'ignore'});
 const anvil=spawn(process.env.ANVIL_PATH||'/workspace/chain-tools/foundry/anvil',['--host','127.0.0.1','--port',String(rpcPort),'--chain-id','31337','--hardfork','cancun','--silent'],{stdio:'ignore'});
 let browser;
 async function rpc(method,params=[]){const r=await fetch(rpcUrl,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});const data=await r.json();if(data.error)throw Error(data.error.message);return data.result;}
 async function send(from,data,to,value){const tx={from,data,gas:'0x3d0900'};if(to)tx.to=to;if(value)tx.value=value;const hash=await rpc('eth_sendTransaction',[tx]);for(let i=0;i<100;i++){const r=await rpc('eth_getTransactionReceipt',[hash]);if(r){assert.equal(r.status,'0x1');return r;}await new Promise(r=>setTimeout(r,50));}throw Error('transaction not mined');}
 const wa=x=>x.slice(2).padStart(64,'0'),wn=x=>BigInt(x).toString(16).padStart(64,'0');
 try{
  let ready=false;for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok&&(await rpc('eth_chainId'))==='0x7a69'){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,50));}assert.ok(ready,'local processes failed to start');
  const accounts=await rpc('eth_accounts'),claimant=accounts[0],refundee=accounts[1];
  const tokenArtifact=JSON.parse(await readFile('contracts/ethereum/out/TokenHTLC.t.sol/Sample20.json','utf8'));
  const escrowArtifact=JSON.parse(await readFile('contracts/ethereum/out/TokenHTLC.sol/TokenHTLC.json','utf8'));
  const token=(await send(refundee,tokenArtifact.bytecode.object+wa(refundee))).contractAddress;
  const hashlock=createHash('sha256').update(Buffer.alloc(32,7)).digest('hex');
  const now=BigInt((await rpc('eth_getBlockByNumber',['latest',false])).timestamp),expiry=now+600n;
  const args=wn(0)+wa(token)+wn(0)+wn(100)+hashlock+wa(claimant)+wn(expiry);
  const escrow=(await send(refundee,escrowArtifact.bytecode.object+args)).contractAddress;
  await send(refundee,'0x'+tokenArtifact.methodIdentifiers['approve(address,uint256)']+wa(escrow)+wn(100),token);
  await send(refundee,'0x'+escrowArtifact.methodIdentifiers['fund()'],escrow);await rpc('evm_mine');await rpc('evm_mine');
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const context=await browser.newContext();
  await context.exposeFunction('testRpc',async ({method,params})=>method==='eth_requestAccounts'?[claimant]:rpc(method,params));
  await context.addInitScript(()=>{window.ethereum={request:args=>window.testRpc(args)};});
  const page=await context.newPage();await page.goto(base);await page.getByRole('button',{name:'Connect Ethereum wallet'}).click();
  const values={contract:escrow,kind:'0',token,tokenId:'0',amount:'100',hashlock:'0x'+hashlock,claimant,refundee,expiry:expiry.toString()};
  for(const [name,value] of Object.entries(values)){const element=page.locator(`#verify-form [name="${name}"]`);if(name==='kind')await element.selectOption(value);else await element.fill(value);}
  await page.getByRole('button',{name:'Verify escrow'}).click();try{await page.getByText('Verified funded and unspent at block',{exact:false}).waitFor({timeout:5000});}catch{throw Error('verification status: '+await page.locator('#verify-status').textContent());}
  await page.locator('#verify-form [name="amount"]').fill('99');await page.getByRole('button',{name:'Verify escrow'}).click();await page.getByText('escrow bytecode or terms mismatch').waitFor();
  const nativeArtifact=JSON.parse(await readFile('contracts/ethereum/out/HegemonHTLC.sol/HegemonHTLC.json','utf8'));
  const native=(await send(refundee,nativeArtifact.bytecode.object+hashlock+wa(claimant)+wn(expiry),undefined,'0xde0b6b3a7640000')).contractAddress;
  await rpc('evm_mine');await rpc('evm_mine');
  await page.locator('#verify-form [name="kind"]').selectOption('eth');
  await page.locator('#verify-form [name="contract"]').fill(native);await page.locator('#verify-form [name="amount"]').fill('1000000000000000000');
  assert.equal(await page.locator('#verify-form [name="token"]').isDisabled(),true);
  await page.getByRole('button',{name:'Verify escrow'}).click();await page.getByText('Verified funded and unspent at block',{exact:false}).waitFor();
  // The browser uses the real isolated Anvil chain; only the companion's HTTP
  // transport is substituted here (its actual endpoint is tested separately).
  const companionRoute=async route=>{
   const headers={'access-control-allow-origin':base,'access-control-allow-methods':'GET, POST, OPTIONS','access-control-allow-headers':'authorization, content-type','content-type':'application/json'};
   if(route.request().method()==='OPTIONS')return route.fulfill({status:204,headers});
   let result={status:'ok',capabilities:['ethereum-local-anchor']};
   if(route.request().url().endsWith('/ethereum/head')){const genesis=await rpc('eth_getBlockByNumber',['0x0',false]),head=await rpc('eth_getBlockByNumber',['latest',false]);result={genesis:genesis.hash.slice(2),tip_hash:head.hash,time_seconds:BigInt(head.timestamp).toString()};}
   return route.fulfill({status:200,headers,body:JSON.stringify(result)});
  };
  await page.route('http://127.0.0.1:8788/**',companionRoute);
  await page.locator('#companion-token').fill('a'.repeat(64));await page.getByRole('button',{name:'Connect local companion'}).click();
  await page.locator('#ethereum-actions').waitFor({state:'visible'});
  const deployment={amount:'1000000',hashlock:'0x'+hashlock,claimant,refundee,expiry:expiry.toString()};
  for(const [name,value] of Object.entries(deployment))await page.locator(`#ethereum-action-form [name="${name}"]`).fill(value);
  await page.getByRole('button',{name:'Deploy local escrow'}).click();
  await page.getByText('Deployment submitted; check the receipt and confirmations.').waitFor();
  const submitted=JSON.parse(await page.locator('#ethereum-action-result').textContent());
  assert.equal(submitted.confirmed,false);const receipt=await rpc('eth_getTransactionReceipt',[submitted.txid]);
  assert.equal(receipt.status,'0x1');assert.ok(receipt.contractAddress);
  await page.locator('#ethereum-action-form [name="kind"]').selectOption('0');
  await page.locator('#ethereum-action-form [name="token"]').fill(token);await page.locator('#ethereum-action-form [name="tokenId"]').fill('0');
  await page.locator('#ethereum-action-form [name="amount"]').fill('100');
  await page.getByRole('button',{name:'Deploy local escrow'}).click();
  await page.getByText('Deployment submitted, but the token escrow is not funded.',{exact:false}).waitFor();
  const tokenSubmission=JSON.parse(await page.locator('#ethereum-action-result').textContent());
  const tokenReceipt=await rpc('eth_getTransactionReceipt',[tokenSubmission.txid]);assert.equal(tokenReceipt.status,'0x1');assert.ok(tokenReceipt.contractAddress);
  await page.locator('#ethereum-action-form [name="contract"]').fill(tokenReceipt.contractAddress);
  await page.getByRole('button',{name:'Approve token for escrow'}).click();await page.getByText('Token approval submitted.',{exact:false}).waitFor();
  const approval=JSON.parse(await page.locator('#ethereum-action-result').textContent());assert.equal((await rpc('eth_getTransactionReceipt',[approval.txid])).status,'0x1');
  await page.getByRole('button',{name:'Fund token escrow'}).click();await page.getByText('Funding submitted.',{exact:false}).waitFor();
  const funding=JSON.parse(await page.locator('#ethereum-action-result').textContent());assert.equal((await rpc('eth_getTransactionReceipt',[funding.txid])).status,'0x1');
  await rpc('evm_mine');await rpc('evm_mine');
  await page.locator('#verify-form [name="kind"]').selectOption('0');
  for(const [name,value] of Object.entries({contract:tokenReceipt.contractAddress,token,tokenId:'0',amount:'100'}))await page.locator(`#verify-form [name="${name}"]`).fill(value);
  await page.getByRole('button',{name:'Verify escrow'}).click();await page.getByText('Verified funded and unspent at block',{exact:false}).waitFor();
  await page.getByRole('button',{name:'Refund expired escrow'}).click();await page.getByText('refund is not yet available').waitFor();
  await rpc('evm_setNextBlockTimestamp',[Number(expiry)]);await rpc('evm_mine');
  await page.getByRole('button',{name:'Refund expired escrow'}).click();await page.getByText('Refund submitted.',{exact:false}).waitFor();
  const refund=JSON.parse(await page.locator('#ethereum-action-result').textContent());assert.equal((await rpc('eth_getTransactionReceipt',[refund.txid])).status,'0x1');
  // A fresh browser backup supplies the preimage for a separate local claim.
  const backupPhrase='different local backup passphrase';
  await page.locator('#vault-create [name="label"]').fill('Claim fixture');
  await page.locator('#vault-create [name="passphrase"]').fill(backupPhrase);await page.locator('#vault-create [name="confirm"]').fill(backupPhrase);
  await page.getByRole('button',{name:'Create encrypted secret'}).click();await page.getByText('Encrypted secret created.',{exact:false}).waitFor();
  const backup=JSON.parse(await page.locator('#vault-backup').inputValue()),claimHash=backup.envelope.hashlock;
  const claimExpiry=(BigInt((await rpc('eth_getBlockByNumber',['latest',false])).timestamp)+600n).toString();
  await page.locator('#ethereum-action-form [name="kind"]').selectOption('eth');
  for(const [name,value] of Object.entries({hashlock:'0x'+claimHash,expiry:claimExpiry,amount:'1000000'}))await page.locator(`#ethereum-action-form [name="${name}"]`).fill(value);
  await page.getByRole('button',{name:'Deploy local escrow'}).click();await page.getByText('Deployment submitted; check the receipt and confirmations.').waitFor();
  const claimDeploy=JSON.parse(await page.locator('#ethereum-action-result').textContent());const claimReceipt=await rpc('eth_getTransactionReceipt',[claimDeploy.txid]);assert.equal(claimReceipt.status,'0x1');
  await rpc('evm_mine');await rpc('evm_mine');await page.locator('#ethereum-action-form [name="contract"]').fill(claimReceipt.contractAddress);
  await page.locator('#ethereum-claim-backup').selectOption(claimHash);await page.locator('#ethereum-claim-passphrase').fill('wrong backup passphrase');
  page.once('dialog',dialog=>dialog.accept());await page.getByRole('button',{name:'Claim local escrow'}).click();await page.getByText('Could not unlock encrypted backup.').waitFor();
  await page.locator('#ethereum-claim-passphrase').fill(backupPhrase);page.once('dialog',dialog=>dialog.accept());await page.getByRole('button',{name:'Claim local escrow'}).click();
  await page.getByText('Claim submitted. The preimage is public;',{exact:false}).waitFor();
  const claim=JSON.parse(await page.locator('#ethereum-action-result').textContent()),claimResult=await rpc('eth_getTransactionReceipt',[claim.txid]);assert.equal(claimResult.status,'0x1');
  const claimTx=await rpc('eth_getTransactionByHash',[claim.txid]);assert.equal(createHash('sha256').update(Buffer.from(claimTx.input.slice(10),'hex')).digest('hex'),claimHash);
  await rpc('evm_mine');await rpc('evm_mine');
  const observerContext=await browser.newContext();await observerContext.exposeFunction('testRpc',async ({method,params})=>method==='eth_requestAccounts'?[refundee]:rpc(method,params));
  await observerContext.addInitScript(()=>{window.ethereum={request:args=>window.testRpc(args)};});
  const observer=await observerContext.newPage();await observer.route('http://127.0.0.1:8788/**',companionRoute);const networkBodies=[];
  observer.on('request',request=>{if(request.postData())networkBodies.push(request.postData());});
  await observer.goto(base);await observer.getByRole('button',{name:'Connect Ethereum wallet'}).click();
  await observer.locator('#companion-token').fill('a'.repeat(64));await observer.getByRole('button',{name:'Connect local companion'}).click();await observer.locator('#ethereum-actions').waitFor({state:'visible'});
  for(const [name,value] of Object.entries({contract:claimReceipt.contractAddress,hashlock:'0x'+claimHash,expiry:claimExpiry,amount:'1000000',claimant,refundee}))await observer.locator(`#ethereum-action-form [name="${name}"]`).fill(value);
  const observedPhrase='separate observed backup passphrase';await observer.locator('#ethereum-observe-label').fill('Observed fixture');await observer.locator('#ethereum-observe-passphrase').fill(observedPhrase);await observer.locator('#ethereum-observe-confirm').fill(observedPhrase);
  await observer.getByRole('button',{name:'Observe confirmed Ethereum claim'}).click();await observer.getByText('Confirmed local claim observed.',{exact:false}).waitFor();
  const observedBackup=JSON.parse(await observer.locator('#vault-backup').inputValue());assert.equal(observedBackup.envelope.hashlock,claimHash);
  assert.equal(networkBodies.some(body=>body.includes(observedPhrase)||body.includes(claimTx.input.slice(10))),false);await observerContext.close();
  await context.close();
 }finally{
  if(browser)await browser.close();
  for(const child of [server,anvil])if(child.exitCode===null){child.kill('SIGTERM');await once(child,'exit');}
  await rm(dir,{recursive:true,force:true});
 }
});
