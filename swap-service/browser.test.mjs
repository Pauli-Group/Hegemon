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
  await context.close();
 }finally{
  if(browser)await browser.close();
  for(const child of [server,anvil])if(child.exitCode===null){child.kill('SIGTERM');await once(child,'exit');}
  await rm(dir,{recursive:true,force:true});
 }
});
