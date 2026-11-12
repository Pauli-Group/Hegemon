import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {bitcoinMessageWallet,cardanoWallet,ethereumWallet} from '../swap-ui/test-wallets.mjs';
import {p2wpkh,TEST_NETWORK,Transaction,secp256k1,SigHash} from '../swap-ui/vendor/btc-signer.mjs';
import {TESTNET4_GENESIS} from '../swap-ui/bitcoin-testnet-verifier.mjs';
import {SEPOLIA_GENESIS} from '../swap-ui/sepolia-verifier.mjs';
import {HEGEMON_GENESIS,HEGEMON_CHAIN_ID} from '../swap-ui/session-hegemon-read.mjs';
import {HOSTED_CSP} from './cloudflare/client-policy.mjs';
import {softwareWallet,rowOf} from './tools/cardano-bridge.mjs';
import * as ct from '../swap-ui/cardano-tx.mjs';
import {decode,fromHex,toHex} from '../swap-ui/cbor.mjs';
import {PREVIEW_HTLC_ADDRESS} from '../swap-ui/cardano-preview-verifier.mjs';
import {expectedEtherRuntime} from '../swap-ui/ethereum-escrow.mjs';
const TEST_TOKEN='ab'.repeat(28)+'.cd';
async function port(){const s=createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const p=s.address().port;await new Promise(r=>s.close(r));return p;}
async function participant(browser,base,html,seed,cardanoParams,etherTemplate,network){
 const context=await browser.newContext(),cardano=cardanoWallet(seed.repeat(32)),bitcoin=bitcoinMessageWallet(seed.repeat(32)),ethereum=ethereumWallet((Number(seed)+1).toString(16).padStart(2,'0').repeat(32));
 if(network.hegemon){
  const hgn=network.hegemon,headers={'access-control-allow-origin':base,'access-control-allow-methods':'GET, POST, OPTIONS','access-control-allow-headers':'authorization, content-type','access-control-allow-private-network':'true'};
  await context.grantPermissions(['local-network-access'],{origin:base});
  await context.addInitScript(()=>localStorage.setItem('hegemon.companion.pairing-token','aa'.repeat(32)));
  await context.exposeFunction('__testSetHgnSecret',secret=>{hgn.secret=secret;});
  await context.route('http://127.0.0.1:8788/**',route=>{
   const req=route.request(),path=new URL(req.url()).pathname;if(req.method()==='OPTIONS')return route.fulfill({status:204,headers});
   const data=req.method()==='POST'?req.postDataJSON():null;let value;
   if(path==='/health')value={status:'ok',capabilities:['hegemon-public-status','hegemon-public-balance','hegemon-swap-verify','hegemon-swap-actions','hegemon-swap-observe','hegemon-swap-select']};
   else if(path==='/hegemon/status')value={network:'v0.11 pre-mainnet',height:'10000',syncing:false,peers:8,wallet_rpc_ready:true};
   else if(path==='/hegemon/unlock'||path==='/hegemon/balance'){const balance={available_atoms:'9999999999',reserved_atoms:'0',htlc_atoms:'0',immature_atoms:'0',synced_height:'10000',observed_height:'10000',observed_at:String(Date.now()),watch_only:false};value=path.endsWith('/unlock')?{unlocked:true,balance}:balance;}
   else if(path==='/hegemon/swap/head')value={network:'pre-mainnet',genesis:HEGEMON_GENESIS,chain_id:HEGEMON_CHAIN_ID,height:'10000'};
   else if(path==='/hegemon/swap/address')value={address:'shca1'+(seed==='11'?'q':'p').repeat(100)};
   else if(path==='/hegemon/swap/select')value={inputs:[data.exclude.length?'8':'7'],total:String(BigInt(data.amount)+BigInt(data.fee)+1000n),synced_height:'10000'};
   else if(path==='/hegemon/swap/inclusion'){const action=data.attempt==='11'.repeat(32)?'ab'.repeat(48):'cd'.repeat(48);value={state:'confirmed',action_id:action,block_height:'9998',block_hash:'0x'+'ef'.repeat(32),confirmations:3};}
   else if(path==='/hegemon/swap/locate')value={position:'9',created_height:'9998',synced_height:'10000'};
   else if(path==='/hegemon/swap/verify')value={verified:true,snapshot:{verified:true,position:data.locked,created_height:'9998',reference_height:'10000',confirmations:'3',commitment:'cc'.repeat(56),action_id:data.action_id,refund_ready:data.refund_ready}};
   else if(path==='/hegemon/swap/note-status')value=hgn.claimed?{state:'claimed',lock_height:'9998',action_id:'cd'.repeat(48),block_height:'9998',confirmations:3,preimage:hgn.secret}:{state:'unspent',lock_height:'9998'};
   else if(path==='/hegemon/swap/action'){
    const request=data.action||data;let result;
    if(request.operation==='lock')result={operation:'lock',attempt:'11'.repeat(32),refund_handoff:'22'.repeat(16)+'.bin',submitted:false};
    else if(request.operation==='import-refund-handoff')result={operation:request.operation,commitment:'cc'.repeat(56),block_height:request.block_height};
    else if(request.operation==='claim')result={operation:'claim',attempt:'33'.repeat(32),submitted:false};
    else if(request.operation==='submit'){if(request.attempt==='33'.repeat(32))hgn.claimed=true;result={operation:'submit',attempt:request.attempt,txid:(request.attempt==='11'.repeat(32)?'ab':'cd').repeat(48),submitted:true};}
    else throw Error('Unexpected Hegemon action '+request.operation);
    hgn.approvals++;value={completed:true,result};
   }else if(path==='/hegemon/wallet-activity')value={};
   else throw Error('Unexpected Hegemon path '+path);
   return route.fulfill({status:200,json:value,headers});
  });
 }
 const seedBytes=new Uint8Array(32).fill(parseInt(seed,16)),address=ct.toBech32(fromHex(cardano.addressHex));
 const bitcoinAddress=p2wpkh(secp256k1.getPublicKey(seedBytes,true),TEST_NETWORK).address;
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
 await context.route('**/bitcoin-testnet4/head',route=>route.fulfill({json:{genesis:TESTNET4_GENESIS,tip:network.bitcoin.tip}}));
 await context.route('**/bitcoin-testnet4/utxos?*',route=>{const address=new URL(route.request().url()).searchParams.get('address');return route.fulfill({json:{address,tip:network.bitcoin.tip,utxos:[{txid:seed.repeat(32),vout:0,amount_sats:200000,confirmations:3}]}});});
 await context.route('**/bitcoin-testnet4/escrow?*',route=>{const u=new URL(route.request().url()),txid=u.searchParams.get('txid'),vout=Number(u.searchParams.get('vout')),output=network.bitcoin.outputs.get(txid+':'+vout);return route.fulfill({json:{genesis:TESTNET4_GENESIS,txid,vout,tip:network.bitcoin.tip,confirmed:true,confirmations:2,block_height:network.bitcoin.tip-1,block_hash:'aa'.repeat(32),spent:!!output?.spent,amount_sats:output?.amount,script:output?.script}});});
 await context.route('**/bitcoin-testnet4/spend?*',route=>{const u=new URL(route.request().url()),txid=u.searchParams.get('txid'),vout=Number(u.searchParams.get('vout')),spend=network.bitcoin.spends.get(txid+':'+vout);return route.fulfill({json:{genesis:TESTNET4_GENESIS,txid,vout,tip:network.bitcoin.tip,spent:!!spend,...(spend?{spend}: {})}});});
 await context.route('**/bitcoin-testnet4/broadcast',route=>{const {tx:raw}=route.request().postDataJSON(),tx=Transaction.fromRaw(fromHex(raw)),id=tx.id,input=tx.getInput(0),ref=toHex(input.txid)+':'+input.index,output=network.bitcoin.outputs.get(ref);
  if(output){output.spent=true;network.bitcoin.spends.set(ref,{txid:id,witness:input.finalScriptWitness.map(toHex),confirmations:2});}
  else{const first=tx.getOutput(0);network.bitcoin.outputs.set(id+':0',{amount:Number(first.amount),script:toHex(first.script),spent:false});}
  return route.fulfill({json:{txid:id}});
 });
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
 await context.exposeFunction('__testBtcMessage',text=>bitcoin.sign(text));
 await context.exposeFunction('__testBtcPsbt',encoded=>{const tx=Transaction.fromPSBT(Buffer.from(encoded,'base64'));for(let i=0;i<tx.inputsLength;i++){const input=tx.getInput(i);if(input.witnessScript){const digest=tx.preimageWitnessV0(i,input.witnessScript,SigHash.ALL,input.witnessUtxo.amount),signature=secp256k1.sign(digest,seedBytes,{prehash:false,format:'der'});tx.updateInput(i,{partialSig:[[secp256k1.getPublicKey(seedBytes,true),new Uint8Array([...signature,SigHash.ALL])]]});}else tx.signIdx(seedBytes,i);}return Buffer.from(tx.toPSBT()).toString('base64');});
 await context.exposeFunction('__testEthRead',ethRead);
 await context.exposeFunction('__testEthSend',tx=>{if(tx.to){if(tx.data.slice(0,10)==='0xbd66528a')network.ethereum.secret=tx.data.slice(10);else if(tx.data==='0x590e1ae3')network.ethereum.refunded=true;else throw Error('Unexpected test spend');network.ethereum.claimTx='0x'+'88'.repeat(32);return network.ethereum.claimTx;}
  const tail=tx.data.slice(-192),fields={hashlock:'0x'+tail.slice(0,64),claimant:'0x'+tail.slice(88,128),expiry:BigInt('0x'+tail.slice(128,192)).toString(),refundee:tx.from.toLowerCase(),amount:BigInt(tx.value).toString()};const txid='0x'+'66'.repeat(32),contract='0x'+'77'.repeat(20);network.ethereum={txid,contract,fields};return txid;});
 await context.exposeFunction('__testAdaWallet',(method,args)=>wallet[method](...args));
 await context.addInitScript(({adaAddress,ethAddress,genesis})=>{
  window.signatures=Number(sessionStorage.getItem('test.signatures')||0);window.transactions=Number(sessionStorage.getItem('test.transactions')||0);
  window.__signBitcoinMessage=text=>{sessionStorage.setItem('test.signatures',String(++window.signatures));return window.__testBtcMessage(text);};
  window.__signBitcoinPsbt=psbt=>{sessionStorage.setItem('test.transactions',String(++window.transactions));return window.__testBtcPsbt(psbt);};
  window.ethereum={request:async({method,params=[]})=>{if(method==='eth_requestAccounts'||method==='eth_accounts')return [ethAddress];if(method==='personal_sign'){sessionStorage.setItem('test.signatures',String(++window.signatures));return window.__testEthSign(params[0]);}if(method==='eth_sendTransaction'){sessionStorage.setItem('test.transactions',String(++window.transactions));return window.__testEthSend(params[0]);}return window.__testEthRead({method,params});},on(){}};
  window.cardano={test:{name:'Test wallet',enable:async()=>({getNetworkId:async()=>0,getUsedAddresses:async()=>[adaAddress],getUnusedAddresses:async()=>[],getUtxos:(...a)=>window.__testAdaWallet('getUtxos',a),getCollateral:(...a)=>window.__testAdaWallet('getCollateral',a),getChangeAddress:(...a)=>window.__testAdaWallet('getChangeAddress',a),signTx:(...a)=>{sessionStorage.setItem('test.transactions',String(++window.transactions));return window.__testAdaWallet('signTx',a);},submitTx:(...a)=>window.__testAdaWallet('submitTx',a),signData:async(a,p)=>{sessionStorage.setItem('test.signatures',String(++window.signatures));return window.__testAdaSign(a,p);}})}};
 },{adaAddress:cardano.addressHex,ethAddress:ethereum.address,genesis:SEPOLIA_GENESIS});
 return {context,page:await context.newPage(),bitcoin:{publicKey:bitcoin.publicKey,address:bitcoinAddress}};
}
async function createOffer(page,native=false,reverse=false,bitcoin=false,hegemon=false,hgnFirst=false){
 await page.getByRole('button',{name:/Create an offer/}).click();
 await page.locator('#journey-give-type').selectOption(hgnFirst?'hegemon:hgn':reverse||hegemon?'ethereum:eth':bitcoin?'bitcoin:btc':native?'cardano:native':'cardano:ada');if(native)await page.locator('#journey-give-id').fill(TEST_TOKEN);await page.locator('#journey-next').click();
 await page.locator('#journey-give-amount').fill(hgnFirst?'5':reverse||hegemon?'0.1':bitcoin?'0.0005':'5');if(hgnFirst){await page.waitForFunction(()=>document.querySelector('#companion-indicator')?.dataset.state==='connected');await page.locator('#journey-hgn-unlock').click();await page.waitForFunction(()=>!document.querySelector('#journey-next').disabled);}await page.locator('#journey-next').click();
 await page.locator('#journey-receive-type').selectOption(hgnFirst?'ethereum:eth':hegemon?'hegemon:hgn':reverse?'cardano:ada':'ethereum:eth');await page.locator('#journey-next').click();
 await page.locator('#journey-receive-amount').fill(hgnFirst?'0.1':reverse||hegemon?'5':'0.1');await page.locator('#journey-next').click();
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
async function signParticipant(page,phrase,reverse=false,bitcoin=null,hegemon=false){
 const panel=page.locator('#session-wizard');
 if(hegemon){await panel.getByRole('button',{name:'I understand'}).click();await page.waitForFunction(()=>document.querySelector('#companion-indicator')?.dataset.state==='connected');}
 await panel.getByRole('button',{name:'Connect Ethereum wallet'}).click();
 if(hegemon){await panel.getByRole('button',{name:'Sign with Ethereum'}).click();await panel.getByText('Update your recovery backup').waitFor();return;}
 await page.waitForFunction(()=>['Connect your Cardano wallet','Enter your Bitcoin public key','Update your recovery backup'].includes(document.querySelector('#session-wizard h3')?.textContent));
 if(await panel.getByText('Update your recovery backup').isVisible())await updateBackup(page,phrase);
 if(bitcoin){await panel.getByLabel('Bitcoin public key').fill(bitcoin.publicKey);await panel.getByRole('button',{name:'Continue',exact:true}).click();const message=await panel.locator('textarea[readonly]').inputValue(),signature=await page.evaluate(text=>window.__signBitcoinMessage(text),message);await panel.getByLabel('Bitcoin signature').fill(signature);await panel.getByRole('button',{name:'Check signature'}).click();await panel.getByRole('button',{name:'Sign with Ethereum'}).click();}
 else{await panel.getByLabel('Cardano wallet').selectOption('test');await panel.getByRole('button',{name:'Connect Cardano wallet'}).click();
  await panel.getByRole('button',{name:reverse?'Sign with Ethereum':'Sign with Cardano'}).click();
  await panel.getByRole('button',{name:reverse?'Sign with Cardano':'Sign with Ethereum'}).click();}
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

async function nativeOffer(page,first,second){
 await page.getByRole('button',{name:/Create an offer/}).click();
 const type={cardano:'cardano:ada',bitcoin:'bitcoin:btc',hegemon:'hegemon:hgn',ethereum:'ethereum:eth'},amount={cardano:'5',bitcoin:'0.0005',hegemon:'5',ethereum:'0.1'};
 await page.locator('#journey-give-type').selectOption(type[first]);await page.locator('#journey-next').click();
 await page.locator('#journey-give-amount').fill(amount[first]);
 if(first==='hegemon'){await page.waitForFunction(()=>document.querySelector('#companion-indicator')?.dataset.state==='connected');await page.locator('#journey-hgn-unlock').click();await page.waitForFunction(()=>!document.querySelector('#journey-next').disabled);}
 await page.locator('#journey-next').click();await page.locator('#journey-receive-type').selectOption(type[second]);await page.locator('#journey-next').click();await page.locator('#journey-receive-amount').fill(amount[second]);await page.locator('#journey-next').click();
 await page.locator('[name="journey-visibility"][value="private"]').check();await page.locator('#journey-next').click();await page.locator('#journey-lifetime').selectOption('86400');await page.locator('#journey-next').click();await page.locator('[name="journey-backup"][value="no"]').check();await page.locator('#journey-next').click();await page.locator('#journey-publish').click();await page.locator('#journey-created').waitFor({state:'visible'});return page.locator('#journey-share-link').inputValue();
}
async function signNativePair(person,chains){
 const page=person.page,panel=page.locator('#session-wizard');
 if(chains.includes('hegemon'))await page.waitForFunction(()=>document.querySelector('#companion-indicator')?.dataset.state==='connected');
 await page.waitForFunction(()=>document.querySelector('#session-wizard h3')?.textContent!=='Save your encrypted recovery backup');
 for(let i=0;i<8;i++){
  const title=await panel.locator('h3').first().innerText();
  if(title==='Update your recovery backup')return;
  if(title==='Review your Hegemon address')await panel.getByRole('button',{name:'I understand'}).click();
  else if(title==='Connect your Ethereum wallet')await panel.getByRole('button',{name:'Connect Ethereum wallet'}).click();
  else if(title==='Connect your Cardano wallet'){await panel.getByLabel('Cardano wallet').selectOption('test');await panel.getByRole('button',{name:'Connect Cardano wallet'}).click();}
  else if(title==='Enter your Bitcoin public key'){await panel.getByLabel('Bitcoin public key').fill(person.bitcoin.publicKey);await panel.getByRole('button',{name:'Continue',exact:true}).click();}
  else if(title==='Sign with your Bitcoin wallet'){const text=await panel.locator('textarea[readonly]').inputValue(),signature=await page.evaluate(value=>window.__signBitcoinMessage(value),text);await panel.getByLabel('Bitcoin signature').fill(signature);await panel.getByRole('button',{name:'Check signature'}).click();}
  else if(title==='Sign with your Cardano wallet')await panel.getByRole('button',{name:'Sign with Cardano'}).click();
  else if(title==='Sign with your Ethereum wallet')await panel.getByRole('button',{name:'Sign with Ethereum'}).click();
  else throw Error('Unexpected participant step: '+title);
  await page.waitForFunction(previous=>document.querySelector('#session-wizard h3')?.textContent!==previous,title);
 }
 throw Error('Participant signatures did not finish.');
}
async function fundNativePair(person,chain,phrase){
 const page=person.page,panel=page.locator('#session-wizard');await panel.getByText('Prepare your funding action').waitFor();await panel.getByRole('button',{name:'Prepare funding'}).click();await updateBackup(page,phrase);
 if(chain==='bitcoin'){
  await panel.getByLabel('Bitcoin testnet4 address').fill(person.bitcoin.address);await panel.getByRole('button',{name:'Prepare Bitcoin PSBT'}).click();await updateBackup(page,phrase);
  const unsigned=await panel.getByLabel('Unsigned Bitcoin PSBT').inputValue(),signed=await page.evaluate(value=>window.__signBitcoinPsbt(value),unsigned);await panel.getByLabel('Signed Bitcoin PSBT',{exact:true}).fill(signed);await panel.getByRole('button',{name:'Check and broadcast'}).click();await updateBackup(page,phrase);
 }else if(chain==='hegemon'){
  await panel.getByRole('button',{name:'Prepare Hegemon lock'}).click();await updateBackup(page,phrase);await panel.getByRole('button',{name:'Submit lock'}).click();await updateBackup(page,phrase);await updateBackup(page,phrase);await panel.getByRole('button',{name:'Import refund handoff'}).click();await updateBackup(page,phrase);
 }else if(chain==='ethereum'){
  await panel.getByRole('button',{name:'Connect Ethereum wallet'}).click();await panel.getByRole('button',{name:'Review funding transaction'}).click();await panel.getByRole('button',{name:'Approve and open wallet'}).click();await updateBackup(page,phrase);
 }else{
  await panel.getByLabel('Cardano wallet').selectOption('test');await panel.getByRole('button',{name:'Connect Cardano wallet'}).click();await panel.getByRole('button',{name:'Review funding transaction'}).click();await panel.getByRole('button',{name:'Approve and open wallet'}).click();await updateBackup(page,phrase);
 }
 await updateBackup(page,phrase);
}
async function claimNativePair(person,chain,phrase){
 const page=person.page,panel=page.locator('#session-wizard');await panel.getByText('Prepare your claim').waitFor();await panel.getByRole('button',{name:'Prepare claim'}).click();await updateBackup(page,phrase);
 if(chain==='bitcoin'){
  await panel.getByLabel('Bitcoin testnet4 destination').fill(person.bitcoin.address);await panel.getByRole('button',{name:'Prepare Bitcoin PSBT'}).click();await updateBackup(page,phrase);const unsigned=await panel.getByLabel('Unsigned Bitcoin PSBT').inputValue(),signed=await page.evaluate(value=>window.__signBitcoinPsbt(value),unsigned);await panel.getByLabel('Signed Bitcoin PSBT',{exact:true}).fill(signed);await panel.getByLabel('Recovery passphrase').fill(phrase);await panel.getByRole('button',{name:'Check and broadcast'}).click();await updateBackup(page,phrase);
 }else if(chain==='hegemon'){
  await panel.getByRole('button',{name:'Prepare Hegemon claim'}).click();await updateBackup(page,phrase);await panel.getByRole('button',{name:'Submit claim'}).click();await updateBackup(page,phrase);await updateBackup(page,phrase);
 }else if(chain==='ethereum'){
  await panel.getByRole('button',{name:'Connect Ethereum wallet'}).click();await panel.getByLabel('Recovery passphrase').fill(phrase);await panel.getByRole('button',{name:'Review claim transaction'}).click();await panel.getByRole('button',{name:'Approve and open wallet'}).click();await updateBackup(page,phrase);
 }else{
  await panel.getByLabel('Cardano wallet').selectOption('test');await panel.getByRole('button',{name:'Connect Cardano wallet'}).click();await panel.getByLabel('Recovery passphrase').fill(phrase);await panel.getByRole('button',{name:'Review claim transaction'}).click();await panel.getByRole('button',{name:'Approve and open wallet'}).click();await updateBackup(page,phrase);
 }
}

for(const scenario of ['claim','reverse','btc-eth','eth-hgn','hgn-eth','cardano-token','refund-cardano','refund-ethereum'])test(`guided session: ${scenario} with refresh and explicit wallet approval`,{timeout:160000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-wizard-')),p=await port(),base=`http://127.0.0.1:${p}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(p)},stdio:'ignore'});
 let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  const html=await readFile('swap-ui/hosted.html'),cardanoParams=JSON.parse(await readFile('swap-ui/fixtures/cardano-preview-params.json','utf8')),etherTemplate=JSON.parse(await readFile('swap-ui/ether-escrow-template.json','utf8'));browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const hgnFirst=scenario==='hgn-eth',hegemon=scenario==='eth-hgn'||hgnFirst,network={cardano:new Map(),cardanoSpends:new Map(),bitcoin:{tip:150000,outputs:new Map(),spends:new Map()},ethereum:null,elapsed:0,...(hegemon?{hegemon:{claimed:false,secret:null,approvals:0}}:{})},owner=await participant(browser,base,html,'11',cardanoParams,etherTemplate,network),taker=await participant(browser,base,html,'21',cardanoParams,etherTemplate,network),a=owner.page,b=taker.page;
  const reverse=scenario==='reverse',btc=scenario==='btc-eth';await a.goto(base);const link=await createOffer(a,scenario==='cardano-token',reverse,btc,hegemon,hgnFirst);await a.locator('#journey-see-offer').click();
  await b.goto(link);await b.locator('#selected').waitFor({state:'visible'});await b.locator('#reserve').click();await b.getByText('No funds have been locked.',{exact:false}).last().waitFor();
  await b.locator('#journey-session-next').click();await b.locator('#session-wizard').getByRole('button',{name:'Join swap'}).click();
  await b.locator('#session-wizard').getByText('Waiting for the maker or unable to access the session').waitFor();
  await a.reload();await a.locator('#journey-session-next').click();await a.locator('#session-wizard').getByRole('button',{name:'Accept and start'}).click();
  await a.locator('#session-wizard').getByText('Waiting for their session setup').waitFor();
  await b.reload();await b.locator('#session-wizard').waitFor({state:'visible'});
  await initialBackup(b,'taker disposable passphrase');
  await a.reload();await a.locator('#session-wizard').waitFor({state:'visible'});await initialBackup(a,'owner disposable passphrase');
  await signParticipant(a,'owner disposable passphrase',reverse,btc?owner.bitcoin:null,hegemon);await updateBackup(a,'owner disposable passphrase');
  await a.locator('#session-wizard').getByText('Waiting for their signed details').waitFor();
  await signParticipant(b,'taker disposable passphrase',reverse,btc?taker.bitcoin:null,hegemon);await updateBackup(b,'taker disposable passphrase');
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
  if(hegemon)await a.evaluate(async()=>{const db=await new Promise((resolve,reject)=>{const request=indexedDB.open('hegemon.swap.sessions.v1');request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);}),rows=await new Promise((resolve,reject)=>{const request=db.transaction('sessions').objectStore('sessions').getAll();request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);}),{unlockRecovery}=await import('/recovery.mjs'),{toHex}=await import('/cbor.mjs'),secret=await unlockRecovery(rows[0].snapshot.secretEnvelope,'owner disposable passphrase');try{await window.__testSetHgnSecret(toHex(secret));}finally{secret.fill(0);db.close();}});
  await a.locator('#session-wizard').getByText('Review and send the terms').waitFor();
  if(btc){const summary=await a.locator('#session-wizard-content').innerText();assert.match(summary,/refund after block 15\d+/);assert.doesNotMatch(summary,/1970/);}
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
  if(hgnFirst){
   await a.locator('#session-wizard').getByRole('button',{name:'Prepare Hegemon lock'}).click();await updateBackup(a,'owner disposable passphrase');
   await a.locator('#session-wizard').getByRole('button',{name:'Submit lock'}).click();await updateBackup(a,'owner disposable passphrase');await updateBackup(a,'owner disposable passphrase');
   await a.locator('#session-wizard').getByRole('button',{name:'Import refund handoff'}).click();await updateBackup(a,'owner disposable passphrase');
  }else if(btc){
   await a.locator('#session-wizard').getByLabel('Bitcoin testnet4 address').fill(owner.bitcoin.address);await a.locator('#session-wizard').getByRole('button',{name:'Prepare Bitcoin PSBT'}).click();await updateBackup(a,'owner disposable passphrase');
   const unsigned=await a.locator('#session-wizard').getByLabel('Unsigned Bitcoin PSBT').inputValue();assert.equal(await a.evaluate(()=>window.transactions),0);
   const signed=await a.evaluate(psbt=>window.__signBitcoinPsbt(psbt),unsigned);await a.locator('#session-wizard').getByLabel('Signed Bitcoin PSBT',{exact:true}).fill(signed);await a.locator('#session-wizard').getByRole('button',{name:'Check and broadcast'}).click();
  }else{
   if(reverse||hegemon)await a.locator('#session-wizard').getByRole('button',{name:'Connect Ethereum wallet'}).click();
   else{await a.locator('#session-wizard').getByText('Connect your Cardano wallet').waitFor();await a.locator('#session-wizard').getByLabel('Cardano wallet').selectOption('test');await a.locator('#session-wizard').getByRole('button',{name:'Connect Cardano wallet'}).click();}
   await a.locator('#session-wizard').getByText('Lock your side of the swap').waitFor();await a.locator('#session-wizard').getByRole('button',{name:'Review funding transaction'}).click();await a.locator('#session-wizard').getByText('Review the wallet transaction').waitFor();
   assert.equal(await a.evaluate(()=>window.transactions),0,'the wallet must not sign before the local review is approved');await a.locator('#session-wizard').getByRole('button',{name:'Approve and open wallet'}).click();
  }
  if(!hgnFirst)await updateBackup(a,'owner disposable passphrase');
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
  if(hegemon&&!hgnFirst){
   await b.locator('#session-wizard').getByRole('button',{name:'Prepare Hegemon lock'}).click();await updateBackup(b,'taker disposable passphrase');
   await b.locator('#session-wizard').getByRole('button',{name:'Submit lock'}).click();await updateBackup(b,'taker disposable passphrase');await updateBackup(b,'taker disposable passphrase');
   await b.locator('#session-wizard').getByRole('button',{name:'Import refund handoff'}).click();await updateBackup(b,'taker disposable passphrase');await updateBackup(b,'taker disposable passphrase');
  }else{
   if(reverse){await b.locator('#session-wizard').getByLabel('Cardano wallet').selectOption('test');await b.locator('#session-wizard').getByRole('button',{name:'Connect Cardano wallet'}).click();}
   else{await b.locator('#session-wizard').getByText('Connect your Ethereum wallet').waitFor();await b.locator('#session-wizard').getByRole('button',{name:'Connect Ethereum wallet'}).click();}
   await b.locator('#session-wizard').getByText('Lock your side of the swap').waitFor();
   await b.locator('#session-wizard').getByRole('button',{name:'Review funding transaction'}).click();
   await b.locator('#session-wizard').getByText('Review the wallet transaction').waitFor();
   assert.equal(await b.evaluate(()=>window.transactions),0,'Ethereum funding must wait for the local review');
   await b.locator('#session-wizard').getByRole('button',{name:'Approve and open wallet'}).click();
   await updateBackup(b,'taker disposable passphrase');await updateBackup(b,'taker disposable passphrase');
  }
  await b.locator('#session-wizard').getByText('Waiting for their claim').waitFor();
  if(scenario==='refund-ethereum'){await refundAfterRelayFailure(taker,'taker disposable passphrase',network,'ethereum');return;}
  await a.reload();await updateBackup(a,'owner disposable passphrase');
  await a.locator('#session-wizard').getByText('Prepare your claim').waitFor();
  await a.locator('#session-wizard').getByRole('button',{name:'Prepare claim'}).click();await updateBackup(a,'owner disposable passphrase');
  if(hegemon&&!hgnFirst){
   await a.locator('#session-wizard').getByRole('button',{name:'Prepare Hegemon claim'}).click();await updateBackup(a,'owner disposable passphrase');
   await a.locator('#session-wizard').getByRole('button',{name:'Submit claim'}).click();await updateBackup(a,'owner disposable passphrase');await updateBackup(a,'owner disposable passphrase');
  }else{
   if(reverse){await a.locator('#session-wizard').getByLabel('Cardano wallet').selectOption('test');await a.locator('#session-wizard').getByRole('button',{name:'Connect Cardano wallet'}).click();}
   else await a.locator('#session-wizard').getByRole('button',{name:'Connect Ethereum wallet'}).click();
   await a.locator('#session-wizard').getByLabel('Recovery passphrase').fill('owner disposable passphrase');
   await a.locator('#session-wizard').getByRole('button',{name:'Review claim transaction'}).click();
   await a.locator('#session-wizard').getByText('Review the wallet transaction').waitFor();
   assert.equal(await a.evaluate(()=>window.transactions),hgnFirst?0:1,'the claim must wait for explicit local approval');
   await a.locator('#session-wizard').getByRole('button',{name:'Approve and open wallet'}).click();await updateBackup(a,'owner disposable passphrase');
  }
  await a.locator('#session-wizard').getByText('Your claim is confirmed').waitFor();
  await b.reload();await b.locator('#session-wizard').getByText('Save the claim recovery data').waitFor();
  await b.locator('#session-wizard').getByLabel('Recovery passphrase').fill('taker disposable passphrase');
  await b.locator('#session-wizard').getByRole('button',{name:'Protect claim recovery'}).click();await updateBackup(b,'taker disposable passphrase');
  await b.locator('#session-wizard').getByRole('button',{name:'Prepare claim'}).click();await updateBackup(b,'taker disposable passphrase');
  if(hgnFirst){
   await b.locator('#session-wizard').getByRole('button',{name:'Prepare Hegemon claim'}).click();await updateBackup(b,'taker disposable passphrase');
   await b.locator('#session-wizard').getByRole('button',{name:'Submit claim'}).click();await updateBackup(b,'taker disposable passphrase');await updateBackup(b,'taker disposable passphrase');
  }else if(btc){
   await b.locator('#session-wizard').getByLabel('Bitcoin testnet4 destination').fill(taker.bitcoin.address);await b.locator('#session-wizard').getByRole('button',{name:'Prepare Bitcoin PSBT'}).click();await updateBackup(b,'taker disposable passphrase');
   const unsigned=await b.locator('#session-wizard').getByLabel('Unsigned Bitcoin PSBT').inputValue();assert.equal(await b.evaluate(()=>window.transactions),1);
   const signed=await b.evaluate(psbt=>window.__signBitcoinPsbt(psbt),unsigned);await b.locator('#session-wizard').getByLabel('Signed Bitcoin PSBT',{exact:true}).fill(signed);await b.locator('#session-wizard').getByLabel('Recovery passphrase').fill('taker disposable passphrase');await b.locator('#session-wizard').getByRole('button',{name:'Check and broadcast'}).click();
  }else{
   if(reverse||hegemon)await b.locator('#session-wizard').getByRole('button',{name:'Connect Ethereum wallet'}).click();
   else{await b.locator('#session-wizard').getByLabel('Cardano wallet').selectOption('test');await b.locator('#session-wizard').getByRole('button',{name:'Connect Cardano wallet'}).click();}
   await b.locator('#session-wizard').getByLabel('Recovery passphrase').fill('taker disposable passphrase');await b.locator('#session-wizard').getByRole('button',{name:'Review claim transaction'}).click();await b.locator('#session-wizard').getByText('Review the wallet transaction').waitFor();
   assert.equal(await b.evaluate(()=>window.transactions),hegemon?0:1,'the claim must wait for explicit local approval');await b.locator('#session-wizard').getByRole('button',{name:'Approve and open wallet'}).click();
  }
  if(!hgnFirst)await updateBackup(b,'taker disposable passphrase');
  await b.locator('#session-wizard').getByText('Swap complete').waitFor();
  assert.equal(await a.evaluate(()=>window.signatures),hegemon?1:2);assert.equal(await b.evaluate(()=>window.signatures),hegemon?1:2);
  assert.equal(await a.evaluate(()=>window.transactions),hegemon?1:2);assert.equal(await b.evaluate(()=>window.transactions),hegemon?1:2);
 }finally{await browser?.close();server.kill('SIGTERM');await Promise.race([once(server,'exit'),new Promise(r=>setTimeout(r,2000))]);await rm(dir,{recursive:true,force:true});}
});

for(const [first,second] of [['cardano','bitcoin'],['bitcoin','cardano'],['cardano','hegemon'],['hegemon','cardano'],['bitcoin','hegemon'],['hegemon','bitcoin'],['ethereum','bitcoin']])test(`guided native pair: ${first} to ${second}`,{timeout:160000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-native-pair-')),p=await port(),base=`http://127.0.0.1:${p}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(p)},stdio:'ignore'});let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  const html=await readFile('swap-ui/hosted.html'),cardanoParams=JSON.parse(await readFile('swap-ui/fixtures/cardano-preview-params.json','utf8')),etherTemplate=JSON.parse(await readFile('swap-ui/ether-escrow-template.json','utf8'));
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const chains=[first,second],network={cardano:new Map(),cardanoSpends:new Map(),bitcoin:{tip:150000,outputs:new Map(),spends:new Map()},ethereum:null,elapsed:0,...(chains.includes('hegemon')?{hegemon:{claimed:false,secret:null,approvals:0}}:{})};
  const owner=await participant(browser,base,html,'11',cardanoParams,etherTemplate,network),taker=await participant(browser,base,html,'21',cardanoParams,etherTemplate,network),a=owner.page,b=taker.page,op='owner disposable passphrase',tp='taker disposable passphrase';
  await a.goto(base);const link=await nativeOffer(a,first,second);await a.locator('#journey-see-offer').click();await b.goto(link);await b.locator('#selected').waitFor({state:'visible'});await b.locator('#reserve').click();await b.getByText('No funds have been locked.',{exact:false}).last().waitFor();
  await b.locator('#journey-session-next').click();await b.locator('#session-wizard').getByRole('button',{name:'Join swap'}).click();await b.locator('#session-wizard').getByText('Waiting for the maker or unable to access the session').waitFor();
  await a.reload();await a.locator('#journey-session-next').click();await a.locator('#session-wizard').getByRole('button',{name:'Accept and start'}).click();await a.locator('#session-wizard').getByText('Waiting for their session setup').waitFor();
  await b.reload();await b.locator('#session-wizard').waitFor({state:'visible'});await initialBackup(b,tp);await a.reload();await a.locator('#session-wizard').waitFor({state:'visible'});await initialBackup(a,op);
  await signNativePair(owner,chains);await updateBackup(a,op);await a.locator('#session-wizard').getByText('Waiting for their signed details').waitFor();await signNativePair(taker,chains);await updateBackup(b,tp);
  await b.locator('#session-wizard').getByText('Confirm the other person’s code').waitFor();const text=await b.locator('#session-wizard-content').innerText(),takerCode=text.match(/Your code: ([0-9a-f]{16})/)[1],ownerCode=text.match(/Their code shown here: ([0-9a-f]{16})/)[1];
  await b.locator('#session-wizard').getByLabel('Code they gave you').fill(ownerCode);await b.locator('#session-wizard').getByRole('button',{name:'Confirm code'}).click();await a.reload();await updateBackup(a,op);await a.locator('#session-wizard').getByLabel('Code they gave you').fill(takerCode);await a.locator('#session-wizard').getByRole('button',{name:'Confirm code'}).click();
  await a.locator('#session-wizard').getByLabel('Recovery passphrase').fill(op);await a.locator('#session-wizard').getByRole('button',{name:'Prepare terms'}).click();await updateBackup(a,op);
  if(chains.includes('hegemon'))await a.evaluate(async phrase=>{const db=await new Promise((resolve,reject)=>{const request=indexedDB.open('hegemon.swap.sessions.v1');request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);}),rows=await new Promise((resolve,reject)=>{const request=db.transaction('sessions').objectStore('sessions').getAll();request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);}),{unlockRecovery}=await import('/recovery.mjs'),{toHex}=await import('/cbor.mjs'),secret=await unlockRecovery(rows[0].snapshot.secretEnvelope,phrase);try{await window.__testSetHgnSecret(toHex(secret));}finally{secret.fill(0);db.close();}},op);
  await a.locator('#session-wizard').getByRole('button',{name:'Send these terms'}).click();await updateBackup(a,op);await a.locator('#session-wizard').getByText('Waiting for their acceptance').waitFor();
  await b.reload();await updateBackup(b,tp);await b.locator('#session-wizard').getByRole('button',{name:'Accept these terms'}).click();await updateBackup(b,tp);await b.locator('#session-wizard').getByText('Waiting for the first lock').waitFor();
  await a.reload();await fundNativePair(owner,first,op);await a.locator('#session-wizard').getByText('Waiting for their lock').waitFor();
  await b.reload();await updateBackup(b,tp);await fundNativePair(taker,second,tp);await b.locator('#session-wizard').getByText('Waiting for their claim').waitFor();
  await a.reload();await updateBackup(a,op);await claimNativePair(owner,second,op);await a.locator('#session-wizard').getByText('Your claim is confirmed').waitFor();
  await b.reload();await b.locator('#session-wizard').getByText('Save the claim recovery data').waitFor();await b.locator('#session-wizard').getByLabel('Recovery passphrase').fill(tp);await b.locator('#session-wizard').getByRole('button',{name:'Protect claim recovery'}).click();await updateBackup(b,tp);
  await claimNativePair(taker,first,tp);await b.locator('#session-wizard').getByText('Swap complete').waitFor();
 }finally{await browser?.close();server.kill('SIGTERM');await Promise.race([once(server,'exit'),new Promise(r=>setTimeout(r,2000))]);await rm(dir,{recursive:true,force:true});}
});
