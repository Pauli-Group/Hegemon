import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {ethereumWallet,bitcoinMessageWallet} from '../swap-ui/test-wallets.mjs';
import {SEPOLIA_GENESIS} from '../swap-ui/sepolia-verifier.mjs';

for(const chain of ['ethereum','cardano'])test(`recover ${chain} funding only from the exact unspent escrow`,{timeout:45000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-recover-')),sock=createServer();sock.listen(0,'127.0.0.1');await once(sock,'listening');const port=sock.address().port;await new Promise(r=>sock.close(r));
 const base=`http://127.0.0.1:${port}`,server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(port)},stdio:'ignore'});let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const page=await browser.newPage();await page.goto(base);
  const result=await page.evaluate(async fixture=>{
   const {deriveSessionId,sessionOfferDigest}=await import('/session-identity.mjs'),{createSessionRecovery}=await import('/session-recovery.mjs'),{addSession,getSession,acknowledgeSessionBackup}=await import('/session-store.mjs');
   const {recoverFundingReference}=await import('/session-reconcile.mjs'),{sessionAssetTerms}=await import('/session-assets.mjs'),{expectedEtherRuntime}=await import('/ethereum-escrow.mjs'),{datumBytes}=await import('/cardano-tx.mjs'),{toHex}=await import('/cbor.mjs'),{PREVIEW_HTLC_ADDRESS}=await import('/cardano-preview-verifier.mjs');
   const id='11'.repeat(32),reservation='22'.repeat(32),session=await deriveSessionId(id,reservation),role='owner',now=Math.floor(Date.now()/1000),txid='55'.repeat(32),attemptId='66'.repeat(16),passphrase='disposable test passphrase',timing=await (await fetch('/chain-timing.json')).json();
   const give=fixture.chain==='ethereum'?{chain:'ethereum',kind:'eth',id:'',amount:'100000000000000'}:{chain:'cardano',kind:'ada',id:'',amount:'4000000'},receive={chain:'bitcoin',kind:'btc',id:'',amount:'50000'};
   const offer={id,visibility:'private',expires:now+3600,ownerPublicKey:'04'+'aa'.repeat(64),give,receive},long=fixture.chain==='ethereum'?{asset:give,network:'sepolia',refundee:fixture.ethA,claimant:fixture.ethB,expiry:now-100}:{asset:give,network:'preview',refundee:'11'.repeat(28),claimant:'22'.repeat(28),expiry:now-100};
   const terms={version:2,hashlock:'77'.repeat(32),legs:{long,short:{asset:receive,network:'testnet4',refundee:fixture.btcB,claimant:fixture.btcA,expiry:150337}}},blank=()=>({fund:[],claim:[],refund:[]}),snapshot={version:3,offer,offerDigest:await sessionOfferDigest(offer),reservation,credential:'44'.repeat(32),channelKey:'33'.repeat(32),sessionExpires:now+20*86400,terms,escrows:{long:null,short:null},secretEnvelope:null,ownerBlob:null,takerBlob:null,transport:{next:1,previous:null},actions:{long:blank(),short:blank()}};
   snapshot.actions.long.fund.push({id:attemptId,state:'uncertain',txid:null});const record=await addSession((await createSessionRecovery({session,role,snapshot,passphrase})).envelope,passphrase);await acknowledgeSessionBackup(session,role,record.revision);
   let spent=true;const reference=fixture.chain==='ethereum'?{chain:'ethereum',txid}:{chain:'cardano',txid,vout:0},contract='0x'+'88'.repeat(20),fields=sessionAssetTerms(terms,'long',{reference,...(fixture.chain==='ethereum'?{contract}:{})}).operationTerms;
   const template=await (await fetch('/ether-escrow-template.json')).json(),code=fixture.chain==='ethereum'?expectedEtherRuntime(template,fields):null;
   const readers={ethereum:{provider:{request:async({method,params=[]})=>{if(method==='eth_getTransactionReceipt')return {transactionHash:'0x'+txid,status:'0x1',contractAddress:contract};if(method==='eth_getTransactionByHash')return {hash:'0x'+txid,to:null,from:fixture.ethA};if(method==='eth_chainId')return '0xaa36a7';if(method==='eth_blockNumber')return '0x5';if(method==='eth_getBlockByNumber')return params[0]==='0x0'?{hash:fixture.genesis}:{hash:'0x'+'aa'.repeat(32),number:params[0]==='latest'?'0x5':params[0],timestamp:'0x'+now.toString(16)};if(method==='eth_getCode')return code;if(method==='eth_getBalance')return '0x'+BigInt(give.amount).toString(16);if(method==='eth_call')return '0x'+(spent?'1':'0').padStart(64,'0');throw Error('unexpected RPC '+method);}}},cardano:{escrow:async outref=>({network:'preview',magic:2,system_start:1666656000,slot:now-1666656000,confirmations:2,output:{tx_hash:outref.split('#')[0],tx_index:0,address:PREVIEW_HTLC_ADDRESS,value:give.amount,is_spent:spent,asset_list:[],inline_datum:{bytes:toHex(datumBytes(fields)),value:{constructor:0,fields:[{bytes:fields.hashlock},{bytes:fields.claimant},{bytes:fields.refundee},{int:Number(fields.expiry_ms)}]}}}})}};
   const opts={session,role,attemptId,txid,readers,config:timing,templates:{ether:template}};let rejected=false;try{await recoverFundingReference(opts);}catch{rejected=true;}const before=(await getSession(session,role)).snapshot.escrows.long;spent=false;
   const recovered=await recoverFundingReference(opts),saved=await getSession(session,role);return {rejected,before,recovered:recovered.reference,state:saved.snapshot.actions.long.fund[0].state};
  },{chain,ethA:ethereumWallet('03'.repeat(32)).address,ethB:ethereumWallet('04'.repeat(32)).address,btcA:bitcoinMessageWallet('01'.repeat(32)).publicKey,btcB:bitcoinMessageWallet('02'.repeat(32)).publicKey,genesis:SEPOLIA_GENESIS});
  assert.equal(result.rejected,true);assert.equal(result.before,null);assert.equal(result.recovered.chain,chain);assert.equal(result.state,'submitted');
 }finally{await browser?.close();server.kill('SIGTERM');await Promise.race([once(server,'exit'),new Promise(r=>setTimeout(r,2000))]);await rm(dir,{recursive:true,force:true});}
});
