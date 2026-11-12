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

test('an unsigned Bitcoin wallet handoff survives refresh and cannot be silently replaced',{timeout:30000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'bitcoin-draft-')),p=await port(),base=`http://127.0.0.1:${p}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(p)},stdio:'ignore'});let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const page=await browser.newPage();await page.goto(base);
  const info=await page.evaluate(async()=>{
   const {Address,TEST_NETWORK,secp256k1}=await import('/vendor/btc-signer.mjs'),{prepareBitcoinPsbt}=await import('/bitcoin-wallet.mjs'),{saveBitcoinDraft}=await import('/session-bitcoin-draft.mjs');
   const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join(''),pub=n=>hex(secp256k1.getPublicKey(new Uint8Array(32).fill(n),true));
   const session='11'.repeat(32),role='owner',side='long',operation='fund',attemptId='22'.repeat(16),address=Address(TEST_NETWORK).encode({type:'wpkh',hash:new Uint8Array(20).fill(3)}),agreed={hashlock:'33'.repeat(32),claimant_key:pub(4),refund_key:pub(5),refund_height:'130000',amount_sats:'50000'};
   const draft=await prepareBitcoinPsbt({op:operation,terms:agreed,address,feeRate:2,read:{utxos:async a=>({address:a,tip:129000,utxos:[{txid:'44'.repeat(32),vout:0,amount_sats:200000,confirmations:3}]})},verifyEscrow:async()=>{},journal:{begin:async()=>attemptId}});
   await saveBitcoinDraft({session,role,side,operation,attemptId,draft,agreed});return {session,role,side,operation,attemptId,agreed,txid:draft.txid};
  });
  await page.reload();
  const result=await page.evaluate(async info=>{
   const {saveBitcoinDraft,loadBitcoinDraft}=await import('/session-bitcoin-draft.mjs'),loaded=await loadBitcoinDraft(info);let duplicate=false,changed=false;
   try{await saveBitcoinDraft({...info,draft:loaded.draft});}catch{duplicate=true;}
   try{await loadBitcoinDraft({...info,agreed:{...info.agreed,amount_sats:'50001'}});}catch{changed=true;}
   return {txid:loaded.draft.txid,duplicate,changed};
  },info);
  assert.deepEqual(result,{txid:info.txid,duplicate:true,changed:true});
 }finally{await browser?.close();server.kill('SIGTERM');await Promise.race([once(server,'exit'),new Promise(r=>setTimeout(r,2000))]);await rm(dir,{recursive:true,force:true});}
});
