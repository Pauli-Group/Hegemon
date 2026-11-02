import {test} from 'node:test';
import assert from 'node:assert/strict';
import {buildLocalEscrowDeployment,submitLocalEscrowDeployment,submitLocalTokenFundingStep,submitLocalEscrowClaim,observeLocalEthereumClaim} from './ethereum-actions.mjs';
import {expectedEtherRuntime,expectedTokenRuntime} from './ethereum-escrow.mjs';
const account='0x'+'1'.repeat(40),claimant='0x'+'2'.repeat(40),token='0x'+'3'.repeat(40);
const terms={kind:'0',token,tokenId:'0',amount:'100',claimant,refundee:account,hashlock:'0x'+'a'.repeat(64),expiry:'1000'};
const template={creation:'6000'},anchor={genesis:'b'.repeat(64),tip_hash:'0x'+'c'.repeat(64),time_seconds:'100'};
function provider({wrong=false,fail=false}={}){let sends=0;return {get sends(){return sends;},request:async({method})=>{
 if(method==='eth_chainId')return '0x7a69';if(method==='eth_accounts')return [account];
 if(method==='eth_getBlockByNumber')return wrong?{hash:'0x'+'d'.repeat(64),timestamp:'0x64'}:{hash:'0x'+(providerCalls++===0?anchor.genesis:'c'.repeat(64)),timestamp:'0x64'};
 if(method==='eth_sendTransaction'){sends++;if(fail)throw Error('connection lost');return '0x'+'e'.repeat(64);}throw Error('unexpected request');}};}
let providerCalls=0;
test('constructor data uses the expected static fields and rejects invalid NFT amount',()=>{
 const tx=buildLocalEscrowDeployment(template,terms);assert.equal(tx.from,account);assert.equal(tx.value,'0x0');assert.equal(tx.data.length,2+template.creation.length+7*64);
 assert.throws(()=>buildLocalEscrowDeployment(template,{...terms,kind:'1',tokenId:'42',amount:'2'}));
 const native=buildLocalEscrowDeployment(template,{...terms,kind:'eth'});assert.equal(native.value,'0x64');assert.equal(native.data.length,2+template.creation.length+3*64);
});
test('wrong local chain anchor prevents submission',async()=>{
 providerCalls=0;const p=provider({wrong:true});await assert.rejects(submitLocalEscrowDeployment(p,template,terms,anchor),/do not agree/);assert.equal(p.sends,0);
});
test('uncertain wallet send is attempted once and requires manual history check',async()=>{
 providerCalls=0;const p=provider({fail:true});await assert.rejects(submitLocalEscrowDeployment(p,template,terms,anchor),/Check wallet history/);assert.equal(p.sends,1);
});
test('funding requires exact escrow terms and a stable local head',async()=>{
 const names=['kind','token','tokenId','amount','hashlock','claimant','refundee','expiry'];
 const artifact={runtime:'00'.repeat(32*names.length),immutableReferences:Object.fromEntries(names.map((n,i)=>[n,[{start:i*32,length:32}]]))};
 const t={...terms,contract:'0x'+'4'.repeat(40)},code=expectedTokenRuntime(artifact,t);
 for(const mode of ['wrong-code','changed-head','ok']){
  let block=0,sends=0;const p={request:async({method,params})=>{
   if(method==='eth_chainId')return '0x7a69';if(method==='eth_accounts')return [account];
   if(method==='eth_getBlockByNumber')return params[0]==='0x0'?{hash:'0x'+anchor.genesis}:{hash:mode==='changed-head'&&block++?'0x'+'d'.repeat(64):anchor.tip_hash,timestamp:'0x64',number:'0x2'};
   if(method==='eth_getCode')return mode==='wrong-code'?'0x':code;
   if(method==='eth_call')return params[0].data==='0xb60d4288'?'0x':'0x'+'0'.repeat(64);
   if(method==='eth_sendTransaction'){sends++;return '0x'+'e'.repeat(64);}throw Error('unexpected request');}};
  if(mode==='ok'){const result=await submitLocalTokenFundingStep(p,artifact,t,anchor,'fund');assert.equal(result.confirmed,false);assert.equal(sends,1);}
  else {await assert.rejects(submitLocalTokenFundingStep(p,artifact,t,anchor,'fund'),mode==='wrong-code'?/bytecode/:/chain changed/);assert.equal(sends,0);}
 }
});
test('a mismatched preimage never reaches the wallet provider',async()=>{
 let requests=0;const p={request:async()=>{requests++;throw Error('must not be called');}};
 const secret=new Uint8Array(32).fill(7);
 await assert.rejects(submitLocalEscrowClaim(p,{}, {...terms,kind:'eth'},anchor,secret),/does not match/);
 assert.equal(requests,0);secret.fill(0);
});
test('observed claim requires a canonical confirmed receipt and stable head',async()=>{
 const bytes=new Uint8Array(32).fill(7),digest=Buffer.from(await crypto.subtle.digest('SHA-256',bytes)).toString('hex');
 const names=['hashlock','claimant','refundee','expiry'],artifact={runtime:'00'.repeat(32*names.length),immutableReferences:Object.fromEntries(names.map((n,i)=>[n,[{start:i*32,length:32}]]))};
 const t={...terms,kind:'eth',contract:'0x'+'4'.repeat(40),hashlock:'0x'+digest},code=expectedEtherRuntime(artifact,t);
 const event={address:t.contract,topics:['0x0508a8b4117d9a7b3d8f5895f6413e61b4f9a2df35afbfb41e78d0ecfff1843f','0x'+claimant.slice(2).padStart(64,'0')],data:'0x'+Buffer.from(bytes).toString('hex')+'0'.repeat(63)+'1',blockHash:'0x'+'5'.repeat(64),blockNumber:'0x2',transactionHash:'0x'+'6'.repeat(64),logIndex:'0x0',removed:false};
 for(const mode of ['ok','bad-receipt','reorg','unconfirmed']){
  const log={...event,...(mode==='unconfirmed'?{blockNumber:'0x3'}:{})};let heads=0;
  const p={request:async({method,params})=>{
   if(method==='eth_chainId')return '0x7a69';
   if(method==='eth_getBlockByNumber'){
    if(params[0]==='0x0')return {hash:'0x'+anchor.genesis};
    if(params[0]==='latest')return {hash:mode==='reorg'&&heads++? '0x'+'9'.repeat(64):anchor.tip_hash,number:'0x3',timestamp:'0x64'};
    return {hash:event.blockHash,number:'0x2'};
   }
   if(method==='eth_getCode')return code;if(method==='eth_call')return '0x'+'0'.repeat(63)+'1';
   if(method==='eth_getLogs')return [log];
   if(method==='eth_getTransactionReceipt')return {status:'0x1',blockNumber:'0x2',blockHash:event.blockHash,transactionHash:event.transactionHash,logs:mode==='bad-receipt'?[]:[event]};
   throw Error('unexpected request');}};
  if(mode==='ok'){const result=await observeLocalEthereumClaim(p,artifact,t,anchor,'0',2);assert.deepEqual(result.secret,bytes);result.secret.fill(0);}
  else await assert.rejects(observeLocalEthereumClaim(p,artifact,t,anchor,'0',2),mode==='bad-receipt'?/not canonical/:mode==='reorg'?/chain changed/:/enough confirmations/);
 }
 bytes.fill(0);
});
