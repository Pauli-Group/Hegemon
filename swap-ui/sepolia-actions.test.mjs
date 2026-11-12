import {test} from 'node:test';
import assert from 'node:assert/strict';
import {deploySepoliaEscrow,tokenSepoliaStep,refundSepoliaEscrow} from './sepolia-actions.mjs';
import {expectedEtherRuntime,expectedTokenRuntime} from './ethereum-escrow.mjs';
import {SEPOLIA_GENESIS} from './sepolia-verifier.mjs';

const from='0x'+'1'.repeat(40),claimant='0x'+'2'.repeat(40),token='0x'+'3'.repeat(40),contract='0x'+'4'.repeat(40);
const names=['hashlock','claimant','refundee','expiry'],tokenNames=['kind','token','tokenId','amount',...names];
const artifact=keys=>({creation:'6000',runtime:'00'.repeat(32*keys.length),immutableReferences:Object.fromEntries(keys.map((n,i)=>[n,[{start:i*32,length:32}]]))});
const ethTemplate=artifact(names),tokenTemplate=artifact(tokenNames),base={kind:'eth',contract,token:'',tokenId:'',amount:'100',hashlock:'0x'+'a'.repeat(64),claimant,refundee:from,expiry:'5000'};
function wallet({wrong=false,headChange=false,failSend=false,code='0x',timestamp=100,funded=0,spent=0,balance=100}={}){
 let sends=[],heads=0;return {sends,request:async({method,params=[]})=>{
  if(method==='eth_chainId')return '0xaa36a7';if(method==='eth_accounts')return [from];
  if(method==='eth_getBlockByNumber')return params[0]==='0x0'?{hash:wrong?'0x'+'0'.repeat(64):SEPOLIA_GENESIS}:{number:'0x10',timestamp:'0x'+timestamp.toString(16),hash:'0x'+(headChange&&heads++?'e':'b').repeat(64)};
  if(method==='eth_getCode')return code;if(method==='eth_getBalance')return '0x'+balance.toString(16);
  if(method==='eth_call'){const data=params[0].data;if(data==='0x7ab71b7a')return '0x'+spent.toString(16).padStart(64,'0');if(data==='0xf3a504f2')return '0x'+funded.toString(16).padStart(64,'0');return '0x';}
  if(method==='eth_sendTransaction'){sends.push(params[0]);if(failSend)throw Error('lost response');return '0x'+'9'.repeat(64);}throw Error('unexpected '+method);
 }};
}
test('Sepolia deployment verifies network and submits exactly once',async()=>{
 const p=wallet(),result=await deploySepoliaEscrow(p,ethTemplate,base);assert.equal(result.submitted,true);assert.equal(p.sends.length,1);assert.equal(p.sends[0].value,'0x64');
 for(const options of [{wrong:true},{headChange:true}]){const q=wallet(options);await assert.rejects(deploySepoliaEscrow(q,ethTemplate,base));assert.equal(q.sends.length,0);}
 const uncertain=wallet({failSend:true});await assert.rejects(deploySepoliaEscrow(uncertain,ethTemplate,base),/Check wallet history/);assert.equal(uncertain.sends.length,1);
});
test('token funding and native refund check exact escrow and deadline',async()=>{
 const terms={...base,kind:'0',token,tokenId:'0'},code=expectedTokenRuntime(tokenTemplate,terms),good=wallet({code});
 await tokenSepoliaStep(good,tokenTemplate,terms,'fund');assert.equal(good.sends[0].to,contract);assert.equal(good.sends[0].data,'0xb60d4288');
 const bad=wallet({code:'0x'});await assert.rejects(tokenSepoliaStep(bad,tokenTemplate,terms,'fund'),/bytecode/);assert.equal(bad.sends.length,0);
 const ethCode=expectedEtherRuntime(ethTemplate,base),early=wallet({code:ethCode,timestamp:100});await assert.rejects(refundSepoliaEscrow(early,ethTemplate,base),/deadline/);assert.equal(early.sends.length,0);
 const mature=wallet({code:ethCode,timestamp:5000});await refundSepoliaEscrow(mature,ethTemplate,base);assert.equal(mature.sends[0].data,'0x590e1ae3');
 const blocked=wallet({code:ethCode,timestamp:5000});await assert.rejects(refundSepoliaEscrow(blocked,ethTemplate,base,{verify:async()=>{throw Error('swap state changed');}}),/swap state changed/);assert.equal(blocked.sends.length,0);
});
test('a failed swap-level check blocks deployment and token funding before the wallet request',async()=>{
 const deploy=wallet();await assert.rejects(deploySepoliaEscrow(deploy,ethTemplate,base,{verify:async()=>{throw Error('other leg changed');}}),/other leg changed/);assert.equal(deploy.sends.length,0);
 const terms={...base,kind:'0',token,tokenId:'0'},fund=wallet({code:expectedTokenRuntime(tokenTemplate,terms)});
 await assert.rejects(tokenSepoliaStep(fund,tokenTemplate,terms,'fund',{verify:async()=>{throw Error('policy changed');}}),/policy changed/);assert.equal(fund.sends.length,0);
});

test('forced ETH cannot block refunds but insufficient balance and spent escrows still do',async()=>{
 const code=expectedEtherRuntime(ethTemplate,base);
 const extra=wallet({code,timestamp:5000,balance:101});
 await refundSepoliaEscrow(extra,ethTemplate,base);
 assert.equal(extra.sends.length,1);
 for(const options of [{balance:99},{spent:1}]){
  const blocked=wallet({code,timestamp:5000,...options});
  await assert.rejects(refundSepoliaEscrow(blocked,ethTemplate,base),/balance|spent/);
  assert.equal(blocked.sends.length,0);
 }
});
