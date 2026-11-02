import {test} from 'node:test';
import assert from 'node:assert/strict';
import {buildLocalEscrowDeployment,submitLocalEscrowDeployment} from './ethereum-actions.mjs';
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
