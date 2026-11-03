/** Manual Sepolia escrow actions. The wallet must approve every transaction.
 * These actions do not verify the other leg or implement a complete swap. */
import {buildLocalEscrowDeployment} from './ethereum-actions.mjs';
import {expectedEtherRuntime,expectedTokenRuntime} from './ethereum-escrow.mjs';
import {assertSepoliaIdentity} from './sepolia-verifier.mjs';

function addr(value){if(typeof value!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(value)||/^0x0{40}$/i.test(value))throw Error('Invalid Ethereum address.');return value.toLowerCase();}
function wordAddress(value){return addr(value).slice(2).padStart(64,'0');}
function wordNumber(value){if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,77})$/.test(value)||BigInt(value)>=(1n<<256n))throw Error('Invalid token amount or ID.');return BigInt(value).toString(16).padStart(64,'0');}
async function context(provider,from){
 await assertSepoliaIdentity(provider);const request=(method,params=[])=>provider.request({method,params});
 const accounts=await request('eth_accounts');if(!Array.isArray(accounts)||!accounts.some(a=>typeof a==='string'&&a.toLowerCase()===from))throw Error('The connected wallet does not control the refund address.');
 const head=await request('eth_getBlockByNumber',['latest',false]);
 if(!head||!/^0x[0-9a-f]+$/i.test(head.number||'')||!/^0x[0-9a-f]{64}$/i.test(head.hash||'')||!/^0x[0-9a-f]+$/i.test(head.timestamp||''))throw Error('Invalid Sepolia head.');
 return {request,head};
}
async function beforeSend(provider,request,head,from){
 await assertSepoliaIdentity(provider);const [latest,accounts]=await Promise.all([request('eth_getBlockByNumber',['latest',false]),request('eth_accounts')]);
 if(!latest||String(latest.hash).toLowerCase()!==String(head.hash).toLowerCase())throw Error('Sepolia head changed. Recheck the action.');
 if(!Array.isArray(accounts)||!accounts.some(a=>typeof a==='string'&&a.toLowerCase()===from))throw Error('Wallet account changed. Reconnect and check the action.');
}
async function send(request,tx){
 let id;try{id=await request('eth_sendTransaction',[tx]);}catch{throw Error('Wallet submission was not confirmed. Check wallet history before retrying.');}
 if(typeof id!=='string'||!/^0x[0-9a-f]{64}$/i.test(id))throw Error('Wallet returned no usable transaction ID. Check wallet history before retrying.');
 return {txid:id.toLowerCase(),submitted:true,confirmed:false,from:tx.from};
}
function requireTime(terms,head){if(BigInt(terms.expiry)-BigInt(head.timestamp)<1200n)throw Error('Allow at least 20 minutes before the Sepolia refund deadline.');}
async function contractState(request,head,terms,template,{funded}){
 const contract=addr(terms.contract),expected=terms.kind==='eth'?expectedEtherRuntime(template,terms):expectedTokenRuntime(template,terms);
 const code=await request('eth_getCode',[contract,head.number]);if(typeof code!=='string'||code.toLowerCase()!==expected)throw Error('Escrow bytecode or terms do not match.');
 const state=async data=>{const v=await request('eth_call',[{to:contract,data},head.number]);if(typeof v!=='string'||!/^0x[0-9a-f]{64}$/i.test(v))throw Error('Invalid escrow state.');return BigInt(v);};
 if(await state('0x7ab71b7a')!==0n)throw Error('Escrow is already spent.');
 if(terms.kind!=='eth'&&await state('0xf3a504f2')!==BigInt(funded?1:0))throw Error(funded?'Escrow is not funded.':'Escrow is already funded.');
 if(terms.kind==='eth'&&BigInt(await request('eth_getBalance',[contract,head.number]))!==BigInt(terms.amount))throw Error('Escrow balance does not match.');
 return contract;
}
export async function deploySepoliaEscrow(provider,template,terms){
 const tx=buildLocalEscrowDeployment(template,terms),from=addr(terms.refundee),{request,head}=await context(provider,from);requireTime(terms,head);
 await beforeSend(provider,request,head,from);return send(request,tx);
}
export async function tokenSepoliaStep(provider,template,terms,step){
 if(!['0','1','2'].includes(terms.kind)||!['approve','fund','revoke'].includes(step)||(step==='revoke'&&terms.kind!=='2'))throw Error('Invalid token action.');
 const from=addr(terms.refundee),token=addr(terms.token),{request,head}=await context(provider,from),contract=addr(terms.contract);
 if(step==='revoke'){
  const code=await request('eth_getCode',[contract,head.number]);if(typeof code!=='string'||code.toLowerCase()!==expectedTokenRuntime(template,terms))throw Error('Escrow bytecode or terms do not match.');
 }else{requireTime(terms,head);await contractState(request,head,terms,template,{funded:false});}
 const data=step==='fund'?'0xb60d4288':terms.kind==='2'?'0xa22cb465'+wordAddress(contract)+wordNumber(step==='revoke'?'0':'1'):'0x095ea7b3'+wordAddress(contract)+wordNumber(terms.kind==='0'?terms.amount:terms.tokenId);
 const tx={from,to:step==='fund'?contract:token,data,value:'0x0'},sim=await request('eth_call',[tx,head.number]);
 if(typeof sim!=='string'||!/^0x(?:[0-9a-f]{2})*$/i.test(sim)||(step==='approve'&&terms.kind==='0'&&sim!=='0x'&&(!/^0x[0-9a-f]{64}$/i.test(sim)||BigInt(sim)!==1n)))throw Error('Token action simulation failed.');
 await beforeSend(provider,request,head,from);return {...await send(request,tx),step};
}
export async function refundSepoliaEscrow(provider,template,terms){
 if(!['eth','0','1','2'].includes(terms.kind))throw Error('Invalid escrow type.');
 const from=addr(terms.refundee),{request,head}=await context(provider,from);
 if(BigInt(head.timestamp)<BigInt(terms.expiry))throw Error('The refund deadline has not passed.');
 const contract=await contractState(request,head,terms,template,{funded:true}),tx={from,to:contract,data:'0x590e1ae3',value:'0x0'};
 const simulation=await request('eth_call',[tx,head.number]);if(typeof simulation!=='string'||!/^0x(?:[0-9a-f]{2})*$/i.test(simulation))throw Error('Refund simulation failed.');
 await beforeSend(provider,request,head,from);return {...await send(request,tx),step:'refund'};
}
