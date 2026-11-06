/** Manual Sepolia escrow actions. The wallet must approve every transaction.
 * These actions do not verify the other leg or implement a complete swap. */
import {buildLocalEscrowDeployment} from './ethereum-actions.mjs';
import {expectedEtherRuntime,expectedTokenRuntime} from './ethereum-escrow.mjs';
import {assertSepoliaIdentity,verifySepoliaEscrow} from './sepolia-verifier.mjs';

function addr(value){if(typeof value!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(value)||/^0x0{40}$/i.test(value))throw Error('Invalid Ethereum address.');return value.toLowerCase();}
function wordAddress(value){return addr(value).slice(2).padStart(64,'0');}
function wordNumber(value){if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,77})$/.test(value)||BigInt(value)>=(1n<<256n))throw Error('Invalid token amount or ID.');return BigInt(value).toString(16).padStart(64,'0');}
async function context(provider,from,owner='refund'){
 await assertSepoliaIdentity(provider);const request=(method,params=[])=>provider.request({method,params});
 const accounts=await request('eth_accounts');if(!Array.isArray(accounts)||!accounts.some(a=>typeof a==='string'&&a.toLowerCase()===from))throw Error('The connected wallet does not control the '+owner+' address.');
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
/** Absolute floor for wallet actions. The swap policy (timelock-policy.mjs) is judged separately when two escrows are compared. */
export const SEPOLIA_ACTION_FLOOR_SECONDS=1200n;
function requireTime(terms,head){if(BigInt(terms.expiry)-BigInt(head.timestamp)<SEPOLIA_ACTION_FLOOR_SECONDS)throw Error('Allow at least 20 minutes before the Sepolia refund deadline.');}
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
/** Claim a Sepolia escrow with the preimage from an unlocked encrypted backup.
 *
 * Checks, in order: the preimage hashes to the escrow's hashlock; the wallet is on Sepolia and controls the
 * claimant address; the pinned runtime, terms, funded and unspent state at a confirmed snapshot and at the
 * head; at least `cutoffSeconds` (the policy's action time) remain before the deadline; the caller's
 * `verify(snapshot)` hook (the swap-level gate: the other leg and the claim cutoff) accepts; and the head
 * did not move between the checks and the wallet request.
 *
 * The preimage reaches the wallet when `eth_sendTransaction` is called, even if the user then rejects it, and a
 * submitted claim is public. This function therefore never simulates the claim with `eth_call`: a simulation
 * would send the preimage to the wallet's RPC provider before the user has approved anything.
 * `options` = `{cutoffSeconds, confirmations, verify}`. The secret is not modified or retained. */
export async function claimSepoliaEscrow(provider,template,terms,secret,options={}){
 if(!terms||!['eth','0','1','2'].includes(terms.kind))throw Error('Invalid escrow type.');
 if(!(secret instanceof Uint8Array)||secret.length!==32)throw Error('Invalid preimage.');
 const cutoff=options.cutoffSeconds??60;if(!Number.isSafeInteger(cutoff)||cutoff<1||cutoff>86400)throw Error('Invalid claim cutoff.');
 const digest='0x'+Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',secret)),b=>b.toString(16).padStart(2,'0')).join('');
 if(digest!==String(terms.hashlock).toLowerCase())throw Error('The backup does not match the escrow hashlock.');
 const from=addr(terms.claimant);
 const snapshot=await verifySepoliaEscrow(provider,template,terms,{confirmations:options.confirmations,minClaimWindowSeconds:cutoff,remainingFloorSeconds:1});
 const {request,head}=await context(provider,from,'claimant');
 if(BigInt(terms.expiry)-BigInt(head.timestamp)<BigInt(cutoff))throw Error('Too close to the Sepolia deadline to claim safely.');
 if(typeof options.verify==='function')await options.verify({...snapshot,headTimestamp:Number(BigInt(head.timestamp))});
 const tx={from,to:addr(terms.contract),data:'0xbd66528a'+Array.from(secret,b=>b.toString(16).padStart(2,'0')).join(''),value:'0x0'};
 await beforeSend(provider,request,head,from);
 return {...await send(request,tx),step:'claim'};
}
