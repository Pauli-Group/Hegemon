/** Explicit local-Anvil transaction primitives. These do not implement an atomic
 * swap or verify the other leg. The provider must be user-approved; the trusted
 * companion supplies the non-forked local Anvil anchor. Never auto-retry a send.
 */
import {expectedEtherRuntime,expectedTokenRuntime,verifyEtherEscrow,verifyTokenEscrow} from './ethereum-escrow.mjs';
function addr(value){if(typeof value!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(value)||/^0x0{40}$/i.test(value))throw Error('invalid address');return value.slice(2).toLowerCase().padStart(64,'0');}
function uint(value){if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,77})$/.test(value)||BigInt(value)>=1n<<256n)throw Error('invalid integer');return BigInt(value).toString(16).padStart(64,'0');}
function hash(value){if(typeof value!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(value))throw Error('invalid hashlock');return value.slice(2).toLowerCase();}
export function buildLocalEscrowDeployment(template,terms){
 if(!terms||!['eth','0','1','2'].includes(terms.kind)||!template||typeof template.creation!=='string'||!/^[0-9a-f]+$/.test(template.creation)||template.creation.length>200000)throw Error('invalid escrow type or creation template');
 const recipient=addr(terms.claimant),sender='0x'+addr(terms.refundee).slice(24),digest=hash(terms.hashlock),expiry=uint(terms.expiry),amount=uint(terms.amount);
 if(BigInt(terms.amount)===0n)throw Error('invalid amount');
 if(terms.kind==='eth')return {from:sender,data:'0x'+template.creation+digest+recipient+expiry,value:'0x'+BigInt(terms.amount).toString(16)};
 const token=addr(terms.token),id=uint(terms.tokenId);
 if((terms.kind==='0'&&terms.tokenId!=='0')||(terms.kind==='1'&&terms.amount!=='1'))throw Error('invalid token quantity');
 return {from:sender,data:'0x'+template.creation+uint(terms.kind)+token+id+amount+digest+recipient+expiry,value:'0x0'};
}
async function localAnchor(provider,anchor,from){
 if(!provider||typeof provider.request!=='function'||!anchor||!/^([0-9a-f]{64})$/.test(anchor.genesis||'')||!/^0x[0-9a-f]{64}$/i.test(anchor.tip_hash||'')||!/^(0|[1-9][0-9]*)$/.test(anchor.time_seconds||''))throw Error('invalid local chain anchor');
 const request=(method,params=[])=>provider.request({method,params});
 if(BigInt(await request('eth_chainId'))!==31337n)throw Error('wallet is not on the local Ethereum chain');
 if(from){const accounts=await request('eth_accounts');if(!Array.isArray(accounts)||!accounts.some(a=>typeof a==='string'&&a.toLowerCase()===from))throw Error('wallet does not control the required address');}
 const genesis=await request('eth_getBlockByNumber',['0x0',false]),head=await request('eth_getBlockByNumber',['latest',false]);
 if(!genesis||!head||String(genesis.hash).toLowerCase()!=='0x'+anchor.genesis||String(head.hash).toLowerCase()!==anchor.tip_hash.toLowerCase()||BigInt(head.timestamp)!==BigInt(anchor.time_seconds))throw Error('wallet and local node do not agree on the chain');
 return {request,head};
}
async function sendOnce(request,tx){
 let txid;
 try{txid=await request('eth_sendTransaction',[tx]);}
 catch{throw Error('Wallet submission was not confirmed. Check wallet history before retrying.');}
 if(typeof txid!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(txid))throw Error('Wallet returned no usable transaction ID. Check wallet history before retrying.');
 return {txid:txid.toLowerCase(),submitted:true,confirmed:false,from:tx.from};
}
export async function submitLocalEscrowDeployment(provider,template,terms,anchor){
 const tx=buildLocalEscrowDeployment(template,terms),{request,head}=await localAnchor(provider,anchor,tx.from);
 if(BigInt(terms.expiry)-BigInt(head.timestamp)<60n)throw Error('escrow deadline too close');
 return sendOnce(request,tx);
}
/** One approval or funding operation; callers must separately confirm receipts.
 * ERC-1155 approval authorizes the escrow as operator for all of that token's
 * IDs until revoked. Never call this before independently agreeing the terms.
 */
export async function submitLocalTokenFundingStep(provider,template,terms,anchor,step){
 if(!['approve','fund','revoke'].includes(step)||(step==='revoke'&&terms.kind!=='2'))throw Error('invalid funding step');
 const contract='0x'+addr(terms.contract).slice(24),token='0x'+addr(terms.token).slice(24),from='0x'+addr(terms.refundee).slice(24);
 const expected=expectedTokenRuntime(template,terms),{request,head}=await localAnchor(provider,anchor,from);
 if(typeof head.number!=='string'||!/^0x[0-9a-f]+$/i.test(head.number))throw Error('invalid local head');
 if(step!=='revoke'&&BigInt(terms.expiry)-BigInt(head.timestamp)<60n)throw Error('escrow deadline too close');
 const code=await request('eth_getCode',[contract,head.number]);
 if(typeof code!=='string'||code.toLowerCase()!==expected)throw Error('escrow bytecode or terms mismatch');
 for(const selector of step==='revoke'?[]:['f3a504f2','7ab71b7a']){
  const state=await request('eth_call',[{to:contract,data:'0x'+selector},head.number]);
  if(typeof state!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(state)||BigInt(state)!==0n)throw Error('escrow is already funded or spent');
 }
 let data;
 if(step==='fund')data='0xb60d4288';
 else if(terms.kind==='2')data='0xa22cb465'+addr(contract)+uint(step==='revoke'?'0':'1');
 else data='0x095ea7b3'+addr(contract)+uint(terms.kind==='0'?terms.amount:terms.tokenId);
 const tx={from,to:step==='fund'?contract:token,data,value:'0x0'};
 const simulation=await request('eth_call',[tx,head.number]);
 if(typeof simulation!=='string'||!/^0x(?:[0-9a-fA-F]{2})*$/.test(simulation)||(step==='approve'&&terms.kind==='0'&&simulation!=='0x'&&(!/^0x[0-9a-fA-F]{64}$/.test(simulation)||BigInt(simulation)!==1n)))throw Error('transaction simulation failed');
 const latest=await request('eth_getBlockByNumber',['latest',false]);
 if(!latest||latest.hash!==head.hash||BigInt(await request('eth_chainId'))!==31337n)throw Error('chain changed before submission');
 return {...await sendOnce(request,tx),step};
}
/** Refund only after expiry, with the original source-pinned terms and state. */
export async function submitLocalEscrowRefund(provider,template,terms,anchor){
 if(!terms||!['eth','0','1','2'].includes(terms.kind))throw Error('invalid escrow type');
 const contract='0x'+addr(terms.contract).slice(24),from='0x'+addr(terms.refundee).slice(24);
 const expected=terms.kind==='eth'?expectedEtherRuntime(template,terms):expectedTokenRuntime(template,terms);
 const {request,head}=await localAnchor(provider,anchor,from);
 if(typeof head.number!=='string'||!/^0x[0-9a-f]+$/i.test(head.number))throw Error('invalid local head');
 if(BigInt(head.timestamp)<BigInt(terms.expiry))throw Error('refund is not yet available');
 const code=await request('eth_getCode',[contract,head.number]);
 if(typeof code!=='string'||code.toLowerCase()!==expected)throw Error('escrow bytecode or terms mismatch');
 const call=async(data)=>{const value=await request('eth_call',[{to:contract,data},head.number]);
  if(typeof value!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(value))throw Error('invalid escrow state');return BigInt(value);};
 if(await call('0x7ab71b7a')!==0n||(terms.kind!=='eth'&&await call('0xf3a504f2')!==1n))throw Error('escrow is not funded and unspent');
 if(terms.kind==='eth'&&BigInt(await request('eth_getBalance',[contract,head.number]))!==BigInt(terms.amount))throw Error('escrow balance mismatch');
 const tx={from,to:contract,data:'0x590e1ae3',value:'0x0'};
 const simulation=await request('eth_call',[tx,head.number]);
 if(typeof simulation!=='string'||!/^0x(?:[0-9a-fA-F]{2})*$/.test(simulation))throw Error('refund simulation failed');
 const latest=await request('eth_getBlockByNumber',['latest',false]);
 if(!latest||latest.hash!==head.hash||BigInt(await request('eth_chainId'))!==31337n)throw Error('chain changed before submission');
 return {...await sendOnce(request,tx),step:'refund'};
}
/** Manual local claim. Calling the wallet exposes the preimage to that wallet,
 * even if the user later rejects the transaction; a submitted claim is public.
 * This verifies only this escrow and does not verify the counterparty leg. */
export async function submitLocalEscrowClaim(provider,template,terms,anchor,secret){
 if(!terms||!['eth','0','1','2'].includes(terms.kind)||!(secret instanceof Uint8Array)||secret.length!==32)throw Error('invalid claim');
 const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',secret)),b=>b.toString(16).padStart(2,'0')).join('');
 if(digest!==hash(terms.hashlock))throw Error('backup does not match the escrow hashlock');
 const contract='0x'+addr(terms.contract).slice(24),from='0x'+addr(terms.claimant).slice(24);
 const verifyTerms={...terms,chainId:'0x7a69'};
 await (terms.kind==='eth'?verifyEtherEscrow(provider,template,verifyTerms,2):verifyTokenEscrow(provider,template,verifyTerms,2));
 const {request}=await localAnchor(provider,anchor,from);
 const data='0xbd66528a'+Array.from(secret,b=>b.toString(16).padStart(2,'0')).join('');
 return {...await sendOnce(request,{from,to:contract,data,value:'0x0'}),step:'claim'};
}
/** Recover a confirmed claim secret locally. The provider and companion node
 * are trusted; a chain reorganization can still disclose and later orphan it. */
export async function observeLocalEthereumClaim(provider,template,terms,anchor,fromBlock,confirmations=2){
 if(!terms||!['eth','0','1','2'].includes(terms.kind)||!Number.isSafeInteger(confirmations)||confirmations<1||confirmations>100||typeof fromBlock!=='string'||!/^(0|[1-9][0-9]{0,15})$/.test(fromBlock))throw Error('invalid observation terms');
 const contract='0x'+addr(terms.contract).slice(24),expected=terms.kind==='eth'?expectedEtherRuntime(template,terms):expectedTokenRuntime(template,terms);
 const {request,head}=await localAnchor(provider,anchor);
 if(typeof head.number!=='string'||!/^0x[0-9a-f]+$/i.test(head.number))throw Error('invalid local head');
 const latest=BigInt(head.number),start=BigInt(fromBlock);if(latest<BigInt(confirmations-1)||start>latest||latest-start>100000n)throw Error('invalid observation block range');
 const finalBlock=latest-BigInt(confirmations-1);if(finalBlock<start)throw Error('not enough confirmations');
 const code=await request('eth_getCode',[contract,head.number]);
 if(typeof code!=='string'||code.toLowerCase()!==expected)throw Error('escrow bytecode or terms mismatch');
 const spent=await request('eth_call',[{to:contract,data:'0x7ab71b7a'},head.number]);
 if(typeof spent!=='string'||!/^0x[0-9a-f]{64}$/i.test(spent)||BigInt(spent)!==1n)throw Error('escrow has not been spent');
 const topic=terms.kind==='eth'?'0x0508a8b4117d9a7b3d8f5895f6413e61b4f9a2df35afbfb41e78d0ecfff1843f':'0xeddf608ef698454af2fb41c1df7b7e5154ff0d46969f895e0f39c7dfe7e6380a';
 const logs=await request('eth_getLogs',[{address:contract,topics:[topic],fromBlock:'0x'+start.toString(16),toBlock:'0x'+finalBlock.toString(16)}]);
 if(!Array.isArray(logs)||logs.length!==1)throw Error('confirmed claim event not found or ambiguous');
 const log=logs[0],topics=log?.topics;
 if(log.removed!==false||String(log.address).toLowerCase()!==contract||!Array.isArray(topics)||String(topics[0]).toLowerCase()!==topic||topics.length!==(terms.kind==='eth'?2:1)||terms.kind==='eth'&&String(topics[1]).toLowerCase()!=='0x'+addr(terms.claimant)||typeof log.data!=='string'||!(terms.kind==='eth'?/^0x[0-9a-f]{128}$/i:/^0x[0-9a-f]{64}$/i).test(log.data)||!/^0x[0-9a-f]{64}$/i.test(log.blockHash||'')||!/^0x[0-9a-f]{64}$/i.test(log.transactionHash||'')||!/^0x[0-9a-f]+$/i.test(log.blockNumber||'')||!/^0x[0-9a-f]+$/i.test(log.logIndex||''))throw Error('invalid claim event');
 if(BigInt(log.blockNumber)<start||BigInt(log.blockNumber)>finalBlock)throw Error('claim does not have enough confirmations');
 const [block,receipt]=await Promise.all([request('eth_getBlockByNumber',[log.blockNumber,false]),request('eth_getTransactionReceipt',[log.transactionHash])]);
 if(!block||String(block.hash).toLowerCase()!==log.blockHash.toLowerCase()||BigInt(block.number)!==BigInt(log.blockNumber)||!receipt||BigInt(receipt.status)!==1n||BigInt(receipt.blockNumber)!==BigInt(log.blockNumber)||String(receipt.blockHash).toLowerCase()!==log.blockHash.toLowerCase()||String(receipt.transactionHash).toLowerCase()!==log.transactionHash.toLowerCase()||!Array.isArray(receipt.logs)||!receipt.logs.some(item=>String(item.logIndex).toLowerCase()===log.logIndex.toLowerCase()&&String(item.address).toLowerCase()===contract&&String(item.data).toLowerCase()===log.data.toLowerCase()&&Array.isArray(item.topics)&&JSON.stringify(item.topics.map(x=>String(x).toLowerCase()))===JSON.stringify(topics.map(x=>String(x).toLowerCase()))))throw Error('claim receipt is not canonical');
 const secret=Uint8Array.from(log.data.slice(2,66).match(/../g),s=>parseInt(s,16));
 try{
  const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',secret)),b=>b.toString(16).padStart(2,'0')).join('');
  if(digest!==hash(terms.hashlock))throw Error('claim preimage does not match hashlock');
  const again=await request('eth_getBlockByNumber',['latest',false]);if(!again||again.hash!==head.hash||BigInt(await request('eth_chainId'))!==31337n)throw Error('chain changed during observation');
  return {secret,snapshot:{transaction:log.transactionHash.toLowerCase(),blockHash:log.blockHash.toLowerCase(),blockNumber:BigInt(log.blockNumber).toString(),confirmations:(latest-BigInt(log.blockNumber)+1n).toString()}};
 }catch(e){secret.fill(0);throw e;}
}
