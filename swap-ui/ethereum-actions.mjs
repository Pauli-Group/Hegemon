/** Explicit local-Anvil deployment primitives. These do not implement an atomic
 * swap or verify the other leg. The provider must be user-approved; the trusted
 * companion supplies the non-forked local Anvil anchor. Never auto-retry a send.
 */
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
export async function submitLocalEscrowDeployment(provider,template,terms,anchor){
 if(!provider||typeof provider.request!=='function'||!anchor||!/^([0-9a-f]{64})$/.test(anchor.genesis||'')||!/^0x[0-9a-f]{64}$/i.test(anchor.tip_hash||'')||!/^(0|[1-9][0-9]*)$/.test(anchor.time_seconds||''))throw Error('invalid local chain anchor');
 const tx=buildLocalEscrowDeployment(template,terms),request=(method,params=[])=>provider.request({method,params});
 if(BigInt(await request('eth_chainId'))!==31337n)throw Error('wallet is not on the local Ethereum chain');
 const accounts=await request('eth_accounts');if(!Array.isArray(accounts)||!accounts.some(a=>typeof a==='string'&&a.toLowerCase()===tx.from))throw Error('wallet does not control the refund address');
 const genesis=await request('eth_getBlockByNumber',['0x0',false]),head=await request('eth_getBlockByNumber',['latest',false]);
 if(!genesis||!head||String(genesis.hash).toLowerCase()!=='0x'+anchor.genesis||String(head.hash).toLowerCase()!==anchor.tip_hash.toLowerCase()||BigInt(head.timestamp)!==BigInt(anchor.time_seconds))throw Error('wallet and local node do not agree on the chain');
 if(BigInt(terms.expiry)-BigInt(head.timestamp)<60n)throw Error('escrow deadline too close');
 let txid;
 try{txid=await request('eth_sendTransaction',[tx]);}
 catch{throw Error('Wallet submission was not confirmed. Check wallet history before retrying.');}
 if(typeof txid!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(txid))throw Error('Wallet returned no usable transaction ID. Check wallet history before retrying.');
 return {txid:txid.toLowerCase(),submitted:true,confirmed:false,from:tx.from};
}
