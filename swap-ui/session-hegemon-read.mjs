/** Bounded Hegemon pre-mainnet access through the paired local companion.
 * Read methods never transact. Each explicit action requires local approval;
 * the companion checks its loopback node, release manifest and wallet. */
import {fromHex,toHex} from './cbor.mjs';
import {checkSessionAddress} from './session-identity.mjs';

export const HEGEMON_GENESIS='0xd9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3';
export const HEGEMON_CHAIN_ID='0x7b7b0899d5444ffd92c38b38188e9ce4f891913ca7cca854fdcae0aa22ca1b49';
const DEC=/^(0|[1-9][0-9]{0,19})$/;
const HEX=/^[0-9a-f]{64}$/;
function integer(value){if(typeof value!=='string'||!DEC.test(value)||BigInt(value)>=1n<<64n)throw Error('Invalid Hegemon integer.');return BigInt(value);}
function number(value){const n=integer(value);if(n>BigInt(Number.MAX_SAFE_INTEGER))throw Error('Hegemon height is too large.');return Number(n);}

export function hegemonSessionReader({request,enabled}){
 if(typeof request!=='function'||typeof enabled!=='function')throw Error('The local companion reader is unavailable.');
 const call=(path,body)=>{if(!enabled())throw Error('Connect the local Hegemon swap companion first.');return request(path,body);};
 const head=async()=>{
  const value=await call('/hegemon/swap/head');
  if(value?.network!=='pre-mainnet'||value.genesis!==HEGEMON_GENESIS||value.chain_id!==HEGEMON_CHAIN_ID)throw Error('The companion is not on the expected Hegemon testnet.');
  const height=number(value.height);if(height<1||height>=2**48)throw Error('Invalid Hegemon chain height.');return {genesis:value.genesis,chain_id:value.chain_id,height};
 };
 return Object.freeze({
  available:()=>enabled(),
  head,
  async address(){const value=await call('/hegemon/swap/address');checkSessionAddress('hegemon',value?.address);return value.address;},
  async select(amount,fee,exclude=[]){
   const required=integer(amount)+integer(fee);
   if(integer(amount)===0n||required>=1n<<64n||!Array.isArray(exclude)||exclude.length>2||new Set(exclude).size!==exclude.length)throw Error('Invalid Hegemon note selection.');
   for(const position of exclude)integer(position);
   const current=await head(),result=await call('/hegemon/swap/select',{amount,fee,exclude});
   if(!result||!Array.isArray(result.inputs)||result.inputs.length<1||result.inputs.length>2||new Set(result.inputs).size!==result.inputs.length||result.inputs.some(position=>exclude.includes(position)))throw Error('Invalid Hegemon note selection.');
   for(const position of result.inputs)integer(position);
   const total=integer(result.total),synced=number(result.synced_height),latest=await head();
   if(total<required||synced>latest.height||latest.height-synced>2||latest.height<current.height)throw Error('The Hegemon note selection is stale or insufficient.');
   return {inputs:result.inputs,total:result.total,syncedHeight:synced};
  },
  async locate(commitment){
   if(!/^[0-9a-f]{112}$/.test(commitment||''))throw Error('Invalid Hegemon note commitment.');
   const current=await head(),result=await call('/hegemon/swap/locate',{commitment}),position=integer(result?.position),created=number(result?.created_height),synced=number(result?.synced_height),latest=await head();
   if(created<1||created>synced||synced>latest.height||latest.height-synced>2||latest.height<current.height)throw Error('The Hegemon note lookup is stale.');
   return {position:position.toString(),createdHeight:created,syncedHeight:synced};
  },
  async inclusion(attempt,actionId=null){
   if(!HEX.test(attempt||'')||!(actionId===null||/^[0-9a-f]{96}$/.test(actionId)))throw Error('Invalid Hegemon attempt reference.');
   const result=await call('/hegemon/swap/inclusion',{attempt,action_id:actionId});
   if(!(result?.action_id===null||/^[0-9a-f]{96}$/.test(result?.action_id||''))||actionId!==null&&result.action_id!==null&&result.action_id!==actionId)throw Error('Invalid Hegemon action reference.');
   if(result?.state==='pending')return {state:'pending',actionId:result.action_id};
   if(result?.state!=='confirmed'||result.action_id===null||!/^0x[0-9a-f]{64}$/.test(result.block_hash||'')||!Number.isSafeInteger(result.confirmations)||result.confirmations<2)throw Error('Invalid Hegemon inclusion.');
   const block=number(result.block_height),latest=await head();
   if(block<1||block>latest.height||latest.height-block+1<result.confirmations)throw Error('The Hegemon inclusion is stale.');
   return {state:'confirmed',actionId:result.action_id,blockHeight:block,blockHash:result.block_hash,confirmations:result.confirmations};
  },
  async action(request,{secretEnvelope=null}={}){
   if(!request||!['lock','claim','refund','submit','import-refund-handoff'].includes(request.operation)||secretEnvelope!==null&&request.operation!=='claim')throw Error('Invalid Hegemon swap action.');
   const response=await call('/hegemon/swap/action',secretEnvelope===null?request:{action:request,secret_envelope:secretEnvelope});
   if(response?.completed!==true||response.result?.operation!==request.operation)throw Error('The local wallet action is uncertain. Check wallet status before retrying.');
   return response.result;
  },
  async escrow(terms,{confirmations,minBlocksToExpiry,refundReady=false}={}){
   if(!terms||!HEX.test(terms.hashlock||'')||!/^[0-9a-f]{96}$/.test(terms.action_id||'')||typeof refundReady!=='boolean'||!Number.isSafeInteger(confirmations)||confirmations<2||confirmations>100||!Number.isSafeInteger(minBlocksToExpiry)||minBlocksToExpiry<1)throw Error('Invalid Hegemon escrow verification request.');
   checkSessionAddress('hegemon',terms.claim);checkSessionAddress('hegemon',terms.refund);
   const locked=integer(terms.locked),timeout=integer(terms.timeout),amount=integer(terms.amount);
   if(timeout>=1n<<48n||amount===0n||terms.claim===terms.refund)throw Error('Invalid Hegemon escrow terms.');
   const current=await head();
   const result=await call('/hegemon/swap/verify',{locked:locked.toString(),claim:terms.claim,refund:terms.refund,hashlock:terms.hashlock,timeout:timeout.toString(),amount:amount.toString(),min_confirmations:String(confirmations),min_remaining_blocks:String(minBlocksToExpiry),action_id:terms.action_id,refund_ready:refundReady}),s=result?.snapshot;
   if(result?.verified!==true||s?.verified!==true||integer(s.position)!==locked||s.action_id!==terms.action_id||s.refund_ready!==refundReady||!/^[0-9a-f]{112}$/.test(s.commitment||''))throw Error('The local wallet did not verify the Hegemon note.');
   const created=number(s.created_height),reference=number(s.reference_height),depth=number(s.confirmations),latest=await head();
   if(created<1||reference<created||reference-created+1!==depth||depth<confirmations||latest.height<reference||latest.height<current.height||(refundReady?BigInt(latest.height)<timeout:timeout-BigInt(latest.height)<BigInt(minBlocksToExpiry)))throw Error('The Hegemon escrow observation is stale or inconsistent.');
   return {position:locked.toString(),commitment:s.commitment,actionId:s.action_id,createdHeight:created,referenceHeight:reference,confirmations:depth,height:latest.height,refundReady};
  },
  async noteStatus(terms,{confirmations,creationHeight}={}){
   if(!terms||!HEX.test(terms.hashlock||'')||!/^[0-9a-f]{96}$/.test(terms.action_id||'')||!Number.isSafeInteger(confirmations)||confirmations<2||confirmations>100||!Number.isSafeInteger(creationHeight)||creationHeight<1||creationHeight>=2**48)throw Error('Invalid Hegemon note observation.');
   checkSessionAddress('hegemon',terms.claim);checkSessionAddress('hegemon',terms.refund);
   const locked=integer(terms.locked),timeout=integer(terms.timeout),amount=integer(terms.amount);
   if(timeout>=1n<<48n||amount===0n||terms.claim===terms.refund)throw Error('Invalid Hegemon note terms.');
   const first=await head(),result=await call('/hegemon/swap/note-status',{locked:locked.toString(),claim:terms.claim,refund:terms.refund,hashlock:terms.hashlock,timeout:timeout.toString(),amount:amount.toString(),min_confirmations:String(confirmations),min_remaining_blocks:'1',action_id:terms.action_id,refund_ready:false});
   if(number(result?.lock_height)!==creationHeight)throw Error('The Hegemon lock block does not match.');
   if(result?.state==='unspent')return {state:'unspent'};
   if(!['claimed','refunded'].includes(result?.state)||!/^[0-9a-f]{96}$/.test(result.action_id||'')||!Number.isSafeInteger(result.confirmations)||result.confirmations<1)throw Error('Invalid Hegemon note observation.');
   const block=number(result.block_height),latest=await head();
   if(block<1||block>latest.height||latest.height<first.height||latest.height-block+1<result.confirmations)throw Error('The Hegemon note observation is stale.');
   if(result.state==='refunded')return {state:'refunded',actionId:result.action_id,confirmations:result.confirmations,enough:result.confirmations>=confirmations};
   if(!HEX.test(result.preimage||''))throw Error('Invalid Hegemon claim secret.');
   const secret=fromHex(result.preimage);try{if(toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',secret)))!==terms.hashlock)throw Error('Hegemon claim secret does not match.');}
   finally{secret.fill(0);}
   return {state:'claimed',actionId:result.action_id,preimage:result.preimage,confirmations:result.confirmations,enough:result.confirmations>=confirmations};
  },
  async observe(hashlock,startHeight,{confirmations=2}={}){
   if(!HEX.test(hashlock||'')||!Number.isSafeInteger(startHeight)||startHeight<1||startHeight>=2**48||!Number.isSafeInteger(confirmations)||confirmations<2||confirmations>100)throw Error('Invalid Hegemon claim observation.');
   const result=await call('/hegemon/swap/observe',{hashlock,start_height:String(startHeight)});
   if(result?.state==='pending')return {state:'pending'};
   if(result?.state!=='secret-revealed'||!HEX.test(result.preimage||'')||!/^[0-9a-f]{96}$/.test(result.action_id||'')||!/^0x[0-9a-f]{64}$/.test(result.block_hash||'')||!Number.isSafeInteger(result.confirmations)||result.confirmations<confirmations)throw Error('Invalid Hegemon claim observation.');
   const block=number(result.block_height),latest=await head(),secret=fromHex(result.preimage);
   try{
    const digest=toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',secret)));
    if(digest!==hashlock||block<startHeight||block>latest.height||latest.height-block+1<result.confirmations)throw Error('Hegemon secret observation does not match the chain.');
    // A matching secret does not prove this exact private note was spent.
    return {state:'secret-revealed',preimage:result.preimage,actionId:result.action_id,blockHeight:block,confirmations:result.confirmations,enough:true};
   }finally{secret.fill(0);}
  },
 });
}
