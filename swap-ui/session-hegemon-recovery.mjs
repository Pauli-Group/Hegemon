/** Exact, append-only public Hegemon action references saved inside the
 * encrypted session recovery snapshot. Wallet keys and handoff passphrases
 * stay on the user's computer. This module does not submit wallet actions. */
const HEX64=/^[0-9a-f]{64}$/,ACTION=/^[0-9a-f]{96}$/,COMMITMENT=/^[0-9a-f]{112}$/,HANDOFF=/^[0-9a-f]{32}\.bin$/,DEC=/^(0|[1-9][0-9]{0,19})$/;
const fields=['candidate','handoff','actionId','blockHeight','commitment','position'];
const exact=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const fail=()=>{throw Error('Invalid saved Hegemon wallet action.');};
const integer=value=>typeof value==='string'&&DEC.test(value)&&BigInt(value)<1n<<64n;
export function validateHegemonRecovery(snapshot){
 const state=snapshot?.hegemon;
 if(!exact(state,['long','short']))fail();
 for(const side of ['long','short']){
  if(!exact(state[side],['fund','claim','refund']))fail();
  for(const operation of ['fund','claim','refund']){
   const item=state[side][operation];if(item===null)continue;
   if(!exact(item,fields)||snapshot.terms?.legs?.[side]?.asset?.chain!=='hegemon'||!HEX64.test(item.candidate||'')||
      (operation==='fund'?!HANDOFF.test(item.handoff||''):item.handoff!==null)||
      !(item.actionId===null||ACTION.test(item.actionId))||
      !(item.blockHeight===null||integer(item.blockHeight)&&BigInt(item.blockHeight)>0n&&BigInt(item.blockHeight)<1n<<48n)||
      !(item.commitment===null||operation==='fund'&&COMMITMENT.test(item.commitment))||
      !(item.position===null||operation==='fund'&&integer(item.position))||
      item.blockHeight!==null&&item.actionId===null||item.commitment!==null&&item.blockHeight===null||item.position!==null&&item.commitment===null)fail();
   const attempt=snapshot.actions?.[side]?.[operation]?.at(-1);
   if(!attempt||attempt.txid!==item.candidate||!['prepared','submitted','uncertain'].includes(attempt.state))fail();
  }
 }
 return state;
}
export function validateHegemonRecoveryAdvance(previous,next){
 if(previous.version!==4)return;
 for(const side of ['long','short'])for(const operation of ['fund','claim','refund']){
  const old=previous.hegemon[side][operation],current=next.hegemon[side][operation];
  if(old===null)continue;
  if(current===null)fail();
  for(const field of fields)if(old[field]!==null&&old[field]!==current[field])fail();
 }
}
