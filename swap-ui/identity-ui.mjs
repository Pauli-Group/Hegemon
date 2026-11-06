/* Page glue for signed identity statements and the owner's inbox key backup. Everything it needs from the page is passed in
 * so a test page can drive it. It never sees a wallet key: wallets sign, and every statement is verified here before it is
 * trusted. The relay stores statements but is not believed: a failed check blocks the conversation and the pair check. */
import {legSpecs,draftStatement,statementText,signEthereum,signCardano,bitcoinProof,addProof,publishable,expectedInbox,judgeIdentity} from './identity-flow.mjs';
import {inboxFingerprint,parsePublicSession} from './public-inbox.mjs';
import {fromHex,toHex} from './cbor.mjs';

export function initIdentity(d){
 const {$,msg}=d;
 const state={draft:null,proofs:[],busy:false,failed:new Map()};
 const now=()=>Math.floor(Date.now()/1000);
 const pinKey=(id,role)=>'offer-identity-pin:'+id+':'+role;
 const linkCode=id=>{const [offerId,,code]=location.hash.slice(1).split('.');return offerId===id&&/^[0-9a-f]{16}$/.test(code||'')?code:'';};
 function roleOf(id,offer){if(d.credential(id))return 'owner';return d.reservationToken(id)&&offer.reservationId?'taker':'viewer';}
 const describeLeg=(identity,side)=>identity.statement.legs[side].chain+' '+identity.addresses[side]+(identity.statement.legs[side].chain==='hegemon'?' (identity not available yet)':identity.proven[side]?' (proven by wallet signature)':' (asserted, not signed with that chain)');

 function peerLines(role,result){
  const who=role==='owner'?'Owner':'Taker';
  if(result.status==='none')return [who+' identity: not published. Nothing ties this '+role+' to a wallet address yet.'];
  if(result.status==='failed')return [who+' identity FAILED verification: '+result.error,'Do not continue with this '+role+' until you have confirmed them another way.'];
  const {identity}=result,mode=result.pinned?'matches the pinned code':'first seen here; confirm the code with them through a channel other than this relay';
  return [who+' identity verified, code '+identity.code+' ('+mode+').','  Give leg: '+describeLeg(identity,'give'),'  Receive leg: '+describeLeg(identity,'receive')];
 }

 /** Judge what the relay shows for the other participant (and the owner, for a viewer). Returns `{blocked, owner, taker}`. */
 async function evaluate(id,offer,messages){
  const role=roleOf(id,offer),at=now(),results={};
  for(const target of ['owner','taker']){
   if(target==='taker'&&role!=='owner'&&role!=='taker')continue;
   const blob=target==='owner'?offer.ownerIdentity:offer.reservationIdentity;
   const inbox=await expectedInbox({role:target,offer,messages});
   let pin=linkCode(id)&&target==='owner'?linkCode(id):localStorage.getItem(pinKey(id,target))||'';
   let result=await judgeIdentity({role:target,offer,blob,inbox,now:at,pin});
   // The owner's own offer-level statement must also name this browser's stored inbox key, not only the relay's copy.
   if(result.status==='verified'&&!pin&&target!==role)localStorage.setItem(pinKey(id,target),result.identity.code);
   if(result.status==='verified'&&target===role&&role==='owner'&&localStorage.getItem('offer-inbox:'+id)&&localStorage.getItem('offer-inbox:'+id)!==offer.ownerPublicKey)result={status:'failed',error:'The inbox key the relay shows is not the one this browser created.'};
   results[target]=result;
  }
  const blocked=Object.entries(results).some(([target,result])=>result.status==='failed'&&target!==role);
  state.failed.set(id,blocked);
  return {role,blocked,...results};
 }
 async function context(id){
  const offer=await d.api('/offers/'+id),token=d.participantToken(id);
  const messages=token?(await d.api('/offers/'+id+'/messages',{headers:{authorization:'Bearer '+token}})).messages:[];
  return {offer,messages};
 }
 function legInputs(offer,role){
  const box=$('identity-legs');box.replaceChildren();
  for(const spec of legSpecs(offer,role)){
   const label=document.createElement('label'),input=document.createElement('input');
   label.textContent=spec.label;input.name=spec.side;input.autocomplete='off';input.maxLength=80;input.required=spec.chain!=='hegemon';input.dataset.chain=spec.chain;
   if(spec.chain==='hegemon'){input.value='pending';input.readOnly=true;}
   label.append(input);box.append(label);
  }
 }
 /** Render the identity panel for the selected offer. Called by the page whenever it refreshes the offer or messages. */
 async function render(id,offer,messages){
  const role=roleOf(id,offer);
  $('identity').hidden=false;
  const result=await evaluate(id,offer,messages);
  const lines=[];
  for(const target of ['owner','taker']){if(result[target])lines.push(...peerLines(target,result[target]));}
  $('identity-peer').textContent=lines.join('\n');$('identity-peer').className=result.blocked?'error':'';
  const can=role==='owner'||role==='taker';
  $('identity-form').hidden=!can;
  const key=d.messageKey(id),mine=result.owner?.status==='verified'&&role==='owner';
  $('identity-link-row').hidden=!mine||!key;if(mine&&key)$('identity-link').value=location.origin+'/#'+id+'.'+key+'.'+result.owner.identity.code;
  if(can&&$('identity-legs').dataset.offer!==id+':'+role){legInputs(offer,role);$('identity-legs').dataset.offer=id+':'+role;state.draft=null;state.proofs=[];$('identity-sign').hidden=true;}
  return result;
 }
 function renderProofs(){
  const list=$('identity-proofs');list.replaceChildren();
  for(const p of state.proofs){const li=document.createElement('li');li.textContent=p.chain+' · '+p.scheme+' · '+p.signer;list.append(li);}
  $('identity-publish').disabled=state.proofs.length===0;
 }
 async function ownInbox(id,offer,messages,role){
  if(role==='owner'){
   if(!offer.ownerPublicKey)throw Error('This offer has no inbox key to bind an identity to.');
   if(localStorage.getItem('offer-inbox:'+id)!==offer.ownerPublicKey)throw Error('The inbox key the relay shows is not the one this browser created.');
   return inboxFingerprint(offer.ownerPublicKey);
  }
  const inbox=await expectedInbox({role:'taker',offer,messages});
  if(!inbox)throw Error('Finish the conversation setup first: your statement binds the key in your handshake.');
  return inbox;
 }
 $('identity-form').addEventListener('submit',async event=>{event.preventDefault();if(state.busy)return;
  try{const id=d.currentOffer(),{offer,messages}=await context(id),role=roleOf(id,offer);
   if(role==='viewer')throw Error('Reserve the offer or open your own offer first.');
   const addresses=Object.fromEntries([...$('identity-legs').querySelectorAll('input')].map(i=>[i.name,i.value]));
   const inbox=await ownInbox(id,offer,messages,role);
   state.draft={id,role,statement:draftStatement({role,offer,reservation:offer.reservationId,inbox,addresses,now:now()})};state.proofs=[];
   $('identity-text').textContent=statementText(state.draft.statement);$('identity-sign').hidden=false;renderProofs();
   msg($('identity-status'),'Statement prepared. Sign it with the wallet for each address you want proven, then publish.');
  }catch(e){state.draft=null;$('identity-sign').hidden=true;msg($('identity-status'),e.message,true);}
 });
 async function sign(make){
  if(!state.draft||state.draft.id!==d.currentOffer())throw Error('Prepare a statement for the selected offer first.');
  const proof=await make(statementText(state.draft.statement));
  state.proofs=addProof(state.draft.statement,state.proofs,proof);renderProofs();
  msg($('identity-status'),'Added '+proof.chain+' signature. Publish when every address you want proven is signed.');
 }
 $('identity-sign-ethereum').addEventListener('click',async()=>{try{
  const provider=d.getEthereum();if(!provider)throw Error('Connect an Ethereum wallet first.');
  const account=(await provider.request({method:'eth_accounts'}))[0];if(!account)throw Error('The Ethereum wallet has no account available.');
  await sign(text=>signEthereum(provider,account,text));}catch(e){msg($('identity-status'),e.message,true);}});
 $('identity-sign-cardano').addEventListener('click',async()=>{try{await sign(text=>signCardano(d.getCardano(),text));}catch(e){msg($('identity-status'),e.message,true);}});
 $('identity-bitcoin-add').addEventListener('click',async()=>{try{await sign(text=>bitcoinProof($('identity-bitcoin-scheme').value,$('identity-bitcoin-signature').value,text));$('identity-bitcoin-signature').value='';}catch(e){msg($('identity-status'),e.message,true);}});
 $('identity-ethereum-use').addEventListener('click',async()=>{try{const provider=d.getEthereum();if(!provider)throw Error('Connect an Ethereum wallet first.');
  const account=(await provider.request({method:'eth_accounts'}))[0];if(!account)throw Error('The Ethereum wallet has no account available.');
  for(const input of $('identity-legs').querySelectorAll('input'))if(input.dataset.chain==='ethereum')input.value=account.toLowerCase();}catch(e){msg($('identity-status'),e.message,true);}});
 $('identity-cardano-use').addEventListener('click',async()=>{try{const api=d.getCardano();if(!api)throw Error('Connect a Cardano wallet first.');
  const used=await api.getUsedAddresses(),found=used.map(fromHex).find(b=>b.length>=29&&[0,2,4,6].includes(b[0]>>4));if(!found)throw Error('The wallet has no payment-key address.');
  for(const input of $('identity-legs').querySelectorAll('input'))if(input.dataset.chain==='cardano')input.value=toHex(found.slice(1,29));}catch(e){msg($('identity-status'),e.message,true);}});
 $('identity-publish').addEventListener('click',async()=>{if(state.busy)return;state.busy=true;$('identity-publish').disabled=true;
  try{const id=d.currentOffer();if(!state.draft||state.draft.id!==id||!state.proofs.length)throw Error('Prepare and sign a statement first.');
   const {offer,messages}=await context(id),role=roleOf(id,offer);
   if(role!==state.draft.role||(role==='taker'&&state.draft.statement.reservation!==offer.reservationId))throw Error('The reservation changed. Prepare the statement again.');
   const blob=publishable(state.draft.statement,state.proofs);
   // Verify what we are about to publish exactly as the other side will.
   const self=await judgeIdentity({role,offer,blob,inbox:await ownInbox(id,offer,messages,role),now:now()});
   if(self.status!=='verified')throw Error('Your statement does not verify: '+self.error);
   await d.api('/offers/'+id+'/identity',{method:'POST',headers:{authorization:'Bearer '+d.participantToken(id)},body:JSON.stringify(role==='owner'?{identity:blob}:{identity:blob,reservationId:offer.reservationId})});
   msg($('identity-status'),'Published. Your identity code is '+self.identity.code+'. Give it to the other participant through a channel other than this relay.');
   state.draft=null;$('identity-sign').hidden=true;const fresh=await context(id);await render(id,fresh.offer,fresh.messages);
  }catch(e){msg($('identity-status'),e.message,true);}finally{state.busy=false;renderProofs();}
 });
 $('identity-pin-save').addEventListener('click',()=>{try{
  const id=d.currentOffer(),code=$('identity-pin').value.trim().toLowerCase();if(!/^[0-9a-f]{16}$/.test(code))throw Error('Enter the 16-character identity code the other participant gave you.');
  localStorage.setItem(pinKey(id,d.credential(id)?'taker':'owner'),code);$('identity-pin').value='';
  context(id).then(c=>render(id,c.offer,c.messages));msg($('identity-status'),'Pinned. A different identity will now fail verification.');
 }catch(e){msg($('identity-status'),e.message,true);}});

 /** Both verified identities, or an error: the pair check refuses to run without them. */
 async function requireIdentities(id){
  const {offer,messages}=await context(id),result=await evaluate(id,offer,messages);
  for(const target of ['owner','taker']){
   const item=result[target];
   if(!item||item.status==='none')throw Error('The '+target+' has not published a signed identity. Both participants must publish one before the escrows can be checked against them.');
   if(item.status!=='verified')throw Error('The '+target+' identity does not verify: '+item.error);
  }
  return {offer,identities:{owner:result.owner.identity,taker:result.taker.identity}};
 }
 /** Before reserving: a published owner identity that does not verify blocks the reservation. Returns a note for the status line. */
 async function checkOwnerBeforeReserve(id,offer){
  const inbox=await expectedInbox({role:'owner',offer,messages:[]});
  const result=await judgeIdentity({role:'owner',offer,blob:offer.ownerIdentity,inbox,now:now(),pin:linkCode(id)||localStorage.getItem(pinKey(id,'owner'))||''});
  if(result.status==='failed')throw Error('Owner identity failed verification: '+result.error);
  if(result.status==='verified'&&!result.pinned)localStorage.setItem(pinKey(id,'owner'),result.identity.code);
  return result.status==='none'?'The owner has not published a signed identity.':'Owner identity code '+result.identity.code+(result.pinned?' matches the pinned code.':'; confirm it with them another way.');
 }
 return {render,evaluate,requireIdentities,checkOwnerBeforeReserve,blocked:id=>state.failed.get(id)===true,parsePublicSession};
}
