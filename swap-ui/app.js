'use strict';
import {newMessageKey,encryptMessage,decryptMessage} from './crypto.mjs';
import {verifyTokenEscrow,verifyEtherEscrow} from './ethereum-escrow.mjs';
import {submitLocalEscrowDeployment} from './ethereum-actions.mjs';
import {validateWatch,evaluateWatch} from './deadlines.mjs';
import {createRecovery,unlockRecovery,validateRecoveryEnvelope} from './recovery.mjs';
import {vaultLabel,listVault,addVault,removeVault} from './vault-store.mjs';
const types=[['ethereum:eth','Ethereum · ETH'],['ethereum:erc20','Ethereum · ERC-20'],['ethereum:erc721','Ethereum · ERC-721'],['ethereum:erc1155','Ethereum · ERC-1155'],['cardano:ada','Cardano · ADA'],['cardano:native','Cardano · native token'],['bitcoin:btc','Bitcoin · BTC'],['hegemon:hgn','Hegemon · HGN']];
const $=id=>document.getElementById(id);
for(const name of ['give-type','receive-type']) for(const [value,label] of types) document.querySelector(`[name="${name}"]`).add(new Option(label,value));
function refreshWallets(){const select=$('cardano-wallet'),selected=select.value;select.replaceChildren(new Option('No wallet selected',''));
 for(const [id,wallet] of Object.entries(window.cardano||{}))if(wallet && typeof wallet.enable==='function')select.add(new Option(String(wallet.name||id),id));
 select.value=Array.from(select.options).some(option=>option.value===selected)?selected:'';
}
refreshWallets();$('refresh-wallets').addEventListener('click',refreshWallets);
async function api(path,options={}){
 const response=await fetch(path,{...options,headers:{...(options.body?{'content-type':'application/json'}:{}),...options.headers}});
 const result=await response.json();if(!response.ok)throw Error(result.error||'Request failed');return result;
}
function describe(asset){return `${asset.amount} · ${asset.chain} ${asset.kind}${asset.id?' · '+asset.id:''}`;}
function msg(element,value,error=false){element.textContent=value;element.className=error?'error':'';}
let observedEthereumProvider,activeEthereumProvider;
const verifyForm=$('verify-form');
function toggleTokenFields(){const native=verifyForm.elements.kind.value==='eth';for(const name of ['token','tokenId']){verifyForm.elements[name].disabled=native;verifyForm.elements[name].required=!native;}}
verifyForm.elements.kind.addEventListener('change',toggleTokenFields);toggleTokenFields();
$('connect-ethereum').addEventListener('click',async()=>{
 try{const provider=window.ethereum;if(!provider||typeof provider.request!=='function')throw Error('No Ethereum browser wallet found.');
  const accounts=await provider.request({method:'eth_requestAccounts'}),chain=await provider.request({method:'eth_chainId'});
  if(!Array.isArray(accounts)||!/^0x[0-9a-fA-F]{40}$/.test(accounts[0])||typeof chain!=='string')throw Error('Wallet returned an invalid account or network.');
  if(provider!==observedEthereumProvider && typeof provider.on==='function'){
   const changed=()=>{activeEthereumProvider=null;msg($('wallet-status'),'Ethereum wallet changed. Reconnect to refresh the account and network.');};
   provider.on('accountsChanged',changed);provider.on('chainChanged',changed);provider.on('disconnect',changed);observedEthereumProvider=provider;
  }
  activeEthereumProvider=provider;msg($('wallet-status'),'Ethereum connected: '+accounts[0]+' · chain '+chain+'. No transaction has been requested.');
 }catch(e){msg($('wallet-status'),e.message,true);}
});
$('verify-form').addEventListener('submit',async event=>{event.preventDefault();
 try{if(!activeEthereumProvider)throw Error('Connect an Ethereum wallet first.');
  const provider=activeEthereumProvider;
  const data=new FormData(event.currentTarget),terms={chainId:'0x7a69'};
  for(const name of ['contract','kind','token','tokenId','amount','hashlock','claimant','refundee','expiry'])terms[name]=String(data.get(name)).trim();
  const native=terms.kind==='eth',response=await fetch(native?'/ether-escrow-template.json':'/token-escrow-template.json');if(!response.ok)throw Error('Escrow template unavailable.');
  const result=await (native?verifyEtherEscrow(provider,await response.json(),terms,2):verifyTokenEscrow(provider,await response.json(),terms,2));
  if(provider!==activeEthereumProvider)throw Error('Wallet changed during verification. Reconnect and retry.');
  msg($('verify-status'),'Verified funded and unspent at block '+result.blockNumber+' ('+result.blockHash+'). The node and token issuer remain trust assumptions.');
 }catch(e){msg($('verify-status'),e.message,true);}
});
$('connect-cardano').addEventListener('click',async()=>{
 try{const id=$('cardano-wallet').value,wallet=window.cardano?.[id];if(!wallet||typeof wallet.enable!=='function')throw Error('Select an available Cardano browser wallet.');
  const api=await wallet.enable(),network=await api.getNetworkId();if(network!==0&&network!==1)throw Error('Wallet returned an invalid network.');
  msg($('wallet-status'),'Cardano connected: '+String(wallet.name||id)+' · '+(network===1?'mainnet':'testnet')+'. No transaction has been requested.');
 }catch(e){msg($('wallet-status'),e.message,true);}
});
let companionToken=null,companionCapabilities=[];
async function companion(path,token,body){
 const response=await fetch('http://127.0.0.1:8788'+path,{method:body?'POST':'GET',credentials:'omit',headers:{authorization:'Bearer '+token,...(body?{'content-type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
 const result=await response.json();if(!response.ok)throw Error(result.error||'Companion request failed');return result;
}
$('connect-companion').addEventListener('click',async()=>{
 const token=$('companion-token').value;$('companion-token').value='';companionToken=null;companionCapabilities=[];$('hegemon-actions').hidden=true;$('ethereum-actions').hidden=true;
 try{if(!/^[0-9a-f]{64}$/.test(token))throw Error('Enter the 64-character pairing token.');
  const result=await companion('/health',token);if(!Array.isArray(result.capabilities)||!result.capabilities.length)throw Error('No local verifiers are available.');
  companionToken=token;companionCapabilities=result.capabilities;$('hegemon-actions').hidden=!companionCapabilities.includes('hegemon-local-actions');$('ethereum-actions').hidden=!companionCapabilities.includes('ethereum-local-anchor');msg($('companion-status'),companionCapabilities.includes('hegemon-local-actions')?'Local companion connected with experimental Hegemon actions enabled.':'Local read-only companion connected.');
 }catch(e){msg($('companion-status'),e.message,true);}
});
const ethereumActionForm=$('ethereum-action-form');
function toggleEthereumActionFields(){const native=ethereumActionForm.elements.kind.value==='eth';for(const name of ['token','tokenId']){ethereumActionForm.elements[name].disabled=native;ethereumActionForm.elements[name].required=!native;}}
ethereumActionForm.elements.kind.addEventListener('change',toggleEthereumActionFields);toggleEthereumActionFields();
ethereumActionForm.addEventListener('submit',async event=>{event.preventDefault();const button=event.currentTarget.querySelector('button[type="submit"]');
 try{if(!activeEthereumProvider)throw Error('Connect an Ethereum wallet first.');if(!companionToken||!companionCapabilities.includes('ethereum-local-anchor'))throw Error('Connect a companion configured for local Anvil.');
  const provider=activeEthereumProvider,data=new FormData(event.currentTarget),terms={};
  for(const name of ['kind','token','tokenId','amount','hashlock','claimant','refundee','expiry'])terms[name]=String(data.get(name)||'').trim();
  button.disabled=true;$('ethereum-action-result').textContent='';msg($('ethereum-action-status'),'Checking the local chain and requesting wallet approval.');
  const [anchor,response]=await Promise.all([companion('/ethereum/head',companionToken),fetch(terms.kind==='eth'?'/ether-escrow-template.json':'/token-escrow-template.json')]);
  if(!response.ok)throw Error('Escrow template unavailable.');const template=await response.json();
  const guarded={request:args=>{if(provider!==activeEthereumProvider)throw Error('Wallet changed. Reconnect and check wallet history before retrying.');return provider.request(args);}};
  const result=await submitLocalEscrowDeployment(guarded,template,terms,anchor);
  $('ethereum-action-result').textContent=JSON.stringify(result,null,2);
  msg($('ethereum-action-status'),terms.kind==='eth'?'Deployment submitted; check the receipt and confirmations.':'Deployment submitted, but the token escrow is not funded. Check the receipt and confirmations.');
 }catch(e){msg($('ethereum-action-status'),e.message,true);}finally{button.disabled=false;}
});
$('bitcoin-form').addEventListener('submit',async event=>{event.preventDefault();
 try{if(!companionToken||!companionCapabilities.includes('bitcoin-regtest-verify'))throw Error('Connect a companion configured for Bitcoin.');const data=new FormData(event.currentTarget),terms={};
  for(const name of ['txid','hashlock','claimant_key','refund_key','genesis_hash'])terms[name]=String(data.get(name)).trim();
  for(const name of ['vout','amount_sats','refund_height']){terms[name]=Number(data.get(name));if(!Number.isSafeInteger(terms[name]))throw Error('Invalid numeric value.');}
  const result=await companion('/bitcoin/verify',companionToken,terms);
  if(!result.verified)throw Error('Escrow not verified.');
  msg($('bitcoin-status'),'Verified unspent with '+result.snapshot.confirmations+' confirmations at regtest block '+result.snapshot.block_height+'. The local node remains a trust assumption.');
 }catch(e){msg($('bitcoin-status'),e.message,true);}
});
$('cardano-form').addEventListener('submit',async event=>{event.preventDefault();
 try{if(!companionToken||!companionCapabilities.includes('cardano-local-verify'))throw Error('Connect a companion configured for Cardano.');
  const data=new FormData(event.currentTarget),terms={};
  for(const name of ['outref','hashlock','claimant','refundee','expiry_ms','genesis_sha256'])terms[name]=String(data.get(name)).trim();
  terms.expected_value={lovelace:String(data.get('lovelace')).trim()};
  for(const line of String(data.get('assets')).split(/\r?\n/).map(x=>x.trim()).filter(Boolean)){
   const match=line.match(/^([0-9a-f]{56})\.((?:[0-9a-f]{2}){0,32})=([1-9][0-9]{0,18})$/);
   if(!match||BigInt(match[3])>=1n<<63n)throw Error('Invalid Cardano asset line.');
   const [,policy,name,quantity]=match;terms.expected_value[policy]??={};
   if(Object.hasOwn(terms.expected_value[policy],name))throw Error('Duplicate Cardano asset.');
   terms.expected_value[policy][name]=quantity;
  }
  const result=await companion('/cardano/verify',companionToken,terms);
  if(!result.verified||result.snapshot.confirmations!==null)throw Error('Cardano snapshot not verified.');
  msg($('cardano-status'),'Verified at local tip block '+result.snapshot.tip_block+'. Confirmation depth is unknown.');
 }catch(e){msg($('cardano-status'),e.message,true);}
});
$('hegemon-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.currentTarget.querySelector('button[type="submit"]');
 try{if(!companionToken||!companionCapabilities.includes('hegemon-local-verify'))throw Error('Connect a companion configured for the Hegemon wallet.');
  const data=new FormData(event.currentTarget),terms={};
  for(const name of ['locked','claim','refund','hashlock','timeout','amount','min_confirmations','min_remaining_blocks'])terms[name]=String(data.get(name)).trim();
  button.disabled=true;msg($('hegemon-status'),'Approve the request and unlock the wallet in the local companion terminal.');
  const result=await companion('/hegemon/verify',companionToken,terms);
  if(!result.verified||result.snapshot?.verified!==true)throw Error('Hegemon note not verified.');
  msg($('hegemon-status'),'Verified unspent with '+result.snapshot.confirmations+' confirmations at local height '+result.snapshot.reference_height+'.');
 }catch(e){msg($('hegemon-status'),e.message,true);}finally{button.disabled=false;}
});
const hegemonActionForm=$('hegemon-action-form');
function updateHegemonActionFields(){const op=hegemonActionForm.elements.operation.value;
 for(const label of hegemonActionForm.querySelectorAll('[data-ops]')){const visible=label.dataset.ops.split(' ').includes(op);label.hidden=!visible;for(const field of label.querySelectorAll('input,textarea,select')){field.disabled=!visible;field.required=visible;}}
}
hegemonActionForm.elements.operation.addEventListener('change',updateHegemonActionFields);updateHegemonActionFields();
hegemonActionForm.addEventListener('submit',async event=>{event.preventDefault();const button=event.currentTarget.querySelector('button[type="submit"]');
 try{if(!companionToken||!companionCapabilities.includes('hegemon-local-actions'))throw Error('Connect a companion with experimental Hegemon actions enabled.');
  const data=new FormData(event.currentTarget),operation=String(data.get('operation')),request={operation};
  const fields={status:[],ordinary:['inputs','recipient','amount','fee'],lock:['inputs','claim','refund','hashlock','timeout','amount','fee'],claim:['locked','fee_input','recipient','fee'],refund:['locked','fee_input','recipient','fee'],submit:['attempt']}[operation];
  if(!fields)throw Error('Unsupported action.');
  for(const field of fields){const value=String(data.get(field)).trim();request[field]=field==='inputs'?value.split(',').map(x=>x.trim()):value;}
  button.disabled=true;$('hegemon-action-result').textContent='';msg($('hegemon-action-status'),'Review and approve this request in the companion terminal.');
  const result=await companion('/hegemon/action',companionToken,request);
  if(result.completed!==true)throw Error('The local action did not complete. Check wallet status before retrying.');
  $('hegemon-action-result').textContent=JSON.stringify(result,null,2);msg($('hegemon-action-status'),'Local action completed. Review the result before submitting anything.');
 }catch(e){msg($('hegemon-action-status'),e.message,true);}finally{button.disabled=false;}
});
function credential(id){return localStorage.getItem('offer-owner:'+id);}
function currentOffer(){return location.hash.slice(1).split('.')[0];}
function messageKey(id){return localStorage.getItem('offer-message-key:'+id);}
function participantToken(id){return credential(id)||localStorage.getItem('offer-reservation:'+id);}
function selectOffer(id){location.hash=id;return loadSelected();}
function updateChat(id){$('chat').hidden=!(messageKey(id)&&participantToken(id));if(!$('chat').hidden)refreshChat();}
async function refreshChat(){const id=currentOffer(),key=messageKey(id),token=participantToken(id);if(!key||!token)return;
 try{const {messages}=await api('/offers/'+id+'/messages',{headers:{authorization:'Bearer '+token}});$('chat-list').replaceChildren();
  for(const item of messages){const p=document.createElement('p');try{p.textContent=item.sender+': '+await decryptMessage(key,id,item.ciphertext);}catch{p.textContent=item.sender+': [unable to decrypt message]';} $('chat-list').append(p);}
  msg($('chat-status'),messages.length?'':'No messages yet.');
 }catch(e){msg($('chat-status'),e.message,true);}}
async function loadSelected(){
 const [id,key]=location.hash.slice(1).split('.');if(!/^[0-9a-f]{64}$/.test(id)){$('selected').hidden=true;$('chat').hidden=true;return;}
 if(key&&/^[0-9a-f]{64}$/.test(key))localStorage.setItem('offer-message-key:'+id,key);
 try{const offer=await api('/offers/'+id);$('selected').hidden=false;$('details').replaceChildren();
  for(const line of ['Give: '+describe(offer.give),'Receive: '+describe(offer.receive),'Expires: '+new Date(offer.expires*1000).toLocaleString(),offer.closed?'Closed':'Open']){const p=document.createElement('p');p.textContent=line;$('details').append(p);}
  $('reserve').disabled=offer.closed||offer.expires*1000<=Date.now();$('close').hidden=!credential(id)||offer.closed;msg($('detail-status'),'');updateChat(id);
 }catch(e){$('selected').hidden=false;msg($('details'),e.message,true);$('reserve').disabled=true;$('close').hidden=true;$('chat').hidden=true;}
}
async function refresh(){try{const {offers}=await api('/offers');$('board').replaceChildren();if(!offers.length){$('board').textContent='No public offers right now.';return;}
 for(const offer of offers){const row=document.createElement('div');row.className='offer';const text=document.createElement('p');text.textContent=describe(offer.give)+' → '+describe(offer.receive);const button=document.createElement('button');button.type='button';button.textContent='View offer';button.addEventListener('click',()=>selectOffer(offer.id));row.append(text,button);$('board').append(row);}}
 catch(e){msg($('board'),e.message,true);}}
$('offer-form').addEventListener('submit',async event=>{event.preventDefault();const data=new FormData(event.currentTarget);
 const read=side=>{const [chain,kind]=String(data.get(side+'-type')).split(':');return {chain,kind,id:String(data.get(side+'-id')).trim(),amount:String(data.get(side+'-amount')).trim()};};
 try{const result=await api('/offers',{method:'POST',body:JSON.stringify({give:read('give'),receive:read('receive'),visibility:data.get('visibility'),expires:Math.floor(Date.now()/1000)+Number(data.get('lifetime'))})});
  localStorage.setItem('offer-owner:'+result.id,result.ownerToken);const key=newMessageKey();localStorage.setItem('offer-message-key:'+result.id,key);$('share-link').value=location.origin+'/#'+result.id+'.'+key;$('share').hidden=false;msg($('create-result'),'Offer created.');await refresh();await selectOffer(result.id);
 }catch(e){msg($('create-result'),e.message,true);}});
$('copy-link').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('share-link').value);msg($('create-result'),'Link copied.');}catch{msg($('create-result'),'Select and copy the link above.');}});
$('refresh').addEventListener('click',refresh);
$('reserve').addEventListener('click',async()=>{const id=currentOffer();try{const result=await api('/offers/'+id+'/reserve',{method:'POST'});localStorage.setItem('offer-reservation:'+id,result.reservationToken);msg($('detail-status'),'Reserved until '+new Date(result.expires*1000).toLocaleString()+'. No funds have been locked.');$('reserve').disabled=true;updateChat(id);}catch(e){msg($('detail-status'),e.message,true);}});
$('close').addEventListener('click',async()=>{const id=currentOffer();try{await api('/offers/'+id+'/close',{method:'POST',headers:{authorization:'Bearer '+credential(id)}});await loadSelected();await refresh();msg($('detail-status'),'Offer closed.');}catch(e){msg($('detail-status'),e.message,true);}});
$('chat-refresh').addEventListener('click',refreshChat);
$('chat-form').addEventListener('submit',async event=>{event.preventDefault();const id=currentOffer(),key=messageKey(id),token=participantToken(id),field=event.currentTarget.elements.message;
 try{const ciphertext=await encryptMessage(key,id,field.value);await api('/offers/'+id+'/messages',{method:'POST',headers:{authorization:'Bearer '+token},body:JSON.stringify({ciphertext})});field.value='';await refreshChat();}catch(e){msg($('chat-status'),e.message,true);}});
const WATCH_KEY='hegemon.local.deadline-watches.v1';
async function withStorageLock(key,action){if(!navigator.locks?.request)throw Error('Browser storage locking is unavailable; local records were not changed.');return navigator.locks.request(key,{mode:'exclusive'},action);}
function readWatches(){try{const values=JSON.parse(localStorage.getItem(WATCH_KEY)||'[]');if(!Array.isArray(values)||values.length>30)throw Error();
 const ids=new Set();for(const item of values){if(!item||!/^[0-9a-f]{32}$/.test(item.id)||ids.has(item.id))throw Error();validateWatch(item);ids.add(item.id);}return values;
}catch{throw Error('Saved deadlines are invalid; they were not overwritten.');}}
function saveWatches(values){localStorage.setItem(WATCH_KEY,JSON.stringify(values));}
async function localHead(chain){
 if(chain==='ethereum'){
  const provider=activeEthereumProvider;if(!provider)throw Error('Connect an Ethereum wallet.');
  if(BigInt(await provider.request({method:'eth_chainId'}))!==31337n)throw Error('Wrong Ethereum chain.');
  const genesis=await provider.request({method:'eth_getBlockByNumber',params:['0x0',false]});
  const head=await provider.request({method:'eth_getBlockByNumber',params:['latest',false]});
  if(provider!==activeEthereumProvider||BigInt(await provider.request({method:'eth_chainId'}))!==31337n||!/^0x[0-9a-f]{64}$/i.test(genesis?.hash||'')||!head?.timestamp)throw Error('Ethereum node changed or returned invalid data.');
  return {genesis:genesis.hash.slice(2).toLowerCase(),current:BigInt(head.timestamp).toString()};
 }
 const cap={bitcoin:'bitcoin-regtest-verify',cardano:'cardano-local-verify',hegemon:'hegemon-local-verify'}[chain];
 if(!companionToken||!companionCapabilities.includes(cap))throw Error('Connect the configured local companion.');
 const head=await companion('/'+chain+'/head',companionToken);
 return {genesis:head.genesis,current:chain==='cardano'?head.time_ms:head.height};
}
let watchRefreshing=false;
async function refreshWatches(){if(watchRefreshing)return;watchRefreshing=true;
 try{const entries=readWatches(),heads=new Map();$('watch-list').replaceChildren();
  if(!entries.length){$('watch-list').textContent='No saved deadlines.';return;}
  for(const chain of new Set(entries.map(entry=>entry.chain)))heads.set(chain,localHead(chain).then(value=>({value}),error=>({error})));
  for(const entry of entries){const row=document.createElement('div');row.className='offer';const text=document.createElement('p');
   try{const result=await heads.get(entry.chain);if(result.error)throw result.error;const state=evaluateWatch(entry,result.value);
    const units=entry.chain==='cardano'?'milliseconds':entry.chain==='ethereum'?'seconds':'blocks';
    text.textContent=entry.label+' · '+entry.chain+' · '+state.state+' · '+state.remaining+' '+units+' remaining at last reported tip';
   }catch(e){text.textContent=entry.label+' · '+entry.chain+' · unavailable: '+e.message;}
   const remove=document.createElement('button');remove.type='button';remove.textContent='Remove';remove.addEventListener('click',async()=>{try{await withStorageLock(WATCH_KEY,()=>saveWatches(readWatches().filter(item=>item.id!==entry.id)));row.remove();refreshWatches();}catch(e){msg($('watch-status'),e.message,true);}});row.append(text,remove);$('watch-list').append(row);
  }
 }catch(e){$('watch-list').replaceChildren();msg($('watch-status'),e.message,true);}finally{watchRefreshing=false;}}
$('watch-form').addEventListener('submit',async event=>{event.preventDefault();try{
 const data=new FormData(event.currentTarget),watch=validateWatch(Object.fromEntries(['chain','label','genesis','deadline','warning'].map(key=>[key,String(data.get(key)).trim()])));
 const id=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
 await withStorageLock(WATCH_KEY,()=>{const entries=readWatches();if(entries.length>=30)throw Error('Remove a deadline before adding another.');saveWatches([...entries,{id,...watch}]);});msg($('watch-status'),'Deadline saved in this browser.');await refreshWatches();
 }catch(e){msg($('watch-status'),e.message,true);}});
$('watch-refresh').addEventListener('click',refreshWatches);
setInterval(refreshWatches,15000);refreshWatches();
const VAULT_KEY='hegemon.local.encrypted-secrets.v1';
const vaultChannel=typeof BroadcastChannel==='function'?new BroadcastChannel('hegemon.local.encrypted-secrets.v2'):null;
function notifyVault(){vaultChannel?.postMessage('changed');}
let vaultRenderVersion=0;
async function renderVault(){const version=++vaultRenderVersion;let entries;
 try{entries=await listVault();}catch(e){if(version===vaultRenderVersion){$('vault-list').replaceChildren();msg($('vault-status'),e.message,true);}return;}
 if(version!==vaultRenderVersion)return;$('vault-list').replaceChildren();if(!entries.length){$('vault-list').textContent='No encrypted secrets saved.';return;}
 for(const entry of entries){const row=document.createElement('div');row.className='offer';const text=document.createElement('p');text.textContent=entry.label+' · hashlock '+entry.envelope.hashlock;
  const exportButton=document.createElement('button');exportButton.type='button';exportButton.textContent='Show encrypted backup';exportButton.addEventListener('click',()=>{$('vault-backup').value=JSON.stringify(entry);msg($('vault-status'),'Encrypted backup ready to copy and save.');});
  const testButton=document.createElement('button');testButton.type='button';testButton.textContent='Test unlock';testButton.addEventListener('click',async()=>{const phrase=$('vault-unlock').value;$('vault-unlock').value='';testButton.disabled=true;let secret;
   try{secret=await unlockRecovery(entry.envelope,phrase);msg($('vault-status'),'Backup unlocked and hashlock verified.');}catch(e){msg($('vault-status'),e.message,true);}finally{secret?.fill(0);testButton.disabled=false;}});
  const remove=document.createElement('button');remove.type='button';remove.textContent='Delete local copy';remove.addEventListener('click',async()=>{if(!window.confirm('Delete this local encrypted secret? Keep a verified backup and its passphrase first.'))return;try{await removeVault(entry.envelope.hashlock);notifyVault();await renderVault();msg($('vault-status'),'Local copy deleted.');}catch(e){msg($('vault-status'),e.message,true);}});
  row.append(text,exportButton,testButton,remove);$('vault-list').append(row);
 }}
$('vault-create').addEventListener('submit',async event=>{event.preventDefault();const form=event.currentTarget,data=new FormData(form),button=form.querySelector('button[type="submit"]');
 try{const label=vaultLabel(String(data.get('label'))),phrase=String(data.get('passphrase'));if(phrase!==String(data.get('confirm')))throw Error('Passphrases do not match.');
  button.disabled=true;msg($('vault-status'),'Encrypting locally…');
  const envelope=await createRecovery(phrase);await addVault({label,envelope});notifyVault();$('vault-backup').value=JSON.stringify({label,envelope});form.reset();await renderVault();
  msg($('vault-status'),'Encrypted secret created. Copy and safely store its backup and passphrase.');
 }catch(e){msg($('vault-status'),e.message,true);}finally{button.disabled=false;}});
$('vault-import').addEventListener('click',async()=>{try{const item=JSON.parse($('vault-backup').value);if(!item||Object.keys(item).sort().join(',')!=='envelope,label')throw Error('Invalid encrypted backup.');
 const entry={label:vaultLabel(item.label),envelope:validateRecoveryEnvelope(item.envelope)};await addVault(entry);notifyVault();await renderVault();msg($('vault-status'),'Encrypted backup imported. Test unlock before relying on it.');
 }catch(e){msg($('vault-status'),e.message||'Invalid encrypted backup.',true);}});
if(vaultChannel)vaultChannel.onmessage=()=>renderVault();
$('vault-refresh').addEventListener('click',renderVault);
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')renderVault();});
renderVault();
window.addEventListener('storage',event=>{if(event.key===VAULT_KEY)renderVault();if(event.key===WATCH_KEY)refreshWatches();});
window.addEventListener('hashchange',loadSelected);
refresh();loadSelected();
