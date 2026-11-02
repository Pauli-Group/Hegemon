'use strict';
import {newMessageKey,encryptMessage,decryptMessage} from './crypto.mjs';
import {verifyTokenEscrow,verifyEtherEscrow} from './ethereum-escrow.mjs';
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
window.addEventListener('hashchange',loadSelected);
refresh();loadSelected();
