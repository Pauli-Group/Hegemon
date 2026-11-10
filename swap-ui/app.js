'use strict';
import {newMessageKey,encryptMessage,decryptMessage} from './crypto.mjs';
import {createInbox,createInboxWithBackup,restoreInbox,inboxPrivateKey,inboxFingerprint,sealPublicSession,openPublicSession,parsePublicSession} from './public-inbox.mjs';
import {initIdentity} from './identity-ui.mjs';
import {verifyTokenEscrow,verifyEtherEscrow} from './ethereum-escrow.mjs';
import {verifySepoliaEscrow} from './sepolia-verifier.mjs';
import {deploySepoliaEscrow,tokenSepoliaStep,refundSepoliaEscrow,claimSepoliaEscrow} from './sepolia-actions.mjs';
import {verifyBitcoinTestnetEscrow} from './bitcoin-testnet-verifier.mjs';
import {verifyCardanoPreviewEscrow} from './cardano-preview-verifier.mjs';
import {submitLocalEscrowDeployment,submitLocalTokenFundingStep,submitLocalEscrowRefund,submitLocalEscrowClaim,observeLocalEthereumClaim} from './ethereum-actions.mjs';
import {validateWatch,evaluateWatch} from './deadlines.mjs';
import {createRecovery,encryptRecovery,unlockRecovery,validateRecoveryEnvelope} from './recovery.mjs';
import {vaultLabel,listVault,addVault,removeVault} from './vault-store.mjs';
import {listActions,beginAction,finishAction,uncertainAction,removeAction,importActions} from './action-journal.mjs';
import {comparePair} from './pair-check.mjs';
import {legRequirements,validateTiming,actionSeconds} from './timelock-policy.mjs';
import {cardanoOfferValue,checkPublicPair} from './public-pair.mjs';
import {initCardanoWalletActions} from './cardano-ui.mjs';
import {initBitcoinWalletActions} from './bitcoin-ui.mjs';
import {initObserver} from './observer-ui.mjs';
import {initGuided} from './guided-ui.mjs';
import {initJourney} from './journey-ui.mjs';
import {assertHegemonGiveSnapshot,formatBaseUnits} from './offer-draft.mjs';
const types=[['ethereum:eth','Ethereum · ETH'],['ethereum:erc20','Ethereum · ERC-20'],['ethereum:erc721','Ethereum · ERC-721'],['ethereum:erc1155','Ethereum · ERC-1155'],['cardano:ada','Cardano · ADA'],['cardano:native','Cardano · native token'],['bitcoin:btc','Bitcoin · BTC'],['hegemon:hgn','Hegemon · HGN']];
const $=id=>document.getElementById(id);
let journey;
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
function describe(asset){let amount;try{amount=formatBaseUnits(asset.chain+':'+asset.kind,asset.amount);}catch{amount=String(asset.amount)+' base units';}return `${amount} · ${asset.chain} ${asset.kind}${asset.id?' · '+asset.id:''}`;}
function msg(element,value,error=false){element.textContent=value;element.className=error?'error':'';}
const actionChannel=typeof BroadcastChannel==='function'?new BroadcastChannel('hegemon.local.action-journal.v1'):null;
function refreshActionViews(){actionChannel?.postMessage('changed');renderActionJournal();}
async function recordedAction(chain,operation,terms,action){
 const id=await beginAction(chain,operation,terms);refreshActionViews();
 try{const result=await action();if(!result||typeof result.submitted!=='boolean')throw Error('Action outcome uncertain. Check the wallet or transaction before retrying.');
  const saved={submitted:result.submitted};for(const field of ['confirmed','txid','attempt','refund_handoff','journal_record'])if(field in result)saved[field]=result[field];
  let warning='';try{await finishAction(id,saved);}catch{warning='Action returned a result, but the local journal could not be updated. Save the result and check the wallet before retrying.';}
  refreshActionViews();return {result,warning};
 }catch(e){try{await uncertainAction(id);}catch{}refreshActionViews();throw e;}
}
let observedEthereumProvider,activeEthereumProvider;
const sepoliaForm=$('sepolia-form');
function toggleSepoliaTokenFields(){const native=sepoliaForm.elements.kind.value==='eth';for(const name of ['token','tokenId']){sepoliaForm.elements[name].disabled=native;sepoliaForm.elements[name].required=!native;}}
sepoliaForm.elements.kind.addEventListener('change',toggleSepoliaTokenFields);toggleSepoliaTokenFields();
sepoliaForm.addEventListener('submit',async event=>{event.preventDefault();
 try{if(!activeEthereumProvider)throw Error('Connect an Ethereum wallet first.');const provider=activeEthereumProvider,data=new FormData(sepoliaForm),terms={};
  for(const name of ['contract','kind','token','tokenId','amount','hashlock','claimant','refundee','expiry'])terms[name]=String(data.get(name)||'').trim();
  const response=await fetch(terms.kind==='eth'?'/ether-escrow-template.json':'/token-escrow-template.json');if(!response.ok)throw Error('Escrow template unavailable.');
  const result=await verifySepoliaEscrow(provider,await response.json(),terms);if(provider!==activeEthereumProvider)throw Error('Wallet changed during verification. Reconnect and retry.');
  msg($('sepolia-status'),'Matched funded and unspent Sepolia escrow at block '+BigInt(result.blockNumber).toString()+'. This checks only the Ethereum leg and trusts your wallet provider.');
 }catch(e){msg($('sepolia-status'),e.message,true);}
});
const sepoliaActionForm=$('sepolia-action-form');let sepoliaActionBusy=false;
function toggleSepoliaActionFields(){const kind=sepoliaActionForm.elements.kind.value,native=kind==='eth';for(const name of ['token','tokenId']){sepoliaActionForm.elements[name].disabled=native;sepoliaActionForm.elements[name].required=!native;}$('sepolia-approve').hidden=native;$('sepolia-fund').hidden=native;$('sepolia-revoke').hidden=kind!=='2';}
sepoliaActionForm.elements.kind.addEventListener('change',toggleSepoliaActionFields);toggleSepoliaActionFields();
async function sepoliaAction(operation){
 if(sepoliaActionBusy)return;let secret;
 try{if(!sepoliaActionForm.reportValidity())return;if(!activeEthereumProvider)throw Error('Connect an Ethereum wallet first.');
  const data=new FormData(sepoliaActionForm),terms={};for(const name of ['kind','contract','token','tokenId','amount','hashlock','claimant','refundee','expiry'])terms[name]=String(data.get(name)||'').trim();
  if(operation!=='deploy'&&!/^0x[0-9a-fA-F]{40}$/.test(terms.contract))throw Error('Enter the deployed escrow address.');
  const provider=activeEthereumProvider,guarded={request:args=>{if(provider!==activeEthereumProvider)throw Error('Wallet changed. Reconnect and check wallet history before retrying.');return provider.request(args);}};
  sepoliaActionBusy=true;for(const button of sepoliaActionForm.querySelectorAll('button'))button.disabled=true;$('sepolia-action-result').textContent='';msg($('sepolia-action-status'),'Checking Sepolia and requesting wallet approval.');
  const response=await fetch(terms.kind==='eth'?'/ether-escrow-template.json':'/token-escrow-template.json');if(!response.ok)throw Error('Escrow template unavailable.');const template=await response.json();
  const action=async()=>{
   if(operation==='claim'){
    const selected=$('sepolia-claim-backup').value,phrase=$('sepolia-claim-passphrase').value;$('sepolia-claim-passphrase').value='';
    if(!selected||!phrase)throw Error('Select an encrypted backup and enter its passphrase.');
    const entry=(await listVault()).find(item=>item.envelope.hashlock===selected);if(!entry)throw Error('Encrypted backup not found.');
    if('0x'+selected!==terms.hashlock.toLowerCase())throw Error('The selected backup is for a different hashlock.');
    const config=await loadTiming();secret=await unlockRecovery(entry.envelope,phrase);
    return claimSepoliaEscrow(guarded,template,terms,secret,{cutoffSeconds:actionSeconds(config.chains.ethereum),confirmations:legRequirements(config,'ethereum').confirmations});
   }
   return operation==='deploy'?deploySepoliaEscrow(guarded,template,terms):operation==='refund'?refundSepoliaEscrow(guarded,template,terms):tokenSepoliaStep(guarded,template,terms,operation);
  };
  if(operation==='claim'&&!window.confirm('This claim does not check the other swap leg unless you started it from a guided swap. Your wallet receives the preimage as soon as the request is made, even if you reject it. Continue only after verifying the other leg and its deadlines.'))return;
  const {result,warning}=await recordedAction('ethereum',operation,terms,action);$('sepolia-action-result').textContent=JSON.stringify(result,null,2);
  msg($('sepolia-action-status'),warning||(operation==='deploy'&&terms.kind!=='eth'?'Deployment submitted. Check its receipt, then approve and fund the token escrow.':'Transaction submitted. Check its receipt and confirmations.'),!!warning);
 }catch(e){msg($('sepolia-action-status'),e.message,true);}finally{secret?.fill(0);sepoliaActionBusy=false;for(const button of sepoliaActionForm.querySelectorAll('button'))button.disabled=false;}
}
sepoliaActionForm.addEventListener('submit',event=>{event.preventDefault();sepoliaAction('deploy');});
for(const operation of ['approve','fund','revoke','refund','claim'])$('sepolia-'+operation).addEventListener('click',()=>sepoliaAction(operation));
async function readBitcoinTestnet(txid,vout){const response=await fetch('/bitcoin-testnet4/escrow?'+new URLSearchParams({txid,vout:String(vout)}));const value=await response.json();if(!response.ok)throw Error(value.error||'Bitcoin testnet service unavailable.');return value;}
async function readJson(path,fallback){const response=await fetch(path);const value=await response.json();if(!response.ok)throw Error(value.error||fallback);return value;}
const cardanoRead={params:()=>readJson('/cardano-preview/params','Cardano preview service unavailable.'),utxos:refs=>readJson('/cardano-preview/utxos?'+new URLSearchParams({refs:refs.join(',')}),'Cardano preview service unavailable.')};
initCardanoWalletActions({$,msg,getApi:()=>activeCardanoApi,loadTiming:()=>loadTiming(),legRequirements,actionSeconds,listVault,unlockRecovery,
 verifyEscrow:(terms,limits)=>verifyCardanoPreviewEscrow(terms,readCardanoPreview,limits),read:cardanoRead,refresh:()=>refreshActionViews(),
 journal:{begin:beginAction,finish:finishAction,uncertain:uncertainAction,remove:removeAction}});
class BroadcastRejected extends Error{constructor(m){super(m);this.rejected=true;}}
const bitcoinRead={
 utxos:address=>readJson('/bitcoin-testnet4/utxos?'+new URLSearchParams({address}),'Bitcoin testnet service unavailable.'),
 async broadcast(tx){const response=await fetch('/bitcoin-testnet4/broadcast',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({tx})});const value=await response.json();
  if(response.status===400)throw new BroadcastRejected(value.reason||value.error||'rejected');if(!response.ok)throw Error(value.error||'Bitcoin testnet service unavailable.');return value;}};
initBitcoinWalletActions({$,msg,loadTiming:()=>loadTiming(),legRequirements,listVault,unlockRecovery,verifyEscrow:(terms,limits)=>verifyBitcoinTestnetEscrow(terms,readBitcoinTestnet,limits),read:bitcoinRead,refresh:()=>refreshActionViews(),
 journal:{begin:beginAction,finish:finishAction,uncertain:uncertainAction,remove:removeAction}});
initObserver({$,msg,loadTiming:()=>loadTiming(),legRequirements,vaultLabel,encryptRecovery,addVault,listVault,notifyVault:()=>notifyVault(),renderVault:()=>renderVault(),
 read:{bitcoin:(txid,vout)=>readJson('/bitcoin-testnet4/spend?'+new URLSearchParams({txid,vout:String(vout)}),'Bitcoin testnet service unavailable.'),
  ethereum:(contract,from)=>readJson('/sepolia/escrow-events?'+new URLSearchParams({contract,from_block:String(from)}),'Sepolia service unavailable.'),
  cardano:outref=>readJson('/cardano-preview/spend?'+new URLSearchParams({outref}),'Cardano preview service unavailable.')}});
const sepoliaReader={async request({method,params}){const response=await fetch('/sepolia/rpc',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({method,params})});const value=await response.json();if(!response.ok)throw Error(value.error||'Sepolia service unavailable.');return value.result;}};
initGuided({$,msg,showSection:id=>journey?.showSection(id),loadTiming:()=>loadTiming(),listVault,listActions,template:async()=>{const response=await fetch('/ether-escrow-template.json');if(!response.ok)throw Error('Escrow template unavailable.');return response.json();},
 readers:{bitcoin:{head:()=>readJson('/bitcoin-testnet4/head','Bitcoin testnet service unavailable.'),escrow:(txid,vout)=>readBitcoinTestnet(txid,vout),spend:(txid,vout)=>readJson('/bitcoin-testnet4/spend?'+new URLSearchParams({txid,vout:String(vout)}),'Bitcoin testnet service unavailable.')},
  cardano:{params:()=>cardanoRead.params(),escrow:outref=>readCardanoPreview(outref),spend:outref=>readJson('/cardano-preview/spend?'+new URLSearchParams({outref}),'Cardano preview service unavailable.')},
  ethereum:{provider:sepoliaReader,events:(contract,from)=>readJson('/sepolia/escrow-events?'+new URLSearchParams({contract,from_block:String(from)}),'Sepolia service unavailable.')}}});
async function readCardanoPreview(outref){const response=await fetch('/cardano-preview/escrow?'+new URLSearchParams({outref}));const value=await response.json();if(!response.ok)throw Error(value.error||'Cardano preview service unavailable.');return value;}
$('bitcoin-testnet-form').addEventListener('submit',async event=>{event.preventDefault();
 try{const data=new FormData(event.currentTarget),terms={};for(const name of ['txid','hashlock','claimant_key','refund_key'])terms[name]=String(data.get(name)||'').trim();
  for(const name of ['vout','amount_sats','refund_height'])terms[name]=Number(data.get(name));
  const result=await verifyBitcoinTestnetEscrow(terms,readBitcoinTestnet);msg($('bitcoin-testnet-status'),'Matched unspent Bitcoin testnet4 escrow with '+result.confirmations+' confirmations at height '+result.block_height+'. This checks only the Bitcoin leg and trusts the public service.');
 }catch(e){msg($('bitcoin-testnet-status'),e.message,true);}
});
$('cardano-preview-form').addEventListener('submit',async event=>{event.preventDefault();
 try{const data=new FormData(event.currentTarget),terms={};for(const name of ['outref','lovelace','assets','hashlock','claimant','refundee'])terms[name]=String(data.get(name)||'').trim();terms.expiry_ms=Number(data.get('expiry_ms'));
  const result=await verifyCardanoPreviewEscrow(terms,readCardanoPreview);msg($('cardano-preview-status'),'Matched unspent Cardano preview escrow with '+result.confirmations+' confirmations at slot '+result.slot+'. This checks only the Cardano leg and trusts the public service.');
 }catch(e){msg($('cardano-preview-status'),e.message,true);}
});
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
let activeCardanoApi=null;
$('connect-cardano').addEventListener('click',async()=>{
 try{const id=$('cardano-wallet').value,wallet=window.cardano?.[id];if(!wallet||typeof wallet.enable!=='function')throw Error('Select an available Cardano browser wallet.');
  activeCardanoApi=null;const api=await wallet.enable(),network=await api.getNetworkId();if(network!==0&&network!==1)throw Error('Wallet returned an invalid network.');
  if(network===0)activeCardanoApi=api;
  msg($('wallet-status'),'Cardano connected: '+String(wallet.name||id)+' · '+(network===1?'mainnet':'testnet')+'. No transaction has been requested.');
 }catch(e){msg($('wallet-status'),e.message,true);}
});
let companionToken=null,companionCapabilities=[],companionState='disconnected',companionCheckBusy=false,companionCheckAgain=false;
function companionIndicator(state,detail){
 companionState=state;$('companion-indicator').dataset.state=state;
 $('companion-indicator-label').textContent=state==='connected'?'Companion connected':state==='checking'?'Checking companion':'Companion not connected';
 $('companion-details-status').textContent=detail;
}
async function companion(path,token,body,timeout=0){
 const response=await fetch('http://127.0.0.1:8788'+path,{method:body?'POST':'GET',credentials:'omit',redirect:'error',...(timeout?{signal:AbortSignal.timeout(timeout)}:{}),headers:{authorization:'Bearer '+token,...(body?{'content-type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
 const result=await response.json();if(!response.ok)throw Error(result.error||'Companion request failed');return result;
}
async function refreshCompanion(){
 const token=companionToken;if(!token)return;if(companionCheckBusy){companionCheckAgain=true;return;}companionCheckBusy=true;
 try{const health=await companion('/health',token,undefined,5000);if(companionToken!==token)return;
  if(health.status!=='ok'||!Array.isArray(health.capabilities)||health.capabilities.join(',')!==companionCapabilities.join(','))throw Error('Companion capabilities changed.');
  companionIndicator('connected',document.documentElement.hasAttribute('data-hosted-testnet')?'Companion connected. Checking your Hegemon node…':'Local companion connected.');
  if(document.documentElement.hasAttribute('data-hosted-testnet')){
   try{const node=await companion('/hegemon/status',token,undefined,15000);if(companionToken!==token)return;
    if(node.network!=='v0.11 pre-mainnet'||typeof node.height!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(node.height)||typeof node.syncing!=='boolean'||!Number.isSafeInteger(node.peers)||node.peers<0||typeof node.wallet_rpc_ready!=='boolean')throw Error('Invalid node status.');
    const balanceMode=companionCapabilities.includes('hegemon-public-balance');
    companionIndicator('connected','Hegemon node · block '+node.height+' · '+(node.syncing?'syncing':'not syncing')+' · '+node.peers+' peers. '+(node.wallet_rpc_ready?'The expected wallet RPC is available.':'Wallet RPC compatibility is not confirmed.')+(balanceMode?' HGN offers can use the unlocked wallet on this computer. Creating a listing does not lock funds.':' This checks status only; Hegemon swaps are not ready here yet.'));
   }catch{if(companionToken===token)companionIndicator('connected','Companion connected, but the Hegemon node status is unavailable.');}
  }
 }catch{if(companionToken===token)companionIndicator('disconnected','The companion connection was lost. Check that it is running and reconnect.');}
 finally{companionCheckBusy=false;if(companionCheckAgain){companionCheckAgain=false;void refreshCompanion();}}
}
$('companion-indicator').addEventListener('click',()=>{if(companionState==='connected'){$('companion-details').showModal();void refreshCompanion();}else journey?.showNode();});
setInterval(()=>{if(!document.hidden)void refreshCompanion();},15000);
window.addEventListener('focus',()=>{if(companionToken){companionIndicator('checking','Checking the companion connection…');void refreshCompanion();}});
$('connect-companion').addEventListener('click',async()=>{
 const token=$('companion-token').value;$('companion-token').value='';companionToken=null;companionCapabilities=[];journey?.clearHegemonFunds();$('hegemon-actions').hidden=true;$('ethereum-actions').hidden=true;$('bitcoin-actions').hidden=true;$('cardano-actions').hidden=true;
 companionIndicator('checking','Checking the companion connection…');
 try{if(!/^[0-9a-f]{64}$/.test(token))throw Error('Enter the 64-character pairing token.');
  const result=await companion('/health',token);if(!Array.isArray(result.capabilities)||!result.capabilities.length)throw Error('No local verifiers are available.');
  if(document.documentElement.hasAttribute('data-hosted-testnet')){
   const names=result.capabilities;
   if(names.some(item=>item!=='hegemon-public-status'&&item!=='hegemon-public-balance')||!names.includes('hegemon-public-status')||new Set(names).size!==names.length)throw Error('Start the companion in hosted node status mode.');
   const node=await companion('/hegemon/status',token);
   if(node.network!=='v0.11 pre-mainnet'||typeof node.height!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(node.height)||typeof node.syncing!=='boolean'||!Number.isSafeInteger(node.peers)||node.peers<0||typeof node.wallet_rpc_ready!=='boolean')throw Error('The local node returned an invalid status.');
   companionToken=token;companionCapabilities=names;
   const balanceMode=names.includes('hegemon-public-balance');
   msg($('companion-status'),'Hegemon node connected · block '+node.height+' · '+(node.syncing?'syncing':'not syncing')+' · '+node.peers+' peers. '+(node.wallet_rpc_ready?'The expected wallet RPC is available.':'Wallet RPC compatibility is not confirmed.')+(balanceMode?' HGN offers can use the unlocked wallet on this computer. Creating a listing does not lock funds.':' This is a status check; Hegemon swaps are not ready here yet.'));
   companionIndicator('connected',$('companion-status').textContent);
   return;
  }
  companionToken=token;companionCapabilities=result.capabilities;$('hegemon-actions').hidden=!companionCapabilities.includes('hegemon-local-actions');$('ethereum-actions').hidden=!companionCapabilities.includes('ethereum-local-anchor');$('bitcoin-actions').hidden=!companionCapabilities.includes('bitcoin-regtest-actions');$('cardano-actions').hidden=!companionCapabilities.includes('cardano-local-actions');msg($('companion-status'),companionCapabilities.includes('hegemon-local-actions')?'Local companion connected with experimental Hegemon actions enabled.':companionCapabilities.includes('bitcoin-regtest-actions')?'Local companion connected with experimental Bitcoin actions enabled.':companionCapabilities.includes('cardano-local-actions')?'Local companion connected with experimental Cardano actions enabled.':companionCapabilities.includes('ethereum-local-anchor')?'Local companion connected with an Ethereum test-chain anchor.':'Local read-only companion connected.');companionIndicator('connected',$('companion-status').textContent);
 }catch(e){const hosted=document.documentElement.hasAttribute('data-hosted-testnet');
  const message=hosted&&e instanceof TypeError?'Cannot reach the local companion. Start it on this computer and allow local network access in your browser settings.':hosted&&e.message==='forbidden'?'Pairing code not accepted. Check the code in your local token file.':e.message;
  journey?.clearHegemonFunds();msg($('companion-status'),message,true);companionIndicator('disconnected',message);}
});
const ethereumActionForm=$('ethereum-action-form');let ethereumActionBusy=false;
function toggleEthereumActionFields(){const kind=ethereumActionForm.elements.kind.value,native=kind==='eth';for(const name of ['token','tokenId']){ethereumActionForm.elements[name].disabled=native;ethereumActionForm.elements[name].required=!native;}$('ethereum-token-steps').hidden=native;$('ethereum-revoke').hidden=kind!=='2';}
function setEthereumActionBusy(value){ethereumActionBusy=value;for(const button of ethereumActionForm.querySelectorAll('button'))button.disabled=value;}
function ethereumActionTerms(){const data=new FormData(ethereumActionForm),terms={};for(const name of ['kind','contract','token','tokenId','amount','hashlock','claimant','refundee','expiry'])terms[name]=String(data.get(name)||'').trim();return terms;}
ethereumActionForm.elements.kind.addEventListener('change',toggleEthereumActionFields);toggleEthereumActionFields();
ethereumActionForm.addEventListener('submit',async event=>{event.preventDefault();if(ethereumActionBusy)return;
 try{if(!activeEthereumProvider)throw Error('Connect an Ethereum wallet first.');if(!companionToken||!companionCapabilities.includes('ethereum-local-anchor'))throw Error('Connect a companion configured for local Anvil.');
  const provider=activeEthereumProvider,terms=ethereumActionTerms();
  setEthereumActionBusy(true);$('ethereum-action-result').textContent='';msg($('ethereum-action-status'),'Checking the local chain and requesting wallet approval.');
  const [anchor,response]=await Promise.all([companion('/ethereum/head',companionToken),fetch(terms.kind==='eth'?'/ether-escrow-template.json':'/token-escrow-template.json')]);
  if(!response.ok)throw Error('Escrow template unavailable.');const template=await response.json();
  const guarded={request:args=>{if(provider!==activeEthereumProvider)throw Error('Wallet changed. Reconnect and check wallet history before retrying.');return provider.request(args);}};
  const {result,warning}=await recordedAction('ethereum','deploy',terms,()=>submitLocalEscrowDeployment(guarded,template,terms,anchor));
  $('ethereum-action-result').textContent=JSON.stringify(result,null,2);
  msg($('ethereum-action-status'),warning||(terms.kind==='eth'?'Deployment submitted; check the receipt and confirmations.':'Deployment submitted, but the token escrow is not funded. Check the receipt and confirmations.'),!!warning);
 }catch(e){msg($('ethereum-action-status'),e.message,true);}finally{setEthereumActionBusy(false);}
});
async function ethereumTokenStep(step){if(ethereumActionBusy)return;
 try{if(!ethereumActionForm.reportValidity())return;if(!activeEthereumProvider)throw Error('Connect an Ethereum wallet first.');if(!companionToken||!companionCapabilities.includes('ethereum-local-anchor'))throw Error('Connect a companion configured for local Anvil.');
  const provider=activeEthereumProvider,terms=ethereumActionTerms();if(terms.kind==='eth')throw Error('Select a token.');
  setEthereumActionBusy(true);$('ethereum-action-result').textContent='';msg($('ethereum-action-status'),'Checking the local escrow and requesting wallet approval.');
  const [anchor,response]=await Promise.all([companion('/ethereum/head',companionToken),fetch('/token-escrow-template.json')]);
  if(!response.ok)throw Error('Escrow template unavailable.');const template=await response.json();
  const guarded={request:args=>{if(provider!==activeEthereumProvider)throw Error('Wallet changed. Reconnect and check wallet history before retrying.');return provider.request(args);}};
  const {result,warning}=await recordedAction('ethereum',step,terms,()=>submitLocalTokenFundingStep(guarded,template,terms,anchor,step));
  $('ethereum-action-result').textContent=JSON.stringify(result,null,2);
  msg($('ethereum-action-status'),warning||(step==='approve'?'Token approval submitted. Check its receipt before funding.':step==='revoke'?'Operator revocation submitted. Check its receipt.':'Funding submitted. Check its receipt and verify the funded escrow.'),!!warning);
 }catch(e){msg($('ethereum-action-status'),e.message,true);}finally{setEthereumActionBusy(false);}
}
$('ethereum-approve').addEventListener('click',()=>ethereumTokenStep('approve'));
$('ethereum-fund').addEventListener('click',()=>ethereumTokenStep('fund'));
$('ethereum-revoke').addEventListener('click',()=>ethereumTokenStep('revoke'));
$('ethereum-refund').addEventListener('click',async()=>{if(ethereumActionBusy)return;
 try{if(!ethereumActionForm.reportValidity())return;if(!activeEthereumProvider)throw Error('Connect an Ethereum wallet first.');if(!companionToken||!companionCapabilities.includes('ethereum-local-anchor'))throw Error('Connect a companion configured for local Anvil.');
  const provider=activeEthereumProvider,terms=ethereumActionTerms();setEthereumActionBusy(true);$('ethereum-action-result').textContent='';msg($('ethereum-action-status'),'Checking the expired local escrow and requesting wallet approval.');
  const [anchor,response]=await Promise.all([companion('/ethereum/head',companionToken),fetch(terms.kind==='eth'?'/ether-escrow-template.json':'/token-escrow-template.json')]);
  if(!response.ok)throw Error('Escrow template unavailable.');const template=await response.json();
  const guarded={request:args=>{if(provider!==activeEthereumProvider)throw Error('Wallet changed. Reconnect and check wallet history before retrying.');return provider.request(args);}};
  const {result,warning}=await recordedAction('ethereum','refund',terms,()=>submitLocalEscrowRefund(guarded,template,terms,anchor));$('ethereum-action-result').textContent=JSON.stringify(result,null,2);
  msg($('ethereum-action-status'),warning||'Refund submitted. Check its receipt and confirmations.',!!warning);
 }catch(e){msg($('ethereum-action-status'),e.message,true);}finally{setEthereumActionBusy(false);}
});
$('ethereum-claim').addEventListener('click',async()=>{if(ethereumActionBusy)return;const phrase=$('ethereum-claim-passphrase').value;$('ethereum-claim-passphrase').value='';let secret;
 try{if(!ethereumActionForm.reportValidity())return;if(!activeEthereumProvider)throw Error('Connect an Ethereum wallet first.');if(!companionToken||!companionCapabilities.includes('ethereum-local-anchor'))throw Error('Connect a companion configured for local Anvil.');
  const provider=activeEthereumProvider,terms=ethereumActionTerms(),selected=$('ethereum-claim-backup').value;
  if(!selected||!phrase)throw Error('Select an encrypted backup and enter its passphrase.');
  if(!window.confirm('This manual local claim does not verify the other swap leg. The wallet receives the preimage even if you reject its transaction request. Continue only after verifying the other leg and its deadlines.'))return;
  setEthereumActionBusy(true);$('ethereum-action-result').textContent='';msg($('ethereum-action-status'),'Unlocking the backup and checking the local escrow.');
  const entries=await listVault(),entry=entries.find(item=>item.envelope.hashlock===selected);if(!entry)throw Error('Encrypted backup not found.');
  const [anchor,response]=await Promise.all([companion('/ethereum/head',companionToken),fetch(terms.kind==='eth'?'/ether-escrow-template.json':'/token-escrow-template.json')]);
  if(!response.ok)throw Error('Escrow template unavailable.');const template=await response.json();secret=await unlockRecovery(entry.envelope,phrase);
  const guarded={request:args=>{if(provider!==activeEthereumProvider)throw Error('Wallet changed. Reconnect and check wallet history before retrying.');return provider.request(args);}};
  const {result,warning}=await recordedAction('ethereum','claim',terms,()=>submitLocalEscrowClaim(guarded,template,terms,anchor,secret));$('ethereum-action-result').textContent=JSON.stringify(result,null,2);
  msg($('ethereum-action-status'),warning||'Claim submitted. The preimage is public; check the receipt and confirmations.',!!warning);
 }catch(e){msg($('ethereum-action-status'),e.message,true);}finally{secret?.fill(0);setEthereumActionBusy(false);}
});
$('ethereum-observe').addEventListener('click',async()=>{if(ethereumActionBusy)return;const phrase=$('ethereum-observe-passphrase').value,repeat=$('ethereum-observe-confirm').value;$('ethereum-observe-passphrase').value='';$('ethereum-observe-confirm').value='';let secret;
 try{if(!ethereumActionForm.reportValidity())return;if(!activeEthereumProvider)throw Error('Connect an Ethereum wallet first.');if(!companionToken||!companionCapabilities.includes('ethereum-local-anchor'))throw Error('Connect a companion configured for local Anvil.');
  if(phrase!==repeat||phrase.length<12||phrase.length>1024)throw Error('Backup passphrases must match and contain at least 12 characters.');const label=vaultLabel($('ethereum-observe-label').value),provider=activeEthereumProvider,terms=ethereumActionTerms();
  setEthereumActionBusy(true);$('ethereum-action-result').textContent='';msg($('ethereum-action-status'),'Checking confirmed local claim events.');
  const [anchor,response]=await Promise.all([companion('/ethereum/head',companionToken),fetch(terms.kind==='eth'?'/ether-escrow-template.json':'/token-escrow-template.json')]);
  if(!response.ok)throw Error('Escrow template unavailable.');const template=await response.json();
  const guarded={request:args=>{if(provider!==activeEthereumProvider)throw Error('Wallet changed. Reconnect and retry.');return provider.request(args);}};
  const observed=await observeLocalEthereumClaim(guarded,template,terms,anchor,$('ethereum-observe-from').value.trim(),2);secret=observed.secret;
  const envelope=await encryptRecovery(secret,phrase);await addVault({label,envelope});notifyVault();$('vault-backup').value=JSON.stringify({label,envelope});await renderVault();
  $('ethereum-action-result').textContent=JSON.stringify(observed.snapshot,null,2);msg($('ethereum-action-status'),'Confirmed local claim observed. Encrypted secret backup saved; copy it from the backup section.');
 }catch(e){msg($('ethereum-action-status'),e.message,true);}finally{secret?.fill(0);setEthereumActionBusy(false);}
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
const bitcoinActionForm=$('bitcoin-action-form');
function updateBitcoinActionFields(){const spend=bitcoinActionForm.elements.operation.value!=='lock';for(const label of bitcoinActionForm.querySelectorAll('[data-spend]')){label.hidden=!spend;for(const input of label.querySelectorAll('input')){input.disabled=!spend;input.required=spend;}}}
bitcoinActionForm.elements.operation.addEventListener('change',updateBitcoinActionFields);updateBitcoinActionFields();
bitcoinActionForm.addEventListener('submit',async event=>{event.preventDefault();const button=event.currentTarget.querySelector('button[type="submit"]');
 try{if(!companionToken||!companionCapabilities.includes('bitcoin-regtest-actions'))throw Error('Connect a companion with experimental Bitcoin actions enabled.');
  const data=new FormData(event.currentTarget),request={};for(const [key,value] of data.entries())request[key]=String(value).trim();
  button.disabled=true;$('bitcoin-action-result').textContent='';msg($('bitcoin-action-status'),'Review and approve this request in the companion terminal.');
  const {result,warning}=await recordedAction('bitcoin',request.operation,request,async()=>{const response=await companion('/bitcoin/action',companionToken,request);if(response.completed!==true)throw Error('Action outcome uncertain. Check wallet history before retrying.');return response.result;});
  $('bitcoin-action-result').textContent=JSON.stringify(result,null,2);msg($('bitcoin-action-status'),warning||'Bitcoin transaction submitted. Check its receipt and confirmations.',!!warning);
 }catch(e){msg($('bitcoin-action-status'),e.message,true);}finally{button.disabled=false;}
});
function cardanoValue(data){const value={lovelace:String(data.get('lovelace')).trim()};
  for(const line of String(data.get('assets')).split(/\r?\n/).map(x=>x.trim()).filter(Boolean)){
   const match=line.match(/^([0-9a-f]{56})\.((?:[0-9a-f]{2}){0,32})=([1-9][0-9]{0,18})$/);
   if(!match||BigInt(match[3])>=1n<<63n)throw Error('Invalid Cardano asset line.');
   const [,policy,name,quantity]=match;value[policy]??={};
   if(Object.hasOwn(value[policy],name))throw Error('Duplicate Cardano asset.');
   value[policy][name]=quantity;
  }
  return value;
}
$('cardano-form').addEventListener('submit',async event=>{event.preventDefault();
 try{if(!companionToken||!companionCapabilities.includes('cardano-local-verify'))throw Error('Connect a companion configured for Cardano.');
  const data=new FormData(event.currentTarget),terms={};
  for(const name of ['outref','hashlock','claimant','refundee','expiry_ms','genesis_sha256'])terms[name]=String(data.get(name)).trim();
  terms.expected_value=cardanoValue(data);
  const result=await companion('/cardano/verify',companionToken,terms);
  if(!result.verified||result.snapshot.confirmations!==null)throw Error('Cardano snapshot not verified.');
  msg($('cardano-status'),'Verified at local tip block '+result.snapshot.tip_block+'. Confirmation depth is unknown.');
 }catch(e){msg($('cardano-status'),e.message,true);}
});
const cardanoActionForm=$('cardano-action-form');
function updateCardanoActionFields(){const lock=cardanoActionForm.elements.operation.value==='lock';for(const label of cardanoActionForm.querySelectorAll('[data-cardano-lock],[data-cardano-spend]')){const visible=label.hasAttribute('data-cardano-lock')?lock:!lock;label.hidden=!visible;for(const input of label.querySelectorAll('input')){input.disabled=!visible;input.required=visible;}}}
cardanoActionForm.elements.operation.addEventListener('change',updateCardanoActionFields);updateCardanoActionFields();
cardanoActionForm.addEventListener('submit',async event=>{event.preventDefault();const button=event.currentTarget.querySelector('button[type="submit"]');
 try{if(!companionToken||!companionCapabilities.includes('cardano-local-actions'))throw Error('Connect a companion with experimental Cardano actions enabled.');
  const data=new FormData(event.currentTarget),operation=String(data.get('operation')),request={operation,expected_value:cardanoValue(data)};
  for(const name of ['hashlock','claimant','refundee','expiry_ms'])request[name]=String(data.get(name)).trim();
  if(operation==='lock')request.inputs=String(data.get('inputs')).split(',').map(x=>x.trim());
  else for(const name of ['outref','fee_input','collateral'])request[name]=String(data.get(name)).trim();
  button.disabled=true;$('cardano-action-result').textContent='';msg($('cardano-action-status'),'Review and approve this request in the companion terminal.');
  const {result,warning}=await recordedAction('cardano',operation,request,async()=>{const response=await companion('/cardano/action',companionToken,request);if(response.completed!==true)throw Error('Action outcome uncertain. Check the transaction before retrying.');return response.result;});
  $('cardano-action-result').textContent=JSON.stringify(result,null,2);msg($('cardano-action-status'),warning||'Cardano transaction submitted. Check its inclusion and confirmations.',!!warning);
 }catch(e){msg($('cardano-action-status'),e.message,true);}finally{button.disabled=false;}
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
  const invoke=async()=>{const response=await companion('/hegemon/action',companionToken,request);if(response.completed!==true)throw Error('The local action did not complete. Check wallet status before retrying.');return response.result;};
  if(operation==='status'){const result=await invoke();$('hegemon-action-result').textContent=JSON.stringify(result,null,2);msg($('hegemon-action-status'),'Local action completed. Review the result before submitting anything.');}
  else {const {result,warning}=await recordedAction('hegemon',operation,request,invoke);$('hegemon-action-result').textContent=JSON.stringify(result,null,2);msg($('hegemon-action-status'),warning||'Local action completed. Review the result before submitting anything.',!!warning);}
 }catch(e){msg($('hegemon-action-status'),e.message,true);}finally{button.disabled=false;}
});
let pairContext=null,pairLegs={give:null,receive:null},pairBusy=false,publicPairLegs={give:null,receive:null},publicPairBusy=false;
function credential(id){return localStorage.getItem('offer-owner:'+id);}
function currentOffer(){return location.hash.slice(1).split('.')[0];}
function messageKey(id){return localStorage.getItem('offer-message-key:'+id);}
function sessionId(id){return localStorage.getItem('offer-session:'+id);}
function checkOwnerInbox(id,offer){const known=localStorage.getItem('offer-inbox:'+id);if(credential(id)&&known&&known!==offer.ownerPublicKey)throw Error('Offer inbox key changed. Verify the offer independently.');}
function participantToken(id){return credential(id)||localStorage.getItem('offer-reservation:'+id);}
const identityUi=initIdentity({$,msg,api,getEthereum:()=>activeEthereumProvider,getCardano:()=>activeCardanoApi,credential,participantToken,messageKey,reservationToken:id=>localStorage.getItem('offer-reservation:'+id),currentOffer});
function selectOffer(id){location.hash=id;return loadSelected();}
let chatRenderVersion=0,selectionVersion=0;
function updateChat(id){$('chat').hidden=!participantToken(id);$('chat-form').querySelector('button').disabled=true;$('chat-form').elements.message.disabled=true;if(!$('chat').hidden)refreshChat();else chatRenderVersion++;}
async function refreshChat(){const version=++chatRenderVersion,id=currentOffer(),token=participantToken(id);if(!token)return;
 try{const offer=await api('/offers/'+id),{messages}=await api('/offers/'+id+'/messages',{headers:{authorization:'Bearer '+token}});if(version!==chatRenderVersion||id!==currentOffer())return;checkOwnerInbox(id,offer);
  const identity=await identityUi.render(id,offer,messages);if(version!==chatRenderVersion||id!==currentOffer())return;
  let key=messageKey(id),bound=sessionId(id);const reservation=offer.reservationId;
  const handshake=offer.ownerPublicKey&&reservation?messages.find(item=>item.sender==='taker'&&parsePublicSession(item.ciphertext)?.reservation===reservation):null;
  if(credential(id)&&offer.ownerPublicKey&&reservation&&bound!==reservation){
   if(handshake&&!identity.blocked){const privateKey=await inboxPrivateKey(offer.ownerPublicKey);key=await openPublicSession(privateKey,offer.ownerPublicKey,id,reservation,handshake.ciphertext);localStorage.setItem('offer-message-key:'+id,key);localStorage.setItem('offer-session:'+id,reservation);bound=reservation;}
  }
  const ownerFingerprint=offer.ownerPublicKey?await inboxFingerprint(offer.ownerPublicKey):'',sessionFingerprint=handshake?await inboxFingerprint(parsePublicSession(handshake.ciphertext).ephemeral):'';
  if(version!==chatRenderVersion||id!==currentOffer())return;
  $('chat-fingerprints').textContent=ownerFingerprint?'Owner inbox SHA-256: '+ownerFingerprint+(sessionFingerprint?' · Reservation key SHA-256: '+sessionFingerprint:''):'This older offer has no public inbox fingerprint.';
  const ready=!identity.blocked&&!!key&&(!offer.ownerPublicKey||(!!reservation&&bound===reservation)),readable=ready||!!(key&&offer.ownerPublicKey&&!reservation&&bound);$('chat-form').querySelector('button').disabled=!ready;$('chat-form').elements.message.disabled=!ready;$('chat-list').replaceChildren();
  for(const item of messages){if(parsePublicSession(item.ciphertext))continue;const p=document.createElement('p');try{if(!readable)throw Error();p.textContent=item.sender+': '+await decryptMessage(key,id,item.ciphertext);}catch{p.textContent=item.sender+': [unable to decrypt message]';}if(version!==chatRenderVersion||id!==currentOffer())return;$('chat-list').append(p);}
  $('retry-handshake').hidden=!localStorage.getItem('offer-handshake:'+id);
  msg($('chat-status'),identity.blocked?'Blocked: the other participant\'s signed identity failed verification. See Signed identity above.':ready?(messages.length?'':'No messages yet.'):readable?'Reservation expired; retained messages remain available.':'Waiting for a reserved participant to establish the encrypted conversation.');
 }catch(e){if(version===chatRenderVersion&&id===currentOffer()){$('chat-form').querySelector('button').disabled=true;$('chat-form').elements.message.disabled=true;msg($('chat-status'),e.message,true);}}}
async function loadSelected(){
 const version=++selectionVersion,[id,key]=location.hash.slice(1).split('.');if(!/^[0-9a-f]{64}$/.test(id)){$('selected').hidden=true;$('chat').hidden=true;$('public-pair').hidden=true;$('identity').hidden=true;return;}
 if(key&&/^[0-9a-f]{64}$/.test(key))localStorage.setItem('offer-message-key:'+id,key);
 try{const offer=await api('/offers/'+id);if(version!==selectionVersion||currentOffer()!==id)return;checkOwnerInbox(id,offer);$('selected').hidden=false;$('details').replaceChildren();
  if(pairContext?.id!==id){pairContext={id,give:structuredClone(offer.give),receive:structuredClone(offer.receive)};pairLegs={give:null,receive:null};publicPairLegs={give:null,receive:null};$('public-pair-result').textContent='';msg($('public-pair-status'),'Capture both escrow terms from the checks above.');$('pair-result').textContent='';msg($('pair-status'),'Capture both escrow terms from the verification forms.');}
  $('public-pair').hidden=!document.documentElement.hasAttribute('data-hosted-testnet');
  for(const line of ['Maker gives: '+describe(offer.give),'Maker wants: '+describe(offer.receive),'Expires: '+new Date(offer.expires*1000).toLocaleString(),offer.closed?'Closed':'Open']){const p=document.createElement('p');p.textContent=line;$('details').append(p);}
  $('reserve').disabled=offer.closed||offer.expires*1000<=Date.now();$('close').hidden=!credential(id)||offer.closed;msg($('detail-status'),'');updateChat(id);
  const owner=!!credential(id),reserved=!!localStorage.getItem('offer-reservation:'+id)&&!!offer.reservationId;
  document.dispatchEvent(new CustomEvent('journey:offer-selected',{detail:{id,owner,reserved,participant:owner||reserved,available:true}}));
  if(!participantToken(id))identityUi.render(id,offer,[]).catch(e=>msg($('identity-status'),e.message,true));
 }catch(e){if(version!==selectionVersion||currentOffer()!==id)return;chatRenderVersion++;pairContext=null;pairLegs={give:null,receive:null};publicPairLegs={give:null,receive:null};$('public-pair').hidden=true;$('identity').hidden=true;$('pair-result').textContent='';$('selected').hidden=false;msg($('details'),e.message,true);$('reserve').disabled=true;$('close').hidden=true;$('chat').hidden=true;document.dispatchEvent(new CustomEvent('journey:offer-selected',{detail:{id,owner:false,reserved:false,participant:false,available:false}}));}
}
function capturedPairTerms(chain){
 const form={ethereum:$('verify-form'),bitcoin:$('bitcoin-form'),cardano:$('cardano-form'),hegemon:$('hegemon-form')}[chain];
 if(!form||!form.reportValidity())throw Error('Complete the '+chain+' verification form first.');const data=new FormData(form),terms={};
 const fields={ethereum:['contract','kind','token','tokenId','amount','hashlock','claimant','refundee','expiry'],bitcoin:['txid','vout','amount_sats','genesis_hash','hashlock','claimant_key','refund_key','refund_height'],cardano:['outref','hashlock','claimant','refundee','expiry_ms','genesis_sha256'],hegemon:['locked','claim','refund','hashlock','timeout','amount','min_confirmations','min_remaining_blocks']}[chain];
 for(const name of fields)terms[name]=String(data.get(name)||'').trim();if(chain==='cardano')terms.expected_value=cardanoValue(data);return terms;
}
for(const side of ['give','receive'])$('pair-capture-'+side).addEventListener('click',()=>{try{if(pairBusy||!pairContext||currentOffer()!==pairContext.id)throw Error('Select an offer first.');const chain=pairContext[side].chain;pairLegs[side]={chain,terms:capturedPairTerms(chain)};$('pair-result').textContent='';msg($('pair-status'),'Captured '+side+'-side '+chain+' terms. Capture the other side, then check both.');}catch(e){msg($('pair-status'),e.message,true);}});
async function checkPairLeg(leg){
 const t=leg.terms;if(!companionToken)throw Error('Connect the configured local companion.');
 if(leg.chain==='ethereum'){
  if(!activeEthereumProvider||!companionCapabilities.includes('ethereum-local-anchor'))throw Error('Connect an Ethereum wallet and a companion configured for local Anvil.');
  const provider=activeEthereumProvider,anchor=await companion('/ethereum/head',companionToken),response=await fetch(t.kind==='eth'?'/ether-escrow-template.json':'/token-escrow-template.json');if(!response.ok)throw Error('Escrow template unavailable.');
  const template=await response.json(),terms={...t,chainId:'0x7a69'};const snapshot=await (t.kind==='eth'?verifyEtherEscrow(provider,template,terms,2):verifyTokenEscrow(provider,template,terms,2));
  const [genesis,head]=await Promise.all([provider.request({method:'eth_getBlockByNumber',params:['0x0',false]}),provider.request({method:'eth_getBlockByNumber',params:['latest',false]})]);
  if(provider!==activeEthereumProvider||String(genesis?.hash).toLowerCase()!=='0x'+anchor.genesis||String(head?.hash).toLowerCase()!==anchor.tip_hash||BigInt(head.timestamp)!==BigInt(anchor.time_seconds))throw Error('Ethereum wallet and local node do not agree.');
  return {chain:leg.chain,genesis:anchor.genesis,remaining:(BigInt(t.expiry)-BigInt(anchor.time_seconds)).toString(),unit:'seconds',snapshot};
 }
 if(leg.chain==='bitcoin'){
  if(!companionCapabilities.includes('bitcoin-regtest-verify'))throw Error('Connect a companion configured for Bitcoin.');const request={...t};
  for(const name of ['vout','amount_sats','refund_height']){request[name]=Number(t[name]);if(!Number.isSafeInteger(request[name]))throw Error('Invalid Bitcoin amount or height.');}
  const result=await companion('/bitcoin/verify',companionToken,request),head=await companion('/bitcoin/head',companionToken);if(result.verified!==true||head.genesis!==t.genesis_hash||head.tip_hash!==result.snapshot?.block_hash)throw Error('Bitcoin snapshot changed; check again.');
  return {chain:leg.chain,genesis:head.genesis,remaining:(BigInt(t.refund_height)-BigInt(head.height)).toString(),unit:'blocks',snapshot:result.snapshot};
 }
 if(leg.chain==='cardano'){
  if(!companionCapabilities.includes('cardano-local-verify'))throw Error('Connect a companion configured for Cardano.');
  const result=await companion('/cardano/verify',companionToken,t),head=await companion('/cardano/head',companionToken);if(result.verified!==true||result.snapshot?.confirmations!==null||head.genesis!==t.genesis_sha256)throw Error('Cardano snapshot unavailable.');
  return {chain:leg.chain,genesis:head.genesis,remaining:(BigInt(t.expiry_ms)-BigInt(head.time_ms)).toString(),unit:'milliseconds',snapshot:result.snapshot};
 }
 if(leg.chain==='hegemon'){
  if(!companionCapabilities.includes('hegemon-local-verify'))throw Error('Connect a companion configured for the Hegemon wallet.');msg($('pair-status'),'Approve the Hegemon wallet read in the local companion terminal.');
  const result=await companion('/hegemon/verify',companionToken,t),head=await companion('/hegemon/head',companionToken);if(result.verified!==true||result.snapshot?.verified!==true)throw Error('Hegemon note was not verified.');
  return {chain:leg.chain,genesis:head.genesis,remaining:(BigInt(t.timeout)-BigInt(head.height)).toString(),unit:'blocks',snapshot:result.snapshot};
 }
 throw Error('Unsupported chain.');
}
$('pair-verify').addEventListener('click',async()=>{if(pairBusy)return;pairBusy=true;for(const button of document.querySelectorAll('#pair-check button'))button.disabled=true;
 try{if(!pairContext||!pairLegs.give||!pairLegs.receive||currentOffer()!==pairContext.id)throw Error('Capture both escrow terms for the selected offer.');
  const context=structuredClone(pairContext),legs=structuredClone(pairLegs),before=await api('/offers/'+context.id);checkOwnerInbox(context.id,before);
  if(JSON.stringify(before.give)!==JSON.stringify(context.give)||JSON.stringify(before.receive)!==JSON.stringify(context.receive))throw Error('Offer terms changed. Select it again.');
  const comparison=comparePair(context,legs.give,legs.receive);msg($('pair-status'),'Checking the two local escrow snapshots.');
  const give=await checkPairLeg(legs.give),receive=await checkPairLeg(legs.receive),after=await api('/offers/'+context.id);checkOwnerInbox(context.id,after);
  if(currentOffer()!==context.id||JSON.stringify(after.give)!==JSON.stringify(context.give)||JSON.stringify(after.receive)!==JSON.stringify(context.receive))throw Error('Offer changed during verification.');
  if(give.chain===receive.chain&&give.genesis!==receive.genesis)throw Error('Same-chain legs have different network identities.');
  if(BigInt(give.remaining)<=0n||BigInt(receive.remaining)<=0n)throw Error('An escrow deadline has passed.');
  $('pair-result').textContent=JSON.stringify({hashlock:comparison.hashlock,give,receive},null,2);
  msg($('pair-status'),'Both escrow terms match the offer at separate local snapshots. This does not establish safe cross-chain timing or finality; Cardano confirmation depth may be unknown.');
 }catch(e){$('pair-result').textContent='';msg($('pair-status'),e.message,true);}finally{pairBusy=false;for(const button of document.querySelectorAll('#pair-check button'))button.disabled=false;}
});
function capturePublicTerms(chain){
 const forms={ethereum:$('sepolia-form'),bitcoin:$('bitcoin-testnet-form'),cardano:$('cardano-preview-form')};
 const fields={ethereum:['contract','kind','token','tokenId','amount','hashlock','claimant','refundee','expiry'],bitcoin:['txid','vout','amount_sats','hashlock','claimant_key','refund_key','refund_height'],cardano:['outref','lovelace','assets','hashlock','claimant','refundee','expiry_ms']};
 const form=forms[chain];if(!form)throw Error('Hegemon public-testnet verification is not available yet.');if(!form.reportValidity())throw Error('Complete the '+chain+' testnet check above first.');
 const data=new FormData(form),terms={};for(const field of fields[chain])terms[field]=String(data.get(field)||'').trim();
 if(chain==='cardano')terms.expected_value=cardanoOfferValue(terms.lovelace,terms.assets);return terms;
}
for(const side of ['give','receive'])$('public-pair-capture-'+side).addEventListener('click',()=>{try{
 if(publicPairBusy||!pairContext||currentOffer()!==pairContext.id)throw Error('Select an offer first.');const chain=pairContext[side].chain;
 publicPairLegs[side]={chain,terms:capturePublicTerms(chain)};$('public-pair-result').textContent='';msg($('public-pair-status'),'Captured owner-'+side+' '+chain+' terms. Capture the other side, then check both.');
 }catch(e){msg($('public-pair-status'),e.message,true);}});
let publicTimingConfig=null;
async function loadTiming(){
 if(publicTimingConfig)return publicTimingConfig;const response=await fetch('/chain-timing.json');if(!response.ok)throw Error('Timing policy unavailable.');
 publicTimingConfig=validateTiming(await response.json());return publicTimingConfig;
}
function formatSeconds(value){
 if(!Number.isFinite(value))return 'unknown';const sign=value<0?'-':'',total=Math.abs(Math.round(value)),d=Math.floor(total/86400),h=Math.floor(total%86400/3600),m=Math.floor(total%3600/60);
 return sign+(d?d+'d ':'')+(d||h?h+'h ':'')+m+'m';
}
function renderTiming(element,verdict,config){
 element.replaceChildren();element.hidden=false;element.className='timing '+(verdict.ok?'ok':'fail');
 const title=document.createElement('h3');title.textContent=verdict.ok?'Timing check passed':'Timing check failed';element.append(title);
 const m=verdict.metrics||{};
 if(Number.isFinite(m.gapSeconds)){
  const list=document.createElement('dl');
  for(const [label,value] of [['Later-expiring leg',verdict.long==='give'?'owner gives':'owner receives'],['Time between the other leg\u2019s last safe claim and this leg\u2019s earliest refund',formatSeconds(m.gapSeconds)+' (needs '+formatSeconds(m.gapRequiredSeconds)+')'],['Time to claim the earlier-expiring leg',formatSeconds(m.shortClaimWindowSeconds)+' (needs '+formatSeconds(m.shortClaimRequiredSeconds)+')'],['Longest funds could stay locked',formatSeconds(Math.max(m.longLockUpperSeconds,m.shortLockUpperSeconds))]]){
   const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;list.append(dt,dd);
  }
  element.append(list);
 }
 if(verdict.reasons.length){const ul=document.createElement('ul');for(const reason of verdict.reasons){const li=document.createElement('li');li.textContent=reason.message;ul.append(li);}element.append(ul);}
 const note=document.createElement('p');
 note.textContent='Testnet policy from measured block times. It assumes no Bitcoin or Hegemon stall longer than '+formatSeconds(Math.max(config.chains.bitcoin.outageAllowanceSeconds,config.chains.hegemon.outageAllowanceSeconds))+' and honest clocks. It is not a guarantee for real funds.';
 element.append(note);
}
async function checkPublicLeg(leg){
 const t=leg.terms,limits=publicTimingConfig?legRequirements(publicTimingConfig,leg.chain):{};
 if(leg.chain==='ethereum'){
  if(!activeEthereumProvider)throw Error('Connect an Ethereum wallet first.');const provider=activeEthereumProvider,response=await fetch(t.kind==='eth'?'/ether-escrow-template.json':'/token-escrow-template.json');if(!response.ok)throw Error('Escrow template unavailable.');
  const snapshot=await verifySepoliaEscrow(provider,await response.json(),t,limits);if(provider!==activeEthereumProvider)throw Error('Ethereum wallet changed during verification.');return {chain:'ethereum',snapshot};
 }
 if(leg.chain==='bitcoin')return {chain:'bitcoin',snapshot:await verifyBitcoinTestnetEscrow({...t,vout:Number(t.vout),amount_sats:Number(t.amount_sats),refund_height:Number(t.refund_height)},readBitcoinTestnet,limits)};
 if(leg.chain==='cardano')return {chain:'cardano',snapshot:await verifyCardanoPreviewEscrow({...t,expiry_ms:Number(t.expiry_ms)},readCardanoPreview,limits)};
 throw Error('Hegemon public-testnet verification is not available yet.');
}
$('public-pair-verify').addEventListener('click',async()=>{if(publicPairBusy)return;publicPairBusy=true;for(const button of document.querySelectorAll('#public-pair button'))button.disabled=true;
 try{if(!pairContext||!publicPairLegs.give||!publicPairLegs.receive||currentOffer()!==pairContext.id)throw Error('Capture both escrow terms for the selected offer.');
  const context=structuredClone(pairContext),legs=structuredClone(publicPairLegs),before=await api('/offers/'+context.id);checkOwnerInbox(context.id,before);
  if(JSON.stringify(before.give)!==JSON.stringify(context.give)||JSON.stringify(before.receive)!==JSON.stringify(context.receive))throw Error('Offer terms changed. Select it again.');
  const {identities}=await identityUi.requireIdentities(context.id);const timingConfig=await loadTiming();$('public-pair-timing').hidden=true;msg($('public-pair-status'),'Checking both public-testnet escrow snapshots against the signed identities.');const result=await checkPublicPair(context,legs.give,legs.receive,checkPublicLeg,{config:timingConfig,now:Math.floor(Date.now()/1000)},identities);
  const after=await api('/offers/'+context.id);checkOwnerInbox(context.id,after);if(currentOffer()!==context.id||JSON.stringify(after.give)!==JSON.stringify(context.give)||JSON.stringify(after.receive)!==JSON.stringify(context.receive))throw Error('Offer changed during verification.');
  $('public-pair-result').textContent=JSON.stringify(result,null,2);renderTiming($('public-pair-timing'),result.timing,timingConfig);msg($('public-pair-status'),'Both escrow terms match the offer and the signed identities at separate snapshots and the deadlines pass the testnet timing policy. Identities marked asserted were not signed with that chain key; verify them and recovery independently.');
 }catch(e){if(e.verdict){$('public-pair-result').textContent=JSON.stringify(e.result,null,2);renderTiming($('public-pair-timing'),e.verdict,publicTimingConfig);}else $('public-pair-result').textContent='';msg($('public-pair-status'),e.message,true);}finally{publicPairBusy=false;for(const button of document.querySelectorAll('#public-pair button'))button.disabled=false;}
});
async function refresh(){try{const {offers}=await api('/offers');$('board').replaceChildren();if(!offers.length){$('board').textContent='No public offers right now.';return;}
 for(const offer of offers){const row=document.createElement('div');row.className='offer';const text=document.createElement('p');text.textContent=describe(offer.give)+' → '+describe(offer.receive);const button=document.createElement('button');button.type='button';button.textContent='View offer';button.addEventListener('click',()=>selectOffer(offer.id));row.append(text,button);$('board').append(row);}}
 catch(e){msg($('board'),e.message,true);}}
function explainHegemonCompanion(error){
 if(error.message==='wallet_locked')return Error('Unlock the Hegemon wallet in the companion terminal.');
 if(error.message==='hegemon_node_not_ready')return Error('The Hegemon node is still syncing or is not on the public tip. HGN offers stay closed until it is ready.');
 return error;
}
async function hostedHegemonBalance(path,body){
 if(!companionToken||!companionCapabilities.includes('hegemon-public-balance'))throw Error('Connect the local companion started with --hosted-wallet-status before offering HGN.');
 try{const result=await companion(path,companionToken,body,1800000);return path==='/hegemon/unlock'?result.balance:result;}
 catch(error){throw explainHegemonCompanion(error);}
}
let offerSubmitting=false;
$('offer-form').addEventListener('submit',async event=>{event.preventDefault();if(offerSubmitting)return;offerSubmitting=true;const form=event.currentTarget,button=form.querySelector('button[type="submit"]'),data=new FormData(form);button.disabled=true;
 const read=side=>{const [chain,kind]=String(data.get(side+'-type')).split(':');return {chain,kind,id:String(data.get(side+'-id')).trim(),amount:String(data.get(side+'-amount')).trim()};};
 try{const give=read('give');if(document.documentElement.hasAttribute('data-hosted-testnet')&&give.chain==='hegemon'&&give.kind==='hgn')assertHegemonGiveSnapshot(give.amount,await hostedHegemonBalance('/hegemon/balance'));
  const passphrase=String(data.get('backup-passphrase')||''),created=passphrase?await createInboxWithBackup(passphrase):{publicKey:await createInbox(),backup:null},ownerPublicKey=created.publicKey;$('inbox-backup').hidden=!created.backup;$('inbox-backup-text').value=created.backup?JSON.stringify(created.backup):'';const result=await api('/offers',{method:'POST',body:JSON.stringify({give:read('give'),receive:read('receive'),visibility:data.get('visibility'),expires:Math.floor(Date.now()/1000)+Number(data.get('lifetime')),ownerPublicKey})});
  localStorage.setItem('offer-owner:'+result.id,result.ownerToken);localStorage.setItem('offer-inbox:'+result.id,ownerPublicKey);const key=newMessageKey();localStorage.setItem('offer-message-key:'+result.id,key);await refresh();await selectOffer(result.id);$('share-link').value=location.origin+'/#'+result.id+'.'+key;$('share').hidden=false;msg($('create-result'),'Offer created.');form.dispatchEvent(new CustomEvent('journey:created'));
 }catch(e){msg($('create-result'),e.message,true);form.dispatchEvent(new CustomEvent('journey:failed',{detail:{message:e.message}}));}finally{offerSubmitting=false;button.disabled=false;}});
$('copy-link').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('share-link').value);msg($('create-result'),'Link copied.');}catch{msg($('create-result'),'Select and copy the link above.');}});
$('refresh').addEventListener('click',refresh);
async function sendPendingHandshake(id){const raw=localStorage.getItem('offer-handshake:'+id);if(!raw)throw Error('No pending conversation setup.');const item=JSON.parse(raw),token=localStorage.getItem('offer-reservation:'+id),offer=await api('/offers/'+id);
 if(!token||!item||item.reservation!==offer.reservationId||item.ownerPublicKey!==offer.ownerPublicKey)throw Error('Reservation or inbox key changed; this conversation setup is no longer valid.');
 if(!item.ciphertext){item.ciphertext=await sealPublicSession(item.ownerPublicKey,id,item.reservation,messageKey(id));localStorage.setItem('offer-handshake:'+id,JSON.stringify(item));}
 if(!parsePublicSession(item.ciphertext))throw Error('Invalid pending conversation setup.');
 await api('/offers/'+id+'/messages',{method:'POST',headers:{authorization:'Bearer '+token},body:JSON.stringify({ciphertext:item.ciphertext,reservationId:item.reservation})});
 localStorage.setItem('offer-session:'+id,item.reservation);localStorage.removeItem('offer-handshake:'+id);await refreshChat();}
$('reserve').addEventListener('click',async()=>{const id=currentOffer();try{const offer=await api('/offers/'+id),identityNote=await identityUi.checkOwnerBeforeReserve(id,offer),result=await api('/offers/'+id+'/reserve',{method:'POST'});localStorage.setItem('offer-reservation:'+id,result.reservationToken);msg($('detail-status'),'Reserved until '+new Date(result.expires*1000).toLocaleString()+'. No funds have been locked. '+identityNote);$('reserve').disabled=true;document.dispatchEvent(new CustomEvent('journey:reserved',{detail:{id}}));
  if(offer.ownerPublicKey){const fragment=location.hash.slice(1).split('.')[1],key=/^[0-9a-f]{64}$/.test(fragment||'')?fragment:newMessageKey();localStorage.setItem('offer-message-key:'+id,key);localStorage.removeItem('offer-session:'+id);
   localStorage.setItem('offer-handshake:'+id,JSON.stringify({reservation:result.reservationId,ownerPublicKey:offer.ownerPublicKey,ciphertext:null}));updateChat(id);
   try{await sendPendingHandshake(id);}catch{await refreshChat();msg($('chat-status'),'Conversation setup was not confirmed. Use retry; the reservation remains active.',true);$('retry-handshake').hidden=false;}
  }else updateChat(id);
 }catch(e){msg($('detail-status'),e.message,true);}});
$('retry-handshake').addEventListener('click',async()=>{try{await sendPendingHandshake(currentOffer());}catch(e){msg($('chat-status'),e.message,true);}});
$('close').addEventListener('click',async()=>{const id=currentOffer();try{await api('/offers/'+id+'/close',{method:'POST',headers:{authorization:'Bearer '+credential(id)}});await loadSelected();await refresh();msg($('detail-status'),'Offer closed.');}catch(e){msg($('detail-status'),e.message,true);}});
$('chat-refresh').addEventListener('click',refreshChat);
$('chat-form').addEventListener('submit',async event=>{event.preventDefault();const id=currentOffer(),key=messageKey(id),token=participantToken(id),field=event.currentTarget.elements.message;
 try{const offer=await api('/offers/'+id);checkOwnerInbox(id,offer);if(id!==currentOffer()||token!==participantToken(id)||key!==messageKey(id)||!key||offer.ownerPublicKey&&(!offer.reservationId||sessionId(id)!==offer.reservationId))throw Error('Conversation session changed. Refresh messages before sending.');
  const ciphertext=await encryptMessage(key,id,field.value);await api('/offers/'+id+'/messages',{method:'POST',headers:{authorization:'Bearer '+token},body:JSON.stringify({ciphertext,...(offer.ownerPublicKey?{reservationId:offer.reservationId}:{})})});field.value='';await refreshChat();}catch(e){msg($('chat-status'),e.message,true);}});
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
let actionRenderVersion=0;
async function renderActionJournal(){const version=++actionRenderVersion;try{const entries=await listActions();if(version!==actionRenderVersion)return;$('action-journal-list').replaceChildren();
 if(!entries.length){$('action-journal-list').textContent='No saved actions.';return;}
 for(const item of entries){const row=document.createElement('div');row.className='offer';const text=document.createElement('p');text.textContent=item.chain+' · '+item.operation+' · '+item.state+(item.receipt?.txid?' · '+item.receipt.txid:item.receipt?.attempt?' · '+item.receipt.attempt:'');
  const show=document.createElement('button');show.type='button';show.textContent='Show record';show.addEventListener('click',()=>{$('action-journal-text').value=JSON.stringify({version:1,records:[item]});msg($('action-journal-status'),'Public action record ready to copy.');});
  const remove=document.createElement('button');remove.type='button';remove.textContent='Delete record';remove.addEventListener('click',async()=>{if(!window.confirm('Delete this local record? Export it first and check the action outcome.'))return;try{await removeAction(item.id);refreshActionViews();msg($('action-journal-status'),'Local action record deleted.');}catch(e){msg($('action-journal-status'),e.message,true);}});
  row.append(text,show,remove);$('action-journal-list').append(row);
 }
 }catch(e){if(version===actionRenderVersion){$('action-journal-list').replaceChildren();msg($('action-journal-status'),e.message,true);}}}
$('action-journal-export').addEventListener('click',async()=>{try{const records=await listActions();$('action-journal-text').value=JSON.stringify({version:1,records});msg($('action-journal-status'),'Action records ready to copy and store privately.');}catch(e){msg($('action-journal-status'),e.message,true);}});
$('action-journal-import').addEventListener('click',async()=>{try{const text=$('action-journal-text').value;if(text.length>4_000_000)throw Error('Action journal export is too large.');await importActions(JSON.parse(text));refreshActionViews();msg($('action-journal-status'),'Action records imported. Verify their outcomes independently.');}catch(e){msg($('action-journal-status'),e.message||'Invalid action journal export.',true);}});
if(actionChannel)actionChannel.onmessage=()=>renderActionJournal();renderActionJournal();
const VAULT_KEY='hegemon.local.encrypted-secrets.v1';
const vaultChannel=typeof BroadcastChannel==='function'?new BroadcastChannel('hegemon.local.encrypted-secrets.v2'):null;
function notifyVault(){vaultChannel?.postMessage('changed');}
let vaultRenderVersion=0;
async function renderVault(){const version=++vaultRenderVersion;let entries;
 try{entries=await listVault();}catch(e){if(version===vaultRenderVersion){$('vault-list').replaceChildren();msg($('vault-status'),e.message,true);}return;}
 if(version!==vaultRenderVersion)return;for(const choice of [$('ethereum-claim-backup'),$('sepolia-claim-backup'),$('cardano-claim-backup'),$('bitcoin-claim-backup')]){const previous=choice.value;choice.replaceChildren(new Option('Select encrypted backup',''));for(const entry of entries)choice.add(new Option(entry.label+' · '+entry.envelope.hashlock,entry.envelope.hashlock));choice.value=Array.from(choice.options).some(option=>option.value===previous)?previous:'';}
 $('vault-list').replaceChildren();if(!entries.length){$('vault-list').textContent='No encrypted secrets saved.';return;}
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
journey=initJourney({legacyForm:$('offer-form'),msg,hegemonWallet:{
 paired:()=>companionCapabilities.includes('hegemon-public-balance'),
 unlock:()=>hostedHegemonBalance('/hegemon/unlock',{}),
 balance:()=>hostedHegemonBalance('/hegemon/balance'),
}});
refresh();loadSelected();

$('inbox-backup-copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('inbox-backup-text').value);msg($('create-result'),'Backup copied.');}catch{msg($('create-result'),'Select and copy the backup above.');}});
$('restore-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.currentTarget,button=form.querySelector('button');button.disabled=true;
 try{let envelope;try{envelope=JSON.parse(form.elements.backup.value);}catch{throw Error('The backup is not valid JSON.');}
  const result=await restoreInbox(envelope,form.elements.passphrase.value);form.elements.passphrase.value='';
  msg($('restore-result'),result.restored?'Inbox key restored. Fingerprint '+await inboxFingerprint(result.publicKey)+'. Offers that use this key can now open new conversation setup messages in this browser.':'This browser already holds that inbox key; nothing was changed.');
 }catch(e){msg($('restore-result'),e.message,true);}finally{button.disabled=false;}});
