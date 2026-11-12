/** Guided testnet swap session. Every wallet transaction requires approval. */
import {pinOffer,readOfferPin} from './offer-pin.mjs';
import {deriveSessionId,participantText,checkSessionAddress} from './session-identity.mjs';
import {sessionStarter,readSessionFrames} from './session-start.mjs';
import {channelFingerprint,openParticipantFrame} from './session-channel.mjs';
import {getSession,updateSession,setSessionBackup,acknowledgeSessionBackup,sessionBackupCurrent} from './session-store.mjs';
import {updateSessionRecovery} from './session-recovery.mjs';
import {participantDraft,participantStatement,addSessionProof,completeParticipant,participantCode} from './session-participant.mjs';
import {bitcoinProof,signCardano,signEthereum} from './identity-flow.mjs';
import {publishSessionParticipant,publishSessionAgreement,publishSessionEscrow,readPeerSessionPackets,retrySessionMessage,syncSessionTransport} from './session-coordination.mjs';
import {assertSepoliaIdentity} from './sepolia-verifier.mjs';
import {planSessionTerms} from './session-plan.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';
import {sessionTermsDigest} from './session-packets.mjs';
import {loadPinnedScript,pinnedScript} from './cardano-tx.mjs';
import {formatBaseUnits,toBaseUnits} from './offer-draft.mjs';
import {fundSession} from './session-funding.mjs';
import {prepareBitcoinSessionFund,bitcoinSessionFundDraft,broadcastBitcoinSessionFund} from './session-bitcoin-fund.mjs';
import {prepareBitcoinSessionSpend,bitcoinSessionSpendDraft,broadcastBitcoinSessionSpend} from './session-bitcoin-spend.mjs';
import {prepareFundingAttempt,prepareSpendAttempt,actionArmed,recoveryReviewKey} from './session-action.mjs';
import {claimSession} from './session-claim.mjs';
import {checkSessionRefund,refundSession} from './session-refund.mjs';
import {observeSessionLeg} from './session-observation.mjs';
import {encryptRecovery} from './recovery.mjs';
import {restoreSwapBackup} from './session-restore.mjs';
import {canonical} from './identity.mjs';
import {fromHex,toHex} from './cbor.mjs';

const HEX=/^[0-9a-f]{64}$/;
const indexKey=id=>'hegemon.swap.session-index:'+id;
const pinKey=(session,role)=>`hegemon.swap.peer-pin:${session}:${role}`;
const now=()=>Math.floor(Date.now()/1000);
const el=(name,text)=>{const node=document.createElement(name);if(text!==undefined)node.textContent=text;return node;};

export function initSessionWizard(d){
 const {$,msg}=d,content=$('session-wizard-content'),status=$('session-wizard-status');
 let viewId=null,starter=null,draft=null,proofs=[],working=false,epoch=0,refundAvailable=false,inRefund=false;
 function button(label,action,secondary=false){const node=el('button',label);node.type='button';if(secondary)node.className='journey-secondary';node.addEventListener('click',()=>run(action));return node;}
 function screen(actor,title,detail){
  content.replaceChildren();const panel=el('div');panel.className='journey-swap-status';
  const who=el('p','NEXT ACTION: '+actor.toUpperCase());who.className='journey-swap-actor';
  panel.append(who,el('h3',title),el('p',detail));content.append(panel);
  if(refundAvailable&&!inRefund)content.append(button('Refund options',showRefund,true));
  if(inRefund)content.append(button('Return to swap',async()=>{inRefund=false;await advance();},true));
  return panel;
 }
 function refreshButton(panel){panel.append(button('Refresh progress',()=>window.location.reload(),true));}
 async function run(action){if(working)return;working=true;for(const b of content.querySelectorAll('button'))b.disabled=true;try{await action();}catch(error){const message=error?.message||'Could not check the swap.';const panel=screen('Unknown','Could not check the swap',message);refreshButton(panel);msg(status,message,true);}finally{working=false;for(const b of content.querySelectorAll('button'))b.disabled=false;}}
 function readIndex(id){
  const raw=localStorage.getItem(indexKey(id));if(!raw)return null;let value;try{value=JSON.parse(raw);}catch{throw Error('Saved swap setup is invalid.');}
  if(!value||Object.keys(value).sort().join(',')!=='digest,offerId,reservation,role,version'||value.version!==1||value.offerId!==id||!['owner','taker'].includes(value.role)||!HEX.test(value.reservation||'')||!HEX.test(value.digest||''))throw Error('Saved swap setup is invalid.');
  return value;
 }
 function credential(id,role){return role==='owner'?d.ownerToken(id):d.reservationToken(id);}
 async function makeStarter(id,index){
  const pin=await readOfferPin(id),token=credential(id,index.role);
  if(!pin||pin.digest!==index.digest||!token)throw Error('The saved offer or participant credential is unavailable.');
  return sessionStarter({role:index.role,offer:pin.offer,reservation:index.reservation,credential:token,pinnedOfferDigest:index.digest,api:d.api,inboxPrivateKey:d.inboxPrivateKey});
 }
 async function begin(id,offer,role){
  const viewed=d.viewedOffer(id);if(!viewed)throw Error('Review the offer before starting.');
  const pin=await pinOffer(viewed);await pinOffer(offer);
  const token=credential(id,role);if(!token||!HEX.test(offer.reservationId||''))throw Error('An active reservation is required.');
  const index={version:1,offerId:id,role,reservation:offer.reservationId,digest:pin.digest};
  const previous=readIndex(id);if(previous&&canonical(previous)!==canonical(index))throw Error('This browser has a different saved swap for this offer.');
  localStorage.setItem(indexKey(id),JSON.stringify(index));
  starter=await makeStarter(id,index);await advance();
 }
 async function showUnstarted(id){
  const offer=await d.api('/offers/'+id),role=d.ownerToken(id)?'owner':d.reservationToken(id)?'taker':null;
  if(!role)throw Error('Open your own offer or reserve an offer first.');
  if((offer.closed||offer.expires<=now())&&!(role==='taker'&&offer.reservationId)){const panel=screen('Unknown','This offer is no longer open','The page cannot start a new swap from this offer. Existing transactions need separate recovery.');refreshButton(panel);return;}
  if(!offer.reservationId){const panel=screen('The other person','Waiting for a reservation','Share the offer, then refresh after someone reserves it. No funds have moved.');refreshButton(panel);return;}
  const panel=screen('You',role==='owner'?'Accept the reservation':'Join the swap',role==='owner'?'Accepting starts a private swap session and closes the listing. No wallet transaction is requested.':'Joining prepares a private swap session. No wallet transaction is requested.');
  panel.append(button(role==='owner'?'Accept and start':'Join swap',()=>begin(id,offer,role)));
 }
 async function initialBackup(){
  const panel=screen('You','Protect your swap recovery','Choose a passphrase for an encrypted backup of this swap’s coordination data. Save the backup and passphrase before continuing.');
  const label=el('label','Backup passphrase'),input=el('input');input.type='password';input.autocomplete='new-password';input.minLength=12;label.append(input);
  const repeatLabel=el('label','Repeat passphrase'),repeat=el('input');repeat.type='password';repeat.autocomplete='new-password';repeat.minLength=12;repeatLabel.append(repeat);panel.append(label,repeatLabel);
  panel.append(button('Create recovery backup',async()=>{if(input.value!==repeat.value||input.value.length<12)throw Error('Use matching passphrases of at least 12 characters.');const phrase=input.value;input.value='';repeat.value='';await starter.advance(phrase);await advance();}));
 }
 async function showBackup(record,after=advance){
  if(!await sessionBackupCurrent(record)){
   const panel=screen('You','Update your recovery backup','The swap has new details. Enter your backup passphrase to make an updated encrypted copy before continuing.');
   const label=el('label','Backup passphrase'),input=el('input');input.type='password';input.autocomplete='off';label.append(input);panel.append(label);
   panel.append(button('Update recovery backup',async()=>{const phrase=input.value;input.value='';const envelope=await updateSessionRecovery(record.envelope,phrase,record.snapshot);await setSessionBackup(record.session,record.role,record.revision,envelope,phrase);await after();}));return;
  }
  const panel=screen('You','Save your encrypted recovery backup','Save this encrypted copy and its separate passphrase somewhere safe. It restores swap coordination, not your wallet.');
  const label=el('label','Encrypted recovery backup'),area=el('textarea');area.rows=5;area.readOnly=true;area.value=JSON.stringify(record.envelope);label.append(area);panel.append(label);
  panel.append(button('Copy backup',async()=>{try{await navigator.clipboard.writeText(area.value);msg(status,'Encrypted backup copied.');}catch{area.focus();area.select();msg(status,'Select and copy the encrypted backup.');}},true));
  panel.append(button('I saved the backup',async()=>{await acknowledgeSessionBackup(record.session,record.role,record.revision);await after();}));
 }
 function reviewRestoredWallets(record,after){
  const key=recoveryReviewKey(record.session,record.role);if(localStorage.getItem(key)!=='required')return false;
  const panel=screen('You','Review your wallet activity','An older backup may omit transactions you already approved. Check both wallets and their pending transactions, and use the newest backup. Do not operate the same swap in another browser at the same time.');
  panel.append(button('I checked my wallets',async()=>{localStorage.removeItem(key);await after();}));return true;
 }
 async function findPeer(record){
  const snapshot=record.snapshot,peer=record.role==='owner'?'taker':'owner',seq=peer==='owner'?1:2;
  const rows=await readSessionFrames({session:record.session,credential:snapshot.credential,api:d.api});
  const matches=rows.filter(row=>row.sender===peer&&row.sequence===seq);if(!matches.length)return null;
  if(matches.length!==1)throw Error('The participant message history is invalid.');
  const channelDigest=await channelFingerprint(record.session,snapshot.channelKey),expected={session:record.session,role:peer,offer:snapshot.offer.id,reservation:snapshot.reservation,offerDigest:snapshot.offerDigest,channelDigest,assets:{give:snapshot.offer.give,receive:snapshot.offer.receive},sessionExpires:snapshot.sessionExpires};
  const result=await openParticipantFrame(snapshot.channelKey,{session:record.session,role:peer,sequence:seq},matches[0].ciphertext,expected,now());
  if(result.statement.protocolKey===record.publicKey)throw Error('Both participants cannot use the same signing key.');
  return result.blob;
 }
 async function ownProof(record){
  const chains=new Set([record.snapshot.offer.give.chain,record.snapshot.offer.receive.chain]);
  if(chains.has('ethereum')&&!d.getEthereum()){
   const panel=screen('You','Connect your Ethereum wallet','Connect the wallet you will use for this swap. Connecting does not request a signature or move funds.');
   panel.append(button('Connect Ethereum wallet',async()=>{await d.connectEthereum();await advance();}));return;
  }
  if(chains.has('cardano')&&!d.getCardano()){
   const panel=screen('You','Connect your Cardano wallet','Choose your Cardano testnet wallet. Connecting does not request a signature or move funds.');
   const label=el('label','Cardano wallet'),select=el('select');select.add(new Option('Choose a wallet',''));
   for(const [id,wallet] of Object.entries(window.cardano||{}))if(wallet&&typeof wallet.enable==='function')select.add(new Option(String(wallet.name||id),id));
   label.append(select);panel.append(label,button('Connect Cardano wallet',async()=>{if(!select.value)throw Error('Choose a Cardano wallet.');if(!await d.connectCardano(select.value))throw Error('Switch your Cardano wallet to a test network.');await advance();}));return;
  }
  const btcKey=`hegemon.swap.bitcoin-key:${record.session}:${record.role}`,draftKey=`hegemon.swap.identity-draft:${record.session}:${record.role}`;
  if(chains.has('bitcoin')&&!localStorage.getItem(btcKey)){
   const panel=screen('You','Enter your Bitcoin public key','Enter the compressed public key for your Bitcoin testnet wallet. This is public information, not a private key.');
   const label=el('label','Bitcoin public key'),input=el('input');input.autocomplete='off';input.maxLength=66;label.append(input);panel.append(label,button('Continue',async()=>{const value=input.value.trim().toLowerCase();checkSessionAddress('bitcoin',value);localStorage.setItem(btcKey,value);await advance();}));return;
  }
  if(!draft||draft.session!==record.session||draft.role!==record.role){
   const provider=d.getEthereum(),cardano=d.getCardano(),addressesByChain={};
   if(chains.has('ethereum')){await assertSepoliaIdentity(provider);const accounts=await provider.request({method:'eth_accounts'});if(provider!==d.getEthereum()||!Array.isArray(accounts)||!/^0x[0-9a-fA-F]{40}$/.test(accounts[0]||''))throw Error('A connected Ethereum account is required.');addressesByChain.ethereum=accounts[0].toLowerCase();}
   if(chains.has('cardano')){const used=await cardano.getUsedAddresses(),unused=used.length?[]:await (cardano.getUnusedAddresses?.()??[]),address=[...used,...unused].map(fromHex).find(bytes=>bytes.length>=29&&[0,2,4,6].includes(bytes[0]>>4));if(cardano!==d.getCardano()||!address)throw Error('The Cardano wallet has no payment-key address.');addressesByChain.cardano=toHex(address.slice(1,29));}
   if(chains.has('bitcoin')){addressesByChain.bitcoin=localStorage.getItem(btcKey);checkSessionAddress('bitcoin',addressesByChain.bitcoin);}
   const assets=record.snapshot.offer,addresses={give:addressesByChain[assets.give.chain],receive:addressesByChain[assets.receive.chain]};
   let prior=null;const raw=sessionStorage.getItem(draftKey);if(raw){try{prior=JSON.parse(raw);}catch{throw Error('The saved wallet proof is invalid.');}if(!prior||Object.keys(prior).sort().join(',')!=='addresses,issued,proofs'||!Number.isSafeInteger(prior.issued)||prior.issued>now()+300||!Array.isArray(prior.proofs)||prior.proofs.length>2||canonical(prior.addresses)!==canonical(addresses))throw Error('The saved wallet proof does not match the connected wallets.');}
   const base=await participantDraft({session:record.session,role:record.role,snapshot:record.snapshot,publicKey:record.publicKey,now:prior?.issued??now()});
   draft={...base,statement:participantStatement(base,addresses)};proofs=[];
   for(const proof of prior?.proofs??[])proofs=addSessionProof(draft.statement,draft.assets,proofs,proof);
  }
  const side=['give','receive'].find(name=>!proofs.some(proof=>proof.chain===draft.assets[name].chain&&proof.signer===draft.statement.addresses[name]));
  if(!side){
   const blob=await completeParticipant(draft,draft.statement,proofs,now()),field=record.role==='owner'?'ownerBlob':'takerBlob';
   record=await updateSession(record.session,record.role,record.revision,{...record.snapshot,[field]:blob});draft=null;proofs=[];sessionStorage.removeItem(draftKey);
   await publishSessionParticipant({session:record.session,role:record.role,outbox:starter.outbox,readFrames:args=>readSessionFrames({...args,api:d.api}),now:now()});
   await advance();return;
  }
  const chain=draft.assets[side].chain;
  if(chain==='bitcoin'){
   const panel=screen('You','Sign with your Bitcoin wallet','Sign this message in your Bitcoin wallet and paste the resulting signature. Signing does not move funds.'),text=participantText(draft.statement),message=el('textarea');message.value=text;message.readOnly=true;message.rows=5;panel.append(message);
   const schemeLabel=el('label','Signature format'),scheme=el('select');scheme.add(new Option('BIP-137','bip137'));scheme.add(new Option('BIP-322 simple','bip322-simple'));schemeLabel.append(scheme);
   const label=el('label','Bitcoin signature'),input=el('textarea');input.rows=3;label.append(input);panel.append(schemeLabel,label,button('Check signature',async()=>{const proof=bitcoinProof(scheme.value,input.value,text);proofs=addSessionProof(draft.statement,draft.assets,proofs,proof);sessionStorage.setItem(draftKey,JSON.stringify({addresses:draft.statement.addresses,issued:draft.now,proofs}));await advance();}));return;
  }
  const panel=screen('You',`Sign with your ${chain==='ethereum'?'Ethereum':'Cardano'} wallet`,'This signature binds your wallet addresses to the swap. It does not move funds.');
  panel.append(button(`Sign with ${chain==='ethereum'?'Ethereum':'Cardano'}`,async()=>{
   const text=participantText(draft.statement),provider=d.getEthereum(),cardano=d.getCardano();
   const proof=chain==='ethereum'?await signEthereum(provider,draft.statement.addresses[side],text):await signCardano(cardano,text);
   if(provider!==d.getEthereum()||cardano!==d.getCardano())throw Error('A wallet changed while signing. Reconnect before continuing.');
   proofs=addSessionProof(draft.statement,draft.assets,proofs,proof);sessionStorage.setItem(draftKey,JSON.stringify({addresses:draft.statement.addresses,issued:draft.now,proofs}));await advance();
  }));
 }
 function termsSummary(terms){
  const describe=leg=>{const asset=leg.asset;let amount;try{amount=formatBaseUnits(asset.chain+':'+asset.kind,asset.amount);}catch{amount=asset.amount+' base units';}
   const deposit=asset.chain==='cardano'&&asset.kind==='native'?` + ${formatBaseUnits('cardano:ada',leg.lovelace)} ADA sent with the token`:'';
   const deadline=['bitcoin','hegemon'].includes(asset.chain)?`block ${leg.expiry}`:new Date(leg.expiry*1000).toLocaleString();
   return `${amount} · ${asset.chain} ${asset.kind}${asset.id?' · '+asset.id:''}${deposit} · refund after ${deadline}`;};
  return `First lock: ${describe(terms.legs.long)}.\nSecond lock: ${describe(terms.legs.short)}.`;
 }
 async function templates(){
  await loadPinnedScript();const [ether,token]=await Promise.all(['/ether-escrow-template.json','/token-escrow-template.json'].map(async path=>{const response=await fetch(path);if(!response.ok)throw Error('The pinned escrow template is unavailable.');return response.json();}));
  return {ether,token,cardanoBudget:pinnedScript().executionUnits};
 }
 async function verifyTerms(record,purpose,references=record.snapshot.escrows){
  const config=await d.loadTiming(),pinned=await templates();
  return verifySessionSnapshot({terms:record.snapshot.terms,offer:record.snapshot.offer,expectedOfferDigest:record.snapshot.offerDigest,channelDigest:await channelFingerprint(record.session,record.snapshot.channelKey),ownerBlob:record.snapshot.ownerBlob,takerBlob:record.snapshot.takerBlob,session:record.session,reservation:record.snapshot.reservation,sessionExpires:record.snapshot.sessionExpires,role:record.role==='owner'?'initiator':'responder',references,purpose,readers:d.readers,config,now:now(),templates:pinned});
 }
 function confirmTransaction(summary){
  const panel=screen('You','Review the wallet transaction',(summary.lines||[]).join('\n'));
  const approve=el('button','Approve and open wallet'),cancel=el('button','Cancel');approve.type=cancel.type='button';cancel.className='journey-secondary';
  panel.append(approve,cancel);
  return new Promise(resolve=>{let done=false;const finish=value=>{if(done)return;done=true;approve.disabled=cancel.disabled=true;resolve(value);};approve.addEventListener('click',()=>finish(true));cancel.addEventListener('click',()=>finish(false));});
 }
 async function fund(record){
  const own=record.role==='owner'?'long':'short',asset=record.snapshot.terms.legs[own].asset,chain=asset.chain;
  if(!((chain==='bitcoin'&&asset.kind==='btc')||(chain==='ethereum'&&asset.kind==='eth')||(chain==='cardano'&&['ada','native'].includes(asset.kind)))){const panel=screen('Not yet available','Token funding is not ready','This guided funding step cannot fund this asset yet. Do not fund an escrow from this screen.');refreshButton(panel);return;}
  const attempt=record.snapshot.actions[own].fund.at(-1);
  if(!attempt||attempt.state==='declined'){
   const panel=screen('You','Prepare your funding action',termsSummary(record.snapshot.terms)+' The page will save a recovery record before opening your wallet.');
   panel.append(button('Prepare funding',async()=>{await verifyTerms(record,record.role==='owner'?'fund_first':'fund_second');await prepareFundingAttempt({session:record.session,role:record.role,outbox:starter.outbox});await advance();}));return;
  }
  if(chain==='bitcoin'&&attempt.state==='prepared'){
   const opts={session:record.session,role:record.role,attemptId:attempt.id,outbox:starter.outbox,readFrames:args=>readSessionFrames({...args,api:d.api}),readers:d.readers,config:await d.loadTiming(),templates:await templates()};
   let handoff;try{handoff=await bitcoinSessionFundDraft(opts);}catch(error){const panel=screen('You','Check the Bitcoin funding action',error.message);refreshButton(panel);return;}
   const panel=screen('You','Sign the Bitcoin transaction','Copy this unsigned transaction to your testnet wallet, review it there, and paste the signed PSBT below. The page will check it again before broadcasting.');
   const summary=el('p',handoff.lines.join('\n')),outLabel=el('label','Unsigned Bitcoin PSBT'),out=el('textarea');out.value=handoff.psbt;out.readOnly=true;out.rows=5;outLabel.append(out);
   const inLabel=el('label','Signed Bitcoin PSBT'),input=el('textarea');input.rows=5;inLabel.append(input);panel.append(summary,outLabel,inLabel,button('Check and broadcast',async()=>{const signedPsbt=input.value.trim();input.value='';const result=await broadcastBitcoinSessionFund({...opts,signedPsbt});msg(status,'Bitcoin funding submitted. Save the updated recovery backup and wait for confirmations.');await advance();}));return;
  }
  if(attempt.state!=='intent'||!actionArmed(record.session,record.role,attempt.id)){
   const panel=screen('You','Check the previous wallet action','This funding attempt may already have reached your wallet. Check the wallet and action journal before trying again.');refreshButton(panel);return;
  }
  if(chain==='bitcoin'){
   const panel=screen('You','Prepare your Bitcoin transaction','Enter the testnet4 address that holds your bitcoin and a fee rate. Your wallet will sign a checked PSBT in the next step.');
   const addressLabel=el('label','Bitcoin testnet4 address'),address=el('input');address.autocomplete='off';addressLabel.append(address);
   const rateLabel=el('label','Fee rate (sat/vB)'),rate=el('input');rate.type='number';rate.min='1';rate.max='200';rate.value='2';rateLabel.append(rate);panel.append(addressLabel,rateLabel,button('Prepare Bitcoin PSBT',async()=>{await prepareBitcoinSessionFund({session:record.session,role:record.role,attemptId:attempt.id,outbox:starter.outbox,readFrames:args=>readSessionFrames({...args,api:d.api}),readers:d.readers,config:await d.loadTiming(),templates:await templates(),address:address.value.trim(),feeRate:Number(rate.value)});await advance();}));return;
  }
  if(chain==='ethereum'&&!d.getEthereum()){const panel=screen('You','Connect your Ethereum wallet','Connect the wallet that will fund this side.');panel.append(button('Connect Ethereum wallet',async()=>{await d.connectEthereum();await advance();}));return;}
  if(chain==='cardano'&&!d.getCardano()){
   const panel=screen('You','Connect your Cardano wallet','Choose the wallet that will fund this side.'),label=el('label','Cardano wallet'),select=el('select');select.add(new Option('Choose a wallet',''));
   for(const [id,wallet] of Object.entries(window.cardano||{}))if(wallet&&typeof wallet.enable==='function')select.add(new Option(String(wallet.name||id),id));label.append(select);panel.append(label,button('Connect Cardano wallet',async()=>{if(!select.value)throw Error('Choose a Cardano wallet.');if(!await d.connectCardano(select.value))throw Error('Switch your Cardano wallet to a test network.');await advance();}));return;
  }
  const panel=screen('You','Lock your side of the swap',termsSummary(record.snapshot.terms)+' Review the transaction and approve it in your wallet.');
  panel.append(button('Review funding transaction',async()=>{
   const result=await fundSession({session:record.session,role:record.role,attemptId:attempt.id,outbox:starter.outbox,readFrames:args=>readSessionFrames({...args,api:d.api}),readers:d.readers,config:await d.loadTiming(),templates:await templates(),getEthereum:d.getEthereum,getCardano:d.getCardano,confirm:confirmTransaction});
   msg(status,result.uncertain?'The wallet did not confirm submission. Check the transaction before retrying.':'Funding transaction submitted. Save the updated recovery backup and wait for confirmations.');await advance();
  }));
 }
 async function bitcoinSpend(record,operation,attempt,config,after){
  const opts={session:record.session,role:record.role,operation,attemptId:attempt.id,outbox:starter.outbox,readFrames:args=>readSessionFrames({...args,api:d.api}),readers:d.readers,config,templates:await templates()};
  if(attempt.state==='prepared'){
   let handoff;try{handoff=await bitcoinSessionSpendDraft(opts);}catch(error){const panel=screen('You','Check the Bitcoin wallet action',error.message);refreshButton(panel);return;}
   const panel=screen('You',operation==='claim'?'Sign your Bitcoin claim':'Sign your Bitcoin refund','Copy this unsigned transaction to your Bitcoin testnet wallet, review and sign it there, then paste the signed PSBT below.');
   const summary=el('p',handoff.lines.join('\n')),outLabel=el('label','Unsigned Bitcoin PSBT'),out=el('textarea');out.value=handoff.psbt;out.readOnly=true;out.rows=5;outLabel.append(out);
   const inLabel=el('label','Signed Bitcoin PSBT'),input=el('textarea');input.rows=5;inLabel.append(input);panel.append(summary,outLabel,inLabel);
   let phrase=null;if(operation==='claim'){const label=el('label','Recovery passphrase');phrase=el('input');phrase.type='password';phrase.autocomplete='off';label.append(phrase);panel.append(label);}
   panel.append(button('Check and broadcast',async()=>{const signedPsbt=input.value.trim(),passphrase=phrase?.value;input.value='';if(phrase)phrase.value='';await broadcastBitcoinSessionSpend({...opts,signedPsbt,passphrase});msg(status,'Bitcoin transaction submitted. Save the updated recovery backup and wait for confirmations.');await after();}));return;
  }
  if(attempt.state!=='intent'||!actionArmed(record.session,record.role,attempt.id)){const panel=screen('You','Check the previous Bitcoin action','This transaction may already have reached your wallet. Check wallet history and the action journal before retrying.');refreshButton(panel);return;}
  const panel=screen('You',operation==='claim'?'Prepare your Bitcoin claim':'Prepare your Bitcoin refund','Enter the testnet4 address that should receive the bitcoin and a fee rate. You will review and sign the transaction in your wallet.');
  const addressLabel=el('label','Bitcoin testnet4 destination'),address=el('input');address.autocomplete='off';addressLabel.append(address);
  const rateLabel=el('label','Fee rate (sat/vB)'),rate=el('input');rate.type='number';rate.min='1';rate.max='200';rate.value='2';rateLabel.append(rate);panel.append(addressLabel,rateLabel,button('Prepare Bitcoin PSBT',async()=>{await prepareBitcoinSessionSpend({...opts,address:address.value.trim(),feeRate:Number(rate.value)});await after();}));
 }
 async function showRefund(){
  inRefund=true;const index=readIndex(viewId);if(!index)throw Error('The saved swap is unavailable.');
  const session=await deriveSessionId(viewId,index.reservation);
  if(!starter||starter.session!==session||starter.role!==index.role)starter=await makeStarter(viewId,index);
  const record=await getSession(session,index.role);if(!record)throw Error('The saved swap is unavailable.');
  const role=record.role,side=role==='owner'?'long':'short',leg=record.snapshot.terms?.legs[side],ref=record.snapshot.escrows[side];
  if(!leg||!ref)throw Error('No saved escrow is available to refund.');
  if(!record.backupAcknowledged||!await sessionBackupCurrent(record)){await showBackup(record,showRefund);return;}
  if(reviewRestoredWallets(record,showRefund))return;
  const config=await d.loadTiming(),seen=leg.asset.chain==='hegemon'?null:await observeSessionLeg({snapshot:record.snapshot,side,readers:d.readers,config});
  if(seen?.state==='claimed'){const panel=screen('Complete','Your escrow was claimed','The other person claimed this escrow. It is no longer available for a refund.');if(!seen.enough)refreshButton(panel);return;}
  if(seen?.state==='refunded'){const panel=screen(seen.enough?'Complete':'Network',seen.enough?'Refund confirmed':'Waiting for refund confirmations',seen.enough?'Your refund was confirmed.':'Your refund was seen on chain. Refresh after more confirmations.');if(!seen.enough)refreshButton(panel);return;}
  if(seen?.state==='pending'){const panel=screen('Network','Checking the escrow spend','The chain service has not indexed the spend yet. Refresh to check again.');refreshButton(panel);return;}
  try{await checkSessionRefund({snapshot:record.snapshot,role,readers:d.readers,config});}
  catch(error){const deadline=['bitcoin','hegemon'].includes(leg.asset.chain)?`block ${leg.expiry}`:new Date(leg.expiry*1000).toLocaleString();const panel=screen('Network or time','Refund not ready',`${error.message} Refund deadline: ${deadline}. Refresh to check again.`);refreshButton(panel);return;}
  if(leg.asset.chain==='hegemon'){const panel=screen('Not yet available','Hegemon refund coordination is not ready','The local wallet verified this refund note, but this wizard cannot yet prepare the refund.');refreshButton(panel);return;}
  const attempt=record.snapshot.actions[side].refund.at(-1);
  if(!attempt||attempt.state==='declined'){
   const panel=screen('You','Prepare your refund','The deadline has passed. Prepare a recovery record before requesting a refund from your wallet.');
   panel.append(button('Prepare refund',async()=>{await checkSessionRefund({snapshot:record.snapshot,role,readers:d.readers,config});await prepareSpendAttempt({session,role,operation:'refund',outbox:starter.outbox});await showRefund();}));return;
  }
  if(attempt.state==='submitted'){const panel=screen('Network','Waiting for your refund','Your refund was submitted. Refresh to check for confirmation.');refreshButton(panel);return;}
  if(leg.asset.chain==='bitcoin'&&['intent','prepared'].includes(attempt.state)){await bitcoinSpend(record,'refund',attempt,config,showRefund);return;}
  if(attempt.state!=='intent'||!actionArmed(session,role,attempt.id)){const panel=screen('You','Check the previous refund','This refund may already have reached your wallet. Check the wallet and action journal before retrying.');refreshButton(panel);return;}
  if(leg.asset.chain==='ethereum'&&!d.getEthereum()){const panel=screen('You','Connect your Ethereum wallet','Connect the wallet that funded this escrow.');panel.append(button('Connect Ethereum wallet',async()=>{await d.connectEthereum();await showRefund();}));return;}
  if(leg.asset.chain==='cardano'&&!d.getCardano()){
   const panel=screen('You','Connect your Cardano wallet','Choose the wallet that funded this escrow.'),label=el('label','Cardano wallet'),select=el('select');select.add(new Option('Choose a wallet',''));
   for(const [id,wallet] of Object.entries(window.cardano||{}))if(wallet&&typeof wallet.enable==='function')select.add(new Option(String(wallet.name||id),id));label.append(select);panel.append(label,button('Connect Cardano wallet',async()=>{if(!select.value)throw Error('Choose a Cardano wallet.');if(!await d.connectCardano(select.value))throw Error('Switch your Cardano wallet to a test network.');await showRefund();}));return;
  }
  const panel=screen('You','Refund your escrow','Review the refund transaction and approve it in your wallet.');
  panel.append(button('Review refund transaction',async()=>{const result=await refundSession({session,role,attemptId:attempt.id,readers:d.readers,config,templates:await templates(),getEthereum:d.getEthereum,getCardano:d.getCardano,confirm:confirmTransaction});msg(status,result.uncertain?'The wallet did not confirm submission. Check the transaction before retrying.':'Refund submitted. Save the updated recovery backup and wait for confirmations.');await showRefund();}));
 }
 async function claim(record){
  const role=record.role,side=role==='owner'?'short':'long',chain=record.snapshot.terms.legs[side].asset.chain,config=await d.loadTiming();
  const seen=await observeSessionLeg({snapshot:record.snapshot,side,readers:d.readers,config});
  if(seen.state==='claimed'){
   if(!seen.enough){const panel=screen('Network','Waiting for claim confirmations','Your claim was seen on chain. Refresh after more confirmations.');refreshButton(panel);return;}
   const other=await observeSessionLeg({snapshot:record.snapshot,side:role==='owner'?'long':'short',readers:d.readers,config});
   if(other.state==='claimed'&&other.enough){screen('Complete','Swap complete','Both sides have been claimed and confirmed.');return;}
   if(other.state==='refunded'&&other.enough){screen('You','Your escrow was refunded','Your claim was confirmed, and your escrow was later refunded. Check both transactions in your wallets.');return;}
   const panel=screen(other.state==='claimed'||other.state==='pending'?'Network':'The other person','Your claim is confirmed','Refresh to check whether the other side has been claimed.');refreshButton(panel);return;
  }
  if(seen.state==='refunded'){const panel=screen('You','This escrow was refunded','The asset you expected to claim was refunded. Check your own escrow and its refund deadline.');refreshButton(panel);return;}
  if(seen.state==='pending'){const panel=screen('Network','Checking the escrow spend','The chain service has not indexed the spend yet. Refresh to check again.');refreshButton(panel);return;}
  if(seen.state==='secret-revealed'){const panel=screen('Network','Checking the Hegemon note','A matching secret was revealed, but this alone does not prove this particular note was spent. Check the local wallet.');refreshButton(panel);return;}
  if(role==='taker'){
   const other=await observeSessionLeg({snapshot:record.snapshot,side:'short',readers:d.readers,config});
   if(!['claimed','secret-revealed'].includes(other.state)||!other.enough){const panel=screen(other.state==='claimed'?'Network':'The other person',other.state==='claimed'?'Waiting for their claim confirmations':'Waiting for their claim','Refresh to check whether the maker has claimed your locked asset.');refreshButton(panel);return;}
   if(!record.snapshot.secretEnvelope){
    const panel=screen('You','Save the claim recovery data','The other person’s confirmed claim revealed the swap secret. Enter a recovery passphrase to encrypt it locally before claiming.');
    const label=el('label','Recovery passphrase'),phrase=el('input');phrase.type='password';phrase.autocomplete='off';label.append(phrase);panel.append(label,button('Protect claim recovery',async()=>{
     const passphrase=phrase.value;phrase.value='';const checked=await observeSessionLeg({snapshot:record.snapshot,side:'short',readers:d.readers,config});
     if(!['claimed','secret-revealed'].includes(checked.state)||!checked.enough)throw Error('The other secret is no longer confirmed. Refresh to check again.');
     const secret=fromHex(checked.preimage);try{const envelope=await encryptRecovery(secret,passphrase);await updateSession(record.session,role,record.revision,{...record.snapshot,secretEnvelope:envelope});}finally{secret.fill(0);}await advance();
    }));return;
   }
  }
  const attempt=record.snapshot.actions[side].claim.at(-1);
  if(attempt?.state==='submitted'){
   const panel=screen('Network','Waiting for your claim','Your claim was submitted. Refresh to check for confirmation.');refreshButton(panel);return;
  }
  if(!attempt||attempt.state==='declined'){
   const panel=screen('You','Prepare your claim','The page will check the swap and save a recovery record before opening your wallet.');
   panel.append(button('Prepare claim',async()=>{await verifyTerms(record,role==='owner'?'claim_short':'claim_long');await prepareSpendAttempt({session:record.session,role,operation:'claim',outbox:starter.outbox});await advance();}));return;
  }
  if(chain==='bitcoin'&&['intent','prepared'].includes(attempt.state)){await bitcoinSpend(record,'claim',attempt,config,advance);return;}
  if(attempt.state!=='intent'||!actionArmed(record.session,role,attempt.id)){
   const panel=screen('You','Check the previous wallet action','This claim may already have reached your wallet. Check your wallet and the action journal before trying again.');refreshButton(panel);return;
  }
  if(chain==='ethereum'&&!d.getEthereum()){const panel=screen('You','Connect your Ethereum wallet','Connect the wallet that will receive the asset.');panel.append(button('Connect Ethereum wallet',async()=>{await d.connectEthereum();await advance();}));return;}
  if(chain==='cardano'&&!d.getCardano()){
   const panel=screen('You','Connect your Cardano wallet','Choose the wallet that will receive the asset.'),label=el('label','Cardano wallet'),select=el('select');select.add(new Option('Choose a wallet',''));
   for(const [id,wallet] of Object.entries(window.cardano||{}))if(wallet&&typeof wallet.enable==='function')select.add(new Option(String(wallet.name||id),id));label.append(select);panel.append(label,button('Connect Cardano wallet',async()=>{if(!select.value)throw Error('Choose a Cardano wallet.');if(!await d.connectCardano(select.value))throw Error('Switch your Cardano wallet to a test network.');await advance();}));return;
  }
  const panel=screen('You','Claim your asset','Enter your recovery passphrase. You will review the transaction before approving it in your wallet.');
  const label=el('label','Recovery passphrase'),phrase=el('input');phrase.type='password';phrase.autocomplete='off';label.append(phrase);panel.append(label,button('Review claim transaction',async()=>{
   const passphrase=phrase.value;phrase.value='';const result=await claimSession({session:record.session,role,attemptId:attempt.id,outbox:starter.outbox,readFrames:args=>readSessionFrames({...args,api:d.api}),readers:d.readers,config,templates:await templates(),getEthereum:d.getEthereum,getCardano:d.getCardano,confirm:confirmTransaction,passphrase});
   msg(status,result.uncertain?'The wallet did not confirm submission. Check the transaction before retrying.':'Claim submitted. Save the updated recovery backup and wait for confirmations.');await advance();
  }));
 }
 async function agreement(record){
  const role=record.role,session=record.session,readFrames=args=>readSessionFrames({...args,api:d.api});
  const peers=await readPeerSessionPackets({session,role,readFrames,now:now()});
  if(!record.snapshot.terms){
   if(role==='taker'){
    if(!peers.length){const panel=screen('The other person','Waiting for the proposed swap terms','The maker needs to prepare the swap. Refresh to check again. No funds have moved.');refreshButton(panel);return;}
    if(peers.length!==1||peers[0].body.payload.type!=='proposal')throw Error('The maker’s signed proposal is missing or out of order.');
    const terms=peers[0].body.payload.terms;
    const preview={...record,snapshot:{...record.snapshot,terms}};
    await verifyTerms(preview,'review');
    await updateSession(session,role,record.revision,preview.snapshot);await advance();return;
   }
   const panel=screen('You','Prepare the swap terms','The page will calculate the refund deadlines from both testnets and create an encrypted swap secret. No wallet transaction is requested.');
   const label=el('label','Recovery passphrase'),phrase=el('input');phrase.type='password';phrase.autocomplete='off';label.append(phrase);panel.append(label);
   let deposit=null;
   if([record.snapshot.offer.give,record.snapshot.offer.receive].some(asset=>asset.chain==='cardano'&&asset.kind==='native')){
    const depositLabel=el('label','ADA to send with the Cardano token'),input=el('input');input.inputMode='decimal';input.value='2';depositLabel.append(input);panel.append(depositLabel,el('p','This ADA is locked with the token and goes to the recipient if the swap completes.'));
    deposit=input;
   }
   panel.append(button('Prepare terms',async()=>{
    const passphrase=phrase.value;phrase.value='';await loadPinnedScript();
    const planned=await planSessionTerms({session,role,snapshot:record.snapshot,readers:d.readers,config:await d.loadTiming(),passphrase,cardanoDeposit:deposit?toBaseUnits('cardano:ada',deposit.value):undefined,now:now()});
    await updateSession(session,role,record.revision,{...record.snapshot,terms:planned.terms,secretEnvelope:planned.secretEnvelope});await advance();
   }));return;
  }
  const terms=record.snapshot.terms,digest=await sessionTermsDigest(terms),outbox=await starter.outbox.inspect();
  if(role==='taker'){
   if(!peers.length||peers[0].body.payload.type!=='proposal'||canonical(peers[0].body.payload.terms)!==canonical(terms))throw Error('The maker’s signed proposal no longer matches the saved terms.');
   if(outbox.next===3){
    const panel=screen('You','Review and accept the terms',termsSummary(terms));
    panel.append(button('Accept these terms',async()=>{await verifyTerms(record,'review');await publishSessionAgreement({session,role,outbox:starter.outbox,readFrames,now:now()});await advance();}));return;
   }
   if(peers.length<2){const panel=screen('The other person','Waiting for the first lock','The maker has not yet supplied a verified first escrow. Refresh after they lock their side.');refreshButton(panel);return;}
   const notice=peers[1].body.payload;
   if(notice.type!=='escrow'||notice.leg!=='long'||notice.termsDigest!==digest)throw Error('The first escrow announcement does not match the agreed terms.');
   if(record.snapshot.escrows.long===null){
    const references={...record.snapshot.escrows,long:notice.reference};
    try{await verifyTerms(record,'fund_second',references);}catch(error){const panel=screen('Network or service','First lock not verified',error.message+' Refresh to check again; do not fund yet.');refreshButton(panel);return;}
    await updateSession(session,role,record.revision,{...record.snapshot,escrows:references});await advance();return;
   }
   if(canonical(record.snapshot.escrows.long)!==canonical(notice.reference))throw Error('The first escrow reference changed.');
   if(record.snapshot.escrows.short===null){await fund(record);return;}
   if(outbox.next===4){
    try{await publishSessionEscrow({session,role,outbox:starter.outbox,readFrames,now:now(),readers:d.readers,config:await d.loadTiming(),templates:await templates()});await advance();}
    catch(error){const panel=screen('Network or service','Second lock not verified',error.message+' Refresh to check again.');refreshButton(panel);}return;
   }
   await claim(record);return;
  }
  if(outbox.next===2){
   const panel=screen('You','Review and send the terms',termsSummary(terms));
   panel.append(button('Send these terms',async()=>{await verifyTerms(record,'fund_first');await publishSessionAgreement({session,role,outbox:starter.outbox,readFrames,now:now()});await advance();}));return;
  }
  if(!peers.length){const panel=screen('The other person','Waiting for their acceptance','The other participant must review the signed terms. Refresh to check again.');refreshButton(panel);return;}
  if(peers[0].body.payload.type!=='accept'||peers[0].body.payload.termsDigest!==digest)throw Error('The other participant’s acceptance does not match the saved terms.');
  if(record.snapshot.escrows.long===null){await fund(record);return;}
  if(outbox.next===3){
   try{await publishSessionEscrow({session,role,outbox:starter.outbox,readFrames,now:now(),readers:d.readers,config:await d.loadTiming(),templates:await templates()});await advance();}
   catch(error){const panel=screen('Network or service','First lock not verified',error.message+' Refresh to check again.');refreshButton(panel);}return;
  }
  if(peers.length<2){const panel=screen('The other person','Waiting for their lock','Your confirmed escrow has been shared. Refresh after the other person locks their side.');refreshButton(panel);return;}
  const notice=peers[1].body.payload;
  if(notice.type!=='escrow'||notice.leg!=='short'||notice.termsDigest!==digest)throw Error('The second escrow announcement does not match the agreed terms.');
  if(record.snapshot.escrows.short===null){
   const references={...record.snapshot.escrows,short:notice.reference};
   try{await verifyTerms(record,'claim_short',references);}catch(error){const panel=screen('Network or service','Second lock not verified',error.message+' Refresh to check again; do not claim yet.');refreshButton(panel);return;}
   await updateSession(session,role,record.revision,{...record.snapshot,escrows:references});await advance();return;
  }
  if(canonical(record.snapshot.escrows.short)!==canonical(notice.reference))throw Error('The second escrow reference changed.');
  await claim(record);
 }
 async function advance(){
  const localEpoch=++epoch,id=viewId,index=readIndex(id);if(!index){await showUnstarted(id);return;}
  const existing=await getSession(await deriveSessionId(id,index.reservation),index.role);refundAvailable=!!existing?.snapshot.escrows[index.role==='owner'?'long':'short'];
  if(!starter||starter.session!==await deriveSessionId(id,index.reservation)||starter.role!==index.role)starter=await makeStarter(id,index);
  let result;
  try{result=await starter.advance();}
  catch(error){
   if(index.role==='taker'&&/unauthori[sz]ed|not found/i.test(error?.message||'')){
    const panel=screen('The other person or connection','Waiting for the maker or unable to access the session','Refresh after the offer maker accepts. If this continues, the reservation may have expired or the service may be unavailable.');refreshButton(panel);return;
   }
   throw error;
  }
  if(localEpoch!==epoch)return;
  if(result.stage==='waiting-for-other'){const panel=screen('The other person','Waiting for their session setup','The other participant’s setup has not been seen yet. Refresh after they join.');refreshButton(panel);return;}
  if(result.stage==='backup-required'){await initialBackup();return;}
  let record=await getSession(starter.session,starter.role);if(!record)throw Error('The saved swap session is unavailable.');
  if(!await starter.outbox.exists()){
   const frames=await readSessionFrames({session:record.session,credential:record.snapshot.credential,api:d.api});
   await starter.outbox.restore({snapshot:record.snapshot,publicKey:record.publicKey,frames,now:now()});
  }
  let outbox=await starter.outbox.inspect();
  if(outbox.pending){record=await retrySessionMessage({session:record.session,role:record.role,outbox:starter.outbox,readFrames:args=>readSessionFrames({...args,api:d.api}),now:now()});}
  else if(record.snapshot.transport.next!==outbox.next||record.snapshot.transport.previous!==outbox.previous)record=await syncSessionTransport({session:record.session,role:record.role,outbox:starter.outbox,readFrames:args=>readSessionFrames({...args,api:d.api}),now:now()});
  outbox=await starter.outbox.inspect();
  const ownField=record.role==='owner'?'ownerBlob':'takerBlob',peerField=record.role==='owner'?'takerBlob':'ownerBlob';
  if(record.snapshot[ownField]&&outbox.next===(record.role==='owner'?1:2))record=await publishSessionParticipant({session:record.session,role:record.role,outbox:starter.outbox,readFrames:args=>readSessionFrames({...args,api:d.api}),now:now()});
  const peer=await findPeer(record);
  if(peer&&record.snapshot[peerField]===null)record=await updateSession(record.session,record.role,record.revision,{...record.snapshot,[peerField]:peer});
  else if(peer&&canonical(JSON.parse(peer))!==canonical(JSON.parse(record.snapshot[peerField])))throw Error('The other participant’s signed details changed.');
  if(!record.backupAcknowledged&&(record.snapshot[ownField]||record.revision===1)){await showBackup(record);return;}
  if(reviewRestoredWallets(record,advance))return;
  if(!record.snapshot[ownField]){await ownProof(record);return;}
  const mine=await participantCode(record.snapshot[ownField]);
  if(!record.snapshot[peerField]){const panel=screen('The other person','Waiting for their signed details','Share your code through a separate trusted channel. Refresh after they sign. Your code: '+mine);refreshButton(panel);return;}
  const theirs=await participantCode(record.snapshot[peerField]),saved=localStorage.getItem(pinKey(record.session,record.role));
  if(saved!==theirs){
   if(saved)throw Error('The other participant’s verification code changed.');
   const panel=screen('You','Confirm the other person’s code',`Your code: ${mine}. Their code shown here: ${theirs}. Compare codes through a separate trusted channel before continuing.`);
   const label=el('label','Code they gave you'),input=el('input');input.autocomplete='off';input.maxLength=16;label.append(input);panel.append(label);
   panel.append(button('Confirm code',async()=>{if(input.value.trim().toLowerCase()!==theirs)throw Error('That code does not match.');localStorage.setItem(pinKey(record.session,record.role),theirs);await advance();}));return;
  }
  await agreement(record);
 }
 document.addEventListener('journey:session-open',event=>{const id=event.detail?.id;if(!HEX.test(id||''))return;viewId=id;draft=null;proofs=[];starter=null;refundAvailable=false;inRefund=false;msg(status,'');void run(advance);});
 $('session-restore-open').addEventListener('click',()=>$('session-restore-dialog').showModal());
 $('session-restore-submit').addEventListener('click',async()=>{
  const submit=$('session-restore-submit'),phrase=$('session-restore-passphrase'),data=$('session-restore-data');submit.disabled=true;msg($('session-restore-status'),'Restoring locally…');
  try{const envelope=JSON.parse(data.value),passphrase=phrase.value;phrase.value='';const restored=await restoreSwapBackup({envelope,passphrase});data.value='';location.hash=restored.offerId;location.reload();}
  catch(error){phrase.value='';msg($('session-restore-status'),error?.message||'Could not restore the encrypted backup.',true);submit.disabled=false;}
 });
 return {open:advance};
}
