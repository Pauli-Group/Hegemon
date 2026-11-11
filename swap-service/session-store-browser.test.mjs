import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {cardanoWallet,ethereumWallet} from '../swap-ui/test-wallets.mjs';
async function port(){const server=createServer();server.listen(0,'127.0.0.1');await once(server,'listening');const p=server.address().port;await new Promise(r=>server.close(r));return p;}

test('session state survives a reload, serializes changes and requires an up-to-date recovery backup',{timeout:90000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-store-')),p=await port(),base=`http://127.0.0.1:${p}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(p)},stdio:'ignore'});
 let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const page=await browser.newPage();await page.goto(base);
  const ids=await page.evaluate(async()=>{
   const {deriveSessionId,sessionOfferDigest}=await import('/session-identity.mjs');
   const {createSessionRecovery}=await import('/session-recovery.mjs');
   const {addSession,acknowledgeSessionBackup}=await import('/session-store.mjs');
   const id='11'.repeat(32),reservation='22'.repeat(32),session=await deriveSessionId(id,reservation),role='owner';
   const offer={id,visibility:'private',expires:1800003600,ownerPublicKey:'04'+'aa'.repeat(64),give:{chain:'cardano',kind:'ada',id:'',amount:'5000000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'100000000000000000'}};
   const snapshot={version:1,offer,offerDigest:await sessionOfferDigest(offer),reservation,credential:'33'.repeat(32),channelKey:'44'.repeat(32),sessionExpires:1800100000,terms:null,escrows:{long:null,short:null},secretEnvelope:null,ownerBlob:null,takerBlob:null};
   const created=await createSessionRecovery({session,role,snapshot,passphrase:'a disposable test passphrase'});
   const record=await addSession(created.envelope,'a disposable test passphrase');
   if(record.privateKey.extractable||record.backupAcknowledged)throw Error('Initial key or backup state was incorrect.');
   await acknowledgeSessionBackup(session,role,record.revision);
   return {session,role};
  });
  await page.reload();
  const result=await page.evaluate(async({session,role})=>{
   const {getSession,updateSession,setSessionBackup,acknowledgeSessionBackup,addSession}=await import('/session-store.mjs');
   const {updateSessionRecovery}=await import('/session-recovery.mjs');
   const record=await getSession(session,role);
   if(!record||record.privateKey.extractable||!record.backupAcknowledged)throw Error('Reload did not restore the acknowledged session.');
   let duplicate=false;try{await addSession(record.envelope,'a disposable test passphrase');}catch{duplicate=true;}
   const snapshot={...record.snapshot,ownerBlob:'signed participant record'};
   const next=await updateSession(session,role,record.revision,snapshot);
   let staleAck=false;try{await acknowledgeSessionBackup(session,role,next.revision);}catch{staleAck=true;}
   let oldRevision=false;try{await updateSession(session,role,record.revision,snapshot);}catch{oldRevision=true;}
   const envelope=await updateSessionRecovery(record.envelope,'a disposable test passphrase',snapshot);
   const prepared=await setSessionBackup(session,role,next.revision,envelope,'a disposable test passphrase');
   const acknowledged=await acknowledgeSessionBackup(session,role,prepared.revision);
   let replacement=false;try{await updateSession(session,role,acknowledged.revision,{...snapshot,ownerBlob:'different participant record'});}catch{replacement=true;}
   const concurrent=await Promise.allSettled([
    updateSession(session,role,acknowledged.revision,{...snapshot,takerBlob:'first'}),
    updateSession(session,role,acknowledged.revision,{...snapshot,takerBlob:'second'}),
   ]);
   const after=await getSession(session,role);
   return {duplicate,staleAck,oldRevision,replacement,ack:acknowledged.backupAcknowledged,revision:acknowledged.revision,privateKeyExtractable:acknowledged.privateKey.extractable,concurrent:concurrent.map(x=>x.status).sort(),afterRevision:after.revision,afterAck:after.backupAcknowledged};
  },ids);
  assert.deepEqual(result,{duplicate:true,staleAck:true,oldRevision:true,replacement:true,ack:true,revision:5,privateKeyExtractable:false,concurrent:['fulfilled','rejected'],afterRevision:6,afterAck:false});
  const gate=await page.evaluate(async()=>{
   const {deriveSessionId,sessionOfferDigest}=await import('/session-identity.mjs');
   const {createSessionRecovery}=await import('/session-recovery.mjs');
   const {createRecovery}=await import('/recovery.mjs');
   const {addSession,acknowledgeSessionBackup,sessionFundingPrerequisites}=await import('/session-store.mjs');
   const id='aa'.repeat(32),reservation='bb'.repeat(32),session=await deriveSessionId(id,reservation),role='owner',phrase='a disposable test passphrase';
   const give={chain:'cardano',kind:'ada',id:'',amount:'5000000'},receive={chain:'ethereum',kind:'eth',id:'',amount:'100000000000000000'};
   const offer={id,visibility:'private',expires:1800003600,ownerPublicKey:'04'+'aa'.repeat(64),give,receive},secretEnvelope=await createRecovery(phrase);
   const terms={version:2,hashlock:secretEnvelope.hashlock,legs:{long:{asset:give,network:'preview',refundee:'11'.repeat(28),claimant:'22'.repeat(28),expiry:1800010000},short:{asset:receive,network:'sepolia',refundee:'0x'+'33'.repeat(20),claimant:'0x'+'44'.repeat(20),expiry:1800005000}}};
   const blank=()=>({fund:[],claim:[],refund:[]});
   const snapshot={version:3,offer,offerDigest:await sessionOfferDigest(offer),reservation,credential:'33'.repeat(32),channelKey:'44'.repeat(32),sessionExpires:1800100000,terms,escrows:{long:null,short:null},secretEnvelope,ownerBlob:'owner',takerBlob:'taker',transport:{next:1,previous:null},actions:{long:blank(),short:blank()}};
   const recovery=await createSessionRecovery({session,role,snapshot,passphrase:phrase}),created=await addSession(recovery.envelope,phrase);
   const outbox={next:1,previous:null,pending:false};
   let noBackup=false;try{await sessionFundingPrerequisites({session,role,revision:created.revision,outbox,actions:[]});}catch{noBackup=true;}
   const ready=await acknowledgeSessionBackup(session,role,created.revision);
   const ok=await sessionFundingPrerequisites({session,role,revision:ready.revision,outbox,actions:[]});
   let pending=false;try{await sessionFundingPrerequisites({session,role,revision:ready.revision,outbox:{...outbox,pending:true},actions:[]});}catch{pending=true;}
   let uncertain=false;try{await sessionFundingPrerequisites({session,role,revision:ready.revision,outbox,actions:[{chain:'cardano',operation:'lock',state:'uncertain',request:{hashlock:terms.hashlock}}]});}catch{uncertain=true;}
   let submitted=false;try{await sessionFundingPrerequisites({session,role,revision:ready.revision,outbox,actions:[{chain:'cardano',operation:'lock',state:'completed',request:{hashlock:terms.hashlock},receipt:{submitted:true}}]});}catch{submitted=true;}
   return {noBackup,ready:ok.backupAcknowledged,pending,uncertain,submitted};
  });
  assert.deepEqual(gate,{noBackup:true,ready:true,pending:true,uncertain:true,submitted:true});
 }finally{await browser?.close();server.kill('SIGTERM');await Promise.race([once(server,'exit'),new Promise(r=>setTimeout(r,2000))]);await rm(dir,{recursive:true,force:true});}
});

test('a signed two-wallet participant survives a lost relay response and browser refresh',{timeout:90000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-coordination-')),p=await port(),base=`http://127.0.0.1:${p}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(p)},stdio:'ignore'});
 let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const context=await browser.newContext(),cardano=cardanoWallet('01'.repeat(32)),ethereum=ethereumWallet('02'.repeat(32));
  await context.exposeFunction('__testCardanoSign',(address,payload)=>cardano.signData(address,payload));
  await context.exposeFunction('__testEthereumSign',payload=>ethereum.personalSign(payload));
  const page=await context.newPage();await page.goto(base);
  const result=await page.evaluate(async({cardanoAddress,cardanoKey,ethAddress})=>{
   const {deriveSessionId,sessionOfferDigest,participantText}=await import('/session-identity.mjs');
   const {createSessionRecovery}=await import('/session-recovery.mjs');
   const {participantDraft,participantStatement,addSessionProof,completeParticipant}=await import('/session-participant.mjs');
   const {signCardano,signEthereum}=await import('/identity-flow.mjs');
   const {addSession,updateSession}=await import('/session-store.mjs');
   const {sessionOutbox}=await import('/session-outbox.mjs');
   const {publishSessionParticipant,retrySessionMessage}=await import('/session-coordination.mjs');
   const now=Math.floor(Date.now()/1000),id='cc'.repeat(32),reservation='dd'.repeat(32),session=await deriveSessionId(id,reservation),role='owner';
   const offer={id,visibility:'private',expires:now+3600,ownerPublicKey:'04'+'aa'.repeat(64),give:{chain:'cardano',kind:'ada',id:'',amount:'5000000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'100000000000000000'}};
   const snapshot={version:2,offer,offerDigest:await sessionOfferDigest(offer),reservation,credential:'33'.repeat(32),channelKey:'44'.repeat(32),sessionExpires:now+7*86400,terms:null,escrows:{long:null,short:null},secretEnvelope:null,ownerBlob:null,takerBlob:null,transport:{next:1,previous:null}};
   const envelope=(await createSessionRecovery({session,role,snapshot,passphrase:'a disposable test passphrase'})).envelope;
   let record=await addSession(envelope,'a disposable test passphrase');
   const draft=await participantDraft({session,role,snapshot,publicKey:record.publicKey,now}),statement=participantStatement(draft,{give:cardanoKey,receive:ethAddress}),text=participantText(statement);
   const ada={getUsedAddresses:async()=>[cardanoAddress],signData:(a,p)=>window.__testCardanoSign(a,p)},eth={request:({params})=>window.__testEthereumSign(params[0])};
   let proofs=addSessionProof(statement,draft.assets,[],await signCardano(ada,text));proofs=addSessionProof(statement,draft.assets,proofs,await signEthereum(eth,ethAddress,text));
   const blob=await completeParticipant(draft,statement,proofs,now);
   record=await updateSession(session,role,record.revision,{...snapshot,ownerBlob:blob});
   const frames=[];let lost=true;
   const send=async frame=>{const existing=frames.find(item=>item.sender===role&&item.sequence===frame.sequence);if(existing){if(existing.ciphertext!==frame.ciphertext)throw Error('conflicting retry');return {id:1,duplicate:true};}frames.push({id:1,sender:role,...frame});if(lost){lost=false;throw Error('response lost');}return {id:1,duplicate:false};};
   const outbox=sessionOutbox({session,role,send}),readFrames=async()=>frames;
   let failed=false;try{await publishSessionParticipant({session,role,outbox,readFrames,now});}catch{failed=true;}
   const pending=await outbox.inspect();
   const synced=await retrySessionMessage({session,role,outbox,readFrames,now});
   let duplicate=false;try{await publishSessionParticipant({session,role,outbox,readFrames,now});}catch{duplicate=true;}
   return {session,role,failed,pending:pending.pending,frames:frames.length,next:synced.snapshot.transport.next,backupAcknowledged:synced.backupAcknowledged,duplicate};
  },{cardanoAddress:cardano.addressHex,cardanoKey:cardano.keyHash,ethAddress:ethereum.address});
  assert.deepEqual({...result,session:undefined,role:undefined},{session:undefined,role:undefined,failed:true,pending:true,frames:1,next:2,backupAcknowledged:false,duplicate:true});
  await page.reload();
  const state=await page.evaluate(async({session,role})=>{
   const {getSession}=await import('/session-store.mjs'),{sessionOutbox}=await import('/session-outbox.mjs');
   const record=await getSession(session,role),outbox=sessionOutbox({session,role,send:async()=>{throw Error('not called');}});
   return {storedNext:record.snapshot.transport.next,outboxNext:(await outbox.inspect()).next,hasSignedStatement:!!record.snapshot.ownerBlob};
  },result);
  assert.deepEqual(state,{storedNext:2,outboxNext:2,hasSignedStatement:true});
 }finally{await browser?.close();server.kill('SIGTERM');await Promise.race([once(server,'exit'),new Promise(r=>setTimeout(r,2000))]);await rm(dir,{recursive:true,force:true});}
});
