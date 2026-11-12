import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {ethereumWallet} from '../swap-ui/test-wallets.mjs';
import {SEPOLIA_GENESIS} from '../swap-ui/sepolia-verifier.mjs';
import {HEGEMON_GENESIS,HEGEMON_CHAIN_ID} from '../swap-ui/session-hegemon-read.mjs';
async function port(){const s=createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const p=s.address().port;await new Promise(r=>s.close(r));return p;}

for(const scenario of ['confirmed','lost-submit','lost-proof'])test(`Hegemon funding: ${scenario} keeps recovery and never silently retries`,{timeout:60000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'hegemon-fund-')),p=await port(),base=`http://127.0.0.1:${p}`;
 const server=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(p)},stdio:'ignore'});let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-gpu','--disable-background-networking']});
  const context=await browser.newContext(),ethA=ethereumWallet('03'.repeat(32)),ethB=ethereumWallet('04'.repeat(32));
  await context.exposeFunction('__signEth',(who,hex)=>(who==='owner'?ethA:ethB).personalSign(hex));
  const page=await context.newPage();await page.goto(base);
  const result=await page.evaluate(async fixture=>{
   const {deriveSessionId,sessionOfferDigest,participantText,buildParticipant,serializeParticipant}=await import('/session-identity.mjs');
   const {createSessionRecovery,updateSessionRecovery}=await import('/session-recovery.mjs'),{addSession,updateSession,setSessionBackup,acknowledgeSessionBackup,getSession}=await import('/session-store.mjs');
   const {createProtocolKey,signPacket,sessionTermsDigest}=await import('/session-packets.mjs'),{channelFingerprint,sealParticipantFrame,sealPacketFrame}=await import('/session-channel.mjs');
   const {signEthereum}=await import('/identity-flow.mjs'),{participantCode}=await import('/session-participant.mjs'),{createRecovery}=await import('/recovery.mjs'),{planWithMargin}=await import('/swap-flow.mjs');
   const {prepareFundingAttempt,hegemonConsentKey}=await import('/session-action.mjs'),{prepareHegemonSessionFund,submitHegemonSessionFund,observeHegemonSessionFunding}=await import('/session-hegemon-funding.mjs');
   const timing=await (await fetch('/chain-timing.json')).json(),now=Math.floor(Date.now()/1000),id='11'.repeat(32),reservation='22'.repeat(32),session=await deriveSessionId(id,reservation),role='owner',channelKey='33'.repeat(32),channelDigest=await channelFingerprint(session,channelKey),sessionExpires=now+30*86400,passphrase='disposable test passphrase';
   const hgnA='shca1'+'q'.repeat(100),hgnB='shca1'+'p'.repeat(100),offer={id,visibility:'private',expires:now+3600,ownerPublicKey:'04'+'aa'.repeat(64),give:{chain:'hegemon',kind:'hgn',id:'',amount:'100000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'100000000000000'}},offerDigest=await sessionOfferDigest(offer),blank=()=>({fund:[],claim:[],refund:[]}),empty=()=>({fund:null,claim:null,refund:null});
   const snapshot={version:4,offer,offerDigest,reservation,credential:'44'.repeat(32),channelKey,sessionExpires,terms:null,escrows:{long:null,short:null},secretEnvelope:null,ownerBlob:null,takerBlob:null,transport:{next:1,previous:null},actions:{long:blank(),short:blank()},hegemon:{long:empty(),short:empty()}};
   let record=await addSession((await createSessionRecovery({session,role,snapshot,passphrase})).envelope,passphrase),peer=await createProtocolKey();
   async function certificate(who,publicKey){const addresses=who==='owner'?{give:hgnA,receive:fixture.ethA}:{give:hgnB,receive:fixture.ethB},statement=buildParticipant({session,offer:id,reservation,role:who,offerDigest,channelDigest,protocolKey:publicKey,addresses,issued:now,expires:sessionExpires},offer),text=participantText(statement);return serializeParticipant(statement,[await signEthereum({request:({params})=>window.__signEth(who,params[0])},addresses.receive,text)]);}
   const ownerBlob=await certificate('owner',record.publicKey),takerBlob=await certificate('taker',peer.publicKey),secretEnvelope=await createRecovery(passphrase),heads={long:{height:10000,observedAt:now},short:{timestamp:now,observedAt:now}},plan=planWithMargin(timing,'hegemon','ethereum',heads,now);
   const terms={version:2,hashlock:secretEnvelope.hashlock,legs:{long:{asset:offer.give,network:'pre-mainnet',refundee:hgnA,claimant:hgnB,expiry:plan.long.expiry},short:{asset:offer.receive,network:'sepolia',refundee:fixture.ethB,claimant:fixture.ethA,expiry:plan.short.expiry}}};
   record=await updateSession(session,role,record.revision,{...record.snapshot,terms,secretEnvelope,ownerBlob,takerBlob,transport:{next:3,previous:'55'.repeat(32)}});
   async function backup(){const r=await getSession(session,role),e=await updateSessionRecovery(r.envelope,passphrase,r.snapshot),saved=await setSessionBackup(session,role,r.revision,e,passphrase);await acknowledgeSessionBackup(session,role,saved.revision);}
   await backup();localStorage.setItem(`hegemon.swap.peer-pin:${session}:${role}`,await participantCode(takerBlob));localStorage.setItem(hegemonConsentKey(session,role),'accepted');
   const expected={session,role:'taker',offer:id,reservation,offerDigest,channelDigest,assets:{give:offer.give,receive:offer.receive},sessionExpires},participant=await sealParticipantFrame(channelKey,{session,role:'taker',sequence:2},takerBlob,expected,now),packet=await signPacket(peer.privateKey,{session,role:'taker',sequence:1,previous:null,payload:{type:'accept',termsDigest:await sessionTermsDigest(terms)}}),ciphertext=await sealPacketFrame(channelKey,{session,role:'taker',sequence:3},packet,{session,role:'taker',sequence:1,previous:null,publicKey:peer.publicKey});
   const frames=[{sender:'taker',sequence:1,ciphertext:'YWJj'},{sender:'taker',sequence:2,ciphertext:participant},{sender:'taker',sequence:3,ciphertext}],readFrames=async()=>frames,outbox={session,role,inspect:async()=>({pending:false,next:3,previous:'55'.repeat(32)})};let proofs=0,submissions=0;
   let mined=false;const readers={hegemon:{head:async()=>({genesis:fixture.hgnGenesis,chain_id:fixture.hgnChain,height:10000}),escrow:async()=>{throw Error('not needed');},inclusion:async()=>mined?{state:'confirmed',actionId:'88'.repeat(48),blockHeight:9998}:{state:'pending',actionId:'88'.repeat(48)},select:async(_amount,_fee,exclude)=>exclude.length?{inputs:['8'],total:'101000',syncedHeight:10000}:{inputs:['7'],total:'1000',syncedHeight:10000},action:async request=>{if(request.operation==='lock'){proofs++;if(fixture.scenario==='lost-proof')throw Error('lost response');return {operation:'lock',attempt:'66'.repeat(32),refund_handoff:'77'.repeat(16)+'.bin',submitted:false};}submissions++;if(fixture.scenario==='lost-submit')throw Error('lost response');return {operation:'submit',attempt:'66'.repeat(32),txid:'88'.repeat(48),submitted:true};}},ethereum:{provider:{request:async({method,params=[]})=>{if(method==='eth_chainId')return '0xaa36a7';if(method==='eth_getBlockByNumber')return params[0]==='0x0'?{hash:fixture.ethGenesis}:{timestamp:'0x'+now.toString(16)};throw Error('unexpected RPC');}}}};
   const attempt=await prepareFundingAttempt({session,role,outbox});await backup();const opts={session,role,attemptId:attempt.id,outbox,readFrames,readers,config:timing,templates:{},clock:()=>now};
   let proofLost=false,submitLost=false,blocked=false,duplicate=false,proofError='';
   try{await prepareHegemonSessionFund(opts);}catch(error){proofLost=true;proofError=error.message;}
   if(!proofLost){try{await submitHegemonSessionFund(opts);}catch{blocked=true;}await backup();try{await submitHegemonSessionFund(opts);}catch{submitLost=true;}}
   try{if(proofLost)await prepareHegemonSessionFund(opts);else await submitHegemonSessionFund(opts);}catch{duplicate=true;}
   let pending=null,confirmed=null;if(!proofLost){await backup();pending=(await observeHegemonSessionFunding(opts)).state;mined=true;confirmed=(await observeHegemonSessionFunding(opts)).state;}
   const saved=await getSession(session,role);return {proofLost,proofError,submitLost,blocked,duplicate,proofs,submissions,pending,confirmed,state:saved.snapshot.actions.long.fund[0].state,metadata:saved.snapshot.hegemon.long.fund};
  },{ethA:ethA.address,ethB:ethB.address,ethGenesis:SEPOLIA_GENESIS,hgnGenesis:HEGEMON_GENESIS,hgnChain:HEGEMON_CHAIN_ID,scenario});
  assert.equal(result.proofs,1,result.proofError);assert.equal(result.duplicate,true);
  if(scenario==='lost-proof'){assert.equal(result.proofLost,true);assert.equal(result.submissions,0);assert.equal(result.state,'uncertain');}
  else{assert.equal(result.blocked,true);assert.equal(result.submissions,1);assert.equal(result.submitLost,scenario==='lost-submit');assert.equal(result.state,scenario==='lost-submit'?'uncertain':'prepared');assert.equal(result.pending,'pending');assert.equal(result.confirmed,'confirmed');assert.equal(result.metadata.actionId,'88'.repeat(48));assert.equal(result.metadata.blockHeight,'9998');}
 }finally{await browser?.close();server.kill('SIGTERM');await Promise.race([once(server,'exit'),new Promise(r=>setTimeout(r,2000))]);await rm(dir,{recursive:true,force:true});}
});
