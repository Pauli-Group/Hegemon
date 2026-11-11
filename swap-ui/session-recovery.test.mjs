import test from 'node:test';
import assert from 'node:assert/strict';
import {bitcoinMessageWallet,ethereumWallet} from './test-wallets.mjs';
import {createRecovery} from './recovery.mjs';
import {deriveSessionId,sessionOfferDigest} from './session-identity.mjs';
import {signPacket,verifyPacket} from './session-packets.mjs';
import {createSessionRecovery,openSessionRecovery,updateSessionRecovery,validateSessionSnapshot} from './session-recovery.mjs';

const pass='this is a disposable test passphrase',offerId='11'.repeat(32),reservation='22'.repeat(32),now=1800000000;
const ownerBtc=bitcoinMessageWallet('01'.repeat(32)),ownerEth=ethereumWallet('02'.repeat(32)),takerBtc=bitcoinMessageWallet('03'.repeat(32)),takerEth=ethereumWallet('04'.repeat(32));
async function setup(){
 const session=await deriveSessionId(offerId,reservation),offer={id:offerId,visibility:'public',expires:now+3600,ownerPublicKey:'04'+'aa'.repeat(64),
  give:{chain:'bitcoin',kind:'btc',id:'',amount:'100000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'1000000000000000000'}};
 const snapshot={version:1,offer,offerDigest:await sessionOfferDigest(offer),reservation,credential:'33'.repeat(32),channelKey:'44'.repeat(32),sessionExpires:now+86400,
  terms:null,escrows:{long:null,short:null},secretEnvelope:null,ownerBlob:null,takerBlob:null};
 return {session,snapshot};
}

test('an encrypted backup restores the non-extractable protocol key and private session credentials',async()=>{
 const {session,snapshot}=await setup(),created=await createSessionRecovery({session,role:'owner',snapshot,passphrase:pass});
 assert.equal(created.privateKey.extractable,false);
 const text=JSON.stringify(created.envelope);
 for(const value of [snapshot.credential,snapshot.channelKey])assert.equal(text.includes(value),false);
 const restored=await openSessionRecovery(created.envelope,pass);
 assert.equal(restored.privateKey.extractable,false);assert.equal(restored.publicKey,created.publicKey);assert.deepEqual(restored.snapshot,snapshot);
 const packet=await signPacket(restored.privateKey,{session,role:'owner',sequence:1,previous:null,payload:{type:'cancel',reason:'cancelled'}});
 assert.equal((await verifyPacket(packet,{session,role:'owner',sequence:1,previous:null,publicKey:created.publicKey})).body.payload.reason,'cancelled');
});

test('wrong passphrases, changed envelopes, or malformed recovery state fail closed',async()=>{
 const {session,snapshot}=await setup(),created=await createSessionRecovery({session,role:'owner',snapshot,passphrase:pass});
 await assert.rejects(openSessionRecovery(created.envelope,'this is the wrong passphrase'),/Could not unlock/);
 const flip=value=>(value[0]==='a'?'b':'a')+value.slice(1);
 for(const changed of [
  {...created.envelope,session:'55'.repeat(32)}, {...created.envelope,role:'taker'},
  {...created.envelope,salt:flip(created.envelope.salt)}, {...created.envelope,iv:flip(created.envelope.iv)},
  {...created.envelope,publicKey:'04'+'ff'.repeat(64)}, {...created.envelope,ciphertext:flip(created.envelope.ciphertext)},
 ])await assert.rejects(openSessionRecovery(changed,pass),/Could not unlock|Invalid/);
 await assert.rejects(createSessionRecovery({session,role:'owner',snapshot:{...snapshot,credential:[snapshot.credential]},passphrase:pass}),/Invalid swap recovery data/);
 await assert.rejects(createSessionRecovery({session,role:'owner',snapshot:{...snapshot,secret:'plaintext'},passphrase:pass}),/Invalid swap recovery data/);
 await assert.rejects(validateSessionSnapshot({...snapshot,offer:{...snapshot.offer,expires:now+5}},session),/offer or session/);
});

test('recovery updates retain the agreed terms, secret and previously recorded escrow',async()=>{
 const {session,snapshot}=await setup(),created=await createSessionRecovery({session,role:'owner',snapshot,passphrase:pass}),secret=await createRecovery(pass);
 const terms={version:2,hashlock:secret.hashlock,legs:{
  long:{asset:snapshot.offer.give,network:'testnet4',refundee:ownerBtc.publicKey,claimant:takerBtc.publicKey,expiry:150337},
  short:{asset:snapshot.offer.receive,network:'sepolia',refundee:takerEth.address,claimant:ownerEth.address,expiry:1800013951}}};
 const funded={...snapshot,terms,secretEnvelope:secret,escrows:{long:{chain:'bitcoin',txid:'55'.repeat(32),vout:0},short:null}};
 const updated=await updateSessionRecovery(created.envelope,pass,funded),restored=await openSessionRecovery(updated,pass);
 assert.deepEqual(restored.snapshot,funded);assert.equal(updated.publicKey,created.publicKey);
 await assert.rejects(updateSessionRecovery(updated,pass,{...funded,channelKey:'66'.repeat(32)}),/session identity/);
 await assert.rejects(updateSessionRecovery(updated,pass,{...funded,terms:null}),/escrow.*different chain|changes saved/);
 await assert.rejects(updateSessionRecovery(updated,pass,{...funded,escrows:{...funded.escrows,long:null}}),/escrow reference/);
 await assert.rejects(updateSessionRecovery(updated,pass,{...funded,secretEnvelope:null}),/saved secret backup/);
 await assert.rejects(updateSessionRecovery(updated,pass,{...funded,secretEnvelope:{...secret,ciphertext:'00'.repeat(48)}}),/saved secret backup/);
 const wrong=structuredClone(funded);wrong.terms.legs.long.asset={...wrong.terms.legs.long.asset,amount:'1'};
 await assert.rejects(updateSessionRecovery(updated,pass,wrong),/terms do not match/);
});

test('version-2 backups pin a monotonic sent-packet high-water mark',async()=>{
 const {session,snapshot}=await setup(),v2={...snapshot,version:2,transport:{next:1,previous:null}};
 const created=await createSessionRecovery({session,role:'owner',snapshot:v2,passphrase:pass});
 const sent={...v2,transport:{next:3,previous:'aa'.repeat(32)}};
 const saved=await updateSessionRecovery(created.envelope,pass,sent);
 assert.deepEqual((await openSessionRecovery(saved,pass)).snapshot.transport,sent.transport);
 await assert.rejects(updateSessionRecovery(saved,pass,{...sent,transport:{next:2,previous:null}}),/rolls back/);
 await assert.rejects(updateSessionRecovery(saved,pass,{...sent,transport:{next:3,previous:'bb'.repeat(32)}}),/rolls back/);
 await assert.rejects(updateSessionRecovery(saved,pass,{...sent,version:1}),/Invalid swap recovery data/);
 await assert.rejects(validateSessionSnapshot({...v2,transport:{next:1,previous:'aa'.repeat(32)}},session),/Invalid saved packet history/);
});
