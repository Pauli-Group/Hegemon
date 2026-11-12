/** Encrypted recovery for one participant's swap coordination state, not a wallet backup.
 *
 * A protocol key is created extractable only long enough to encrypt its PKCS#8 bytes and re-import it non-extractable.
 * The envelope also protects the relay credential and channel key. Wallet private keys never belong in this backup.
 * After learning terms or escrow references, update the backup before relying on it for recovery. */
import {canonical} from './identity.mjs';
import {deriveSessionId,sessionOfferDigest,checkSessionAsset} from './session-identity.mjs';
import {validateSessionReference,validateSessionTerms} from './session-packets.mjs';
import {validateRecoveryEnvelope} from './recovery.mjs';
import {fromHex,toHex} from './cbor.mjs';
import {validateHegemonRecovery,validateHegemonRecoveryAdvance} from './session-hegemon-recovery.mjs';

const KIND='hegemon.swap.session-recovery',ITERATIONS=600000,MAX_PLAINTEXT=120000;
const HEX64=/^[0-9a-f]{64}$/;
const enc=new TextEncoder(),dec=new TextDecoder('utf-8',{fatal:true});
const keys=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const fail=message=>{throw Error(message);};
const b64=bytes=>btoa(Array.from(bytes,b=>String.fromCharCode(b)).join(''));
function unb64(text){
 if(typeof text!=='string'||text.length%4||text.length>180000||!/^[A-Za-z0-9+/]+={0,2}$/.test(text))fail('Invalid swap recovery backup.');
 let bytes;try{bytes=Uint8Array.from(atob(text),c=>c.charCodeAt(0));}catch{fail('Invalid swap recovery backup.');}
 if(bytes.length<16||b64(bytes)!==text)fail('Invalid swap recovery backup.');return bytes;
}
async function keyFor(passphrase,salt){
 if(typeof passphrase!=='string'||passphrase.length<12||passphrase.length>1024)fail('Use a recovery passphrase of 12 to 1024 characters.');
 const bytes=enc.encode(passphrase);
 try{const material=await crypto.subtle.importKey('raw',bytes,'PBKDF2',false,['deriveKey']);return await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:ITERATIONS},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
 finally{bytes.fill(0);}
}
function aad(meta){return enc.encode([KIND,'1',meta.session,meta.role,meta.publicKey,String(ITERATIONS),meta.salt].join('\n'));}
function envelopeShape(value){
 if(!keys(value,['version','kind','session','role','publicKey','iterations','salt','iv','ciphertext'])||value.version!==1||value.kind!==KIND||typeof value.session!=='string'||!HEX64.test(value.session)||!['owner','taker'].includes(value.role)||typeof value.publicKey!=='string'||!/^04[0-9a-f]{128}$/.test(value.publicKey)||value.iterations!==ITERATIONS||typeof value.salt!=='string'||!/^[0-9a-f]{32}$/.test(value.salt)||typeof value.iv!=='string'||!/^[0-9a-f]{24}$/.test(value.iv))fail('Invalid swap recovery backup.');
 unb64(value.ciphertext);return value;
}

/** Validate the data needed to reconnect or manually recover. All token and amount values remain exact strings. */
export async function validateSessionSnapshot(snapshot,session){
 const version=snapshot?.version,fields=['version','offer','offerDigest','reservation','credential','channelKey','sessionExpires','terms','escrows','secretEnvelope','ownerBlob','takerBlob',...([2,3,4].includes(version)?['transport']:[]),...(version>=3?['actions']:[]),...(version===4?['hegemon']:[])];
 if(!keys(snapshot,fields)||![1,2,3,4].includes(version)||typeof session!=='string'||!HEX64.test(session)||!['reservation','credential','channelKey','offerDigest'].every(name=>typeof snapshot[name]==='string'&&HEX64.test(snapshot[name]))||!Number.isSafeInteger(snapshot.sessionExpires)||snapshot.sessionExpires<1)fail('Invalid swap recovery data.');
 if(version>=2){const t=snapshot.transport;if(!keys(t,['next','previous'])||!Number.isSafeInteger(t.next)||t.next<1||t.next>257||!(t.previous===null||typeof t.previous==='string'&&HEX64.test(t.previous))||t.next===1&&t.previous!==null)fail('Invalid saved packet history.');}
 if(version>=3){
  if(!keys(snapshot.actions,['long','short']))fail('Invalid saved wallet actions.');
  const ids=new Set();
  for(const side of ['long','short']){
   const leg=snapshot.actions[side];if(!keys(leg,['fund','claim','refund']))fail('Invalid saved wallet actions.');
   for(const operation of ['fund','claim','refund']){
    const attempts=leg[operation];if(!Array.isArray(attempts)||attempts.length>16||(!snapshot.terms&&attempts.length)||attempts.slice(0,-1).some(attempt=>attempt?.state!=='declined'))fail('Invalid saved wallet actions.');
    for(const attempt of attempts){
     if(!keys(attempt,['id','state','txid'])||typeof attempt.id!=='string'||!/^[0-9a-f]{32}$/.test(attempt.id)||ids.has(attempt.id)||!['intent','prepared','submitted','declined','uncertain'].includes(attempt.state)||!(attempt.txid===null||typeof attempt.txid==='string'&&HEX64.test(attempt.txid))||['prepared','submitted'].includes(attempt.state)&&attempt.txid===null||['intent','declined'].includes(attempt.state)&&attempt.txid!==null)fail('Invalid saved wallet action.');
     ids.add(attempt.id);
    }
   }
  }
 }
 if(!keys(snapshot.offer,['id','visibility','give','receive','expires','ownerPublicKey'])||await deriveSessionId(snapshot.offer.id,snapshot.reservation)!==session||await sessionOfferDigest(snapshot.offer)!==snapshot.offerDigest)fail('The saved offer or session does not match.');
 for(const name of ['ownerBlob','takerBlob'])if(snapshot[name]!==null&&(typeof snapshot[name]!=='string'||snapshot[name].length>20000))fail('Invalid saved participant statement.');
 if(!keys(snapshot.escrows,['long','short']))fail('Invalid saved escrow references.');
 if(snapshot.terms!==null){
  validateSessionTerms(snapshot.terms);
  if(canonical(snapshot.terms.legs.long.asset)!==canonical(checkSessionAsset(snapshot.offer.give))||canonical(snapshot.terms.legs.short.asset)!==canonical(checkSessionAsset(snapshot.offer.receive)))fail('The saved terms do not match the offer.');
 }
 for(const name of ['long','short'])if(snapshot.escrows[name]!==null){
  validateSessionReference(snapshot.escrows[name]);
  if(!snapshot.terms||snapshot.escrows[name].chain!==snapshot.terms.legs[name].asset.chain)fail('The saved escrow is for a different chain.');
 }
 if(version>=3)for(const side of ['long','short'])for(const operation of ['fund','claim','refund'])for(const attempt of snapshot.actions[side][operation]){
  if(attempt.state==='submitted'&&(!snapshot.escrows[side]||operation==='fund'&&snapshot.escrows[side].txid!==attempt.txid))fail('A submitted wallet action needs its saved escrow reference.');
 }
 if(version===4)validateHegemonRecovery(snapshot);
 if(snapshot.secretEnvelope!==null){
  const secret=validateRecoveryEnvelope(snapshot.secretEnvelope);
  if(snapshot.terms&&secret.hashlock!==snapshot.terms.hashlock)fail('The saved secret backup is for a different swap.');
 }
 return snapshot;
}
/** Preserve the backed-up packet-history high-water mark. A caller must still
 * authenticate the complete signed history before advancing that mark. */
export function validateTransportAdvance(previous,next){
 if(previous.version!==next.version)fail('Recovery update changes the snapshot version.');
 if(previous.version>=2){
  const a=previous.transport,b=next.transport;
  if(b.next<a.next||b.next===a.next&&b.previous!==a.previous||a.previous!==null&&b.previous===null)fail('Recovery update rolls back the saved packet history.');
 }
}
/** Wallet-attempt histories are append-only. Only the latest intent may be
 * resolved, and a new attempt follows an explicit wallet decline only. */
export function validateActionAdvance(previous,next){
 if(previous.version<3)return;
 for(const side of ['long','short'])for(const operation of ['fund','claim','refund']){
  const a=previous.actions[side][operation],b=next.actions[side][operation];
  if(b.length<a.length||b.length>a.length+1)fail('Recovery update changes wallet action history.');
  for(let i=0;i<a.length;i++){
   if(canonical(a[i])===canonical(b[i]))continue;
   if(i!==a.length-1||b.length!==a.length||b[i].id!==a[i].id)fail('Recovery update changes wallet action history.');
   const from=a[i],to=b[i],allowed=from.state==='intent'&&['prepared','submitted','declined','uncertain'].includes(to.state)||from.state==='prepared'&&['submitted','uncertain'].includes(to.state)&&to.txid===from.txid||from.state==='uncertain'&&to.state==='submitted'&&(from.txid===null||to.txid===from.txid);
   if(!allowed)fail('Recovery update changes wallet action history.');
  }
  if(b.length>a.length&&(b.at(-1).state!=='intent'||a.length&&a.at(-1).state!=='declined'))fail('Resolve the previous wallet action before retrying.');
 }
}
async function sameKey(privateKey,publicKey,session){
 try{
  const pub=await crypto.subtle.importKey('raw',fromHex(publicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const challenge=enc.encode(KIND+'\n'+session),signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,challenge);
  return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,signature,challenge);
 }catch{return false;}
}
async function seal(meta,snapshot,pkcs8,passphrase){
 await validateSessionSnapshot(snapshot,meta.session);
 const json=enc.encode(JSON.stringify(snapshot));
 if(json.length+pkcs8.length+4>MAX_PLAINTEXT)fail('Swap recovery data is too large.');
 const plain=new Uint8Array(4+json.length+pkcs8.length),view=new DataView(plain.buffer);view.setUint32(0,json.length,false);plain.set(json,4);plain.set(pkcs8,4+json.length);
 const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
 const outer={version:1,kind:KIND,session:meta.session,role:meta.role,publicKey:meta.publicKey,iterations:ITERATIONS,salt:toHex(salt),iv:toHex(iv)};
 try{
  const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(outer)},await keyFor(passphrase,salt),plain));
  return {...outer,ciphertext:b64(ciphertext)};
 }finally{json.fill(0);plain.fill(0);salt.fill(0);iv.fill(0);}
}
async function decrypt(envelope,passphrase){
 envelopeShape(envelope);
 const cipher=unb64(envelope.ciphertext),salt=fromHex(envelope.salt),iv=fromHex(envelope.iv);let plain;
 try{plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:aad(envelope)},await keyFor(passphrase,salt),cipher));}
 catch{fail('Could not unlock the swap recovery backup.');}
 finally{cipher.fill(0);salt.fill(0);iv.fill(0);}
 try{
  if(plain.length<5||plain.length>MAX_PLAINTEXT)fail('Invalid swap recovery backup.');
  const length=new DataView(plain.buffer,plain.byteOffset,plain.byteLength).getUint32(0,false);
  if(length<2||length>plain.length-5)fail('Invalid swap recovery backup.');
  let snapshot;try{snapshot=JSON.parse(dec.decode(plain.slice(4,4+length)));}catch{fail('Invalid swap recovery backup.');}
  await validateSessionSnapshot(snapshot,envelope.session);
  const pkcs8=plain.slice(4+length);let privateKey;
  try{privateKey=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);}
  catch{pkcs8.fill(0);fail('Invalid swap recovery key.');}
  if(!await sameKey(privateKey,envelope.publicKey,envelope.session)){pkcs8.fill(0);fail('The swap recovery key does not match.');}
  return {snapshot,privateKey,pkcs8};
 }finally{plain.fill(0);}
}

/** Create an encrypted backup and return a non-extractable key for this browser. */
export async function createSessionRecovery({session,role,snapshot,passphrase}){
 if(typeof session!=='string'||!HEX64.test(session)||!['owner','taker'].includes(role))fail('Invalid session identity.');
 await validateSessionSnapshot(snapshot,session);
 const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const pkcs8=new Uint8Array(await crypto.subtle.exportKey('pkcs8',pair.privateKey)),publicKey=toHex(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)));
 try{
  const privateKey=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  return {privateKey,publicKey,envelope:await seal({session,role,publicKey},snapshot,pkcs8,passphrase)};
 }finally{pkcs8.fill(0);}
}
/** Restore without exposing extractable key bytes. Restoring never modifies existing browser records. */
export async function openSessionRecovery(envelope,passphrase){
 const value=await decrypt(envelope,passphrase);
 try{return {privateKey:value.privateKey,publicKey:envelope.publicKey,snapshot:value.snapshot};}finally{value.pkcs8.fill(0);}
}
/** Update a backup without silently replacing agreed terms, identities, or previously recorded escrow references. */
export async function updateSessionRecovery(envelope,passphrase,snapshot){
 const previous=await decrypt(envelope,passphrase);
 try{
  await validateSessionSnapshot(snapshot,envelope.session);
  for(const name of ['offer','offerDigest','reservation','credential','channelKey','sessionExpires'])if(canonical(snapshot[name])!==canonical(previous.snapshot[name]))fail('Recovery update changes the session identity.');
  validateTransportAdvance(previous.snapshot,snapshot);
  validateActionAdvance(previous.snapshot,snapshot);
  validateHegemonRecoveryAdvance(previous.snapshot,snapshot);
  for(const name of ['terms','ownerBlob','takerBlob'])if(previous.snapshot[name]!==null&&canonical(snapshot[name])!==canonical(previous.snapshot[name]))fail('Recovery update changes saved swap terms or participants.');
  for(const name of ['long','short'])if(previous.snapshot.escrows[name]!==null&&canonical(snapshot.escrows[name])!==canonical(previous.snapshot.escrows[name]))fail('Recovery update changes a saved escrow reference.');
  if(previous.snapshot.secretEnvelope!==null&&canonical(snapshot.secretEnvelope)!==canonical(previous.snapshot.secretEnvelope))fail('Recovery update changes the saved secret backup.');
  return await seal({session:envelope.session,role:envelope.role,publicKey:envelope.publicKey},snapshot,previous.pkcs8,passphrase);
 }finally{previous.pkcs8.fill(0);}
}
