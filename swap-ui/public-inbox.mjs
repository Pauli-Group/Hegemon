/** Encrypted public-offer key handoff. This module alone does not authenticate anyone: identity.mjs binds the inbox key
 * fingerprint to a wallet-signed statement so a relay substituting keys is detected, and it cannot protect against a
 * relay that serves modified client code (see the integrity manifest and scripts/verify_hosted_client.mjs). */
import {sealInboxKey,openInboxBackup} from './inbox-backup.mjs';
const enc=new TextEncoder(),dec=new TextDecoder('utf-8',{fatal:true});
const DB='hegemon.local.offer-inbox.v1',STORE='keys';
const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
const bytes=value=>Uint8Array.from(value.match(/../g)||[],x=>parseInt(x,16));
const id=v=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const pub=v=>typeof v==='string'&&/^04[0-9a-f]{128}$/.test(v);
const b64=v=>btoa(Array.from(v,x=>String.fromCharCode(x)).join(''));
const unb64=v=>Uint8Array.from(atob(v),x=>x.charCodeAt(0));
function checkIds(offer,reservation){if(!id(offer)||!id(reservation))throw Error('Invalid offer session.');}
async function publicKey(raw){if(!pub(raw))throw Error('Invalid inbox public key.');return crypto.subtle.importKey('raw',bytes(raw),{name:'ECDH',namedCurve:'P-256'},true,[]);}
async function derive(privateKey,other,offer,reservation){
 const shared=new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:other},privateKey,256));
 try{const material=await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveKey']);const salt=await crypto.subtle.digest('SHA-256',enc.encode(offer+':'+reservation));
  return await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:enc.encode('hegemon.swap.public-inbox.v1')},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 }finally{shared.fill(0);}
}
function aad(offer,reservation,owner,ephemeral){return enc.encode(['hegemon.swap.public-inbox.v1',offer,reservation,owner,ephemeral].join(':'));}
export async function makeInboxKeyPair(){const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const publicBytes=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey));return {publicKey:hex(publicBytes),privateKey:pair.privateKey};}
const ECDH_P256={name:'ECDH',namedCurve:'P-256'};
/** True only if `privateKey` is the private half of the raw public key `publicKeyHex`: both sides derive the same secret
 * with a fresh ephemeral key. */
export async function keyMatches(privateKey,publicKeyHex){
 try{
  const ephemeral=await crypto.subtle.generateKey(ECDH_P256,false,['deriveBits']);
  const [a,b]=await Promise.all([crypto.subtle.deriveBits({name:'ECDH',public:await publicKey(publicKeyHex)},ephemeral.privateKey,256),crypto.subtle.deriveBits({name:'ECDH',public:ephemeral.publicKey},privateKey,256)]);
  return hex(new Uint8Array(a))===hex(new Uint8Array(b));
 }catch{return false;}
}
/** A fresh inbox key pair that can be backed up once: generated extractable, its PKCS#8 bytes returned for sealing, and the
 * private key re-imported non-extractable for storage. The caller zeroes `pkcs8`. */
export async function makeBackedInboxKeyPair(){
 const pair=await crypto.subtle.generateKey(ECDH_P256,true,['deriveBits']);
 const pkcs8=new Uint8Array(await crypto.subtle.exportKey('pkcs8',pair.privateKey)),raw=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey));
 const privateKey=await crypto.subtle.importKey('pkcs8',pkcs8,ECDH_P256,false,['deriveBits']);
 return {publicKey:hex(raw),privateKey,pkcs8};
}
export async function inboxFingerprint(value){if(!pub(value))throw Error('Invalid inbox public key.');return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes(value))));}
export async function sealPublicSession(owner,offer,reservation,sessionKey){
 checkIds(offer,reservation);if(!pub(owner)||!id(sessionKey))throw Error('Invalid public offer key.');
 const pair=await makeInboxKeyPair(),iv=crypto.getRandomValues(new Uint8Array(12)),plain=bytes(sessionKey);
 try{const key=await derive(pair.privateKey,await publicKey(owner),offer,reservation);
  const cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(offer,reservation,owner,pair.publicKey)},key,plain));
  return b64(enc.encode(JSON.stringify({version:1,type:'public-session',offer,reservation,ephemeral:pair.publicKey,iv:hex(iv),ciphertext:hex(cipher)})));
 }finally{plain.fill(0);iv.fill(0);}
}
export function parsePublicSession(encoded){
 try{if(typeof encoded!=='string'||encoded.length>4096)return null;const value=JSON.parse(dec.decode(unb64(encoded)));
  if(!value||Object.keys(value).sort().join(',')!=='ciphertext,ephemeral,iv,offer,reservation,type,version'||value.version!==1||value.type!=='public-session'||!id(value.offer)||!id(value.reservation)||!pub(value.ephemeral)||typeof value.iv!=='string'||!/^[0-9a-f]{24}$/.test(value.iv)||typeof value.ciphertext!=='string'||!/^[0-9a-f]{96}$/.test(value.ciphertext))return null;
  return value;
 }catch{return null;}
}
export async function openPublicSession(privateKey,owner,offer,reservation,encoded){
 checkIds(offer,reservation);const value=parsePublicSession(encoded);
 if(!value||value.offer!==offer||value.reservation!==reservation||!pub(owner)||!privateKey||privateKey.type!=='private'||privateKey.extractable)throw Error('Invalid public offer handshake.');
 const key=await derive(privateKey,await publicKey(value.ephemeral),offer,reservation);
 try{const plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(value.iv),additionalData:aad(offer,reservation,owner,value.ephemeral)},key,bytes(value.ciphertext)));
  try{if(plain.length!==32)throw Error('Invalid public offer handshake.');return hex(plain);}finally{plain.fill(0);}
 }catch{throw Error('Could not authenticate public offer handshake.');}
}
function openDatabase(){return new Promise((resolve,reject)=>{let blocked=false;const request=indexedDB.open(DB,1);
 request.onupgradeneeded=()=>request.result.createObjectStore(STORE,{keyPath:'publicKey'});request.onerror=()=>reject(Error('Offer inbox storage is unavailable.'));
 request.onblocked=()=>{blocked=true;reject(Error('Offer inbox storage is blocked by another tab.'));};
 request.onsuccess=()=>{const db=request.result;if(blocked){db.close();return;}db.onversionchange=()=>db.close();resolve(db);};
});}
async function locked(action){if(!navigator.locks?.request)throw Error('Browser storage locking is unavailable.');return navigator.locks.request(DB,{mode:'exclusive'},async()=>{const db=await openDatabase();try{return await action(db);}finally{db.close();}});}
function transaction(db,mode,run){return new Promise((resolve,reject)=>{const tx=db.transaction(STORE,mode),store=tx.objectStore(STORE);let result,failure;const req=run(store);
 req.onsuccess=()=>{try{result=req.result;}catch(e){failure=e;tx.abort();}};tx.oncomplete=()=>resolve(result);tx.onabort=()=>reject(failure||Error('Offer inbox storage transaction failed.'));tx.onerror=()=>{};
});}
export async function createInbox(){const pair=await makeInboxKeyPair();await locked(db=>transaction(db,'readwrite',store=>store.add(pair)));return pair.publicKey;}
/** Create an owner inbox key that can be restored: seals it under `passphrase` first (so a bad passphrase creates nothing),
 * stores the non-extractable key, and returns `{publicKey, backup}` where `backup` is the encrypted envelope to save. */
export async function createInboxWithBackup(passphrase){
 const pair=await makeBackedInboxKeyPair();
 try{
  const backup=await sealInboxKey(pair.pkcs8,pair.publicKey,passphrase);
  await locked(db=>transaction(db,'readwrite',store=>store.add({publicKey:pair.publicKey,privateKey:pair.privateKey})));
  return {publicKey:pair.publicKey,backup};
 }finally{pair.pkcs8.fill(0);}
}
/** Restore a backed-up inbox key into this browser. Fails closed on a wrong passphrase or altered envelope, on a key that
 * does not match its public key, and when a different key is already stored under that public key (never overwritten).
 * Restoring a key that is already present changes nothing. */
export async function restoreInbox(envelope,passphrase){
 const {publicKey:owner,pkcs8}=await openInboxBackup(envelope,passphrase);
 let privateKey;
 try{privateKey=await crypto.subtle.importKey('pkcs8',pkcs8,ECDH_P256,false,['deriveBits']);}catch{throw Error('The inbox key backup does not contain a valid key.');}finally{pkcs8.fill(0);}
 if(!await keyMatches(privateKey,owner))throw Error('The inbox key backup does not match its public key.');
 return locked(async db=>{
  const existing=await transaction(db,'readonly',store=>store.get(owner));
  if(existing){
   if(existing.publicKey!==owner||!existing.privateKey||existing.privateKey.extractable||!await keyMatches(existing.privateKey,owner))throw Error('A different inbox key is already stored for this public key; it was not replaced.');
   return {publicKey:owner,restored:false};
  }
  await transaction(db,'readwrite',store=>store.add({publicKey:owner,privateKey}));
  return {publicKey:owner,restored:true};
 });
}
export async function inboxPrivateKey(owner){if(!pub(owner))throw Error('Invalid inbox public key.');const item=await locked(db=>transaction(db,'readonly',store=>store.get(owner)));
 if(!item||item.publicKey!==owner||!item.privateKey||item.privateKey.type!=='private'||item.privateKey.extractable||item.privateKey.algorithm?.name!=='ECDH'||item.privateKey.algorithm?.namedCurve!=='P-256')throw Error('Private offer inbox key is unavailable in this browser.');return item.privateKey;}
