/** Encrypted public-offer key handoff. This does not authenticate wallet
 * identities or protect against a relay that substitutes keys or client code. */
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
export async function inboxPrivateKey(owner){if(!pub(owner))throw Error('Invalid inbox public key.');const item=await locked(db=>transaction(db,'readonly',store=>store.get(owner)));
 if(!item||item.publicKey!==owner||!item.privateKey||item.privateKey.type!=='private'||item.privateKey.extractable||item.privateKey.algorithm?.name!=='ECDH'||item.privateKey.algorithm?.namedCurve!=='P-256')throw Error('Private offer inbox key is unavailable in this browser.');return item.privateKey;}
