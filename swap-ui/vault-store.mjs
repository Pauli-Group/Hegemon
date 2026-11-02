/** Transactional local storage for encrypted preimages. It never stores the
 * passphrase or plaintext. Legacy localStorage entries are migrated under the
 * same cross-tab lock and are removed only after a successful transaction. */
import {validateRecoveryEnvelope} from './recovery.mjs';
const LEGACY_KEY='hegemon.local.encrypted-secrets.v1';
const DATABASE='hegemon.local.encrypted-secrets.v2';
const STORE='encrypted-secrets';

export function vaultLabel(value){
 if(typeof value!=='string'||!value.trim()||value.length>80||/[\u0000-\u001f\u007f]/.test(value))throw Error('Invalid backup label.');
 return value.trim();
}
function entry(value){
 if(!value||typeof value!=='object'||Array.isArray(value))throw Error('Invalid encrypted backup.');
 return {label:vaultLabel(value.label),envelope:validateRecoveryEnvelope(value.envelope)};
}
function openDatabase(){return new Promise((resolve,reject)=>{let blocked=false;
 const request=indexedDB.open(DATABASE,1);
 request.onupgradeneeded=()=>{request.result.createObjectStore(STORE,{keyPath:'hashlock'});};
 request.onerror=()=>reject(Error('Encrypted backup storage is unavailable.'));
 request.onblocked=()=>{blocked=true;reject(Error('Encrypted backup storage is blocked by another tab.'));};
 request.onsuccess=()=>{const db=request.result;if(blocked){db.close();return;}db.onversionchange=()=>db.close();resolve(db);};
});}
function transaction(db,mode,action){return new Promise((resolve,reject)=>{
 const tx=db.transaction(STORE,mode),store=tx.objectStore(STORE);let result,failure;
 const request=store.getAll();
 request.onsuccess=()=>{try{
  const entries=request.result.map(record=>{
   const parsed=entry(record);
   if(record.hashlock!==parsed.envelope.hashlock)throw Error('Encrypted backup identity mismatch.');
   return parsed;
  });
  if(entries.length>30||new Set(entries.map(x=>x.envelope.hashlock)).size!==entries.length)throw Error('Invalid encrypted backup collection.');
  result=action(entries,store);
 }catch(e){failure=e;tx.abort();}};
 tx.oncomplete=()=>resolve(result);
 tx.onabort=()=>reject(failure||Error('Encrypted backup transaction failed.'));
 tx.onerror=()=>{};
});}
async function migrateLegacy(db){
 const raw=localStorage.getItem(LEGACY_KEY);if(raw===null)return;
 let legacy;
 try{const parsed=JSON.parse(raw);if(!Array.isArray(parsed)||parsed.length>30)throw Error();legacy=parsed.map(entry);
  if(new Set(legacy.map(x=>x.envelope.hashlock)).size!==legacy.length)throw Error();
 }catch{throw Error('Saved encrypted backups are invalid; they were not overwritten.');}
 await transaction(db,'readwrite',(entries,store)=>{
  for(const item of legacy){
   const prior=entries.find(x=>x.envelope.hashlock===item.envelope.hashlock);
   if(prior&&JSON.stringify(prior)!==JSON.stringify(item))throw Error('Conflicting encrypted backups; neither was overwritten.');
   if(!prior){if(entries.length>=30)throw Error('Too many encrypted backups to migrate.');store.add({hashlock:item.envelope.hashlock,...item});entries.push(item);}
  }
 });
 // A crash before this removal causes a harmless, idempotent retry.
 if(localStorage.getItem(LEGACY_KEY)===raw)localStorage.removeItem(LEGACY_KEY);
}
async function locked(action){
 if(!navigator.locks?.request)throw Error('Browser storage locking is unavailable; encrypted backups were not changed.');
 return navigator.locks.request(LEGACY_KEY,{mode:'exclusive'},async()=>{
  const db=await openDatabase();try{await migrateLegacy(db);return await action(db);}finally{db.close();}
 });
}
export async function listVault(){return locked(db=>transaction(db,'readonly',entries=>entries));}
export async function addVault(value){
 const item=entry(value);
 return locked(db=>transaction(db,'readwrite',(entries,store)=>{
  if(entries.length>=30)throw Error('Remove a backup before adding another.');
  if(entries.some(x=>x.envelope.hashlock===item.envelope.hashlock))throw Error('This hashlock is already saved.');
  store.add({hashlock:item.envelope.hashlock,...item});return item;
 }));
}
export async function removeVault(hashlock){
 if(typeof hashlock!=='string'||!/^[0-9a-f]{64}$/.test(hashlock))throw Error('Invalid backup identity.');
 return locked(db=>transaction(db,'readwrite',(_entries,store)=>store.delete(hashlock)));
}
