/** Durable browser state for one authenticated swap session. Wallet keys and
 * plaintext preimages never enter this store. The stored protocol key is a
 * non-extractable CryptoKey; the snapshot contains a channel credential and
 * an encrypted preimage envelope, so this database is private browser data. */
import {canonical} from './identity.mjs';
import {openSessionRecovery,validateSessionSnapshot,validateTransportAdvance,validateActionAdvance} from './session-recovery.mjs';
import {fromHex,toHex} from './cbor.mjs';
import {validateHegemonRecoveryAdvance} from './session-hegemon-recovery.mjs';

const DB='hegemon.swap.sessions.v1',STORE='sessions',HEX=/^[0-9a-f]{64}$/;
const fail=message=>{throw Error(message);};
function identity(session,role){if(typeof session!=='string'||!HEX.test(session)||!['owner','taker'].includes(role))fail('Invalid session identity.');return session+':'+role;}
function openDatabase(){return new Promise((resolve,reject)=>{let blocked=false;
 const request=indexedDB.open(DB,1);
 request.onupgradeneeded=()=>request.result.createObjectStore(STORE,{keyPath:'id'});
 request.onerror=()=>reject(Error('Swap session storage is unavailable.'));
 request.onblocked=()=>{blocked=true;reject(Error('Swap session storage is blocked by another tab.'));};
 request.onsuccess=()=>{const db=request.result;if(blocked){db.close();return;}db.onversionchange=()=>db.close();resolve(db);};
});}
function request(db,mode,operation){return new Promise((resolve,reject)=>{
 const tx=db.transaction(STORE,mode),req=operation(tx.objectStore(STORE));let result;
 req.onsuccess=()=>{result=req.result;};tx.oncomplete=()=>resolve(result);
 tx.onabort=()=>reject(Error('Swap session storage did not complete.'));tx.onerror=()=>{};
});}
async function locked(id,operation){
 if(!navigator.locks?.request)fail('Browser storage locking is unavailable.');
 return navigator.locks.request(DB+':'+id,{mode:'exclusive'},async()=>{const db=await openDatabase();try{return await operation(db);}finally{db.close();}});
}
async function digest(value){return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical(value)))));}
async function validKey(key,publicKey,session){
 if(!key||key.type!=='private'||key.extractable||key.algorithm?.name!=='ECDSA'||key.algorithm?.namedCurve!=='P-256'||typeof publicKey!=='string'||!/^04[0-9a-f]{128}$/.test(publicKey))return false;
 try{const publicCrypto=await crypto.subtle.importKey('raw',fromHex(publicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const bytes=new TextEncoder().encode(DB+'\n'+session),signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,bytes);
  return crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},publicCrypto,signature,bytes);
 }catch{return false;}
}
async function validateRecord(record,session,role){
 const id=identity(session,role);
 const fields=['id','version','session','role','revision','snapshot','privateKey','publicKey','envelope','envelopeDigest','backupDigest','backupAcknowledged'];
 if(!record||Object.keys(record).sort().join(',')!==fields.sort().join(',')||record.id!==id||record.version!==1||record.session!==session||record.role!==role||!Number.isSafeInteger(record.revision)||record.revision<1||record.revision>=Number.MAX_SAFE_INTEGER||typeof record.backupAcknowledged!=='boolean'||!record.envelope||record.envelope.session!==session||record.envelope.role!==role||record.envelope.publicKey!==record.publicKey)fail('The saved swap session is invalid.');
 await validateSessionSnapshot(record.snapshot,session);
 if(!await validKey(record.privateKey,record.publicKey,session))fail('The saved session signing key does not match.');
 if(typeof record.backupDigest!=='string'||!HEX.test(record.backupDigest)||record.envelopeDigest!==await digest(record.envelope)||(record.backupAcknowledged&&record.backupDigest!==await digest(record.snapshot)))fail('The saved swap backup is invalid.');
 return record;
}
function same(a,b){return canonical(a)===canonical(b);}
function monotonic(previous,next){
 validateTransportAdvance(previous,next);
 validateActionAdvance(previous,next);
 validateHegemonRecoveryAdvance(previous,next);
 for(const name of ['offer','offerDigest','reservation','credential','channelKey','sessionExpires'])if(!same(previous[name],next[name]))fail('The session identity cannot be changed.');
 for(const name of ['terms','ownerBlob','takerBlob','secretEnvelope'])if(previous[name]!==null&&!same(previous[name],next[name]))fail('Saved swap terms, identities and secret backups cannot be replaced.');
 for(const side of ['long','short'])if(previous.escrows[side]!==null&&!same(previous.escrows[side],next.escrows[side]))fail('A saved escrow reference cannot be replaced.');
}
/** Restore or create from an authenticated encrypted backup. Existing state
 * is never silently replaced, including with an older recovery backup. */
export async function addSession(envelope,passphrase){
 const {snapshot,privateKey,publicKey}=await openSessionRecovery(envelope,passphrase),session=envelope.session,role=envelope.role,id=identity(session,role);
 const record={id,version:1,session,role,revision:1,snapshot,privateKey,publicKey,envelope,envelopeDigest:await digest(envelope),backupDigest:await digest(snapshot),backupAcknowledged:false};
 await validateRecord(record,session,role);
 return locked(id,async db=>{if(await request(db,'readonly',store=>store.get(id)))fail('A swap session already exists in this browser.');await request(db,'readwrite',store=>store.add(record));return record;});
}
export async function getSession(session,role){
 const id=identity(session,role);
 return locked(id,async db=>{const record=await request(db,'readonly',store=>store.get(id));return record?validateRecord(record,session,role):null;});
}
export async function sessionBackupCurrent(record){
 if(!record||!record.snapshot||typeof record.backupDigest!=='string')return false;
 return record.backupDigest===await digest(record.snapshot);
}
/** Require an exact revision and keep authenticated session data immutable.
 * Every update invalidates the backup acknowledgement until it is refreshed. */
export async function updateSession(session,role,expectedRevision,snapshot){
 const id=identity(session,role);await validateSessionSnapshot(snapshot,session);
 return locked(id,async db=>{
  const record=await validateRecord(await request(db,'readonly',store=>store.get(id)),session,role);
  if(record.revision!==expectedRevision)fail('This swap changed in another tab. Refresh before continuing.');
  monotonic(record.snapshot,snapshot);
  if(same(record.snapshot,snapshot))return record;
  const next={...record,revision:record.revision+1,snapshot,backupAcknowledged:false};
  await request(db,'readwrite',store=>store.put(next));return next;
 });
}
/** Only a newly decrypted backup containing the exact current state can be
 * marked ready for the user to export and acknowledge. */
export async function setSessionBackup(session,role,expectedRevision,envelope,passphrase){
 const opened=await openSessionRecovery(envelope,passphrase),id=identity(session,role);
 if(envelope.session!==session||envelope.role!==role)fail('The backup belongs to another session.');
 return locked(id,async db=>{
  const record=await validateRecord(await request(db,'readonly',store=>store.get(id)),session,role);
  if(record.revision!==expectedRevision)fail('This swap changed in another tab. Refresh before continuing.');
  if(opened.publicKey!==record.publicKey||!same(opened.snapshot,record.snapshot))fail('The backup does not contain the current swap state.');
  const next={...record,revision:record.revision+1,envelope,envelopeDigest:await digest(envelope),backupDigest:await digest(record.snapshot),backupAcknowledged:false};
  await request(db,'readwrite',store=>store.put(next));return next;
 });
}
export async function acknowledgeSessionBackup(session,role,expectedRevision){
 const id=identity(session,role);
 return locked(id,async db=>{
  const record=await validateRecord(await request(db,'readonly',store=>store.get(id)),session,role);
  if(record.revision!==expectedRevision)fail('This swap changed in another tab. Refresh before continuing.');
  if(record.backupDigest!==await digest(record.snapshot))fail('Update the encrypted backup before continuing.');
  const next={...record,revision:record.revision+1,backupAcknowledged:true};
  await request(db,'readwrite',store=>store.put(next));return next;
 });
}

/** Check local recovery prerequisites for a *new* funding attempt. This is not
 * an on-chain check or permission to sign: callers must also hold a per-session
 * action lock, revalidate the signed proposal and live chains, and write the
 * action journal before asking a wallet. Never use an empty replacement for an
 * unavailable journal. */
export async function sessionFundingPrerequisites({session,role,revision,outbox,actions,attemptId=null}){
 if(!Array.isArray(actions)||!outbox||!Number.isSafeInteger(outbox.next)||typeof outbox.pending!=='boolean')fail('The local action journal and outbox are required.');
 const record=await getSession(session,role);
 if(!record||record.revision!==revision)fail('This swap changed in another tab. Refresh before continuing.');
 const snapshot=record.snapshot;
 if(![3,4].includes(snapshot.version)||!record.backupAcknowledged||record.backupDigest!==await digest(snapshot))fail('Save and acknowledge the current swap recovery backup before funding.');
 if(outbox.pending||outbox.next!==snapshot.transport.next||outbox.previous!==snapshot.transport.previous)fail('Synchronize and back up the signed message history before funding.');
 if(!snapshot.terms||!snapshot.ownerBlob||!snapshot.takerBlob)fail('Both wallet-signed participants and agreed terms are required.');
 if(role==='owner'&&(!snapshot.secretEnvelope||snapshot.escrows.long!==null))fail('A saved secret backup and an unfunded first leg are required.');
 if(role==='taker'&&(!snapshot.escrows.long||snapshot.escrows.short!==null))fail('A first escrow and an unfunded second leg are required.');
 const own=role==='owner'?'long':'short';
 for(const side of ['long','short'])for(const operation of ['fund','claim','refund'])for(const attempt of snapshot.actions[side][operation]){
  if(['prepared','uncertain'].includes(attempt.state)||attempt.state==='intent'&&attempt.id!==attemptId)fail('A wallet action needs review before funding.');
  if(side===own&&operation==='fund'&&attempt.state==='submitted')fail('A funding action was already submitted. Check its outcome before retrying.');
 }
 const ownChain=snapshot.terms.legs[role==='owner'?'long':'short'].asset.chain,chains=new Set([snapshot.terms.legs.long.asset.chain,snapshot.terms.legs.short.asset.chain]),hash=snapshot.terms.hashlock;
 for(const action of actions){
  if(!action||!chains.has(action.chain))continue;
  const raw=action.request?.hashlock,related=raw===undefined||typeof raw==='string'&&raw.toLowerCase().replace(/^0x/,'')===hash;
  if(!related)continue;
  if(action.state==='pending'||action.state==='uncertain')fail('A related wallet action is pending or uncertain. Check the chain and wallet history first.');
  if(action.chain===ownChain&&['lock','deploy'].includes(action.operation)&&action.state==='completed'&&action.receipt?.submitted===true)fail('A funding action was already submitted. Check its outcome before retrying.');
 }
 return record;
}
