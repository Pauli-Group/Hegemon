/** Public action journal. No passwords, keys, plaintext preimages or signed
 * transactions belong here. Pending/uncertain records require chain checks;
 * records are not complete swap recovery and reveal private activity. */
const DATABASE='hegemon.local.action-journal.v1',STORE='actions',LOCK=DATABASE,MAX=200;
const hex=(v,n)=>typeof v==='string'&&new RegExp(`^[0-9a-f]{${n}}$`).test(v);
const decimal=v=>typeof v==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(v);
const decimal256=v=>typeof v==='string'&&/^(0|[1-9][0-9]{0,77})$/.test(v)&&BigInt(v)<1n<<256n;
const ref=v=>typeof v==='string'&&/^[0-9a-f]{64}#(0|[1-9][0-9]{0,9})$/.test(v);
const ethAddress=v=>typeof v==='string'&&/^0x[0-9a-fA-F]{40}$/.test(v);
const hgnAddress=v=>typeof v==='string'&&/^shca1[023456789acdefghjklmnpqrstuvwxyz]{1,3000}$/.test(v);
const keys=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names.slice().sort().join(',');
function publicRequest(chain,operation,request){
 if(!request||typeof request!=='object'||Array.isArray(request)||JSON.stringify(request).length>16384)throw Error('Invalid public action record.');
 if(chain==='ethereum'){
  if(!['deploy','approve','fund','revoke','refund','claim'].includes(operation)||!keys(request,['kind','contract','token','tokenId','amount','hashlock','claimant','refundee','expiry']))throw Error('Invalid Ethereum action record.');
  const r=request;if(!['eth','0','1','2'].includes(r.kind)||!(r.contract===''||ethAddress(r.contract))||!(r.token===''||ethAddress(r.token))||!(r.tokenId===''||decimal256(r.tokenId))||!decimal256(r.amount)||!/^0x[0-9a-fA-F]{64}$/.test(r.hashlock)||!ethAddress(r.claimant)||!ethAddress(r.refundee)||!decimal256(r.expiry))throw Error('Invalid Ethereum action terms.');
 }else if(chain==='bitcoin'){
  const names=['operation','hashlock','claimant_key','refund_key','refund_height','amount_sats',...(operation==='lock'?[]:['txid','vout','destination'])];
  if(!['lock','claim','refund'].includes(operation)||!keys(request,names)||request.operation!==operation||!hex(request.hashlock,64)||![request.claimant_key,request.refund_key].every(x=>typeof x==='string'&&/^(02|03)[0-9a-f]{64}$/.test(x))||!decimal(request.refund_height)||!decimal(request.amount_sats))throw Error('Invalid Bitcoin action terms.');
  if(operation!=='lock'&&(!hex(request.txid,64)||!decimal(request.vout)||typeof request.destination!=='string'||!(/^(?:bcrt1[023456789acdefghjklmnpqrstuvwxyz]{10,90}|tb1[023456789acdefghjklmnpqrstuvwxyz]{10,90}|BCRT1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{10,90}|[mn2][1-9A-HJ-NP-Za-km-z]{25,34})$/.test(request.destination))))throw Error('Invalid Bitcoin spend terms.');
 }else if(chain==='cardano'){
  const names=['operation','hashlock','claimant','refundee','expiry_ms','expected_value',...(operation==='lock'?['inputs']:['outref','fee_input','collateral'])];
  if(!['lock','claim','refund'].includes(operation)||!keys(request,names)||request.operation!==operation||!hex(request.hashlock,64)||!hex(request.claimant,56)||!hex(request.refundee,56)||!decimal(request.expiry_ms))throw Error('Invalid Cardano action terms.');
  const value=request.expected_value;if(!value||typeof value!=='object'||Array.isArray(value)||!decimal(value.lovelace))throw Error('Invalid Cardano action value.');
  for(const [policy,assets] of Object.entries(value)){if(policy==='lovelace')continue;if(!hex(policy,56)||!assets||typeof assets!=='object'||Array.isArray(assets)||!Object.keys(assets).length)throw Error('Invalid Cardano asset.');for(const [name,quantity] of Object.entries(assets))if(!/^(?:[0-9a-f]{2}){0,32}$/.test(name)||!decimal(quantity))throw Error('Invalid Cardano asset.');}
  if(operation==='lock'){if(!Array.isArray(request.inputs)||!request.inputs.length||request.inputs.length>10||!request.inputs.every(ref))throw Error('Invalid Cardano funding inputs.');}
  else if(![request.outref,request.fee_input,request.collateral].every(ref))throw Error('Invalid Cardano spend inputs.');
 }else if(chain==='hegemon'){
  const fields={ordinary:['inputs','recipient','amount','fee'],lock:['inputs','claim','refund','hashlock','timeout','amount','fee'],claim:['locked','fee_input','recipient','fee'],refund:['locked','fee_input','recipient','fee'],submit:['attempt']}[operation];
  if(!fields||!keys(request,['operation',...fields])||request.operation!==operation)throw Error('Invalid Hegemon action record.');
  for(const name of fields){const value=request[name];
   if(name==='inputs'){if(!Array.isArray(value)||!value.length||value.length>2||!value.every(decimal))throw Error('Invalid Hegemon inputs.');}
   else if(['recipient','claim','refund'].includes(name)){if(!hgnAddress(value))throw Error('Invalid Hegemon address.');}
   else if(['hashlock','attempt'].includes(name)){if(!hex(value,64))throw Error('Invalid Hegemon hash.');}
   else if(!decimal(value))throw Error('Invalid Hegemon amount or position.');
  }
 }else throw Error('Invalid action chain.');
 return structuredClone(request);
}
function receipt(value){
 if(value===null)return null;
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!['submitted','confirmed','txid','attempt','refund_handoff','journal_record'].includes(k)))throw Error('Invalid action result.');
 if(typeof value.submitted!=='boolean'||('confirmed' in value&&value.confirmed!==false))throw Error('Invalid action state.');
 for(const name of ['txid','attempt'])if(name in value&&(typeof value[name]!=='string'||!(/^(?:0x)?[0-9a-f]{64}$/.test(value[name])||/^[0-9a-f]{96}$/.test(value[name]))))throw Error('Invalid action identifier.');
 for(const name of ['refund_handoff','journal_record'])if(name in value&&(typeof value[name]!=='string'||!(/^[0-9a-f]{32}\.bin$/.test(value[name])||/^[0-9a-f]{64}\.json$/.test(value[name]))))throw Error('Invalid local record name.');
 return structuredClone(value);
}
function validate(record){
 if(!keys(record,['version','id','created','chain','operation','request','state','receipt'])||record.version!==1||!hex(record.id,32)||!Number.isSafeInteger(record.created)||record.created<1||!['pending','completed','uncertain'].includes(record.state))throw Error('Invalid saved action journal.');
 const request=publicRequest(record.chain,record.operation,record.request),result=receipt(record.receipt);
 if((record.state==='completed')!==(result!==null))throw Error('Invalid saved action outcome.');
 return {version:1,id:record.id,created:record.created,chain:record.chain,operation:record.operation,request,state:record.state,receipt:result};
}
function openDatabase(){return new Promise((resolve,reject)=>{let blocked=false;const request=indexedDB.open(DATABASE,1);
 request.onupgradeneeded=()=>request.result.createObjectStore(STORE,{keyPath:'id'});
 request.onerror=()=>reject(Error('Action journal storage is unavailable.'));request.onblocked=()=>{blocked=true;reject(Error('Action journal is blocked by another tab.'));};
 request.onsuccess=()=>{const db=request.result;if(blocked){db.close();return;}db.onversionchange=()=>db.close();resolve(db);};
});}
function transaction(db,mode,action){return new Promise((resolve,reject)=>{const tx=db.transaction(STORE,mode),store=tx.objectStore(STORE);let result,failure;
 const all=store.getAll();all.onsuccess=()=>{try{const entries=all.result.map(validate);if(entries.length>MAX||new Set(entries.map(x=>x.id)).size!==entries.length)throw Error('Invalid saved action journal.');result=action(entries,store);}catch(e){failure=e;tx.abort();}};
 tx.oncomplete=()=>resolve(result);tx.onabort=()=>reject(failure||Error('Action journal transaction failed.'));tx.onerror=()=>{};
});}
async function locked(action){if(!navigator.locks?.request)throw Error('Browser storage locking is unavailable; action was not requested.');return navigator.locks.request(LOCK,{mode:'exclusive'},async()=>{const db=await openDatabase();try{return await action(db);}finally{db.close();}});}
export async function listActions(){return locked(db=>transaction(db,'readonly',entries=>entries.sort((a,b)=>b.created-a.created)));}
export async function beginAction(chain,operation,request){const record=validate({version:1,id:Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join(''),created:Date.now(),chain,operation,request,state:'pending',receipt:null});
 return locked(db=>transaction(db,'readwrite',(entries,store)=>{if(entries.length>=MAX)throw Error('Export and remove old action records before continuing.');if(entries.some(x=>x.id===record.id))throw Error('Action record collision.');store.add(record);return record.id;}));}
export async function finishAction(id,result){const item=receipt(result);return locked(db=>transaction(db,'readwrite',(entries,store)=>{const old=entries.find(x=>x.id===id);if(!old||old.state!=='pending')throw Error('Pending action record unavailable.');store.put(validate({...old,state:'completed',receipt:item}));}));}
export async function uncertainAction(id){return locked(db=>transaction(db,'readwrite',(entries,store)=>{const old=entries.find(x=>x.id===id);if(old?.state==='pending')store.put(validate({...old,state:'uncertain'}));}));}
export async function removeAction(id){return locked(db=>transaction(db,'readwrite',(_entries,store)=>{if(!hex(id,32))throw Error('Invalid action record identity.');store.delete(id);}));}
export async function importActions(value){if(!keys(value,['version','records'])||value.version!==1||!Array.isArray(value.records)||value.records.length>MAX)throw Error('Invalid action journal export.');const incoming=value.records.map(validate);if(new Set(incoming.map(x=>x.id)).size!==incoming.length)throw Error('Duplicate action record.');
 return locked(db=>transaction(db,'readwrite',(entries,store)=>{for(const item of incoming){const previous=entries.find(x=>x.id===item.id);if(previous&&JSON.stringify(previous)!==JSON.stringify(item))throw Error('Conflicting action records; neither was overwritten.');if(!previous){if(entries.length>=MAX)throw Error('Too many action records.');store.add(item);entries.push(item);}}}));}
