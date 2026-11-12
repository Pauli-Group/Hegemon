/** Persist an unsigned Bitcoin PSBT and its independently checked expected
 * transaction before handing it to an external wallet. This store never accepts
 * private keys, signed PSBTs, raw signed transactions or claim preimages. */
import {checkPsbt,encodePsbt,addressScript,MAX_FEE_SATS} from './bitcoin-psbt.mjs';
import {TEST_NETWORK} from './vendor/btc-signer.mjs';

const DB='hegemon.swap.bitcoin-drafts.v1',STORE='drafts',HEX=/^[0-9a-f]{64}$/;
const keys=(v,n)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===n.slice().sort().join(',');
const sameBytes=(a,b)=>a instanceof Uint8Array&&b instanceof Uint8Array&&a.length===b.length&&a.every((x,i)=>x===b[i]);
function identity(session,role,operation){
 if(!HEX.test(session||'')||!['owner','taker'].includes(role)||!['fund','claim','refund'].includes(operation))throw Error('Invalid Bitcoin draft identity.');
 return `${session}:${role}:${operation}`;
}
export function validateBitcoinDraft(record,agreed){
 const id=identity(record?.session,record?.role,record?.operation),draft=record?.draft;
 if(!keys(record,['version','id','session','role','side','operation','attemptId','draft'])||record.version!==1||record.id!==id||!['long','short'].includes(record.side)||typeof record.attemptId!=='string'||!/^[0-9a-f]{32}$/.test(record.attemptId)||!keys(draft,['op','terms','address','feeRate','network','built','tip','journalId','txid','fee','lines','psbt'])||draft.op!==record.operation||!HEX.test(draft.txid||'')||typeof draft.psbt!=='string'||draft.psbt.length>200000||!keys(draft.built,['psbt','fee','txid','expect'])||!(draft.built.psbt instanceof Uint8Array)||!draft.built.expect||encodePsbt(draft.built.psbt)!==draft.psbt||draft.built.txid!==draft.txid||typeof draft.address!=='string'||draft.address.length>100||!Number.isFinite(draft.feeRate)||draft.feeRate<1||draft.feeRate>200||!Number.isSafeInteger(draft.tip)||draft.tip<0||typeof draft.journalId!=='string'||!/^[0-9a-f]{32}$/.test(draft.journalId))throw Error('Invalid saved Bitcoin draft.');
 const actual=draft.terms,expected=draft.built.expect.terms;
 const fields=['hashlock','claimant_key','refund_key','refund_height','amount_sats',...(record.operation==='fund'?[]:['txid','vout'])];
 if(!keys(actual,fields)||!keys(expected,fields)||!keys(draft.built.expect,['op','terms','network',...(record.operation==='fund'?['inputs','changeScript']:['escrow','destinationScript']),'fee','unsigned','maxFeeSats'])||draft.built.expect.op!==record.operation||draft.built.expect.maxFeeSats!==MAX_FEE_SATS)throw Error('Invalid Bitcoin draft contents.');
 if(record.operation==='fund'&&(!Array.isArray(draft.built.expect.inputs)||draft.built.expect.inputs.some(i=>!keys(i,['txid','vout','amount','script']))))throw Error('Invalid Bitcoin draft inputs.');
 if(record.operation!=='fund'&&!keys(draft.built.expect.escrow,['txid','vout','amount']))throw Error('Invalid Bitcoin draft escrow.');
 if(!actual||!expected||!agreed||!['hashlock','claimant_key','refund_key'].every(k=>actual[k]===expected[k]&&actual[k]===agreed[k])||!['refund_height','amount_sats'].every(k=>Number.isSafeInteger(actual[k])&&actual[k]===expected[k]&&String(actual[k])===String(agreed[k])))throw Error('The Bitcoin draft does not match the agreed swap terms.');
 if(record.operation!=='fund'&&(!HEX.test(actual.txid||'')||!Number.isSafeInteger(actual.vout)||actual.txid!==agreed.txid||actual.vout!==Number(agreed.vout)||draft.built.expect.escrow?.txid!==actual.txid||draft.built.expect.escrow?.vout!==actual.vout))throw Error('The Bitcoin draft spends a different escrow.');
 const net=draft.built.expect.network;
 if(!keys(net,Object.keys(TEST_NETWORK))||!keys(draft.network,Object.keys(TEST_NETWORK))||Object.keys(TEST_NETWORK).some(k=>net[k]!==TEST_NETWORK[k]||draft.network[k]!==TEST_NETWORK[k]))throw Error('The Bitcoin draft is not for testnet4.');
 const result=checkPsbt(draft.built.psbt,draft.built.expect);
 const destination=addressScript(draft.address,TEST_NETWORK,{allowTaproot:record.operation!=='fund'}),script=record.operation==='fund'?draft.built.expect.changeScript:draft.built.expect.destinationScript;
 if(!sameBytes(destination,script)||result.txid!==draft.txid||String(result.fee)!==String(draft.fee)||String(draft.built.fee)!==String(draft.fee)||JSON.stringify(result.lines)!==JSON.stringify(draft.lines))throw Error('The saved Bitcoin draft changed.');
 for(let i=0;i<result.tx.inputsLength;i++)if(Object.keys(result.tx.getInput(i)).some(k=>!['txid','index','sequence','witnessUtxo','sighashType','witnessScript'].includes(k)))throw Error('The saved Bitcoin draft contains signatures or unexpected data.');
 return record;
}
function open(){return new Promise((resolve,reject)=>{const req=indexedDB.open(DB,1);req.onupgradeneeded=()=>req.result.createObjectStore(STORE,{keyPath:'id'});req.onerror=()=>reject(Error('Bitcoin draft storage is unavailable.'));req.onblocked=()=>reject(Error('Bitcoin draft storage is blocked by another tab.'));req.onsuccess=()=>{req.result.onversionchange=()=>req.result.close();resolve(req.result);};});}
function request(db,mode,fn){return new Promise((resolve,reject)=>{const tx=db.transaction(STORE,mode),req=fn(tx.objectStore(STORE));let result;req.onsuccess=()=>{result=req.result;};tx.oncomplete=()=>resolve(result);tx.onabort=()=>reject(Error('Bitcoin draft storage did not complete.'));tx.onerror=()=>{};});}
async function locked(id,fn){if(!navigator.locks?.request)throw Error('Browser storage locking is unavailable.');return navigator.locks.request(DB+':'+id,{mode:'exclusive'},async()=>{const db=await open();try{return await fn(db);}finally{db.close();}});}

/** Store exactly one checked draft per operation. Never overwrite an existing
 * draft: a previously exported PSBT may already have been signed or sent. */
export async function saveBitcoinDraft({session,role,side,operation,attemptId,draft,agreed}){
 const id=identity(session,role,operation),record=validateBitcoinDraft({version:1,id,session,role,side,operation,attemptId,draft},agreed);
 return locked(id,async db=>{if(await request(db,'readonly',store=>store.get(id)))throw Error('A Bitcoin draft already exists. Check its outcome before trying another.');await request(db,'readwrite',store=>store.add(record));return record;});
}
export async function loadBitcoinDraft({session,role,operation,agreed}){
 const id=identity(session,role,operation);return locked(id,async db=>{const value=await request(db,'readonly',store=>store.get(id));return value?validateBitcoinDraft(value,agreed):null;});
}
