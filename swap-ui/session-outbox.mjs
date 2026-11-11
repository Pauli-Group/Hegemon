/** Durable delivery for encrypted session frames. A lost response must retry exactly
 * the same ciphertext and sequence; generating a fresh frame could conflict with a
 * packet the relay already accepted. This stores ciphertext only, never credentials,
 * wallet data, secret preimages, or plaintext session messages. Callers must
 * also save the channel key and protocol history before enqueueing a frame;
 * retaining the ciphertext alone is not enough to recover the session. */
import {replayOwnFrames} from './session-replay.mjs';
const HEX64=/^[0-9a-f]{64}$/;
const FRAME=/^[A-Za-z0-9+/]+={0,2}$/;
const digest=value=>value===null||(typeof value==='string'&&HEX64.test(value));
const exact=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const keyFor=(session,role)=>`hegemon.swap.session-outbox.v1:${session}:${role}`;
function validFrame(frame){return typeof frame==='string'&&frame.length>0&&frame.length<=12000&&frame.length%4===0&&FRAME.test(frame);}
function identity(session,role){if(typeof session!=='string'||!HEX64.test(session)||!['owner','taker'].includes(role))throw Error('Invalid session outbox identity.');}
function validate(state,session,role){
 if(!exact(state,['version','session','role','next','previous','pending'])||state.version!==1||state.session!==session||state.role!==role||!Number.isSafeInteger(state.next)||state.next<1||state.next>257||!digest(state.previous))throw Error('The saved session outbox is invalid.');
 if(state.pending!==null&&(!exact(state.pending,['sequence','ciphertext','previousAfter'])||state.pending.sequence!==state.next||state.next>256||!validFrame(state.pending.ciphertext)||!digest(state.pending.previousAfter)||state.previous!==null&&state.pending.previousAfter===null))throw Error('The saved session outbox is invalid.');
 return state;
}
/** `send` must POST `{sequence,ciphertext}` for this authenticated session and
 * return the relay acknowledgement. `storage` must persist synchronously, and
 * `locks.request` must serialize all tabs of this origin. */
export function sessionOutbox({session,role,send,storage=globalThis.localStorage,locks=globalThis.navigator?.locks}){
 identity(session,role);
 if(typeof send!=='function'||!storage||typeof storage.getItem!=='function'||typeof storage.setItem!=='function'||typeof locks?.request!=='function')throw Error('Durable session storage is unavailable.');
 const key=keyFor(session,role);
 function read(){
  const raw=storage.getItem(key);
  if(raw===null)return {version:1,session,role,next:1,previous:null,pending:null};
  let parsed;try{parsed=JSON.parse(raw);}catch{throw Error('The saved session outbox is invalid.');}
  return validate(parsed,session,role);
 }
 function write(state){validate(state,session,role);storage.setItem(key,JSON.stringify(state));}
 async function sendPending(state){
  if(!state.pending)return null;
  const frame={sequence:state.pending.sequence,ciphertext:state.pending.ciphertext},ack=await send(frame);
  if(!ack||!Number.isSafeInteger(ack.id)||ack.id<1||typeof ack.duplicate!=='boolean')throw Error('The relay did not confirm the session packet. Retry the saved packet.');
  write({...state,next:state.next+1,previous:state.pending.previousAfter,pending:null});
  return {...ack,sequence:frame.sequence};
 }
 const lock=fn=>locks.request(key,{mode:'exclusive'},fn);
 return Object.freeze({
  session,role,
  /** Build the ciphertext with its allocated sequence while holding the cross-tab
   * lock, then save it. Never call the builder while a prior packet is pending. */
  enqueue(makeFrame){return lock(async()=>{
   if(typeof makeFrame!=='function')throw Error('A session packet builder is required.');
   const state=read();
   if(state.pending)throw Error('Retry the saved session packet before sending another.');
   if(state.next>256)throw Error('This session has reached its packet limit.');
   const built=await makeFrame({sequence:state.next,previous:state.previous});
   if(!exact(built,['ciphertext','previousAfter'])||!digest(built.previousAfter)||state.previous!==null&&built.previousAfter===null)throw Error('Invalid session packet history.');
   const {ciphertext}=built;
   if(!validFrame(ciphertext))throw Error('Invalid encrypted session packet.');
   const pending={sequence:state.next,ciphertext,previousAfter:built.previousAfter};
   write({...state,pending}); // Persist before the first request, including when its response is lost.
   return sendPending({...state,pending});
  });},
  /** Retries only the exact bytes already stored. No pending packet is a no-op. */
  retry(){return lock(()=>sendPending(read()));},
  /** Restore only into an empty browser after checking the wallet-certified
   * signed history against the backup's authenticated high-water mark. */
  restore({snapshot,publicKey,frames,now}){return lock(async()=>{
   if(storage.getItem(key)!==null)throw Error('A session outbox already exists in this browser.');
   const restored=await replayOwnFrames({session,role,snapshot,publicKey,frames,now});
   write({version:1,session,role,next:restored.next,previous:restored.previous,pending:null});
   return restored;
  });},
  inspect(){return lock(()=>{const state=read();return {next:state.next,previous:state.previous,pending:!!state.pending};});},
 });
}
