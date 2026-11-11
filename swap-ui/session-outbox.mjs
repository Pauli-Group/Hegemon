/** Durable delivery for encrypted session frames. A lost response must retry exactly
 * the same ciphertext and sequence; generating a fresh frame could conflict with a
 * packet the relay already accepted. This stores ciphertext only, never credentials,
 * wallet data, secret preimages, or plaintext session messages. Callers must
 * also save the channel key and protocol history before enqueueing a frame;
 * retaining the ciphertext alone is not enough to recover the session. */
const HEX64=/^[0-9a-f]{64}$/;
const FRAME=/^[A-Za-z0-9+/]+={0,2}$/;
const exact=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names.slice().sort().join(',');
const keyFor=(session,role)=>`hegemon.swap.session-outbox.v1:${session}:${role}`;
function validFrame(frame){return typeof frame==='string'&&frame.length>0&&frame.length<=12000&&frame.length%4===0&&FRAME.test(frame);}
function identity(session,role){if(typeof session!=='string'||!HEX64.test(session)||!['owner','taker'].includes(role))throw Error('Invalid session outbox identity.');}
function validate(state,session,role){
 if(!exact(state,['version','session','role','next','pending'])||state.version!==1||state.session!==session||state.role!==role||!Number.isSafeInteger(state.next)||state.next<1||state.next>257)throw Error('The saved session outbox is invalid.');
 if(state.pending!==null&&(!exact(state.pending,['sequence','ciphertext'])||state.pending.sequence!==state.next||state.next>256||!validFrame(state.pending.ciphertext)))throw Error('The saved session outbox is invalid.');
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
  if(raw===null)return {version:1,session,role,next:1,pending:null};
  let parsed;try{parsed=JSON.parse(raw);}catch{throw Error('The saved session outbox is invalid.');}
  return validate(parsed,session,role);
 }
 function write(state){validate(state,session,role);storage.setItem(key,JSON.stringify(state));}
 async function sendPending(state){
  if(!state.pending)return null;
  const frame={...state.pending},ack=await send(frame);
  if(!ack||!Number.isSafeInteger(ack.id)||ack.id<1||typeof ack.duplicate!=='boolean')throw Error('The relay did not confirm the session packet. Retry the saved packet.');
  write({...state,next:state.next+1,pending:null});
  return {...ack,sequence:frame.sequence};
 }
 const lock=fn=>locks.request(key,{mode:'exclusive'},fn);
 return {
  /** Build the ciphertext with its allocated sequence while holding the cross-tab
   * lock, then save it. Never call the builder while a prior packet is pending. */
  enqueue(makeFrame){return lock(async()=>{
   if(typeof makeFrame!=='function')throw Error('A session packet builder is required.');
   const state=read();
   if(state.pending)throw Error('Retry the saved session packet before sending another.');
   if(state.next>256)throw Error('This session has reached its packet limit.');
   const ciphertext=await makeFrame(state.next);
   if(!validFrame(ciphertext))throw Error('Invalid encrypted session packet.');
   const pending={sequence:state.next,ciphertext};
   write({...state,pending}); // Persist before the first request, including when its response is lost.
   return sendPending({...state,pending});
  });},
  /** Retries only the exact bytes already stored. No pending packet is a no-op. */
  retry(){return lock(()=>sendPending(read()));},
  inspect(){return lock(()=>{const state=read();return {next:state.next,pending:!!state.pending};});},
 };
}
