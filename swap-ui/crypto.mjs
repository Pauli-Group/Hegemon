// This shared-link channel protects message contents from storage on the relay.
// Everyone holding the link key can read and forge messages: verify identities
// independently, and never send wallet keys or hashlock preimages through it.
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});
const toHex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
function fromHex(hex){
  if(!/^[0-9a-f]{64}$/.test(hex))throw Error('Invalid message key');
  return Uint8Array.from(hex.match(/../g),v=>parseInt(v,16));
}
async function aes(key,usage){return crypto.subtle.importKey('raw',fromHex(key),'AES-GCM',false,[usage]);}
export function newMessageKey(){return toHex(crypto.getRandomValues(new Uint8Array(32)));}
export async function encryptMessage(key,offerId,message){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:encoder.encode(offerId)},await aes(key,'encrypt'),encoder.encode(message)));
  const combined=new Uint8Array(iv.length+ciphertext.length);combined.set(iv);combined.set(ciphertext,iv.length);
  return btoa(Array.from(combined,v=>String.fromCharCode(v)).join(''));
}
export async function decryptMessage(key,offerId,encoded){
  const combined=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));
  if(combined.length<28)throw Error('Invalid encrypted message');
  const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:combined.slice(0,12),additionalData:encoder.encode(offerId)},await aes(key,'decrypt'),combined.slice(12));
  return decoder.decode(plaintext);
}
