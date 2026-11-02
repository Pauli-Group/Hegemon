/** Versioned encrypted local preimage storage. The passphrase and plaintext
 * never leave the calling client. Protect exported backups and passphrases. */
const enc=new TextEncoder();
const ITERATIONS=600000;
const toHex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
function fromHex(value,length){
 if(typeof value!=='string'||value.length!==length*2||!/^[0-9a-f]+$/.test(value))throw Error('Invalid encrypted backup');
 return Uint8Array.from(value.match(/../g),s=>parseInt(s,16));
}
function password(value){if(typeof value!=='string'||value.length<12||value.length>1024)throw Error('Use a separate passphrase of at least 12 characters.');return enc.encode(value);}
async function keyFor(passphrase,salt){
 const bytes=password(passphrase);
 try{const material=await crypto.subtle.importKey('raw',bytes,'PBKDF2',false,['deriveKey']);
  return await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:ITERATIONS},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 }finally{bytes.fill(0);}
}
function aad(hashlock){return enc.encode('hegemon.swap.secret.v1:'+hashlock);}
export function validateRecoveryEnvelope(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='ciphertext,hashlock,iterations,iv,salt,version'||value.version!==1||value.iterations!==ITERATIONS)throw Error('Invalid encrypted backup');
 fromHex(value.hashlock,32);fromHex(value.salt,16);fromHex(value.iv,12);fromHex(value.ciphertext,48);
 return {version:1,iterations:ITERATIONS,hashlock:value.hashlock,salt:value.salt,iv:value.iv,ciphertext:value.ciphertext};
}
export async function createRecovery(passphrase){
 const secret=crypto.getRandomValues(new Uint8Array(32));
 try{return await encryptRecovery(secret,passphrase);}finally{secret.fill(0);}
}
export async function encryptRecovery(secret,passphrase){
 if(!(secret instanceof Uint8Array)||secret.length!==32)throw Error('Invalid preimage.');
 const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
 try{
  const hashlock=toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',secret)));
  const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(hashlock)},await keyFor(passphrase,salt),secret));
  return {version:1,iterations:ITERATIONS,hashlock,salt:toHex(salt),iv:toHex(iv),ciphertext:toHex(ciphertext)};
 }finally{salt.fill(0);iv.fill(0);}
}
export async function unlockRecovery(value,passphrase){
 const envelope=validateRecoveryEnvelope(value),salt=fromHex(envelope.salt,16),iv=fromHex(envelope.iv,12),cipher=fromHex(envelope.ciphertext,48);
 let secret;
 try{secret=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:aad(envelope.hashlock)},await keyFor(passphrase,salt),cipher));}
 catch{throw Error('Could not unlock encrypted backup.');}
 try{
  const digest=toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',secret)));
  if(secret.length!==32||digest!==envelope.hashlock)throw Error('Encrypted backup hash mismatch.');
 }catch(e){secret.fill(0);throw e;}
 return secret;
}
