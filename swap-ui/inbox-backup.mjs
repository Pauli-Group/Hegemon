/** Passphrase-encrypted backup of the offer owner's inbox private key.
 *
 * Same design as recovery.mjs (PBKDF2-SHA256 at 600000 iterations, AES-256-GCM) with the public key bound as additional
 * data, so an envelope cannot be re-labelled for another key. The plaintext is the PKCS#8 encoding of the P-256 private
 * key. The passphrase and plaintext never leave the calling client. This protects only the inbox key (the ability to open
 * the encrypted conversation); it holds no wallet key and no swap secret. */
const enc=new TextEncoder();
export const INBOX_BACKUP_ITERATIONS=600000;
const toHex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
function fromHex(value,length){
 if(typeof value!=='string'||value.length!==length*2||!/^[0-9a-f]+$/.test(value))throw Error('Invalid inbox key backup.');
 return Uint8Array.from(value.match(/../g),s=>parseInt(s,16));
}
function password(value){if(typeof value!=='string'||value.length<12||value.length>1024)throw Error('Use a separate passphrase of at least 12 characters.');return enc.encode(value);}
async function keyFor(passphrase,salt){
 const bytes=password(passphrase);
 try{const material=await crypto.subtle.importKey('raw',bytes,'PBKDF2',false,['deriveKey']);
  return await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:INBOX_BACKUP_ITERATIONS},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 }finally{bytes.fill(0);}
}
const aad=publicKey=>enc.encode('hegemon.swap.inbox-key.v1:'+publicKey);
const PKCS8_LENGTH=138;
export function validateInboxBackup(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='ciphertext,iterations,iv,publicKey,salt,type,version'||value.version!==1||value.type!=='inbox-key'||value.iterations!==INBOX_BACKUP_ITERATIONS)throw Error('Invalid inbox key backup.');
 if(typeof value.publicKey!=='string'||!/^04[0-9a-f]{128}$/.test(value.publicKey))throw Error('Invalid inbox key backup.');
 fromHex(value.salt,16);fromHex(value.iv,12);fromHex(value.ciphertext,PKCS8_LENGTH+16);
 return {version:1,type:'inbox-key',iterations:INBOX_BACKUP_ITERATIONS,publicKey:value.publicKey,salt:value.salt,iv:value.iv,ciphertext:value.ciphertext};
}
/** Encrypt the PKCS#8 bytes of the private key for `publicKey` (raw uncompressed hex). */
export async function sealInboxKey(pkcs8,publicKey,passphrase){
 if(!(pkcs8 instanceof Uint8Array)||pkcs8.length!==PKCS8_LENGTH)throw Error('Invalid inbox private key.');
 const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
 const cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(publicKey)},await keyFor(passphrase,salt),pkcs8));
 return validateInboxBackup({version:1,type:'inbox-key',iterations:INBOX_BACKUP_ITERATIONS,publicKey,salt:toHex(salt),iv:toHex(iv),ciphertext:toHex(cipher)});
}
/** Decrypt a backup and return `{publicKey, pkcs8}`. The caller zeroes `pkcs8`. Fails closed on a wrong passphrase, any
 * change to the envelope and a public key that differs from the one the backup was sealed for. */
export async function openInboxBackup(value,passphrase){
 const envelope=validateInboxBackup(value);
 let pkcs8;
 try{pkcs8=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:fromHex(envelope.iv,12),additionalData:aad(envelope.publicKey)},await keyFor(passphrase,fromHex(envelope.salt,16)),fromHex(envelope.ciphertext,PKCS8_LENGTH+16)));}
 catch{throw Error('Could not unlock the inbox key backup.');}
 if(pkcs8.length!==PKCS8_LENGTH){pkcs8.fill(0);throw Error('Could not unlock the inbox key backup.');}
 return {publicKey:envelope.publicKey,pkcs8};
}
