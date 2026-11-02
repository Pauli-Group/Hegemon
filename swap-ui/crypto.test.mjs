import {test} from 'node:test';
import assert from 'node:assert/strict';
import {newMessageKey,encryptMessage,decryptMessage} from './crypto.mjs';
test('shared-link encryption authenticates message, key and offer',async()=>{
 const key=newMessageKey(), other=newMessageKey(), id='a'.repeat(64);
 const ciphertext=await encryptMessage(key,id,'hello from an offer');
 assert.equal(await decryptMessage(key,id,ciphertext),'hello from an offer');
 await assert.rejects(decryptMessage(other,id,ciphertext));
 await assert.rejects(decryptMessage(key,'b'.repeat(64),ciphertext));
 const bytes=Uint8Array.from(atob(ciphertext),x=>x.charCodeAt(0));bytes[bytes.length-1]^=1;
 await assert.rejects(decryptMessage(key,id,btoa(Array.from(bytes,x=>String.fromCharCode(x)).join(''))));
});
