import {test} from 'node:test';
import assert from 'node:assert/strict';
import {makeInboxKeyPair,sealPublicSession,openPublicSession,parsePublicSession} from './public-inbox.mjs';

test('public offer handshake protects the key and binds offer and reservation',async()=>{
 const owner=await makeInboxKeyPair(),other=await makeInboxKeyPair(),offer='a'.repeat(64),reservation='b'.repeat(64),key='c'.repeat(64);
 assert.equal(owner.privateKey.extractable,false);
 const sealed=await sealPublicSession(owner.publicKey,offer,reservation,key);assert.ok(parsePublicSession(sealed));assert.ok(!sealed.includes(key));
 assert.equal(await openPublicSession(owner.privateKey,owner.publicKey,offer,reservation,sealed),key);
 await assert.rejects(openPublicSession(other.privateKey,owner.publicKey,offer,reservation,sealed));
 await assert.rejects(openPublicSession(owner.privateKey,owner.publicKey,'d'.repeat(64),reservation,sealed));
 await assert.rejects(openPublicSession(owner.privateKey,owner.publicKey,offer,'e'.repeat(64),sealed));
 const changed=parsePublicSession(sealed);changed.ciphertext=(changed.ciphertext[0]==='0'?'1':'0')+changed.ciphertext.slice(1);
 const tampered=btoa(JSON.stringify(changed));await assert.rejects(openPublicSession(owner.privateKey,owner.publicKey,offer,reservation,tampered));
 assert.equal(parsePublicSession('not-a-handshake'),null);
});
