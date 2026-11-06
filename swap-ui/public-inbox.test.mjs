import {test} from 'node:test';
import assert from 'node:assert/strict';
import {makeInboxKeyPair,inboxFingerprint,sealPublicSession,openPublicSession,parsePublicSession} from './public-inbox.mjs';

test('public offer handshake protects the key and binds offer and reservation',async()=>{
 const owner=await makeInboxKeyPair(),other=await makeInboxKeyPair(),offer='a'.repeat(64),reservation='b'.repeat(64),key='c'.repeat(64);
 assert.equal(owner.privateKey.extractable,false);
 assert.match(await inboxFingerprint(owner.publicKey),/^[0-9a-f]{64}$/);await assert.rejects(inboxFingerprint('invalid'));
 const sealed=await sealPublicSession(owner.publicKey,offer,reservation,key);assert.ok(parsePublicSession(sealed));assert.ok(!sealed.includes(key));
 assert.equal(await openPublicSession(owner.privateKey,owner.publicKey,offer,reservation,sealed),key);
 await assert.rejects(openPublicSession(other.privateKey,owner.publicKey,offer,reservation,sealed));
 await assert.rejects(openPublicSession(owner.privateKey,owner.publicKey,'d'.repeat(64),reservation,sealed));
 await assert.rejects(openPublicSession(owner.privateKey,owner.publicKey,offer,'e'.repeat(64),sealed));
 const changed=parsePublicSession(sealed);changed.ciphertext=(changed.ciphertext[0]==='0'?'1':'0')+changed.ciphertext.slice(1);
 const tampered=btoa(JSON.stringify(changed));await assert.rejects(openPublicSession(owner.privateKey,owner.publicKey,offer,reservation,tampered));
 assert.equal(parsePublicSession('not-a-handshake'),null);
});

import {makeBackedInboxKeyPair,keyMatches} from './public-inbox.mjs';
import {sealInboxKey,openInboxBackup,validateInboxBackup,INBOX_BACKUP_ITERATIONS} from './inbox-backup.mjs';
const PASS='correct horse battery staple';
async function backedUp(){const pair=await makeBackedInboxKeyPair();const backup=await sealInboxKey(pair.pkcs8,pair.publicKey,PASS);return {pair,backup};}
async function restoredKey(backup,pass=PASS){const {publicKey,pkcs8}=await openInboxBackup(backup,pass);const key=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);pkcs8.fill(0);return {publicKey,key};}

test('a backed-up inbox key is stored non-extractable, restores from the envelope and opens a real handshake',async()=>{
 const {pair,backup}=await backedUp();
 assert.equal(pair.privateKey.extractable,false);assert.equal(pair.pkcs8.length,138);assert.equal(backup.iterations,INBOX_BACKUP_ITERATIONS);
 assert.ok(!JSON.stringify(backup).includes(Buffer.from(pair.pkcs8).toString('hex')));
 const {publicKey,key}=await restoredKey(backup);
 assert.equal(publicKey,pair.publicKey);assert.equal(key.extractable,false);assert.equal(await keyMatches(key,publicKey),true);
 const offer='a'.repeat(64),reservation='b'.repeat(64),session='c'.repeat(64);
 const sealed=await sealPublicSession(publicKey,offer,reservation,session);
 assert.equal(await openPublicSession(key,publicKey,offer,reservation,sealed),session);
 assert.equal(await openPublicSession(pair.privateKey,publicKey,offer,reservation,sealed),session);
});

test('key matching rejects another key pair',async()=>{
 const a=await makeBackedInboxKeyPair(),b=await makeBackedInboxKeyPair();
 assert.equal(await keyMatches(a.privateKey,a.publicKey),true);assert.equal(await keyMatches(a.privateKey,b.publicKey),false);assert.equal(await keyMatches(a.privateKey,'zz'),false);
});

test('inbox backups fail closed: wrong passphrase, short passphrase, corruption, relabelling and malformed envelopes',async()=>{
 const {pair,backup}=await backedUp(),other=await makeBackedInboxKeyPair();
 await assert.rejects(openInboxBackup(backup,'wrong passphrase here'),/Could not unlock/);
 await assert.rejects(sealInboxKey(pair.pkcs8,pair.publicKey,'short'),/at least 12/);
 await assert.rejects(openInboxBackup(backup,'short'),/Could not unlock/);
 const flip=hex=>(hex[0]==='0'?'1':'0')+hex.slice(1);
 for(const field of ['ciphertext','iv','salt'])await assert.rejects(openInboxBackup({...backup,[field]:flip(backup[field])},PASS),/Could not unlock/,field);
 // The public key is bound as additional data: an envelope cannot be relabelled for another key.
 await assert.rejects(openInboxBackup({...backup,publicKey:other.publicKey},PASS),/Could not unlock/);
 for(const bad of [null,[],{},{...backup,version:2},{...backup,type:'secret'},{...backup,iterations:1},{...backup,extra:1},{...backup,publicKey:'04'+'0'.repeat(10)},{...backup,ciphertext:backup.ciphertext.slice(2)},{...backup,iv:'zz'.repeat(12)}])
  assert.throws(()=>validateInboxBackup(bad),/Invalid inbox key backup/);
 await assert.rejects(sealInboxKey(new Uint8Array(10),pair.publicKey,PASS),/Invalid inbox private key/);
});

test('a backup whose key does not match its public key is detected by the cross-check',async()=>{
 const a=await makeBackedInboxKeyPair(),b=await makeBackedInboxKeyPair();
 // Sealed for a's public key but containing b's private key: decrypts fine, but the key is not a's.
 const forged=await sealInboxKey(b.pkcs8,a.publicKey,PASS),{publicKey,key}=await restoredKey(forged);
 assert.equal(publicKey,a.publicKey);assert.equal(await keyMatches(key,publicKey),false);
});
