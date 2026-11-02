import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRecovery,unlockRecovery,validateRecoveryEnvelope} from './recovery.mjs';
test('encrypted recovery backup unlocks locally and authenticates its hashlock',async()=>{
 const phrase='correct separate passphrase';const envelope=await createRecovery(phrase);
 assert.equal(validateRecoveryEnvelope(envelope).hashlock,envelope.hashlock);
 const secret=await unlockRecovery(envelope,phrase);assert.equal(secret.length,32);secret.fill(0);
 await assert.rejects(unlockRecovery(envelope,'wrong but long passphrase'));
 await assert.rejects(unlockRecovery({...envelope,hashlock:'0'.repeat(64)},phrase));
 assert.throws(()=>validateRecoveryEnvelope({...envelope,iterations:1}));
 assert.throws(()=>validateRecoveryEnvelope({...envelope,unexpected:'extra'}));
 await assert.rejects(createRecovery('too short'));
});
