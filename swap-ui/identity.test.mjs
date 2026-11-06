import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyIdentity,parseIdentity,statementText,canonical,buildStatement,expectedParticipants,serializeIdentity,MAX_LIFETIME_SECONDS} from './identity.mjs';
import {verifyBip322,verifyBip137,verifyEthereum,verifyCardano,bip322Digests} from './identity-proofs.mjs';

const vectors=JSON.parse(readFileSync(new URL('../config/swap/identity-vectors.json',import.meta.url),'utf8'));
const byName=name=>vectors.cases.find(c=>c.name===name);
const clone=value=>structuredClone(value);
const rejects=(blob,expected,now,pattern)=>assert.rejects(()=>verifyIdentity(typeof blob==='string'?blob:JSON.stringify(blob),expected,now),pattern);

test('official BIP-322 vectors verify',()=>{
 for(const [message,signature] of Object.entries(vectors.bip322_official.signatures))
  assert.equal(verifyBip322({signature},message),vectors.bip322_official.public_key);
 // BIP-322 lists transaction ids in display (reversed) byte order.
 const display=hexText=>Buffer.from(hexText,'hex').reverse().toString('hex');
 assert.equal(display(bip322Digests('',Uint8Array.from(Buffer.from(vectors.bip322_official.public_key,'hex'))).txid),'c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7');
 assert.equal(display(bip322Digests('Hello World',Uint8Array.from(Buffer.from(vectors.bip322_official.public_key,'hex'))).txid),'b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b');
 assert.throws(()=>verifyBip322({signature:vectors.bip322_official.signatures['']},'Hello World'),/does not verify/);
});

for(const c of vectors.cases)test('independently signed vector: '+c.name,async()=>{
 const result=await verifyIdentity(c.blob,c.expected,c.now);
 assert.deepEqual(result.proven,c.proven);assert.deepEqual(result.addresses,c.addresses);
 assert.equal(statementText(result.statement),c.statement_text);
 assert.match(result.code,/^[0-9a-f]{16}$/);
 assert.deepEqual(result.unverified,['give','receive'].filter(side=>result.statement.legs[side].chain==='hegemon'));
});

test('a leg on Hegemon is never proven and a leg without a proof is asserted only',async()=>{
 const hegemon=await verifyIdentity(byName('owner-hegemon-pending-ada').blob,byName('owner-hegemon-pending-ada').expected,byName('owner-hegemon-pending-ada').now);
 assert.equal(hegemon.proven.give,false);assert.deepEqual(hegemon.unverified,['give']);assert.equal(hegemon.proven.receive,true);
 const eth=byName('taker-eth-eth-one-leg-proven');const result=await verifyIdentity(eth.blob,eth.expected,eth.now);
 assert.deepEqual(result.proven,{give:false,receive:true});
});

test('negative: wrong chain, wrong offer, wrong role, wrong inbox, replay on another reservation, expiry, future date',async()=>{
 const c=byName('taker-btc-ada-cip8-enterprise');
 await rejects(c.blob,{...c.expected,give:{chain:'ethereum'}},c.now,/different give chain/);
 await rejects(c.blob,{...c.expected,receive:{chain:'bitcoin'}},c.now,/different receive chain/);
 await rejects(c.blob,{...c.expected,offer:'ff'.repeat(32)},c.now,/different offer/);
 await rejects(c.blob,{...c.expected,role:'owner',reservation:''},c.now,/different role/);
 await rejects(c.blob,{...c.expected,inbox:'ff'.repeat(32)},c.now,/different inbox/);
 await rejects(c.blob,{...c.expected,reservation:'ff'.repeat(32)},c.now,/different reservation/);
 await rejects(c.blob,c.expected,c.now+7200,/expired/);
 await rejects(c.blob,c.expected,c.now-3600,/future/);
 await rejects(c.blob,c.expected,'now',/current time/);
});

test('negative: any edit to the signed statement invalidates every proof',async()=>{
 for(const c of vectors.cases){
  const value=JSON.parse(c.blob);
  for(const edit of [
   v=>{v.statement.nonce='00'.repeat(16);},
   v=>{v.statement.issued+=1;},
   v=>{v.statement.expires+=1;},
   v=>{const side=v.statement.legs.give;const field=Object.keys(side).find(k=>k!=='chain');if(side.chain==='ethereum')side[field]='0x'+'ee'.repeat(20);else if(side.chain==='bitcoin')side[field]='03'+'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';else if(side.chain==='cardano')side[field]='ee'.repeat(28);else return false;}
  ]){
   const copy=clone(value);if(edit(copy)===false)continue;
   await assert.rejects(()=>verifyIdentity(JSON.stringify(copy),c.expected,c.now),/./,c.name);
  }
 }
});

test('negative: proofs must be named, unique, supported and non-empty',async()=>{
 const c=byName('owner-btc-eth-eip191-bip322');const value=JSON.parse(c.blob);
 await rejects({...value,proofs:[]},c.expected,c.now,/no signature/);
 await rejects({...value,proofs:[value.proofs[0],value.proofs[0]]},c.expected,c.now,/Duplicate/);
 const other=clone(value);other.statement.legs.receive.claim='0x'+'11'.repeat(20);
 await rejects(other,c.expected,c.now,/./);
 const scheme=clone(value);scheme.proofs[0].scheme='hmac';await rejects(scheme,c.expected,c.now,/Unsupported/);
 const chain=clone(value);chain.proofs[0].chain='hegemon';await rejects(chain,c.expected,c.now,/Unsupported/);
 const signer=clone(value);signer.proofs[0].signer='0x'+'11'.repeat(20);signer.proofs[1].signer=signer.proofs[1].signer;await rejects(signer,c.expected,c.now,/./);
 const extra=clone(value);extra.extra=1;await rejects(extra,c.expected,c.now,/Invalid identity/);
 const many=clone(value);many.proofs=[...value.proofs,...value.proofs,...value.proofs];await rejects(many,c.expected,c.now,/Invalid identity/);
 await rejects('{',c.expected,c.now,/Invalid identity/);
 await rejects('x'.repeat(9000),c.expected,c.now,/Invalid identity/);
});

test('negative: a proof signed over a different statement does not transfer',async()=>{
 const a=byName('owner-btc-eth-eip191-bip322'),b=byName('owner-btc-eth-bip137-only');
 // Same keys, different nonce is not the case here; swap in proofs from a statement for the other role instead.
 const taker=byName('taker-eth-eth-one-leg-proven'),value=JSON.parse(a.blob);
 value.proofs=JSON.parse(taker.blob).proofs;
 await rejects(value,a.expected,a.now,/./);
 assert.ok(b);
});

test('statement shape: lifetime, reservation and field names are enforced',()=>{
 const base={role:'owner',offer:'11'.repeat(32),inbox:'33'.repeat(32),legs:{give:{chain:'ethereum',address:'0x'+'aa'.repeat(20)},receive:{chain:'cardano',address:'bb'.repeat(28)}},nonce:'cc'.repeat(16),issued:1000,expires:2000};
 const ok=buildStatement(base);
 assert.deepEqual(Object.keys(ok.legs.give).sort(),['chain','refund']);assert.deepEqual(Object.keys(ok.legs.receive).sort(),['chain','claim']);
 assert.throws(()=>buildStatement({...base,expires:1000+MAX_LIFETIME_SECONDS+1}),/lifetime/);
 assert.throws(()=>buildStatement({...base,expires:1000}),/lifetime/);
 assert.throws(()=>buildStatement({...base,reservation:'22'.repeat(32)}),/reservation/);
 assert.throws(()=>buildStatement({...base,role:'taker'}),/reservation/);
 assert.throws(()=>buildStatement({...base,legs:{...base.legs,give:{chain:'ethereum',address:'0x'+'AA'.repeat(20)}}}),/give leg/);
 assert.throws(()=>buildStatement({...base,legs:{...base.legs,give:{chain:'hegemon',address:'0x'+'aa'.repeat(20)}}}),/give leg/);
 assert.throws(()=>buildStatement({...base,legs:{...base.legs,give:{chain:'dogecoin',address:'x'}}}),/Unsupported chain/);
 assert.throws(()=>buildStatement({...base,inbox:'zz'}),/fields/);
 assert.equal(canonical({b:1,a:[true,null,'x']}),'{"a":[true,null,"x"],"b":1}');
 assert.throws(()=>canonical({a:1.5}),/integers/);
 assert.equal(parseIdentity(serializeIdentity(ok,[])).statement.nonce,base.nonce);
});

test('expected participants: each escrow names the counterparties',async()=>{
 const owner=await verifyIdentity(byName('owner-btc-eth-eip191-bip322').blob,byName('owner-btc-eth-eip191-bip322').expected,byName('owner-btc-eth-eip191-bip322').now);
 const taker={addresses:{give:'claimGive',receive:'refundReceive'}};
 const want=expectedParticipants(owner,taker);
 assert.deepEqual(want,{give:{claimant:'claimGive',refundee:owner.addresses.give},receive:{claimant:owner.addresses.receive,refundee:'refundReceive'}});
});

test('primitive verifiers reject malformed input',()=>{
 assert.throws(()=>verifyEthereum({signature:'0x12'},'x'),/Invalid Ethereum/);
 assert.throws(()=>verifyEthereum({signature:'0x'+'00'.repeat(64)+'05'},'x'),/recovery value/);
 assert.throws(()=>verifyBip137({signature:'AAAA'},'x'),/Invalid Bitcoin message/);
 assert.throws(()=>verifyBip322({signature:'AQ=='},'x'),/two-item/);
 assert.throws(()=>verifyCardano({signature:'00',key:'00'},'x'),/COSE|Invalid/);
 const c=byName('taker-btc-ada-cip8-enterprise'),proof=JSON.parse(c.blob).proofs[0];
 assert.throws(()=>verifyCardano(proof,'another text'),/payload/);
 assert.throws(()=>verifyCardano({...proof,key:proof.key.replace(/5820.{64}$/,'5820'+'00'.repeat(32))},c.statement_text),/does not verify|Invalid/);
});
