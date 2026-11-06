import {test} from 'node:test';
import assert from 'node:assert/strict';
import {legSpecs,draftStatement,statementText,signEthereum,signCardano,bitcoinProof,addProof,publishable,expectedInbox,judgeIdentity,normalizeAddress} from './identity-flow.mjs';
import {parseIdentity,verifyIdentity,MAX_LIFETIME_SECONDS} from './identity.mjs';
import {sealPublicSession,makeInboxKeyPair,inboxFingerprint,parsePublicSession} from './public-inbox.mjs';
import {ethereumWallet,cardanoWallet,bitcoinMessageWallet} from './test-wallets.mjs';

const NOW=1_800_000_000,OFFER='1'.repeat(64),RESERVATION='2'.repeat(64);
const eth=ethereumWallet('01'.repeat(32)),ada=cardanoWallet('02'.repeat(32)),btc=bitcoinMessageWallet('03'.repeat(32));
const offer={id:OFFER,give:{chain:'bitcoin',kind:'btc',id:'',amount:'1000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'5'},expires:NOW+3600,reservationId:RESERVATION};
const provider=wallet=>({request:async({method,params})=>{assert.equal(method,'personal_sign');assert.equal(params[1],wallet.address);return wallet.personalSign(params[0]);}});
const cardanoApi=wallet=>({getUsedAddresses:async()=>['e1'+'11'.repeat(28),wallet.addressHex],signData:async(address,payload)=>wallet.signData(address,payload)});

test('each role names the right purpose on each leg',()=>{
 assert.deepEqual(legSpecs(offer,'owner').map(x=>[x.side,x.purpose,x.chain]),[['give','refund','bitcoin'],['receive','claim','ethereum']]);
 assert.deepEqual(legSpecs(offer,'taker').map(x=>[x.side,x.purpose]),[['give','claim'],['receive','refund']]);
 assert.match(legSpecs({...offer,give:{chain:'hegemon'}},'owner')[0].label,/not available yet/);
 assert.equal(normalizeAddress('ethereum',' 0xAbC '),'0xabc');assert.equal(normalizeAddress('hegemon','anything'),'pending');
});

test('drafting binds offer, reservation and inbox and bounds the lifetime',()=>{
 const owner=draftStatement({role:'owner',offer,reservation:RESERVATION,inbox:'3'.repeat(64),addresses:{give:btc.publicKey,receive:eth.address},now:NOW,nonce:'a'.repeat(32)});
 assert.equal(owner.reservation,'');assert.equal(owner.expires,NOW+3600);assert.equal(owner.legs.give.refund,btc.publicKey);assert.equal(owner.legs.receive.claim,eth.address);
 const taker=draftStatement({role:'taker',offer:{...offer,expires:NOW+5*86400},reservation:RESERVATION,inbox:'4'.repeat(64),addresses:{give:btc.publicKey,receive:eth.address.toUpperCase().replace('0X','0x')},now:NOW});
 assert.equal(taker.reservation,RESERVATION);assert.equal(taker.expires,NOW+86400);assert.equal(taker.legs.receive.refund,eth.address);assert.match(taker.nonce,/^[0-9a-f]{32}$/);
 assert.throws(()=>draftStatement({role:'taker',offer,reservation:'',inbox:'4'.repeat(64),addresses:{give:btc.publicKey,receive:eth.address},now:NOW}),/reservation/);
 assert.throws(()=>draftStatement({role:'owner',offer,inbox:'3'.repeat(64),addresses:{give:'03'+'0'.repeat(64),receive:eth.address},now:NOW}),/give leg/);
 assert.ok(owner.expires-owner.issued<=MAX_LIFETIME_SECONDS);
});

test('wallets sign the statement text and the signatures verify; foreign signatures are refused',async()=>{
 const inbox=await inboxFingerprint((await makeInboxKeyPair()).publicKey);
 const statement=draftStatement({role:'owner',offer,inbox,addresses:{give:btc.publicKey,receive:eth.address},now:NOW});
 const text=statementText(statement);let proofs=[];
 proofs=addProof(statement,proofs,await signEthereum(provider(eth),eth.address,text));
 proofs=addProof(statement,proofs,bitcoinProof('bip137',btc.sign(text),text));
 assert.deepEqual(proofs.map(p=>p.chain).sort(),['bitcoin','ethereum']);
 const verified=await verifyIdentity(publishable(statement,proofs),{offer:OFFER,role:'owner',reservation:'',inbox,give:{chain:'bitcoin'},receive:{chain:'ethereum'}},NOW);
 assert.deepEqual(verified.proven,{give:true,receive:true});
 // Signing again replaces rather than duplicates.
 assert.equal(addProof(statement,proofs,bitcoinProof('bip137',btc.sign(text),text)).length,2);
 // A wallet that is not named in the statement, or signs other text, is refused.
 const stranger=ethereumWallet('09'.repeat(32));
 await assert.rejects(async()=>addProof(statement,proofs,await signEthereum(provider(stranger),stranger.address,text)),/not from an address named/);
 // A message signature over other text recovers some other key, which the statement does not name.
 assert.throws(()=>addProof(statement,proofs,bitcoinProof('bip137',btc.sign('different text'),text)),/not from an address named/);
 assert.throws(()=>bitcoinProof('bip137','not base64!',text),/Invalid/);
 await assert.rejects(signEthereum(null,eth.address,text),/Connect an Ethereum wallet/);
 await assert.rejects(signEthereum({request:async()=>'0x12'},eth.address,text),/Invalid Ethereum/);
});

test('cardano signData: the first payment-key address signs and the key hash is proven',async()=>{
 const inbox='5'.repeat(64);
 const statement=draftStatement({role:'taker',offer:{...offer,receive:{chain:'cardano',kind:'ada',id:'',amount:'7'}},reservation:RESERVATION,inbox,addresses:{give:btc.publicKey,receive:ada.keyHash},now:NOW});
 const proof=await signCardano(cardanoApi(ada),statementText(statement));
 assert.equal(proof.signer,ada.keyHash);assert.equal(addProof(statement,[],proof).length,1);
 await assert.rejects(signCardano({getUsedAddresses:async()=>['e1'+'22'.repeat(28)],signData:async()=>({})},'x'),/no payment-key address/);
 await assert.rejects(signCardano({getUsedAddresses:async()=>[ada.addressHex],signData:async()=>({signature:1})},'x'),/unexpected signature/);
 await assert.rejects(signCardano(null,'x'),/Connect a Cardano wallet/);
 // A wallet that signs a different payload is detected when the proof is checked.
 await assert.rejects(signCardano({getUsedAddresses:async()=>[ada.addressHex],signData:async(a,p)=>ada.signData(a,Buffer.from('other').toString('hex'))},'x'),/payload/);
});

async function scene(){
 const ownerKey=await makeInboxKeyPair(),inbox=await inboxFingerprint(ownerKey.publicKey);
 const full={...offer,ownerPublicKey:ownerKey.publicKey};
 const ownerStatement=draftStatement({role:'owner',offer:full,inbox,addresses:{give:btc.publicKey,receive:eth.address},now:NOW});
 const ownerText=statementText(ownerStatement);
 const ownerBlob=publishable(ownerStatement,addProof(ownerStatement,[],bitcoinProof('bip137',btc.sign(ownerText),ownerText)));
 const handshake=await sealPublicSession(ownerKey.publicKey,OFFER,RESERVATION,'6'.repeat(64));
 const takerInbox=await inboxFingerprint(parsePublicSession(handshake).ephemeral);
 const takerStatement=draftStatement({role:'taker',offer:full,reservation:RESERVATION,inbox:takerInbox,addresses:{give:btc.publicKey,receive:eth.address},now:NOW});
 const takerText=statementText(takerStatement);
 const takerBlob=publishable(takerStatement,addProof(takerStatement,[],await signEthereum(provider(eth),eth.address,takerText)));
 return {full,ownerKey,inbox,ownerBlob,takerBlob,takerInbox,messages:[{id:1,sender:'taker',ciphertext:handshake}]};
}

test('judging published statements: verified, none, and every substitution is a loud failure',async()=>{
 const s=await scene();
 const owner=await judgeIdentity({role:'owner',offer:s.full,blob:s.ownerBlob,inbox:await expectedInbox({role:'owner',offer:s.full,messages:s.messages}),now:NOW});
 assert.equal(owner.status,'verified');assert.match(owner.identity.code,/^[0-9a-f]{16}$/);assert.equal(owner.pinned,false);
 const taker=await judgeIdentity({role:'taker',offer:s.full,blob:s.takerBlob,inbox:await expectedInbox({role:'taker',offer:s.full,messages:s.messages}),now:NOW});
 assert.equal(taker.status,'verified');
 assert.deepEqual(await judgeIdentity({role:'owner',offer:s.full,blob:undefined,inbox:s.inbox,now:NOW}),{status:'none'});
 // A relay that substitutes the owner's inbox key: the statement names the real fingerprint.
 const attacker=await makeInboxKeyPair(),swapped={...s.full,ownerPublicKey:attacker.publicKey};
 const substituted=await judgeIdentity({role:'owner',offer:swapped,blob:s.ownerBlob,inbox:await expectedInbox({role:'owner',offer:swapped,messages:[]}),now:NOW});
 assert.equal(substituted.status,'failed');assert.match(substituted.error,/different inbox key/);
 // A relay that substitutes the taker's handshake: the statement names the real ephemeral key.
 const forged=await sealPublicSession(s.ownerKey.publicKey,OFFER,RESERVATION,'7'.repeat(64));
 const replaced=await judgeIdentity({role:'taker',offer:s.full,blob:s.takerBlob,inbox:await expectedInbox({role:'taker',offer:s.full,messages:[{sender:'taker',ciphertext:forged}]}),now:NOW});
 assert.equal(replaced.status,'failed');assert.match(replaced.error,/different inbox key/);
 // A taker statement replayed on another reservation.
 const other=await judgeIdentity({role:'taker',offer:{...s.full,reservationId:'8'.repeat(64)},blob:s.takerBlob,inbox:s.takerInbox,now:NOW});
 assert.match(other.error,/different reservation/);
 // Expired, tampered and wrong-chain statements.
 assert.match((await judgeIdentity({role:'owner',offer:s.full,blob:s.ownerBlob,inbox:s.inbox,now:NOW+99999})).error,/expired/);
 const tampered=JSON.parse(s.ownerBlob);tampered.statement.legs.give.refund='02'+'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
 assert.equal((await judgeIdentity({role:'owner',offer:s.full,blob:JSON.stringify(tampered),inbox:s.inbox,now:NOW})).status,'failed');
 assert.match((await judgeIdentity({role:'owner',offer:{...s.full,receive:{chain:'cardano'}},blob:s.ownerBlob,inbox:s.inbox,now:NOW})).error,/different receive chain/);
 assert.match((await judgeIdentity({role:'owner',offer:{...s.full,id:'9'.repeat(64)},blob:s.ownerBlob,inbox:s.inbox,now:NOW})).error,/different offer/);
 assert.match((await judgeIdentity({role:'taker',offer:s.full,blob:s.takerBlob,inbox:'',now:NOW})).error,/No reservation handshake/);
 assert.match((await judgeIdentity({role:'owner',offer:s.full,blob:s.ownerBlob,inbox:'',now:NOW})).error,/no inbox key/);
 assert.equal(await expectedInbox({role:'owner',offer:{...s.full,ownerPublicKey:undefined},messages:[]}),'');
});

test('a pinned identity code must match: a relay presenting another valid identity is caught',async()=>{
 const s=await scene(),inbox=s.inbox;
 const first=await judgeIdentity({role:'owner',offer:s.full,blob:s.ownerBlob,inbox,now:NOW});
 assert.equal((await judgeIdentity({role:'owner',offer:s.full,blob:s.ownerBlob,inbox,now:NOW,pin:first.identity.code})).pinned,true);
 // The relay swaps in a different, equally valid statement (new nonce, same wallets) or a wholly different identity.
 const again=draftStatement({role:'owner',offer:s.full,inbox,addresses:{give:btc.publicKey,receive:eth.address},now:NOW});
 const text=statementText(again),blob=publishable(again,addProof(again,[],bitcoinProof('bip137',btc.sign(text),text)));
 const changed=await judgeIdentity({role:'owner',offer:s.full,blob,inbox,now:NOW,pin:first.identity.code});
 assert.equal(changed.status,'failed');assert.match(changed.error,/not the pinned code/);
 assert.equal(parseIdentity(blob).statement.role,'owner');
});
