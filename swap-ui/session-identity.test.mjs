import test from 'node:test';
import assert from 'node:assert/strict';
import {buildParticipant,checkSessionAsset,deriveSessionId,participantText,serializeParticipant,sessionOfferDigest,verifyParticipant} from './session-identity.mjs';
import {bitcoinProof,signCardano,signEthereum} from './identity-flow.mjs';
import {bitcoinMessageWallet,cardanoWallet,ethereumWallet} from './test-wallets.mjs';
import {toHex} from './cbor.mjs';

const now=1800000000,offerId='11'.repeat(32),reservation='22'.repeat(32),ownerInbox='04'+'aa'.repeat(64);
const btc=bitcoinMessageWallet('01'.repeat(32)),eth=ethereumWallet('02'.repeat(32)),ada=cardanoWallet('03'.repeat(32));
const assets={give:{chain:'bitcoin',kind:'btc',id:'',amount:'1000'},receive:{chain:'ethereum',kind:'erc20',id:'0x'+'ab'.repeat(20),amount:'100000000000000000000000'}};
const offer={id:offerId,visibility:'public',give:assets.give,receive:assets.receive,expires:now+3600,ownerPublicKey:ownerInbox};
const provider={async request({method,params}){assert.equal(method,'personal_sign');return eth.personalSign(params[0]);}};
async function protocolKey(){const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);return toHex(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)));}
async function setup({selected=assets,addresses={give:btc.publicKey,receive:eth.address}}={}){
 const session=await deriveSessionId(offerId,reservation),digest=await sessionOfferDigest({...offer,give:selected.give,receive:selected.receive});
 const channelDigest='44'.repeat(32),statement=buildParticipant({session,offer:offerId,reservation,role:'owner',offerDigest:digest,channelDigest,protocolKey:await protocolKey(),addresses,issued:now,expires:now+7200},selected);
 const expected={session,offer:offerId,reservation,role:'owner',offerDigest:digest,channelDigest,assets:selected,sessionExpires:now+10000};
 return {statement,expected};
}
async function signed(statement){const text=participantText(statement);return serializeParticipant(statement,[bitcoinProof('bip137',btc.sign(text),text),await signEthereum(provider,eth.address,text)]);}

test('a participant binds an independent protocol key and exact offer to both wallet identities',async()=>{
 const {statement,expected}=await setup(),verified=await verifyParticipant(await signed(statement),expected,now);
 assert.deepEqual(verified.proven,{give:true,receive:true});assert.deepEqual(verified.unverified,[]);
 assert.equal(verified.statement.protocolKey,statement.protocolKey);
 const altered={...offer,receive:{...offer.receive,amount:'100000000000000000000001'}};
 assert.notEqual(await sessionOfferDigest(altered),expected.offerDigest);
 const mixed={...offer,receive:{...offer.receive,id:'0x'+'AB'.repeat(20)}};
 assert.equal(await sessionOfferDigest(mixed),expected.offerDigest,'equivalent token addresses are canonicalized');
});

test('participant signatures cannot be replayed, substituted, truncated, expired, or detached from a wallet',async()=>{
 const {statement,expected}=await setup(),blob=await signed(statement),bad=edit=>{const value=JSON.parse(blob);edit(value);return JSON.stringify(value);};
 for(const [change,pattern] of [
  [e=>({...e,session:'33'.repeat(32)}),/different session|does not match/],
  [e=>({...e,reservation:'33'.repeat(32)}),/does not match/],
  [e=>({...e,offerDigest:'33'.repeat(32)}),/does not match/],
  [e=>({...e,channelDigest:'33'.repeat(32)}),/does not match/],
  [e=>({...e,role:'taker'}),/does not match/],
 ])await assert.rejects(verifyParticipant(blob,change(expected),now),pattern);
 await assert.rejects(verifyParticipant(bad(v=>{v.statement.protocolKey='04'+'00'.repeat(64);}),expected,now),/protocol key/);
 await assert.rejects(verifyParticipant(bad(v=>{v.statement.addresses.receive='0x'+'aa'.repeat(20);}),expected,now),/does not verify|proof|signer/i);
 await assert.rejects(verifyParticipant(bad(v=>{v.proofs.pop();}),expected,now),/missing its wallet proof/);
 await assert.rejects(verifyParticipant(bad(v=>{v.proofs.push(v.proofs[0]);}),expected,now),/Duplicate/);
 await assert.rejects(verifyParticipant(bad(v=>{v.statement.extra='secret';}),expected,now),/Invalid participant statement/);
 await assert.rejects(verifyParticipant(blob,expected,now+7200),/expired/);
 await assert.rejects(verifyParticipant(blob,{...expected,sessionExpires:now+100},now),/session lifetime/);
});

test('Cardano wallet proofs authenticate the payment key, and Hegemon addresses stay explicitly unverified',async()=>{
 const selected={give:{chain:'hegemon',kind:'hgn',id:'',amount:'1'},receive:{chain:'cardano',kind:'ada',id:'',amount:'1000000'}};
 const {statement,expected}=await setup({selected,addresses:{give:'shca1'+'q'.repeat(200),receive:ada.keyHash}});
 const api={getUsedAddresses:async()=>[ada.addressHex],signData:async(address,payload)=>ada.signData(address,payload)};
 const proof=await signCardano(api,participantText(statement));
 const verified=await verifyParticipant(serializeParticipant(statement,[proof]),expected,now);
 assert.deepEqual(verified.proven,{give:false,receive:true});assert.deepEqual(verified.unverified,['give']);
 const modified=structuredClone(statement);modified.addresses.give='shca1'+'p'.repeat(200);
 await assert.rejects(verifyParticipant(serializeParticipant(modified,[proof]),expected,now),/payload|verify/i);
});

test('asset validation keeps exact integer quantities and rejects malformed assets',()=>{
 assert.equal(checkSessionAsset(assets.receive).amount,'100000000000000000000000');
 for(const asset of [
  {...assets.give,amount:'0'}, {...assets.give,amount:'01'}, {...assets.give,id:'unexpected'},
  {...assets.receive,amount:(1n<<256n).toString()}, {...assets.receive,kind:'erc721',id:assets.receive.id+':1',amount:'2'},
  {chain:'cardano',kind:'native',id:'aa'.repeat(28)+'.',amount:(1n<<63n).toString()},
 ])assert.throws(()=>checkSessionAsset(asset));
});
