import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {cardanoWallet,ethereumWallet} from './test-wallets.mjs';
import {signCardano,signEthereum} from './identity-flow.mjs';
import {buildParticipant,deriveSessionId,participantText,serializeParticipant,sessionOfferDigest} from './session-identity.mjs';
import {createProtocolKey} from './session-packets.mjs';
import {channelFingerprint} from './session-channel.mjs';
import {planSessionTerms} from './session-plan.mjs';
import {setPinnedScript} from './cardano-tx.mjs';
import {SEPOLIA_GENESIS} from './sepolia-verifier.mjs';
const now=1800000000,config=JSON.parse(readFileSync(new URL('./chain-timing.json',import.meta.url),'utf8')),params=JSON.parse(readFileSync(new URL('./fixtures/cardano-preview-params.json',import.meta.url),'utf8'));
setPinnedScript(JSON.parse(readFileSync(new URL('./cardano-htlc-script.json',import.meta.url),'utf8')));
const cardA=cardanoWallet('01'.repeat(32)),cardB=cardanoWallet('02'.repeat(32)),ethA=ethereumWallet('03'.repeat(32)),ethB=ethereumWallet('04'.repeat(32));
async function fixture(token=false){
 const id='11'.repeat(32),reservation='22'.repeat(32),session=await deriveSessionId(id,reservation),channelKey='44'.repeat(32),channelDigest=await channelFingerprint(session,channelKey),expires=now+7*86400;
 const give=token?{chain:'cardano',kind:'native',id:'55'.repeat(28)+'.ab',amount:'17'}:{chain:'cardano',kind:'ada',id:'',amount:'5000000'};
 const receive={chain:'ethereum',kind:'eth',id:'',amount:'100000000000000000'},offer={id,visibility:'private',expires:now+3600,ownerPublicKey:'04'+'aa'.repeat(64),give,receive},offerDigest=await sessionOfferDigest(offer);
 async function cert(role,ada,eth){const key=await createProtocolKey(),statement=buildParticipant({session,offer:id,reservation,role,offerDigest,channelDigest,protocolKey:key.publicKey,addresses:{give:ada.keyHash,receive:eth.address},issued:now,expires},{give,receive}),text=participantText(statement);
  return serializeParticipant(statement,[await signCardano({getUsedAddresses:async()=>[ada.addressHex],signData:async(a,p)=>ada.signData(a,p)},text),await signEthereum({request:async({params})=>eth.personalSign(params[0])},eth.address,text)]);}
 const snapshot={version:2,offer,offerDigest,reservation,credential:'33'.repeat(32),channelKey,sessionExpires:expires,terms:null,escrows:{long:null,short:null},secretEnvelope:null,ownerBlob:await cert('owner',cardA,ethA),takerBlob:await cert('taker',cardB,ethB),transport:{next:2,previous:null}};
 const provider={request:async({method,params=[]})=>{if(method==='eth_chainId')return '0xaa36a7';if(method==='eth_getBlockByNumber'&&params[0]==='0x0')return {hash:SEPOLIA_GENESIS};if(method==='eth_getBlockByNumber'&&params[0]==='latest')return {timestamp:'0x'+now.toString(16)};throw Error('Unexpected RPC');}};
 const readers={ethereum:{provider},cardano:{params:async()=>({...params,slot:now-1666656000})}};
 return {session,role:'owner',snapshot,readers,config,passphrase:'a disposable test passphrase',now,nowClock:()=>now};
}
test('plans exact ADA–ETH terms with an encrypted secret and safe ordered deadlines',async()=>{
 const args=await fixture(),out=await planSessionTerms(args);
 assert.equal(out.terms.legs.long.asset.amount,'5000000');assert.equal(out.terms.legs.short.asset.amount,'100000000000000000');
 assert.equal(out.terms.legs.long.refundee,cardA.keyHash);assert.equal(out.terms.legs.short.claimant,ethA.address);
 assert.equal(out.secretEnvelope.hashlock,out.terms.hashlock);assert.equal(out.policy.ok,true);assert.ok(out.terms.legs.long.expiry>out.terms.legs.short.expiry);
});
test('token deposit must cover the actual inline-datum minimum and malformed states fail closed',async()=>{
 const args=await fixture(true);
 await assert.rejects(planSessionTerms({...args,cardanoDeposit:'100000'}),/needs at least/);
 const out=await planSessionTerms({...args,cardanoDeposit:'3000000'});assert.equal(out.terms.legs.long.lovelace,'3000000');assert.ok(BigInt(out.minimumCardanoLovelace)>0n);
 await assert.rejects(planSessionTerms({...args,role:'taker',cardanoDeposit:'3000000'}),/not ready/);
 await assert.rejects(planSessionTerms({...args,nowClock:()=>now-1,cardanoDeposit:'3000000'}),/clock changed/);
});
