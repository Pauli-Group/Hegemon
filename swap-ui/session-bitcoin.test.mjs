import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {bitcoinMessageWallet,ethereumWallet} from './test-wallets.mjs';
import {bitcoinProof,signEthereum} from './identity-flow.mjs';
import {buildParticipant,deriveSessionId,participantText,serializeParticipant,sessionOfferDigest} from './session-identity.mjs';
import {createProtocolKey} from './session-packets.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';
import {sessionAssetTerms} from './session-assets.mjs';
import {expectedBitcoinScript,TESTNET4_GENESIS} from './bitcoin-testnet-verifier.mjs';
import {SEPOLIA_GENESIS} from './sepolia-verifier.mjs';
import {planWithMargin} from './swap-flow.mjs';
import {channelFingerprint} from './session-channel.mjs';
import {planSessionTerms} from './session-plan.mjs';
import {checkSessionRefund} from './session-refund.mjs';

const config=JSON.parse(readFileSync(new URL('./chain-timing.json',import.meta.url),'utf8')),now=1800000000,offerId='11'.repeat(32),reservation='22'.repeat(32),channelKey='33'.repeat(32),btcTx='44'.repeat(32),ethTx='55'.repeat(32),contract='0x'+'66'.repeat(20);
async function fixture(lifetime=20*86400){
 const ownerBtc=bitcoinMessageWallet('01'.repeat(32)),takerBtc=bitcoinMessageWallet('02'.repeat(32)),ownerEth=ethereumWallet('03'.repeat(32)),takerEth=ethereumWallet('04'.repeat(32));
 const offer={id:offerId,visibility:'private',expires:now+3600,ownerPublicKey:'04'+'aa'.repeat(64),give:{chain:'bitcoin',kind:'btc',id:'',amount:'50000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'100000000000000'}};
 const session=await deriveSessionId(offerId,reservation),expectedOfferDigest=await sessionOfferDigest(offer),sessionExpires=now+lifetime,channelDigest=await channelFingerprint(session,channelKey);
 async function person(role,btc,eth){const protocol=await createProtocolKey(),statement=buildParticipant({session,offer:offerId,reservation,role,offerDigest:expectedOfferDigest,channelDigest,protocolKey:protocol.publicKey,addresses:{give:btc.publicKey,receive:eth.address},issued:now,expires:sessionExpires},offer),text=participantText(statement);
  return serializeParticipant(statement,[bitcoinProof('bip137',btc.sign(text),text),await signEthereum({request:async({params})=>eth.personalSign(params[0])},eth.address,text)]);}
 const ownerBlob=await person('owner',ownerBtc,ownerEth),takerBlob=await person('taker',takerBtc,takerEth);
 const heads={long:{height:150000,observedAt:now},short:{timestamp:now,observedAt:now}},plan=planWithMargin(config,'bitcoin','ethereum',heads,now);
 const terms={version:2,hashlock:'77'.repeat(32),legs:{long:{asset:offer.give,network:'testnet4',refundee:ownerBtc.publicKey,claimant:takerBtc.publicKey,expiry:plan.long.expiry},short:{asset:offer.receive,network:'sepolia',refundee:takerEth.address,claimant:ownerEth.address,expiry:plan.short.expiry}}};
 const btcRef={chain:'bitcoin',txid:btcTx,vout:0},ethRef={chain:'ethereum',txid:ethTx},btcFields=sessionAssetTerms(terms,'long',{reference:btcRef}).operationTerms,script=await expectedBitcoinScript({...btcFields,refund_height:Number(btcFields.refund_height)});
 const state={genesis:TESTNET4_GENESIS,script,spent:false,tip:150000};
 const readers={bitcoin:{head:async()=>({genesis:state.genesis,tip:state.tip}),escrow:async(txid,vout)=>({genesis:state.genesis,txid,vout,tip:state.tip,confirmed:true,confirmations:2,block_height:state.tip-1,block_hash:'88'.repeat(32),spent:state.spent,amount_sats:50000,script:state.script})},ethereum:{provider:{request:async({method,params=[]})=>{
  if(method==='eth_chainId')return '0xaa36a7';if(method==='eth_getBlockByNumber')return params[0]==='0x0'?{hash:SEPOLIA_GENESIS}:{timestamp:'0x'+now.toString(16)};
  if(method==='eth_getTransactionReceipt')return {transactionHash:'0x'+ethTx,status:'0x1',contractAddress:contract};
  if(method==='eth_getTransactionByHash')return {hash:'0x'+ethTx,to:null,from:takerEth.address};throw Error('Unexpected RPC '+method);
 }}}};
 return {state,args:{terms,offer,expectedOfferDigest,channelDigest,ownerBlob,takerBlob,session,reservation,sessionExpires,role:'initiator',references:{long:btcRef,short:ethRef},purpose:'claim_short',readers,config,now,nowClock:()=>now,templates:{ether:{}},verifyEthereum:async()=>({contract})}};
}

test('Bitcoin testnet funding is checked against wallet-bound terms and fresh policy',async()=>{
 const {args,state}=await fixture(),result=await verifySessionSnapshot(args);assert.equal(result.escrows.long.tip,150000);
 state.script='0020'+'00'.repeat(32);await assert.rejects(verifySessionSnapshot(args),/does not match/);state.script=await expectedBitcoinScript({...sessionAssetTerms(args.terms,'long',{reference:args.references.long}).operationTerms,refund_height:args.terms.legs.long.expiry});
 state.spent=true;await assert.rejects(verifySessionSnapshot(args),/spent/);state.spent=false;
 state.genesis='00'.repeat(32);await assert.rejects(verifySessionSnapshot(args),/head is unavailable or invalid/);
});
test('Bitcoin height deadlines use their estimated recovery time, not a Unix timestamp',async()=>{
 const {args}=await fixture(3*86400);
 await assert.rejects(verifySessionSnapshot({...args,purpose:'fund_first',references:{}}),/expire too soon/);
});
test('the planner derives Bitcoin block heights and an encrypted secret from both current testnets',async()=>{
 const {args,state}=await fixture(),snapshot={version:2,offer:args.offer,offerDigest:args.expectedOfferDigest,reservation,credential:'99'.repeat(32),channelKey,sessionExpires:args.sessionExpires,terms:null,escrows:{long:null,short:null},secretEnvelope:null,ownerBlob:args.ownerBlob,takerBlob:args.takerBlob,transport:{next:1,previous:null}};
 const input={session:args.session,role:'owner',snapshot,readers:args.readers,config,passphrase:'disposable test passphrase',now,nowClock:()=>now};
 const result=await planSessionTerms(input);
 assert.equal(result.terms.legs.long.network,'testnet4');assert.ok(result.terms.legs.long.expiry>150000);assert.equal(result.minimumCardanoLovelace,null);assert.equal(result.secretEnvelope.hashlock,result.terms.hashlock);
 state.genesis='00'.repeat(32);await assert.rejects(planSessionTerms(input),/Bitcoin testnet4 head/);
});
test('Bitcoin refund recovery verifies the exact unspent escrow after its refund height without a relay',async()=>{
 const {args,state}=await fixture(),snapshot={terms:args.terms,escrows:args.references};
 await assert.rejects(checkSessionRefund({snapshot,role:'owner',readers:args.readers,config}),/refund height has not been reached/);
 state.tip=args.terms.legs.long.expiry;
 assert.equal((await checkSessionRefund({snapshot,role:'owner',readers:args.readers,config})).chain,'bitcoin');
 state.spent=true;await assert.rejects(checkSessionRefund({snapshot,role:'owner',readers:args.readers,config}),/spent/);
});
