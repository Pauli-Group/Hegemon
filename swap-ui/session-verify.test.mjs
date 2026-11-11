import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {cardanoWallet,ethereumWallet} from './test-wallets.mjs';
import {signCardano,signEthereum} from './identity-flow.mjs';
import {buildParticipant,deriveSessionId,participantText,serializeParticipant,sessionOfferDigest} from './session-identity.mjs';
import {createProtocolKey} from './session-packets.mjs';
import {verifySessionSnapshot} from './session-verify.mjs';
import {PREVIEW_HTLC_ADDRESS} from './cardano-preview-verifier.mjs';
import {datumBytes} from './cardano-tx.mjs';
import {toHex} from './cbor.mjs';
import {SEPOLIA_GENESIS} from './sepolia-verifier.mjs';
import {expectedEtherRuntime,expectedTokenRuntime} from './ethereum-escrow.mjs';
import {sessionAssetTerms} from './session-assets.mjs';

const config=JSON.parse(readFileSync(new URL('./chain-timing.json',import.meta.url),'utf8'));
const ether=JSON.parse(readFileSync(new URL('./ether-escrow-template.json',import.meta.url),'utf8'));
const tokenTemplate=JSON.parse(readFileSync(new URL('./token-escrow-template.json',import.meta.url),'utf8'));
const now=1800000000,offerId='11'.repeat(32),reservation='22'.repeat(32),channelDigest='33'.repeat(32),hashlock='44'.repeat(32),cardanoTx='55'.repeat(32),ethTx='66'.repeat(32),contract='0x'+'77'.repeat(20);
const ownerAda=cardanoWallet('01'.repeat(32)),takerAda=cardanoWallet('02'.repeat(32)),ownerEth=ethereumWallet('03'.repeat(32)),takerEth=ethereumWallet('04'.repeat(32));
const give={chain:'cardano',kind:'ada',id:'',amount:'5000000'},receive={chain:'ethereum',kind:'eth',id:'',amount:'100000000000000000'};
const offer={id:offerId,visibility:'private',expires:now+3600,ownerPublicKey:'04'+'aa'.repeat(64),give,receive};
const terms={version:2,hashlock,legs:{long:{asset:give,network:'preview',refundee:ownerAda.keyHash,claimant:takerAda.keyHash,expiry:now+86400},short:{asset:receive,network:'sepolia',refundee:takerEth.address,claimant:ownerEth.address,expiry:now+43200}}};
async function fixture({certLifetime=7*86400,tokenAssets=false,reverse=false}={}){
 const cardAsset=tokenAssets?{chain:'cardano',kind:'native',id:'88'.repeat(28)+'.ab',amount:'17'}:give;
 const ethAsset=tokenAssets?{chain:'ethereum',kind:'erc20',id:'0x'+'99'.repeat(20),amount:'100000000000000000'}:receive;
 const giveAsset=reverse?ethAsset:cardAsset,receiveAsset=reverse?cardAsset:ethAsset;
 const localOffer={...offer,give:giveAsset,receive:receiveAsset};
 const cardDeposit=tokenAssets?{lovelace:'2000000'}:{};
 const localTerms=reverse?{...terms,legs:{long:{asset:ethAsset,network:'sepolia',refundee:ownerEth.address,claimant:takerEth.address,expiry:now+86400},short:{asset:cardAsset,network:'preview',refundee:takerAda.keyHash,claimant:ownerAda.keyHash,expiry:now+43200,...cardDeposit}}}:{...terms,legs:{long:{...terms.legs.long,asset:giveAsset,...cardDeposit},short:{...terms.legs.short,asset:receiveAsset}}};
 const session=await deriveSessionId(offerId,reservation),offerDigest=await sessionOfferDigest(localOffer),sessionExpires=now+7*86400;
 async function cert(role,ada,eth){
  const key=await createProtocolKey();
  const addresses=reverse?{give:eth.address,receive:ada.keyHash}:{give:ada.keyHash,receive:eth.address};
  const statement=buildParticipant({session,offer:offerId,reservation,role,offerDigest,channelDigest,protocolKey:key.publicKey,addresses,issued:now,expires:now+certLifetime},{give:giveAsset,receive:receiveAsset});
  const text=participantText(statement),cardano={getUsedAddresses:async()=>[ada.addressHex],signData:async(a,p)=>ada.signData(a,p)},ethereum={request:async({params})=>eth.personalSign(params[0])};
  return serializeParticipant(statement,[await signCardano(cardano,text),await signEthereum(ethereum,eth.address,text)]);
 }
 const ownerBlob=await cert('owner',ownerAda,ownerEth),takerBlob=await cert('taker',takerAda,takerEth);
 const ethSide=reverse?'long':'short',cardSide=reverse?'short':'long';
 const fields=sessionAssetTerms(localTerms,ethSide,{contract}).operationTerms;
 const slot=now-1666656000,cardanoFields=sessionAssetTerms(localTerms,cardSide).operationTerms;
 const state={value:cardanoFields.lovelace,receiptStatus:'0x1',from:reverse?ownerEth.address:takerEth.address,ethAvailable:true};
 const latest={number:'0x64',hash:'0x'+'aa'.repeat(32),timestamp:'0x'+now.toString(16)},confirmed={number:'0x63',hash:'0x'+'bb'.repeat(32),timestamp:'0x'+(now-12).toString(16)};
 const provider={async request({method,params=[]}){
  if(!state.ethAvailable)throw Error('Ethereum unavailable');
  if(method==='eth_chainId')return '0xaa36a7';
  if(method==='eth_getBlockByNumber')return params[0]==='0x0'?{hash:SEPOLIA_GENESIS}:params[0]==='latest'?latest:confirmed;
  if(method==='eth_blockNumber')return '0x64';
  if(method==='eth_getTransactionReceipt')return {transactionHash:'0x'+ethTx,status:state.receiptStatus,contractAddress:contract};
  if(method==='eth_getTransactionByHash')return {hash:'0x'+ethTx,to:null,from:state.from};
  if(method==='eth_getCode')return tokenAssets?expectedTokenRuntime(tokenTemplate,fields):expectedEtherRuntime(ether,fields);
  if(method==='eth_call')return '0x'+(params[0].data==='0xf3a504f2'?'1':params[0].data.startsWith('0x70a08231')?BigInt(ethAsset.amount).toString(16):'0').padStart(64,'0');
  if(method==='eth_getBalance')return '0x'+BigInt(ethAsset.amount).toString(16);
  throw Error('Unexpected request: '+method);
 }};
 const cardano={params:async()=>({network:'preview',magic:2,system_start:1666656000,slot}),escrow:async()=>({network:'preview',magic:2,system_start:1666656000,slot,confirmations:10,output:{tx_hash:cardanoTx,tx_index:0,address:PREVIEW_HTLC_ADDRESS,value:state.value,asset_list:tokenAssets?[{policy_id:'88'.repeat(28),asset_name:'ab',quantity:'17'}]:[],is_spent:false,inline_datum:{bytes:toHex(datumBytes(cardanoFields)),value:{constructor:0,fields:[{bytes:hashlock},{bytes:cardanoFields.claimant},{bytes:cardanoFields.refundee},{int:Number(cardanoFields.expiry_ms)}]}}}})};
 const cardRef={chain:'cardano',txid:cardanoTx,vout:0},ethRef={chain:'ethereum',txid:ethTx};
 return {state,args:{terms:localTerms,offer:localOffer,expectedOfferDigest:offerDigest,channelDigest,ownerBlob,takerBlob,session,reservation,sessionExpires,role:'initiator',references:reverse?{long:ethRef,short:cardRef}:{long:cardRef,short:ethRef},purpose:'claim_short',readers:{ethereum:{provider},cardano},config,now,nowClock:()=>now,templates:{ether,token:tokenTemplate}}};
}

test('a wallet-bound ADA–ETH session verifies both pinned escrows and exact large quantities',async()=>{
 const {args}=await fixture(),result=await verifySessionSnapshot(args);
 assert.equal(result.policy.ok,true);assert.equal(result.escrows.long.outref,cardanoTx+'#0');assert.equal(result.escrows.short.contract,contract);
});
test('a Cardano native token and an ERC-20 pass the real pinned escrow verifiers',async()=>{
 const {args}=await fixture({tokenAssets:true}),result=await verifySessionSnapshot(args);
 assert.equal(result.policy.ok,true);assert.equal(result.escrows.long.outref,cardanoTx+'#0');assert.equal(result.escrows.short.token,'0x'+'99'.repeat(20));
});
test('the same verified swap works when Ethereum is the first funded leg',async()=>{
 for(const tokenAssets of [false,true]){
  const {args}=await fixture({reverse:true,tokenAssets}),result=await verifySessionSnapshot(args);
  assert.equal(result.escrows.long.contract,contract);assert.equal(result.escrows.short.outref,cardanoTx+'#0');
 }
});
test('chain contradictions, wrong funders, stale snapshots and provider failures block the session',async()=>{
 const {args,state}=await fixture();
 state.value='4999999';await assert.rejects(verifySessionSnapshot(args),/value does not match/);state.value=give.amount;
 state.from=ownerEth.address;await assert.rejects(verifySessionSnapshot(args),/agreed funder/);state.from=takerEth.address;
 state.receiptStatus='0x0';await assert.rejects(verifySessionSnapshot(args),/agreed funder/);state.receiptStatus='0x1';
 state.ethAvailable=false;await assert.rejects(verifySessionSnapshot(args),/Ethereum unavailable/);state.ethAvailable=true;
 await assert.rejects(verifySessionSnapshot({...args,nowClock:()=>now+config.policy.maxObservationAgeSeconds+1}),/deadlines are not safe/);
 await assert.rejects(verifySessionSnapshot({...args,references:{...args.references,long:{chain:'ethereum',txid:cardanoTx}}}),/wrong chain/);
 const changed=structuredClone(terms);changed.legs.short.asset.amount='1';
 await assert.rejects(verifySessionSnapshot({...args,terms:changed}),/assets do not match/);
});
test('the requested action determines which escrows must be independently verified',async()=>{
 const {args}=await fixture();
 const first=await verifySessionSnapshot({...args,purpose:'fund_first',references:{}});
 assert.deepEqual(first.escrows,{long:null,short:null});
 const second=await verifySessionSnapshot({...args,role:'responder',purpose:'fund_second',references:{long:args.references.long}});
 assert.equal(second.escrows.long.outref,cardanoTx+'#0');assert.equal(second.escrows.short,null);
 await assert.rejects(verifySessionSnapshot({...args,role:'responder',purpose:'fund_second',references:{}}),/Invalid escrow reference/);
 await assert.rejects(verifySessionSnapshot({...args,role:'responder',purpose:'claim_short'}),/other participant/);
 await assert.rejects(verifySessionSnapshot({...args,purpose:'refund'}),/Invalid session verification request/);
 await assert.rejects(verifySessionSnapshot({...args,purpose:'claim_short',references:{long:args.references.long}}),/Invalid escrow reference/);
});
test('funding is refused if participant proofs expire before the refund recovery window',async()=>{
 const {args}=await fixture({certLifetime:3600});
 await assert.rejects(verifySessionSnapshot({...args,purpose:'fund_first',references:{}}),/expire too soon/);
 assert.equal((await verifySessionSnapshot({...args,purpose:'claim_short'})).policy.ok,true,'a valid claim must not be blocked only because proof lifetime is short');
});
