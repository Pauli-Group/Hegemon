import test from 'node:test';
import assert from 'node:assert/strict';
import {sessionAssetTerms} from './session-assets.mjs';
import {bitcoinMessageWallet} from './test-wallets.mjs';
import {observeSessionLeg} from './session-observation.mjs';
import {TESTNET4_GENESIS} from './bitcoin-testnet-verifier.mjs';
import {readFileSync} from 'node:fs';
const hashlock='aa'.repeat(32),adaOwner='11'.repeat(28),adaTaker='22'.repeat(28),ethOwner='0x'+'33'.repeat(20),ethTaker='0x'+'44'.repeat(20),txid='55'.repeat(32);
const base={version:2,hashlock,legs:{long:{asset:{chain:'cardano',kind:'ada',id:'',amount:'5000000'},network:'preview',refundee:adaOwner,claimant:adaTaker,expiry:1800010000},short:{asset:{chain:'ethereum',kind:'eth',id:'',amount:'100000000000000000'},network:'sepolia',refundee:ethTaker,claimant:ethOwner,expiry:1800005000}}};
test('converts ADA and ETH terms to wallet fields without rounding',()=>{
 assert.deepEqual(sessionAssetTerms(base,'long',{reference:{chain:'cardano',txid,vout:0}}),{chain:'cardano',operationTerms:{lovelace:'5000000',assets:'',hashlock,claimant:adaTaker,refundee:adaOwner,expiry_ms:'1800010000000',outref:txid+'#0'}});
 assert.deepEqual(sessionAssetTerms(base,'short').operationTerms,{kind:'eth',contract:'',token:'',tokenId:'',amount:'100000000000000000',hashlock:'0x'+hashlock,claimant:ethOwner,refundee:ethTaker,expiry:'1800005000'});
});
test('retains exact native tokens and ERC-20, ERC-721 and ERC-1155 identifiers',()=>{
 const token={...base,legs:{...base.legs,long:{...base.legs.long,asset:{chain:'cardano',kind:'native',id:'66'.repeat(28)+'.abcd',amount:'123456789012345678'},lovelace:'2000000'}}};
 assert.equal(sessionAssetTerms(token,'long').operationTerms.assets,'66'.repeat(28)+'.abcd=123456789012345678');
 assert.equal(sessionAssetTerms(token,'long').operationTerms.lovelace,'2000000');
 for(const [kind,id,amount,walletKind,expectedId] of [['erc20','0x'+'77'.repeat(20),'100000000000000000','0','0'],['erc721','0x'+'77'.repeat(20)+':12345678901234567890','1','1','12345678901234567890'],['erc1155','0x'+'77'.repeat(20)+':12345678901234567890','99','2','12345678901234567890']]){
  const t={...base,legs:{...base.legs,short:{...base.legs.short,asset:{chain:'ethereum',kind,id,amount}}}};
  const result=sessionAssetTerms(t,'short',{contract:'0x'+'88'.repeat(20)}).operationTerms;
  assert.equal(result.kind,walletKind);assert.equal(result.token,'0x'+'77'.repeat(20));assert.equal(result.tokenId,expectedId);assert.equal(result.amount,amount);
 }
});
test('refuses malformed or mismatched terms and references',()=>{
 assert.throws(()=>sessionAssetTerms(base,'other'),/Invalid swap leg/);
 assert.throws(()=>sessionAssetTerms(base,'long',{reference:{chain:'ethereum',txid}}),/different chain/);
 assert.throws(()=>sessionAssetTerms(base,'short',{contract:'0x'+'00'.repeat(20)}),/Invalid escrow/);
 assert.throws(()=>sessionAssetTerms({...base,hashlock:'bad'},'long'),/Invalid session terms/);
});
test('Bitcoin amounts, refund heights and funding outpoints are translated exactly',()=>{
 const owner=bitcoinMessageWallet('01'.repeat(32)).publicKey,taker=bitcoinMessageWallet('02'.repeat(32)).publicKey;
 const btc={...base,legs:{...base.legs,long:{asset:{chain:'bitcoin',kind:'btc',id:'',amount:'2100000000000000'},network:'testnet4',refundee:owner,claimant:taker,expiry:100_000}}};
 assert.deepEqual(sessionAssetTerms(btc,'long',{reference:{chain:'bitcoin',txid,vout:7}}),{chain:'bitcoin',operationTerms:{amount_sats:'2100000000000000',hashlock,claimant_key:taker,refund_key:owner,refund_height:'100000',txid,vout:'7'}});
 for(const amount of ['545','2100000000000001'])assert.throws(()=>sessionAssetTerms({...btc,legs:{...btc.legs,long:{...btc.legs.long,asset:{...btc.legs.long.asset,amount}}}},'long'),/Invalid Bitcoin/);
 assert.throws(()=>sessionAssetTerms({...btc,legs:{...btc.legs,long:{...btc.legs.long,expiry:500000000}}},'long'),/Invalid Bitcoin/);
});
test('a Bitcoin session observes the exact saved testnet outpoint',async()=>{
 const owner=bitcoinMessageWallet('01'.repeat(32)).publicKey,taker=bitcoinMessageWallet('02'.repeat(32)).publicKey;
 const terms={...base,legs:{...base.legs,long:{asset:{chain:'bitcoin',kind:'btc',id:'',amount:'5000'},network:'testnet4',refundee:owner,claimant:taker,expiry:100_000}}};
 const snapshot={terms,escrows:{long:{chain:'bitcoin',txid,vout:1},short:null}},config=JSON.parse(readFileSync(new URL('./chain-timing.json',import.meta.url),'utf8'));
 const readers={bitcoin:{spend:async(id,vout)=>({genesis:TESTNET4_GENESIS,txid:id,vout,tip:99_000,spent:false})}};
 assert.equal((await observeSessionLeg({snapshot,side:'long',readers,config})).state,'unspent');
 readers.bitcoin.spend=async(id,vout)=>({genesis:'00'.repeat(32),txid:id,vout,tip:99_000,spent:false});
 await assert.rejects(observeSessionLeg({snapshot,side:'long',readers,config}),/different output or network/);
});
test('Hegemon references distinguish a wallet candidate, public action and private note position',()=>{
 const leg={asset:{chain:'hegemon',kind:'hgn',id:'',amount:'9007199254740993'},network:'pre-mainnet',claimant:'shca1'+'p'.repeat(100),refundee:'shca1'+'q'.repeat(100),expiry:50000},terms={...base,legs:{...base.legs,long:leg}};
 const reference={chain:'hegemon',txid,action_id:'aa'.repeat(48),position:'9007199254740993',block_height:'49900'};
 assert.deepEqual(sessionAssetTerms(terms,'long',{reference}),{chain:'hegemon',operationTerms:{amount:'9007199254740993',hashlock,claim:leg.claimant,refund:leg.refundee,timeout:'50000',locked:'9007199254740993',action_id:'aa'.repeat(48)}});
 for(const bad of [{...reference,position:'01'},{...reference,position:String(1n<<64n)},{...reference,action_id:'aa'.repeat(32)}])assert.throws(()=>sessionAssetTerms(terms,'long',{reference:bad}),/Invalid Hegemon escrow reference/);
 assert.throws(()=>sessionAssetTerms({...terms,legs:{...terms.legs,long:{...leg,asset:{...leg.asset,amount:String(1n<<64n)}}}},'long'),/Invalid Hegemon/);
});
