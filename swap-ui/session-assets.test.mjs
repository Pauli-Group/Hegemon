import test from 'node:test';
import assert from 'node:assert/strict';
import {sessionAssetTerms} from './session-assets.mjs';
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
