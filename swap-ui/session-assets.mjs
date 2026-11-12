/** Translate authenticated version-2 session terms into the exact values accepted
 * by the public-testnet wallet actions and verifiers. This only constructs data:
 * it does not authenticate a proposal, verify an escrow, or contact a wallet. */
import {validateSessionTerms,validateSessionReference} from './session-packets.mjs';

export function sessionAssetTerms(terms,side,{reference=null,contract=''}={}){
 validateSessionTerms(terms);
 if(!['long','short'].includes(side))throw Error('Invalid swap leg.');
 const leg=terms.legs[side],asset=leg.asset;
 if(reference!==null){validateSessionReference(reference);if(reference.chain!==asset.chain)throw Error('The escrow reference names a different chain.');}
 if(asset.chain==='bitcoin'){
  if(asset.kind!=='btc'||BigInt(asset.amount)<546n||BigInt(asset.amount)>2100000000000000n||leg.expiry>=500000000)throw Error('Invalid Bitcoin testnet amount or refund height.');
  return {chain:'bitcoin',operationTerms:{amount_sats:asset.amount,hashlock:terms.hashlock,claimant_key:leg.claimant,refund_key:leg.refundee,refund_height:String(leg.expiry),...(reference?{txid:reference.txid,vout:String(reference.vout)}:{})}};
 }
 if(asset.chain==='hegemon'){
  if(asset.kind!=='hgn'||BigInt(asset.amount)>=(1n<<64n)||leg.expiry>=2**48)throw Error('Invalid Hegemon amount or refund height.');
  return {chain:'hegemon',operationTerms:{amount:asset.amount,hashlock:terms.hashlock,claim:leg.claimant,refund:leg.refundee,timeout:String(leg.expiry),...(reference?{locked:reference.position,action_id:reference.action_id}:{})}};
 }
 if(asset.chain==='cardano'){
  const expiryMs=leg.expiry*1000;
  if(!Number.isSafeInteger(expiryMs))throw Error('Cardano deadline is too large.');
  const token=asset.kind==='native';
  if(!token&&asset.kind!=='ada')throw Error('Unsupported Cardano asset.');
  return {chain:'cardano',operationTerms:{lovelace:token?leg.lovelace:asset.amount,assets:token?`${asset.id}=${asset.amount}`:'',hashlock:terms.hashlock,claimant:leg.claimant,refundee:leg.refundee,expiry_ms:String(expiryMs),...(reference?{outref:`${reference.txid}#${reference.vout}`}:{})}};
 }
 if(asset.chain==='ethereum'){
  const kind={eth:'eth',erc20:'0',erc721:'1',erc1155:'2'}[asset.kind];
  if(kind===undefined)throw Error('Unsupported Ethereum asset.');
  if(contract&&(!/^0x[0-9a-f]{40}$/.test(contract)||/^0x0{40}$/.test(contract)))throw Error('Invalid escrow contract.');
  const [token,tokenId]=kind==='eth'?['','']:kind==='0'?[asset.id,'0']:asset.id.split(':');
  return {chain:'ethereum',operationTerms:{kind,contract,token,tokenId,amount:asset.amount,hashlock:'0x'+terms.hashlock,claimant:leg.claimant,refundee:leg.refundee,expiry:String(leg.expiry)}};
 }
 throw Error('The browser session adapter does not support this chain yet.');
}
