/** Match two independently checked local escrow terms to one offer. This is a
 * point-in-time comparison, not a timeout guarantee or an atomic coordinator. */
function sameAmount(a,b){return typeof a==='string'&&typeof b==='string'&&/^[1-9][0-9]*$/.test(a)&&a===b;}
function sameText(a,b){return typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();}
export function matchesOfferAsset(asset,leg){
 if(!asset||!leg||asset.chain!==leg.chain||!leg.terms)return false;const t=leg.terms;
 if(leg.chain==='ethereum'){
  const kinds={eth:'eth',erc20:'0',erc721:'1',erc1155:'2'};
  if(kinds[asset.kind]!==t.kind||!sameAmount(asset.amount,t.amount))return false;
  if(asset.kind==='eth')return asset.id==='';
  const id=asset.kind==='erc20'?t.token:t.token+':'+t.tokenId;return sameText(asset.id,id);
 }
 if(leg.chain==='bitcoin')return asset.kind==='btc'&&asset.id===''&&sameAmount(asset.amount,t.amount_sats);
 if(leg.chain==='hegemon')return asset.kind==='hgn'&&asset.id===''&&sameAmount(asset.amount,t.amount);
 if(leg.chain==='cardano'){
  const value=t.expected_value;if(!value||typeof value!=='object'||Array.isArray(value))return false;
  const policies=Object.keys(value).filter(key=>key!=='lovelace');
  if(asset.kind==='ada')return asset.id===''&&policies.length===0&&sameAmount(asset.amount,value.lovelace);
  if(asset.kind!=='native'||policies.length!==1||typeof asset.id!=='string')return false;
  const pieces=asset.id.split('.');if(pieces.length!==2||!sameText(policies[0],pieces[0]))return false;
  const names=Object.keys(value[policies[0]]||{});return names.length===1&&sameText(names[0],pieces[1])&&sameAmount(asset.amount,value[policies[0]][names[0]]);
 }
 return false;
}
function hashlock(leg){const value=leg?.terms?.hashlock;return typeof value==='string'?(value.startsWith('0x')?value.slice(2):value).toLowerCase():'';}
function reference(leg){const t=leg.terms;return leg.chain==='ethereum'?String(t.contract).toLowerCase():leg.chain==='bitcoin'?t.txid+'#'+t.vout:leg.chain==='cardano'?t.outref:leg.chain==='hegemon'?t.locked:'';}
export function comparePair(offer,give,receive){
 if(!offer||!matchesOfferAsset(offer.give,give)||!matchesOfferAsset(offer.receive,receive))throw Error('Escrow assets or amounts do not match the selected offer.');
 const digest=hashlock(give);if(!/^[0-9a-f]{64}$/.test(digest)||digest!==hashlock(receive))throw Error('Both escrow hashlocks must match.');
 if(give.chain===receive.chain&&reference(give)===reference(receive))throw Error('The two legs must be different escrows.');
 return {hashlock:digest,giveChain:give.chain,receiveChain:receive.chain};
}
