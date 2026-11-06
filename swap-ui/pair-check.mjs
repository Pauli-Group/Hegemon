import {checkPair} from './timelock-policy.mjs';
/** Match two independently checked local escrow terms to one offer. Without a
 * `timing` argument this is a point-in-time comparison only. With one, the two
 * deadlines are also judged by the cross-chain timelock policy (timelock-policy.mjs).
 * It is not an atomic coordinator and does not make real-funds swaps safe. */
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
/** The `{chain, expiry}` the timelock policy needs: block height for Bitcoin and
 * Hegemon, whole seconds for Ethereum and Cardano. */
export function policyLeg(leg){
 const t=leg?.terms;if(!t)throw Error('Escrow terms are missing.');
 if(leg.chain==='ethereum')return {chain:'ethereum',expiry:Number(t.expiry)};
 if(leg.chain==='bitcoin')return {chain:'bitcoin',expiry:Number(t.refund_height)};
 if(leg.chain==='hegemon')return {chain:'hegemon',expiry:Number(t.timeout)};
 if(leg.chain==='cardano'){const ms=Number(t.expiry_ms);if(!Number.isSafeInteger(ms)||ms%1000!==0)throw Error('Cardano expiry must be a whole number of seconds.');return {chain:'cardano',expiry:ms/1000};}
 throw Error('Unsupported chain.');
}
/** The chain head the timelock policy needs, from a verifier snapshot. */
export function policyHead(chain,snapshot,now){
 if(!snapshot)throw Error('A chain snapshot is required for the timing check.');
 if(chain==='bitcoin')return {observedAt:now,height:snapshot.tip};
 if(chain==='hegemon')return {observedAt:now,height:snapshot.height};
 return {observedAt:now,timestamp:snapshot.headTimestamp};
}
/** Judge both deadlines. `timing` is `{config, now, heads:{give, receive}}`. Returns the
 * policy verdict; throws only on malformed input. */
export function judgeTiming(give,receive,timing){
 if(!timing||!timing.config||!Number.isSafeInteger(timing.now)||!timing.heads)throw Error('Timing configuration, current time and chain heads are required.');
 const verdict=checkPair(timing.config,{a:policyLeg(give),b:policyLeg(receive),heads:{a:timing.heads.give,b:timing.heads.receive},now:timing.now});
 return {...verdict,long:verdict.long==='a'?'give':'receive'};
}
export class TimingError extends Error{constructor(verdict){super('Unsafe deadlines: '+(verdict.reasons[0]?.message||'timing check failed'));this.verdict=verdict;}}
export function comparePair(offer,give,receive,timing){
 if(!offer||!matchesOfferAsset(offer.give,give)||!matchesOfferAsset(offer.receive,receive))throw Error('Escrow assets or amounts do not match the selected offer.');
 const digest=hashlock(give);if(!/^[0-9a-f]{64}$/.test(digest)||digest!==hashlock(receive))throw Error('Both escrow hashlocks must match.');
 if(give.chain===receive.chain&&reference(give)===reference(receive))throw Error('The two legs must be different escrows.');
 const result={hashlock:digest,giveChain:give.chain,receiveChain:receive.chain};
 if(timing){const verdict=judgeTiming(give,receive,timing);if(!verdict.ok)throw new TimingError(verdict);result.timing=verdict;}
 return result;
}
