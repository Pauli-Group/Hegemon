import {checkPair} from './timelock-policy.mjs';

const isLocalAddress=v=>typeof v==='string'&&v.startsWith('local:');
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
/** The participants an escrow's terms name, in the engine's identity format (lowercase). Hegemon has no scheme yet. */
export function legParticipants(leg){
 const t=leg?.terms;if(!t)throw Error('Escrow terms are missing.');
 const lower=value=>typeof value==='string'?value.toLowerCase():'';
 if(leg.chain==='ethereum'||leg.chain==='cardano')return {claimant:lower(t.claimant),refundee:lower(t.refundee)};
 if(leg.chain==='bitcoin')return {claimant:lower(t.claimant_key),refundee:lower(t.refund_key)};
 if(leg.chain==='hegemon')return null;
 throw Error('Unsupported chain.');
}
/** Require both escrows to name exactly the signed identities. `identities` is `{owner, taker}`, each the result of
 * `verifyIdentity` (identity.mjs). The owner's `give` leg is the offer's give escrow (owner refunds, taker claims); the
 * owner's `receive` leg is the other escrow (taker refunds, owner claims). Returns what was matched; throws on any
 * difference, on a missing identity and on statements for another offer or chain. A Hegemon leg is reported in
 * `unverified` and never counted as matched. */
export function checkIdentities(offer,give,receive,identities){
 const owner=identities?.owner,taker=identities?.taker;
 if(!owner||!taker||owner.role!=='owner'||taker.role!=='taker')throw Error('Signed identity statements from both participants are required.');
 if(owner.statement.offer!==offer?.id||taker.statement.offer!==offer?.id)throw Error('Identity statements are for a different offer.');
 const legs={give,receive},unverified=[],matched=[],localOnly=[];
 for(const side of ['give','receive']){
  const leg=legs[side],chain=leg?.chain;
  if(owner.statement.legs[side].chain!==chain||taker.statement.legs[side].chain!==chain)throw Error('Identity statements are for a different '+side+' chain.');
  const want=side==='give'?{claimant:taker.addresses.give,refundee:owner.addresses.give}:{claimant:owner.addresses.receive,refundee:taker.addresses.receive};
  const have=legParticipants(leg);
  if(!have){
   unverified.push(side);
   // Fixture identities name the wallets; a different wallet in the escrow is still refused.
   if(chain==='hegemon'&&isLocalAddress(want.claimant)&&isLocalAddress(want.refundee)){
    if(leg.terms?.claimant!==want.claimant.slice(6)||leg.terms?.refundee!==want.refundee.slice(6))throw Error('The '+side+' escrow does not name the local Hegemon identities.');
    localOnly.push(side);
   }
   continue;
  }
  if(have.claimant!==want.claimant.toLowerCase())throw Error('The '+side+' escrow claimant is not the signed identity.');
  if(have.refundee!==want.refundee.toLowerCase())throw Error('The '+side+' escrow refund address is not the signed identity.');
  matched.push(side);
 }
 const unproven=[];
 for(const side of ['give','receive']){if(!owner.proven[side])unproven.push('owner.'+side);if(!taker.proven[side])unproven.push('taker.'+side);}
 return {matched,unverified,localOnly,unproven,owner:{code:owner.code},taker:{code:taker.code}};
}
export function comparePair(offer,give,receive,timing,identities){
 if(!offer||!matchesOfferAsset(offer.give,give)||!matchesOfferAsset(offer.receive,receive))throw Error('Escrow assets or amounts do not match the selected offer.');
 const digest=hashlock(give);if(!/^[0-9a-f]{64}$/.test(digest)||digest!==hashlock(receive))throw Error('Both escrow hashlocks must match.');
 if(give.chain===receive.chain&&reference(give)===reference(receive))throw Error('The two legs must be different escrows.');
 const result={hashlock:digest,giveChain:give.chain,receiveChain:receive.chain};
 if(identities)result.identities=checkIdentities(offer,give,receive,identities);
 if(timing){const verdict=judgeTiming(give,receive,timing);if(!verdict.ok)throw new TimingError(verdict);result.timing=verdict;}
 return result;
}
