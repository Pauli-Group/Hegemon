/** Compare offer terms before independently checking both public-testnet legs. */
import {comparePair,judgeTiming,policyHead,TimingError} from './pair-check.mjs';
import {parseCardanoAssets} from './cardano-preview-verifier.mjs';

export function cardanoOfferValue(lovelace,assets){
 const value={lovelace};for(const [id,quantity] of Object.entries(parseCardanoAssets(assets))){const [policy,name]=id.split('.');value[policy]??={};value[policy][name]=quantity;}return value;
}
/** `timing` is `{config, now}`; when given, both snapshots must carry a chain head and the
 * deadlines are judged by the timelock policy. A failing verdict throws a TimingError that
 * carries the verdict and the checked snapshots so callers can show both. */
export async function checkPublicPair(offer,give,receive,check,timing){
 const match=comparePair(offer,give,receive);
 if(typeof check!=='function')throw Error('Escrow verification is unavailable.');
 const first=await check(structuredClone(give)),second=await check(structuredClone(receive));
 if(!first||!second)throw Error('An escrow check did not return a snapshot.');
 const result={hashlock:match.hashlock,give:first,receive:second};
 if(timing){
  const heads={give:policyHead(give.chain,first.snapshot??first,timing.now),receive:policyHead(receive.chain,second.snapshot??second,timing.now)};
  result.timing=judgeTiming(give,receive,{...timing,heads});
  if(!result.timing.ok){const error=new TimingError(result.timing);error.result=result;throw error;}
 }
 return result;
}
