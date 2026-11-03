/** Compare offer terms before independently checking both public-testnet legs. */
import {comparePair} from './pair-check.mjs';
import {parseCardanoAssets} from './cardano-preview-verifier.mjs';

export function cardanoOfferValue(lovelace,assets){
 const value={lovelace};for(const [id,quantity] of Object.entries(parseCardanoAssets(assets))){const [policy,name]=id.split('.');value[policy]??={};value[policy][name]=quantity;}return value;
}
export async function checkPublicPair(offer,give,receive,check){
 const match=comparePair(offer,give,receive);
 if(typeof check!=='function')throw Error('Escrow verification is unavailable.');
 const first=await check(structuredClone(give)),second=await check(structuredClone(receive));
 if(!first||!second)throw Error('An escrow check did not return a snapshot.');
 return {hashlock:match.hashlock,give:first,receive:second};
}
