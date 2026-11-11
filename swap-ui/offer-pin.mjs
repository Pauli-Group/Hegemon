/** The exact offer seen by this browser is pinned before the reservation or
 * session starts. Relay updates may add reservation fields but cannot silently
 * change assets, amounts, visibility, expiry or the maker's inbox key. */
import {sessionOfferDigest} from './session-identity.mjs';
const HEX=/^[0-9a-f]{64}$/;
export function immutableOffer(offer){if(!offer||typeof offer!=='object')throw Error('Invalid offer.');return {id:offer.id,visibility:offer.visibility,give:offer.give,receive:offer.receive,expires:offer.expires,ownerPublicKey:offer.ownerPublicKey};}
export async function readOfferPin(id,storage=globalThis.localStorage){
 if(typeof id!=='string'||!HEX.test(id)||!storage)throw Error('Invalid offer identity.');
 const raw=storage.getItem('hegemon.swap.pinned-offer:'+id);if(raw===null)return null;
 let record;try{record=JSON.parse(raw);}catch{throw Error('The saved offer is invalid.');}
 if(!record||Object.keys(record).sort().join(',')!=='digest,offer,version'||record.version!==1||record.offer?.id!==id||typeof record.digest!=='string'||!HEX.test(record.digest)||await sessionOfferDigest(record.offer)!==record.digest)throw Error('The saved offer is invalid.');
 return record;
}
export async function pinOffer(offer,storage=globalThis.localStorage){
 const fixed=immutableOffer(offer),digest=await sessionOfferDigest(fixed),prior=await readOfferPin(fixed.id,storage);
 if(prior&&prior.digest!==digest)throw Error('The offer changed since you reviewed it.');
 if(!prior)storage.setItem('hegemon.swap.pinned-offer:'+fixed.id,JSON.stringify({version:1,offer:fixed,digest}));
 return prior||{version:1,offer:fixed,digest};
}
