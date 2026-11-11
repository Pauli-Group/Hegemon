/** Restore one encrypted session locally. Wallet keys are not part of this
 * backup; restored wallet intents are deliberately never re-armed. */
import {openSessionRecovery} from './session-recovery.mjs';
import {addSession,getSession} from './session-store.mjs';
import {pinOffer,readOfferPin} from './offer-pin.mjs';
import {canonical} from './identity.mjs';
import {recoveryReviewKey} from './session-action.mjs';

export async function restoreSwapBackup({envelope,passphrase,storage=globalThis.localStorage,tabStorage=globalThis.sessionStorage}){
 if(!storage||!tabStorage)throw Error('Browser storage is unavailable.');
 const {snapshot}=await openSessionRecovery(envelope,passphrase),{session,role}=envelope,id=snapshot.offer.id;
 if(await getSession(session,role))throw Error('This swap already exists in this browser; it was not overwritten.');
 const credentialKey=(role==='owner'?'offer-owner:':'offer-reservation:')+id,indexKey='hegemon.swap.session-index:'+id;
 const index={version:1,offerId:id,role,reservation:snapshot.reservation,digest:snapshot.offerDigest};
 const oldCredential=storage.getItem(credentialKey),oldIndex=storage.getItem(indexKey),pin=await readOfferPin(id,storage);
 if(oldCredential!==null&&oldCredential!==snapshot.credential)throw Error('This browser has a different offer credential.');
 if(oldIndex!==null){let prior;try{prior=JSON.parse(oldIndex);}catch{throw Error('This browser has an invalid saved swap.');}if(canonical(prior)!==canonical(index))throw Error('This browser has a different saved swap for this offer.');}
 if(pin&&pin.digest!==snapshot.offerDigest)throw Error('This browser has a different saved offer.');
 await pinOffer(snapshot.offer,storage);
 storage.setItem(recoveryReviewKey(session,role),'required');
 await addSession(envelope,passphrase);
 storage.setItem(credentialKey,snapshot.credential);storage.setItem(indexKey,JSON.stringify(index));
 tabStorage.setItem('hegemon.swap.route:'+id,'session');
 return {offerId:id,session,role};
}
