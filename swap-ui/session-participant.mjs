/** Prepare and authenticate a participant for an accepted session. Wallets
 * sign only in response to a separate user action; this module never opens a
 * wallet, submits a transaction or sends a statement to the relay. */
import {buildParticipant,participantText,serializeParticipant,verifyParticipant} from './session-identity.mjs';
import {channelFingerprint} from './session-channel.mjs';
import {verifyProof} from './identity-proofs.mjs';
import {validateSessionSnapshot} from './session-recovery.mjs';
import {canonical} from './identity.mjs';
import {toHex} from './cbor.mjs';

export async function participantCode(blob){
 let item;try{item=JSON.parse(blob);}catch{throw Error('Invalid participant statement.');}
 if(!item||!item.statement)throw Error('Invalid participant statement.');
 return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('hegemon.swap.participant-code.v1\n'+canonical(item.statement))))).slice(0,16);
}

export async function participantDraft({session,role,snapshot,publicKey,now}){
 await validateSessionSnapshot(snapshot,session);
 if(![2,3].includes(snapshot.version)||!['owner','taker'].includes(role)||!Number.isSafeInteger(now)||typeof publicKey!=='string'||!/^04[0-9a-f]{128}$/.test(publicKey))throw Error('Invalid session participant request.');
 const existing=role==='owner'?snapshot.ownerBlob:snapshot.takerBlob;
 if(existing!==null)throw Error('This participant statement is already saved.');
 const assets={give:snapshot.offer.give,receive:snapshot.offer.receive};
 if(!['bitcoin','cardano','ethereum'].includes(assets.give.chain)||!['bitcoin','cardano','ethereum'].includes(assets.receive.chain))throw Error('A verified wallet proof is not available for this chain yet.');
 return {session,role,snapshot,publicKey,now,assets,channelDigest:await channelFingerprint(session,snapshot.channelKey)};
}

/** `addresses` are the two public wallet addresses in offer-side order. */
export function participantStatement(draft,addresses){
 return buildParticipant({session:draft.session,offer:draft.snapshot.offer.id,reservation:draft.snapshot.reservation,role:draft.role,offerDigest:draft.snapshot.offerDigest,channelDigest:draft.channelDigest,protocolKey:draft.publicKey,addresses,issued:draft.now,expires:draft.snapshot.sessionExpires},draft.assets);
}

/** Reject signatures by an address not explicitly named in the statement. */
export function addSessionProof(statement,assets,proofs,proof){
 if(!Array.isArray(proofs))throw Error('Invalid session wallet proofs.');
 const checked=verifyProof(proof,participantText(statement));
 if(!['give','receive'].some(side=>assets[side].chain===checked.chain&&statement.addresses[side]===checked.signer))throw Error('This signature is not from a wallet named in the swap.');
 return [...proofs.filter(item=>!(item.chain===checked.chain&&item.signer===checked.signer)),proof];
}

/** Require a verified proof for every address on every supported chain. */
export async function completeParticipant(draft,statement,proofs,now){
 const blob=serializeParticipant(statement,proofs);
 const expected={session:draft.session,role:draft.role,offer:draft.snapshot.offer.id,reservation:draft.snapshot.reservation,offerDigest:draft.snapshot.offerDigest,channelDigest:draft.channelDigest,assets:draft.assets,sessionExpires:draft.snapshot.sessionExpires};
 const participant=await verifyParticipant(blob,expected,now);
 if(participant.statement.protocolKey!==draft.publicKey||participant.unverified.length)throw Error('The wallet proofs do not bind this session.');
 return blob;
}
