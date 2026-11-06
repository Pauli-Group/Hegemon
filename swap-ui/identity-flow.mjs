/** The page-side flow around signed identity statements: what each role must name, how a statement is drafted, how the
 * wallets sign it, and how the counterparty's published statement is judged. No DOM and no network here, so it is unit
 * tested directly; identity-ui.mjs wires it to the page. See `.agent/SWAP_RELAY_IDENTITY_EXECPLAN.md`. */
import {buildStatement,statementText,serializeIdentity,verifyIdentity,MAX_LIFETIME_SECONDS} from './identity.mjs';
import {verifyProof,signerOf} from './identity-proofs.mjs';
import {parsePublicSession,inboxFingerprint} from './public-inbox.mjs';
import {fromHex,toHex} from './cbor.mjs';

const PURPOSE={owner:{give:'refund',receive:'claim'},taker:{give:'claim',receive:'refund'}};
const utf8=new TextEncoder();

/** The two address fields a participant must fill: one per leg, with the purpose its role gives it. */
export function legSpecs(offer,role){
 return ['give','receive'].map(side=>({side,chain:offer[side].chain,purpose:PURPOSE[role][side],
  label:(side==='give'?'Give leg':'Receive leg')+' · '+offer[side].chain+' · your '+PURPOSE[role][side]+(offer[side].chain==='bitcoin'?' public key (compressed hex)':offer[side].chain==='cardano'?' payment key hash':offer[side].chain==='hegemon'?' (not available yet)':' address')}));
}
export function normalizeAddress(chain,value){
 const text=String(value||'').trim();
 if(chain==='hegemon')return 'pending';
 return chain==='ethereum'?text.toLowerCase():text.toLowerCase();
}
/** Draft the statement the user will sign. `now` is whole seconds; the statement expires with the offer, at most a day for
 * a taker (a reservation lasts a day) and never more than the maximum lifetime. */
export function draftStatement({role,offer,reservation,inbox,addresses,now,nonce}){
 const ceiling=role==='owner'?offer.expires:Math.min(offer.expires,now+86400);
 const expires=Math.min(ceiling,now+MAX_LIFETIME_SECONDS);
 return buildStatement({role,offer:offer.id,reservation:role==='owner'?'':reservation,inbox,nonce:nonce??toHex(crypto.getRandomValues(new Uint8Array(16))),issued:now,expires,
  legs:{give:{chain:offer.give.chain,address:normalizeAddress(offer.give.chain,addresses.give)},receive:{chain:offer.receive.chain,address:normalizeAddress(offer.receive.chain,addresses.receive)}}});
}
export {statementText};

// ---------------------------------------------------------------- wallets sign the statement text
/** Ethereum `personal_sign` through an EIP-1193 provider. The signer is whatever account the wallet signs with. */
export async function signEthereum(provider,account,text){
 if(!provider?.request)throw Error('Connect an Ethereum wallet first.');
 const signature=await provider.request({method:'personal_sign',params:['0x'+toHex(utf8.encode(text)),account]});
 const proof={chain:'ethereum',scheme:'eip191',signer:'',signature:String(signature).toLowerCase()};
 proof.signer=signerOf(proof,text);
 return proof;
}
/** CIP-30 `signData` for the wallet's first payment-key address; returns the proof and the key hash it proves. */
export async function signCardano(api,text){
 if(!api?.signData||!api.getUsedAddresses)throw Error('Connect a Cardano wallet first.');
 const used=await api.getUsedAddresses(),unused=used.length?[]:await (api.getUnusedAddresses?.()??[]);
 const address=[...used,...unused].find(hexAddress=>{const bytes=fromHex(hexAddress);return bytes.length>=29&&[0,2,4,6].includes(bytes[0]>>4);});
 if(!address)throw Error('The wallet has no payment-key address to sign with.');
 const result=await api.signData(address,toHex(utf8.encode(text)));
 if(!result||typeof result.signature!=='string'||typeof result.key!=='string')throw Error('The wallet returned an unexpected signature.');
 const proof={chain:'cardano',scheme:'cip8',signer:'',signature:result.signature.toLowerCase(),key:result.key.toLowerCase()};
 proof.signer=signerOf(proof,text);
 return proof;
}
/** A Bitcoin signature pasted from a wallet (base64), checked against the statement before it is accepted. */
export function bitcoinProof(scheme,signature,text){
 const proof={chain:'bitcoin',scheme,signer:'',signature:String(signature||'').trim()};
 proof.signer=signerOf(proof,text);
 return proof;
}
/** Keep only proofs that verify and name an address in the statement; replace an older proof by the same signer. */
export function addProof(statement,proofs,proof){
 const text=statementText(statement),checked=verifyProof(proof,text);
 const named=['give','receive'].some(side=>statement.legs[side].chain===checked.chain&&Object.values(statement.legs[side]).includes(checked.signer));
 if(!named)throw Error('That signature is not from an address named in your statement.');
 return [...proofs.filter(p=>!(p.chain===checked.chain&&p.signer===checked.signer)),proof];
}
export function publishable(statement,proofs){return serializeIdentity(statement,proofs);}

// ---------------------------------------------------------------- judging what the relay shows
/** The fingerprint a participant's statement must name: the owner's inbox key, or the ephemeral key in the taker's handshake
 * for this reservation. Returns '' when it is not known yet. */
export async function expectedInbox({role,offer,messages}){
 if(role==='owner')return offer.ownerPublicKey?inboxFingerprint(offer.ownerPublicKey):'';
 const handshake=(messages||[]).find(item=>item.sender==='taker'&&parsePublicSession(item.ciphertext)?.reservation===offer.reservationId);
 return handshake?inboxFingerprint(parsePublicSession(handshake.ciphertext).ephemeral):'';
}
/** Judge one published statement. `pin` is a previously seen or link-supplied identity code. Never throws: the result is
 * `{status:'none'|'verified'|'failed', error?, identity?, trusted?}` where `trusted` says whether the code was pinned. */
export async function judgeIdentity({role,offer,blob,inbox,now,pin}){
 if(!blob)return {status:'none'};
 if(!inbox)return {status:'failed',error:role==='owner'?'The offer has no inbox key to bind the identity to.':'No reservation handshake to bind the taker identity to.'};
 try{
  const identity=await verifyIdentity(blob,{offer:offer.id,role,reservation:role==='owner'?'':offer.reservationId||'',inbox,give:{chain:offer.give.chain},receive:{chain:offer.receive.chain}},now);
  if(pin&&pin!==identity.code)return {status:'failed',error:'The '+role+' identity code '+identity.code+' is not the pinned code '+pin+'. Do not continue until you have confirmed it another way.',identity};
  return {status:'verified',identity,pinned:!!pin};
 }catch(error){return {status:'failed',error:error.message};}
}
