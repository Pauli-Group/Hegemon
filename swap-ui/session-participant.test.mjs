import test from 'node:test';
import assert from 'node:assert/strict';
import {cardanoWallet,ethereumWallet} from './test-wallets.mjs';
import {signCardano,signEthereum} from './identity-flow.mjs';
import {deriveSessionId,participantText,sessionOfferDigest} from './session-identity.mjs';
import {createProtocolKey} from './session-packets.mjs';
import {addSessionProof,completeParticipant,participantDraft,participantStatement} from './session-participant.mjs';
const now=1800000000,ada=cardanoWallet('01'.repeat(32)),eth=ethereumWallet('02'.repeat(32));
async function setup(){
 const id='11'.repeat(32),reservation='22'.repeat(32),session=await deriveSessionId(id,reservation),key=await createProtocolKey();
 const offer={id,visibility:'private',expires:now+3600,ownerPublicKey:'04'+'aa'.repeat(64),give:{chain:'cardano',kind:'ada',id:'',amount:'5000000'},receive:{chain:'ethereum',kind:'eth',id:'',amount:'100000000000000000'}};
 const snapshot={version:2,offer,offerDigest:await sessionOfferDigest(offer),reservation,credential:'33'.repeat(32),channelKey:'44'.repeat(32),sessionExpires:now+7*86400,terms:null,escrows:{long:null,short:null},secretEnvelope:null,ownerBlob:null,takerBlob:null,transport:{next:1,previous:null}};
 const draft=await participantDraft({session,role:'owner',snapshot,publicKey:key.publicKey,now}),statement=participantStatement(draft,{give:ada.keyHash,receive:eth.address}),text=participantText(statement);
 const cardano={getUsedAddresses:async()=>[ada.addressHex],signData:async(a,p)=>ada.signData(a,p)},ethereum={request:async({params})=>eth.personalSign(params[0])};
 return {draft,statement,cardanoProof:await signCardano(cardano,text),ethereumProof:await signEthereum(ethereum,eth.address,text)};
}
test('both wallet signatures bind the exact session before its participant statement can be published',async()=>{
 const {draft,statement,cardanoProof,ethereumProof}=await setup();
 let proofs=addSessionProof(statement,draft.assets,[],cardanoProof);
 await assert.rejects(completeParticipant(draft,statement,proofs,now),/missing its wallet proof/);
 proofs=addSessionProof(statement,draft.assets,proofs,ethereumProof);
 const blob=await completeParticipant(draft,statement,proofs,now);
 assert.equal(JSON.parse(blob).proofs.length,2);
 const changed=structuredClone(statement);changed.addresses.receive='0x'+'99'.repeat(20);
 await assert.rejects(completeParticipant(draft,changed,proofs,now),/proof|signature|signed payload/i);
});
test('a proof from another address or a modified session is refused',async()=>{
 const {draft,statement,cardanoProof}=await setup(),other=ethereumWallet('09'.repeat(32)),text=participantText(statement);
 const proof=await signEthereum({request:async({params})=>other.personalSign(params[0])},other.address,text);
 assert.throws(()=>addSessionProof(statement,draft.assets,[],proof),/not from a wallet/);
 const changed={...statement,session:'ff'.repeat(32)};
 assert.throws(()=>addSessionProof(changed,draft.assets,[],cardanoProof),/proof|signature|signed payload/i);
 await assert.rejects(participantDraft({...draft,snapshot:{...draft.snapshot,ownerBlob:'already saved'}}),/already saved/);
});
