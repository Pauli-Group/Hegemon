/** Signed identity statements for the offer relay.
 *
 * A statement names the offer, the reservation, the inbox key fingerprint and the participant's address for each leg. A
 * participant signs its canonical text with a wallet on every chain it wants proven (see identity-proofs.mjs). The
 * counterparty verifies locally; the relay only stores the blob and is not trusted with it. See
 * `.agent/SWAP_RELAY_IDENTITY_EXECPLAN.md` for the threat model and what a statement does and does not establish.
 *
 * Roles. The owner's `give` leg is funded by the owner (owner refunds, taker claims) and the owner's `receive` leg is funded
 * by the taker (taker refunds, owner claims). So an owner statement names `give.refund` and `receive.claim`; a taker
 * statement names `give.claim` and `receive.refund`. A Hegemon leg carries the literal `pending`: no Hegemon identity
 * scheme exists yet (P6/P8) and it is never reported as verified. */
import {verifyProof,compressedKey} from './identity-proofs.mjs';

export const IDENTITY_KIND='hegemon.swap.identity';
export const IDENTITY_TEXT_PREFIX='hegemon.swap.identity.v1\n';
export const MAX_LIFETIME_SECONDS=7*86400;
export const CLOCK_SKEW_SECONDS=300;
export const MAX_IDENTITY_BLOB=8192;
const hex=(value,length)=>typeof value==='string'&&new RegExp('^[0-9a-f]{'+length+'}$').test(value);
const fail=message=>{throw Error(message);};
const ADDRESS={
 ethereum:v=>typeof v==='string'&&/^0x[0-9a-f]{40}$/.test(v),
 cardano:v=>hex(v,56),
 bitcoin:v=>{if(typeof v!=='string'||!/^0[23][0-9a-f]{64}$/.test(v))return false;try{compressedKey(v);return true;}catch{return false;}},
 hegemon:v=>v==='pending'
};
const FIELDS={owner:{give:'refund',receive:'claim'},taker:{give:'claim',receive:'refund'}};

export function canonical(value){
 if(value===null||typeof value==='boolean'||typeof value==='string')return JSON.stringify(value);
 if(typeof value==='number'){if(!Number.isSafeInteger(value))fail('Only integers are allowed in a statement.');return String(value);}
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 fail('Unsupported value in a statement.');
}
/** The exact text a wallet signs. */
export function statementText(statement){return IDENTITY_TEXT_PREFIX+canonical(statement);}
async function sha256Hex(text){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text)))].map(b=>b.toString(16).padStart(2,'0')).join('');}
/** The short code two people can compare: first 16 hex characters of the SHA-256 of the canonical statement. */
export async function identityCode(statement){return (await sha256Hex(canonical(statement))).slice(0,16);}

/** `legs` is `{give:{chain, address}, receive:{chain, address}}`; the address field name follows the role. */
export function buildStatement({role,offer,reservation='',inbox,legs,nonce,issued,expires}){
 if(!FIELDS[role])fail('Unknown identity role.');
 const out={};
 for(const side of ['give','receive']){
  const leg=legs?.[side];if(!leg||!ADDRESS[leg.chain])fail('Unsupported chain for the '+side+' leg.');
  out[side]={chain:leg.chain,[FIELDS[role][side]]:leg.address};
 }
 const statement={version:1,kind:IDENTITY_KIND,role,offer,reservation,inbox,legs:out,nonce,issued,expires};
 checkShape(statement);
 return statement;
}
function checkShape(statement){
 if(!statement||typeof statement!=='object'||Array.isArray(statement)||Object.keys(statement).sort().join(',')!=='expires,inbox,issued,kind,legs,nonce,offer,reservation,role,version')fail('Invalid identity statement.');
 if(statement.version!==1||statement.kind!==IDENTITY_KIND)fail('Unsupported identity statement version.');
 if(!FIELDS[statement.role])fail('Unknown identity role.');
 if(!hex(statement.offer,64)||!hex(statement.inbox,64)||!hex(statement.nonce,32))fail('Invalid identity statement fields.');
 if(statement.role==='owner'?statement.reservation!=='':!hex(statement.reservation,64))fail('Invalid reservation in the identity statement.');
 if(!Number.isSafeInteger(statement.issued)||!Number.isSafeInteger(statement.expires)||statement.expires<=statement.issued||statement.expires-statement.issued>MAX_LIFETIME_SECONDS)fail('Invalid identity statement lifetime.');
 const legs=statement.legs;
 if(!legs||typeof legs!=='object'||Object.keys(legs).sort().join(',')!=='give,receive')fail('Invalid identity statement legs.');
 for(const side of ['give','receive']){
  const leg=legs[side],field=FIELDS[statement.role][side];
  if(!leg||typeof leg!=='object'||Object.keys(leg).sort().join(',')!==['chain',field].sort().join(',')||!ADDRESS[leg.chain]||!ADDRESS[leg.chain](leg[field]))fail('Invalid '+side+' leg in the identity statement.');
 }
}
export function legAddress(statement,side){return statement.legs[side][FIELDS[statement.role][side]];}
export function serializeIdentity(statement,proofs){
 const blob=JSON.stringify({statement,proofs});
 if(blob.length>MAX_IDENTITY_BLOB)fail('The identity statement is too large.');
 return blob;
}
export function parseIdentity(blob){
 if(typeof blob!=='string'||blob.length>MAX_IDENTITY_BLOB)fail('Invalid identity statement.');
 let value;try{value=JSON.parse(blob);}catch{fail('Invalid identity statement.');}
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='proofs,statement'||!Array.isArray(value.proofs)||value.proofs.length>4)fail('Invalid identity statement.');
 checkShape(value.statement);
 return value;
}
/** Verify a stored identity blob against what this client independently knows.
 *
 * `expected`: `{offer, role, reservation, inbox, give:{chain}, receive:{chain}}`; `now` is whole seconds.
 * Throws on any mismatch. Returns `{statement, code, role, addresses:{give,receive}, proven:{give,receive}, unverified, proofs}`:
 * a leg is `proven` only when a verified proof's signer equals that leg's address on the leg's chain; Hegemon legs are
 * listed in `unverified` and are never proven. */
export async function verifyIdentity(blob,expected,now){
 if(!Number.isSafeInteger(now))fail('The current time is required.');
 const {statement,proofs}=parseIdentity(blob);
 if(statement.role!==expected.role)fail('The identity statement is for a different role.');
 if(statement.offer!==expected.offer)fail('The identity statement is for a different offer.');
 if(statement.reservation!==(expected.reservation??''))fail('The identity statement is for a different reservation.');
 if(statement.inbox!==expected.inbox)fail('The identity statement names a different inbox key.');
 for(const side of ['give','receive'])if(statement.legs[side].chain!==expected[side]?.chain)fail('The identity statement is for a different '+side+' chain.');
 if(statement.expires<=now)fail('The identity statement has expired.');
 if(statement.issued>now+CLOCK_SKEW_SECONDS)fail('The identity statement is dated in the future.');
 if(!proofs.length)fail('The identity statement has no signature.');
 const text=statementText(statement),seen=new Set(),verified=[];
 for(const proof of proofs){
  const result=verifyProof(proof,text),key=result.chain+':'+result.signer;
  if(seen.has(key))fail('Duplicate identity proof.');seen.add(key);
  const named=['give','receive'].some(side=>statement.legs[side].chain===result.chain&&legAddress(statement,side)===result.signer);
  if(!named)fail('A proof signer is not an address named in the statement.');
  verified.push(result);
 }
 const addresses={give:legAddress(statement,'give'),receive:legAddress(statement,'receive')};
 const proven={};
 for(const side of ['give','receive'])proven[side]=verified.some(p=>p.chain===statement.legs[side].chain&&p.signer===addresses[side]);
 const unverified=['give','receive'].filter(side=>statement.legs[side].chain==='hegemon');
 return {statement,code:await identityCode(statement),role:statement.role,addresses,proven,unverified,proofs:verified};
}
/** The address each escrow must name, from the two verified identities (`owner` and `taker`). `give` and `receive` are the
 * owner's legs, as in the offer. Returns `{give:{claimant,refundee}, receive:{claimant,refundee}}` in engine format. */
export function expectedParticipants(owner,taker){
 return {give:{claimant:taker.addresses.give,refundee:owner.addresses.give},receive:{claimant:owner.addresses.receive,refundee:taker.addresses.receive}};
}
