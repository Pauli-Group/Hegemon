/** Verification of wallet signatures over an identity statement text, one scheme per chain.
 *
 *   ethereum  eip191        `personal_sign`: keccak256("\x19Ethereum Signed Message:\n" + len + text), 65-byte r||s||v,
 *                           signer is the 0x address recovered from it.
 *   cardano   cip8          CIP-30 `signData` result: a COSE_Sign1 (signature) and a COSE_Key (key), payload = the text bytes,
 *                           signer is the blake2b-224 hash of the ed25519 key (the escrow's key hash).
 *   bitcoin   bip322-simple BIP-322 "simple" for P2WPKH (base64 witness stack), signer is the compressed public key.
 *   bitcoin   bip137        the compact message signature (header 31..42, base64) Electrum, Sparrow and Core produce.
 *
 * Every function throws on anything it cannot positively verify and returns the signer in the engine's identity format
 * (Ethereum lowercase address, Cardano 56-hex key hash, Bitcoin compressed public key hex). */
import {keccak_256,blake2b,sha256,ed25519} from './vendor/hash.mjs';
import {secp256k1,p2wpkh,TEST_NETWORK} from './vendor/btc-signer.mjs';
import {decode,encode,fromHex,toHex,concat,equalBytes} from './cbor.mjs';

const utf8=new TextEncoder();
const fail=message=>{throw Error(message);};
const dsha=bytes=>sha256(sha256(bytes));

function hexBytes(value,length,what){
 if(typeof value!=='string'||!/^(?:[0-9a-f]{2})+$/.test(value)||(length&&value.length!==length*2))fail('Invalid '+what+'.');
 return fromHex(value);
}
function base64Bytes(value,what){
 if(typeof value!=='string'||value.length>4096||!/^[A-Za-z0-9+/]+={0,2}$/.test(value)||value.length%4)fail('Invalid '+what+'.');
 return Uint8Array.from(atob(value),c=>c.charCodeAt(0));
}
function recover(rs,recid,digest){
 // noble's recoverable format is recid || r || s.
 try{return secp256k1.recoverPublicKey(concat(Uint8Array.of(recid),rs),digest,{prehash:false});}
 catch{fail('The signature does not recover a public key.');}
}

// ---------------------------------------------------------------- Ethereum
export function verifyEthereum(proof,text){
 const signature=hexBytes(typeof proof.signature==='string'&&proof.signature.startsWith('0x')?proof.signature.slice(2):'',65,'Ethereum signature');
 const message=utf8.encode(text),digest=keccak_256(concat(utf8.encode('\x19Ethereum Signed Message:\n'+message.length),message));
 const v=signature[64],recid=v>=27?v-27:v;
 if(recid!==0&&recid!==1)fail('Invalid Ethereum signature recovery value.');
 const point=recover(signature.slice(0,64),recid,digest),uncompressed=secp256k1.Point.fromBytes(point).toBytes(false);
 return '0x'+toHex(keccak_256(uncompressed.slice(1)).slice(12));
}

// ---------------------------------------------------------------- Cardano
const COSE_ALG_EDDSA=-8;
function mapValue(map,key){if(!(map instanceof Map))fail('Invalid COSE structure.');return map.get(key);}
export function verifyCardano(proof,text){
 const sign1=decode(hexBytes(proof.signature,0,'Cardano signature')),cose=decode(hexBytes(proof.key,0,'Cardano key'));
 if(!Array.isArray(sign1)||sign1.length!==4)fail('Invalid COSE_Sign1.');
 const [protectedBytes,unprotected,payload,signature]=sign1;
 if(!(protectedBytes instanceof Uint8Array)||!(unprotected instanceof Map)||!(payload instanceof Uint8Array)||!(signature instanceof Uint8Array)||signature.length!==64)fail('Invalid COSE_Sign1.');
 if(unprotected.get('hashed')===true)fail('Hashed payloads are not accepted; sign the statement text itself.');
 if(!equalBytes(payload,utf8.encode(text)))fail('The signed payload is not the identity statement.');
 const header=decode(protectedBytes);
 if(mapValue(header,1)!==COSE_ALG_EDDSA)fail('Unsupported COSE algorithm.');
 const key=mapValue(cose,-2);
 if(mapValue(cose,1)!==1||mapValue(cose,-1)!==6||!(key instanceof Uint8Array)||key.length!==32)fail('Invalid COSE_Key.');
 const signed=encode(['Signature1',protectedBytes,new Uint8Array(0),payload]);
 let ok=false;try{ok=ed25519.verify(signature,signed,key);}catch{ok=false;}
 if(!ok)fail('The Cardano signature does not verify.');
 const keyHash=toHex(blake2b(key,{dkLen:28})),address=mapValue(header,'address');
 // The wallet names the address it signed with. For a payment-key address the payment credential must be this key.
 if(!(address instanceof Uint8Array)||address.length<29)fail('The signature does not name an address.');
 const type=address[0]>>4;
 if(![0,2,4,6].includes(type))fail('The signing address does not use a payment key.');
 if(toHex(address.slice(1,29))!==keyHash)fail('The signing address does not belong to the signing key.');
 return keyHash;
}

// ---------------------------------------------------------------- Bitcoin
const varint=n=>n<0xfd?Uint8Array.of(n):n<=0xffff?Uint8Array.of(0xfd,n&255,n>>8):fail('Value too large.');
const varstr=bytes=>concat(varint(bytes.length),bytes);
const le=(value,bytes)=>{const out=new Uint8Array(bytes);let v=BigInt(value);for(let i=0;i<bytes;i++){out[i]=Number(v&255n);v>>=8n;}return out;};
function compressedKey(hex){
 const bytes=hexBytes(hex,33,'Bitcoin public key');
 try{secp256k1.Point.fromBytes(bytes);}catch{fail('Invalid Bitcoin public key.');}
 return bytes;
}
export function verifyBip137(proof,text){
 const raw=base64Bytes(proof.signature,'Bitcoin signature');
 if(raw.length!==65)fail('Invalid Bitcoin message signature.');
 const header=raw[0];
 if(header<31||header>42)fail('Only compressed-key message signatures are accepted.');
 const recid=(header-27)&3,message=utf8.encode(text);
 const digest=dsha(concat(varstr(utf8.encode('Bitcoin Signed Message:\n')),varstr(message)));
 return toHex(recover(raw.slice(1),recid,digest));
}
export function bip322Digests(text,publicKey){
 const tag=sha256(utf8.encode('BIP0322-signed-message')),messageHash=sha256(concat(tag,tag,utf8.encode(text)));
 const script=p2wpkh(publicKey,TEST_NETWORK).script;
 if(script.length!==22)fail('Unexpected P2WPKH script.');
 const toSpend=concat(le(0,4),Uint8Array.of(1),new Uint8Array(32),le(0xffffffff,4),Uint8Array.of(34,0,32),messageHash,le(0,4),
  Uint8Array.of(1),le(0,8),varstr(script),le(0,4));
 const txid=dsha(toSpend),outpoint=concat(txid,le(0,4)),outputs=concat(le(0,8),varstr(Uint8Array.of(0x6a)));
 const scriptCode=concat(Uint8Array.of(0x19,0x76,0xa9,0x14),script.slice(2),Uint8Array.of(0x88,0xac));
 const preimage=concat(le(0,4),dsha(outpoint),dsha(le(0,4)),outpoint,scriptCode,le(0,8),le(0,4),dsha(outputs),le(0,4),le(1,4));
 return {txid:toHex(txid),sighash:dsha(preimage)};
}
export function verifyBip322(proof,text){
 const raw=base64Bytes(proof.signature,'Bitcoin signature');
 let offset=0;
 const byte=()=>offset<raw.length?raw[offset++]:fail('Truncated BIP-322 signature.');
 if(byte()!==2)fail('Only a two-item P2WPKH witness is supported.');
 const item=()=>{const length=byte();if(length>=0xfd||offset+length>raw.length)fail('Invalid BIP-322 signature.');const part=raw.slice(offset,offset+length);offset+=length;return part;};
 const signature=item(),publicKey=item();
 if(offset!==raw.length)fail('Trailing data after the BIP-322 witness.');
 if(publicKey.length!==33)fail('Invalid BIP-322 public key.');
 try{secp256k1.Point.fromBytes(publicKey);}catch{fail('Invalid BIP-322 public key.');}
 if(signature.length<9||signature[signature.length-1]!==1)fail('The BIP-322 signature must use SIGHASH_ALL.');
 const {sighash}=bip322Digests(text,publicKey);
 let ok=false;try{ok=secp256k1.verify(signature.slice(0,-1),sighash,publicKey,{prehash:false,format:'der'});}catch{ok=false;}
 if(!ok)fail('The BIP-322 signature does not verify.');
 return toHex(publicKey);
}

export const SCHEMES={ethereum:{eip191:verifyEthereum},cardano:{cip8:verifyCardano},bitcoin:{'bip322-simple':verifyBip322,bip137:verifyBip137}};
/** The key that really signed `text`, whatever the proof claims. Throws unless the signature verifies. */
export function signerOf(proof,text){
 if(!proof||typeof proof!=='object'||Array.isArray(proof))fail('Invalid identity proof.');
 const verify=Object.hasOwn(SCHEMES,proof.chain)&&Object.hasOwn(SCHEMES[proof.chain],proof.scheme)?SCHEMES[proof.chain][proof.scheme]:null;
 if(!verify)fail('Unsupported identity proof scheme.');
 return verify(proof,text);
}
/** Verify one proof against the statement text and return `{chain, scheme, signer}`. */
export function verifyProof(proof,text){
 const signer=signerOf(proof,text);
 if(proof.signer!==signer)fail('The proof signer is not the key that signed.');
 return {chain:proof.chain,scheme:proof.scheme,signer};
}
export {compressedKey};
