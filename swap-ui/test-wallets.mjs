/** Test-only signers that behave like the wallets the identity flow talks to (EIP-1193 `personal_sign`, CIP-30 `signData`,
 * and a Bitcoin message signer). They hold plain test keys with no value. Not served (see .assetsignore). */
import {keccak_256,blake2b,sha256,ed25519} from './vendor/hash.mjs';
import {secp256k1} from './vendor/btc-signer.mjs';
import {encode,fromHex,toHex,concat} from './cbor.mjs';

const utf8=new TextEncoder();
const dsha=bytes=>sha256(sha256(bytes));
const varstr=bytes=>concat(bytes.length<0xfd?Uint8Array.of(bytes.length):Uint8Array.of(0xfd,bytes.length&255,bytes.length>>8),bytes);

export function ethereumWallet(privateKeyHex){
 const key=fromHex(privateKeyHex),address='0x'+toHex(keccak_256(secp256k1.Point.fromBytes(secp256k1.getPublicKey(key,true)).toBytes(false).slice(1)).slice(12));
 return {address,personalSign(hexMessage){
  const message=fromHex(hexMessage.slice(2)),digest=keccak_256(concat(utf8.encode('\x19Ethereum Signed Message:\n'+message.length),message));
  const recovered=secp256k1.sign(digest,key,{prehash:false,format:'recovered'});
  return '0x'+toHex(recovered.slice(1))+(27+recovered[0]).toString(16);
 }};
}
/** An EIP-1193 provider for a page: `personal_sign` calls `sign(hexMessage)`; everything else is answered with fixed data. */
export function ethereumProviderSource(address){
 return `({request:async({method,params})=>{
  if(method==='eth_requestAccounts'||method==='eth_accounts')return [${JSON.stringify(address)}];
  if(method==='eth_chainId')return '0xaa36a7';
  if(method==='personal_sign')return window.__personalSign(params[0]);
  throw Error('unsupported '+method);},on(){},removeListener(){}})`;
}
export function cardanoWallet(seedHex,{network=0}={}){
 const seed=fromHex(seedHex),publicKey=ed25519.getPublicKey(seed),keyHash=blake2b(publicKey,{dkLen:28});
 const address=concat(Uint8Array.of(0x60|network),keyHash);
 return {keyHash:toHex(keyHash),addressHex:toHex(address),signData(addressHex,payloadHex){
  if(addressHex!==toHex(address))throw Error('unknown address');
  const protectedBytes=encode(new Map([[1,-8],['address',address]])),payload=fromHex(payloadHex);
  const signature=ed25519.sign(encode(['Signature1',protectedBytes,new Uint8Array(0),payload]),seed);
  return {signature:toHex(encode([protectedBytes,new Map([['hashed',false]]),payload,signature])),key:toHex(encode(new Map([[1,1],[3,-8],[-1,6],[-2,publicKey]])))};
 }};
}
/** BIP-137 message signing with a compressed key. Returns `{publicKey, sign(text)->base64}`. */
export function bitcoinMessageWallet(privateKeyHex){
 const key=fromHex(privateKeyHex),publicKey=toHex(secp256k1.getPublicKey(key,true));
 return {publicKey,sign(text){
  const digest=dsha(concat(varstr(utf8.encode('Bitcoin Signed Message:\n')),varstr(utf8.encode(text))));
  const recovered=secp256k1.sign(digest,key,{prehash:false,format:'recovered'});
  return Buffer.from(concat(Uint8Array.of(31+recovered[0]),recovered.slice(1))).toString('base64');
 }};
}
