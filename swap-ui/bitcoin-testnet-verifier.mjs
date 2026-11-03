/** Reconstruct the testnet4 HTLC script and compare it with provider data. */
export const TESTNET4_GENESIS='00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043';
const P=(1n<<256n)-(1n<<32n)-977n;
const fromHex=s=>Uint8Array.from(s.match(/../g),x=>parseInt(x,16));
const toHex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
function pow(base,exp){let result=1n;while(exp){if(exp&1n)result=result*base%P;base=base*base%P;exp>>=1n;}return result;}
function publicKey(value){
  if(typeof value!=='string'||!/^(02|03)[0-9a-f]{64}$/.test(value))throw Error('Invalid compressed Bitcoin public key.');
  const x=BigInt('0x'+value.slice(2));if(x>=P)throw Error('Invalid compressed Bitcoin public key.');
  const rhs=(x*x%P*x+7n)%P,y=pow(rhs,(P+1n)/4n);if(y*y%P!==rhs||(y===0n&&value.startsWith('03')))throw Error('Invalid compressed Bitcoin public key.');
  return value;
}
function lockNumber(n){
  if(!Number.isSafeInteger(n)||n<1||n>=500000000)throw Error('Invalid Bitcoin refund height.');
  if(n<=16)return (0x50+n).toString(16);
  const bytes=[];while(n){bytes.push(n&255);n=Math.floor(n/256);}if(bytes.at(-1)&128)bytes.push(0);
  return bytes.length.toString(16).padStart(2,'0')+toHex(bytes);
}
export async function expectedBitcoinScript(terms){
  if(!terms||typeof terms.hashlock!=='string'||!/^[0-9a-f]{64}$/.test(terms.hashlock))throw Error('Invalid hashlock.');
  const claim=publicKey(terms.claimant_key),refund=publicKey(terms.refund_key);if(claim===refund)throw Error('Claim and refund keys must differ.');
  const witness='6382012088a820'+terms.hashlock+'8821'+claim+'ac67'+lockNumber(terms.refund_height)+'b16921'+refund+'ac68';
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',fromHex(witness)));return '0020'+toHex(digest);
}
export async function verifyBitcoinTestnetEscrow(terms,read){
  if(!terms||typeof terms.txid!=='string'||!/^[0-9a-f]{64}$/.test(terms.txid)||!Number.isSafeInteger(terms.vout)||terms.vout<0||terms.vout>99999||!Number.isSafeInteger(terms.amount_sats)||terms.amount_sats<546||terms.amount_sats>2100000000000000)throw Error('Invalid Bitcoin escrow terms.');
  if(typeof read!=='function')throw Error('Bitcoin provider unavailable.');
  const expected=await expectedBitcoinScript(terms),snapshot=await read(terms.txid,terms.vout);
  if(!snapshot||snapshot.genesis!==TESTNET4_GENESIS||snapshot.txid!==terms.txid||snapshot.vout!==terms.vout||!Number.isSafeInteger(snapshot.tip)||snapshot.tip<0)throw Error('Bitcoin provider returned a different network or output.');
  if(snapshot.confirmed!==true||!Number.isSafeInteger(snapshot.confirmations)||snapshot.confirmations<2||!Number.isSafeInteger(snapshot.block_height)||snapshot.tip-snapshot.block_height+1!==snapshot.confirmations||typeof snapshot.block_hash!=='string'||!/^[0-9a-f]{64}$/.test(snapshot.block_hash))throw Error('Bitcoin escrow lacks two confirmations.');
  if(snapshot.spent!==false)throw Error('Bitcoin escrow is spent or unavailable.');
  if(snapshot.amount_sats!==terms.amount_sats||snapshot.script!==expected)throw Error('Bitcoin escrow does not match the agreed terms.');
  if(terms.refund_height-snapshot.tip<6)throw Error('Bitcoin refund height is too close.');
  return {tip:snapshot.tip,block_height:snapshot.block_height,confirmations:snapshot.confirmations,block_hash:snapshot.block_hash};
}
