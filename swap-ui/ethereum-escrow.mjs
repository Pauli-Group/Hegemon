/** Verify an Ethereum token escrow against a pinned runtime and agreed terms.
 * Provider and chain observations must come from a trusted node. This checks a
 * confirmed snapshot and current head only: token issuers can later freeze, upgrade or lie.
 */
function address(value) {
  if(typeof value!=='string'||!/^0x[0-9a-fA-F]{40}$/.test(value)||/^0x0{40}$/i.test(value))throw Error('invalid address');
  return value.slice(2).toLowerCase().padStart(64,'0');
}
function number(value) {
  if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,77})$/.test(value))throw Error('invalid integer');
  const n=BigInt(value);if(n>=1n<<256n)throw Error('integer exceeds uint256');return n.toString(16).padStart(64,'0');
}
function hash(value) {
  if(typeof value!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(value))throw Error('invalid hashlock');
  return value.slice(2).toLowerCase();
}
function word(value) {
  if(typeof value!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(value))throw Error('invalid call result');
  return BigInt(value);
}
function patchRuntime(template,words) {
  if(!template||typeof template.runtime!=='string'||!/^[0-9a-f]+$/.test(template.runtime))throw Error('invalid runtime template');
  let code=template.runtime.split('');
  const names=Object.keys(words);
  if(!template.immutableReferences||Object.keys(template.immutableReferences).sort().join(',')!==names.slice().sort().join(','))throw Error('invalid immutable map');
  const occupied=new Set();
  for(const name of names){
    const locations=template.immutableReferences[name];if(!Array.isArray(locations)||!locations.length)throw Error('missing immutable');
    for(const loc of locations){
      if(loc.length!==32||!Number.isSafeInteger(loc.start)||loc.start<0||(loc.start+32)*2>code.length)throw Error('invalid immutable location');
      for(let i=loc.start;i<loc.start+32;i++){if(occupied.has(i))throw Error('overlapping immutables');occupied.add(i);}
      code.splice(loc.start*2,64,...words[name]);
    }
  }
  return '0x'+code.join('');
}
export function expectedTokenRuntime(template,terms){
  if(!terms||!['0','1','2'].includes(terms.kind))throw Error('invalid token kind');
  const words={kind:number(terms.kind),token:address(terms.token),tokenId:number(terms.tokenId),amount:number(terms.amount),hashlock:hash(terms.hashlock),claimant:address(terms.claimant),refundee:address(terms.refundee),expiry:number(terms.expiry)};
  if(BigInt(terms.amount)===0n||(terms.kind==='0'&&terms.tokenId!=='0')||(terms.kind==='1'&&terms.amount!=='1'))throw Error('invalid asset quantity');
  return patchRuntime(template,words);
}
export function expectedEtherRuntime(template,terms){
  if(!terms)throw Error('invalid escrow terms');
  const words={hashlock:hash(terms.hashlock),claimant:address(terms.claimant),refundee:address(terms.refundee),expiry:number(terms.expiry)};
  number(terms.amount);if(BigInt(terms.amount)===0n)throw Error('invalid asset quantity');
  return patchRuntime(template,words);
}
export async function verifyEtherEscrow(provider,template,terms,confirmations=2,minimumRemainingSeconds=60){
  if(!provider||typeof provider.request!=='function'||!Number.isSafeInteger(confirmations)||confirmations<1||confirmations>10000||!Number.isSafeInteger(minimumRemainingSeconds)||minimumRemainingSeconds<1)throw Error('invalid provider or verification limits');
  if(!terms||typeof terms.chainId!=='string'||!/^0x[0-9a-f]{1,64}$/i.test(terms.chainId))throw Error('invalid chain');
  const contract='0x'+address(terms.contract).slice(24);
  const words={hashlock:hash(terms.hashlock),claimant:address(terms.claimant),refundee:address(terms.refundee),expiry:number(terms.expiry)};
  number(terms.amount);if(BigInt(terms.amount)===0n)throw Error('invalid asset quantity');
  const request=(method,params=[])=>provider.request({method,params});
  if(BigInt(await request('eth_chainId'))!==BigInt(terms.chainId))throw Error('wrong chain');
  const latest=BigInt(await request('eth_blockNumber'));if(latest<BigInt(confirmations-1))throw Error('not enough blocks');
  const tag='0x'+(latest-BigInt(confirmations-1)).toString(16);
  const block=await request('eth_getBlockByNumber',[tag,false]);
  if(!block||typeof block.hash!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(block.hash)||BigInt(block.timestamp)>=BigInt(terms.expiry))throw Error('missing block or escrow expired');
  const current=await request('eth_getBlockByNumber',['latest',false]);
  if(!current||BigInt(terms.expiry)-BigInt(current.timestamp)<BigInt(minimumRemainingSeconds))throw Error('escrow deadline too close');
  if(typeof current.number!=='string'||!/^0x[0-9a-f]+$/i.test(current.number)||typeof current.hash!=='string'||!/^0x[0-9a-f]{64}$/i.test(current.hash))throw Error('invalid current block');
  const actual=await request('eth_getCode',[contract,tag]);
  const expected=patchRuntime(template,words);
  if(typeof actual!=='string'||actual.toLowerCase()!==expected)throw Error('escrow bytecode or terms mismatch');
  const spent=word(await request('eth_call',[{to:contract,data:'0x7ab71b7a'},tag]));
  const balance=BigInt(await request('eth_getBalance',[contract,tag]));
  if(spent!==0n||balance!==BigInt(terms.amount))throw Error('escrow is not funded and unspent');
  const currentCode=await request('eth_getCode',[contract,current.number]);
  const currentSpent=word(await request('eth_call',[{to:contract,data:'0x7ab71b7a'},current.number]));
  const currentBalance=BigInt(await request('eth_getBalance',[contract,current.number]));
  if(typeof currentCode!=='string'||currentCode.toLowerCase()!==expected||currentSpent!==0n||currentBalance!==BigInt(terms.amount))throw Error('escrow is not funded and unspent at current head');
  const again=await request('eth_getBlockByNumber',[tag,false]);
  if(!again||again.hash!==block.hash||BigInt(await request('eth_chainId'))!==BigInt(terms.chainId))throw Error('snapshot or chain changed');
  const latestBlock=await request('eth_getBlockByNumber',['latest',false]);
  if(!latestBlock||BigInt(terms.expiry)-BigInt(latestBlock.timestamp)<BigInt(minimumRemainingSeconds))throw Error('escrow deadline too close');
  if(latestBlock.hash!==current.hash)throw Error('snapshot or chain changed');
  return {chainId:terms.chainId,blockNumber:tag,blockHash:block.hash,confirmations,contract,balance:balance.toString()};
}
export async function verifyTokenEscrow(provider,template,terms,confirmations=2,minimumRemainingSeconds=60){
  if(!provider||typeof provider.request!=='function'||!Number.isSafeInteger(confirmations)||confirmations<1||confirmations>10000||!Number.isSafeInteger(minimumRemainingSeconds)||minimumRemainingSeconds<1)throw Error('invalid provider or verification limits');
  if(!terms||!['0','1','2'].includes(terms.kind)||typeof terms.chainId!=='string'||!/^0x[0-9a-f]{1,64}$/i.test(terms.chainId))throw Error('invalid chain or token kind');
  const contract='0x'+address(terms.contract).slice(24), token='0x'+address(terms.token).slice(24);
  const words={kind:number(terms.kind),token:address(terms.token),tokenId:number(terms.tokenId),amount:number(terms.amount),hashlock:hash(terms.hashlock),claimant:address(terms.claimant),refundee:address(terms.refundee),expiry:number(terms.expiry)};
  if(BigInt(terms.amount)===0n||(terms.kind==='0'&&terms.tokenId!=='0')||(terms.kind==='1'&&terms.amount!=='1'))throw Error('invalid asset quantity');
  const request=(method,params=[])=>provider.request({method,params});
  if(BigInt(await request('eth_chainId'))!==BigInt(terms.chainId))throw Error('wrong chain');
  const latest=BigInt(await request('eth_blockNumber'));if(latest<BigInt(confirmations-1))throw Error('not enough blocks');
  const tag='0x'+(latest-BigInt(confirmations-1)).toString(16);
  const block=await request('eth_getBlockByNumber',[tag,false]);
  if(!block||typeof block.hash!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(block.hash)||BigInt(block.timestamp)>=BigInt(terms.expiry))throw Error('missing block or escrow expired');
  const current=await request('eth_getBlockByNumber',['latest',false]);
  if(!current||BigInt(terms.expiry)-BigInt(current.timestamp)<BigInt(minimumRemainingSeconds))throw Error('escrow deadline too close');
  if(typeof current.number!=='string'||!/^0x[0-9a-f]+$/i.test(current.number)||typeof current.hash!=='string'||!/^0x[0-9a-f]{64}$/i.test(current.hash))throw Error('invalid current block');
  const actual=await request('eth_getCode',[contract,tag]);
  const expected=patchRuntime(template,words);
  if(typeof actual!=='string'||actual.toLowerCase()!==expected)throw Error('escrow bytecode or terms mismatch');
  const call=async(to,data,at=tag)=>word(await request('eth_call',[{to,data},at]));
  if(await call(contract,'0xf3a504f2')!==1n||await call(contract,'0x7ab71b7a')!==0n)throw Error('escrow is not funded and unspent');
  const owner='0x'+words.token.slice(24);
  let balance;
  if(terms.kind==='0')balance=await call(owner,'0x70a08231'+address(contract));
  else if(terms.kind==='1')balance=(await call(owner,'0x6352211e'+words.tokenId))===BigInt(contract)?1n:0n;
  else balance=await call(owner,'0x00fdd58e'+address(contract)+words.tokenId);
  if(balance<BigInt(terms.amount))throw Error('asset not held by escrow');
  const currentCode=await request('eth_getCode',[contract,current.number]);
  if(typeof currentCode!=='string'||currentCode.toLowerCase()!==expected||await call(contract,'0xf3a504f2',current.number)!==1n||await call(contract,'0x7ab71b7a',current.number)!==0n)throw Error('escrow is not funded and unspent at current head');
  let currentBalance;
  if(terms.kind==='0')currentBalance=await call(owner,'0x70a08231'+address(contract),current.number);
  else if(terms.kind==='1')currentBalance=(await call(owner,'0x6352211e'+words.tokenId,current.number))===BigInt(contract)?1n:0n;
  else currentBalance=await call(owner,'0x00fdd58e'+address(contract)+words.tokenId,current.number);
  if(currentBalance<BigInt(terms.amount))throw Error('asset not held by escrow at current head');
  const again=await request('eth_getBlockByNumber',[tag,false]);
  if(!again||again.hash!==block.hash||BigInt(await request('eth_chainId'))!==BigInt(terms.chainId))throw Error('snapshot or chain changed');
  const latestBlock=await request('eth_getBlockByNumber',['latest',false]);
  if(!latestBlock||BigInt(terms.expiry)-BigInt(latestBlock.timestamp)<BigInt(minimumRemainingSeconds))throw Error('escrow deadline too close');
  if(latestBlock.hash!==current.hash)throw Error('snapshot or chain changed');
  return {chainId:terms.chainId,blockNumber:tag,blockHash:block.hash,confirmations,contract,token,balance:balance.toString()};
}
