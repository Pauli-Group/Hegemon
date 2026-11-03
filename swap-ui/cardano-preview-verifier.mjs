/** Check the pinned Aiken HTLC on preview against a public indexer snapshot. */
export const PREVIEW_HTLC_ADDRESS='addr_test1wqmp4fms223lnjljntag8vk9frl0l8pygsp2pt75tv2llsgmwwmyv';
const HEX=/^[0-9a-f]+$/;
function bytes(hex){if(typeof hex!=='string'||!HEX.test(hex)||hex.length%2)throw Error('Invalid Cardano datum bytes.');return Uint8Array.from(hex.match(/../g),x=>parseInt(x,16));}
function datumBytes(hex){
  const a=bytes(hex);let i=0;const take=()=>{if(i>=a.length)throw Error('Invalid Cardano datum bytes.');return a[i++];};
  if(take()!==0xd8||take()!==0x79)throw Error('Invalid Cardano datum constructor.');
  const array=take();if(array!==0x84&&array!==0x9f)throw Error('Invalid Cardano datum fields.');
  const field=(len)=>{if(take()!==0x58||take()!==len||i+len>a.length)throw Error('Invalid Cardano datum field.');const out=Array.from(a.slice(i,i+len),x=>x.toString(16).padStart(2,'0')).join('');i+=len;return out;};
  const hashlock=field(32),claimant=field(28),refundee=field(28),header=take();let value=0n;
  if(header<24)value=BigInt(header);
  else{const widths={24:1,25:2,26:4,27:8},width=widths[header];if(!width)throw Error('Invalid Cardano datum expiry.');for(let j=0;j<width;j++)value=(value<<8n)|BigInt(take());}
  if(value>BigInt(Number.MAX_SAFE_INTEGER))throw Error('Invalid Cardano datum expiry.');
  if(array===0x9f&&take()!==0xff)throw Error('Invalid Cardano datum fields.');if(i!==a.length)throw Error('Trailing Cardano datum bytes.');
  return {hashlock,claimant,refundee,expiry_ms:Number(value)};
}
export function parseCardanoAssets(text){
  if(typeof text!=='string'||text.length>8192)throw Error('Invalid Cardano assets.');const out={};
  for(const line of text.split(/\r?\n/).map(x=>x.trim()).filter(Boolean)){
    const m=line.match(/^([0-9a-f]{56}\.(?:[0-9a-f]{2}){0,32})=([1-9][0-9]{0,18})$/);
    if(!m||Object.hasOwn(out,m[1])||BigInt(m[2])>=(1n<<63n))throw Error('Invalid Cardano assets.');out[m[1]]=m[2];
  }return out;
}
export async function verifyCardanoPreviewEscrow(terms,read){
  if(!terms||typeof terms.outref!=='string'||!/^[0-9a-f]{64}#(0|[1-9][0-9]{0,9})$/.test(terms.outref)||Number(terms.outref.split('#')[1])>0xffffffff||typeof terms.hashlock!=='string'||!/^[0-9a-f]{64}$/.test(terms.hashlock)||typeof terms.claimant!=='string'||!/^[0-9a-f]{56}$/.test(terms.claimant)||typeof terms.refundee!=='string'||!/^[0-9a-f]{56}$/.test(terms.refundee)||terms.claimant===terms.refundee||!Number.isSafeInteger(terms.expiry_ms)||terms.expiry_ms<=0||typeof terms.lovelace!=='string'||!/^[1-9][0-9]{0,18}$/.test(terms.lovelace)||BigInt(terms.lovelace)>=(1n<<63n))throw Error('Invalid Cardano escrow terms.');
  const expectedAssets=parseCardanoAssets(terms.assets);if(typeof read!=='function')throw Error('Cardano provider unavailable.');
  const s=await read(terms.outref),row=s?.output,[txid,index]=terms.outref.split('#');
  if(s?.network!=='preview'||s?.magic!==2||s?.system_start!==1666656000||!Number.isSafeInteger(s.slot)||s.slot<0||!Number.isSafeInteger(s.confirmations)||s.confirmations<2)throw Error('Cardano escrow lacks confirmed preview data.');
  if(!row||row.tx_hash!==txid||row.tx_index!==Number(index)||row.address!==PREVIEW_HTLC_ADDRESS||row.is_spent!==false)throw Error('Cardano escrow is spent or does not match the validator.');
  if(row.value!==terms.lovelace||!Array.isArray(row.asset_list))throw Error('Cardano escrow value does not match.');
  const actual={};for(const a of row.asset_list){const name=String(a.policy_id)+'.'+String(a.asset_name),quantity=a.quantity;if(!/^[0-9a-f]{56}\.(?:[0-9a-f]{2}){0,32}$/.test(name)||typeof quantity!=='string'||!/^[1-9][0-9]{0,18}$/.test(quantity)||BigInt(quantity)>=(1n<<63n)||Object.hasOwn(actual,name))throw Error('Invalid Cardano asset snapshot.');actual[name]=quantity;}
  const order=x=>JSON.stringify(Object.entries(x).sort(([a],[b])=>a.localeCompare(b)));if(order(actual)!==order(expectedAssets))throw Error('Cardano escrow assets do not match.');
  const value=row.inline_datum?.value,fields=value?.fields,raw=datumBytes(row.inline_datum?.bytes);
  if(value?.constructor!==0||!Array.isArray(fields)||fields.length!==4||fields[0]?.bytes!==terms.hashlock||fields[1]?.bytes!==terms.claimant||fields[2]?.bytes!==terms.refundee||fields[3]?.int!==terms.expiry_ms||raw.hashlock!==terms.hashlock||raw.claimant!==terms.claimant||raw.refundee!==terms.refundee||raw.expiry_ms!==terms.expiry_ms)throw Error('Cardano escrow datum does not match.');
  if(terms.expiry_ms-(s.system_start+s.slot)*1000<600000)throw Error('Cardano escrow deadline is too close.');
  return {slot:s.slot,confirmations:s.confirmations,outref:terms.outref};
}
