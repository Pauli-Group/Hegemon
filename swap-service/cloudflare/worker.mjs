/* Public testnet offer directory. Wallets and swap secrets stay with users. */
import {HOSTED_CSP,HOSTED_ROOT,SERVED_FILES} from './client-policy.mjs';
const SERVED=new Set(SERVED_FILES);
const chains={ethereum:['eth','erc20','erc721','erc1155'],cardano:['ada','native'],bitcoin:['btc'],hegemon:['hgn']};
const hex=/^[0-9a-f]{64}$/;
const now=()=>Math.floor(Date.now()/1000);
const random=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),x=>x.toString(16).padStart(2,'0')).join('');
async function digest(value){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),x=>x.toString(16).padStart(2,'0')).join('');}
const keys=v=>v&&typeof v==='object'&&!Array.isArray(v)?Object.keys(v).sort().join(','):'';
function asset(a){
  if(keys(a)!=='amount,chain,id,kind'||typeof a.chain!=='string'||!Object.hasOwn(chains,a.chain)||typeof a.kind!=='string'||!chains[a.chain].includes(a.kind)||typeof a.id!=='string'||typeof a.amount!=='string'||!/^[1-9][0-9]{0,77}$/.test(a.amount)||BigInt(a.amount)>=(1n<<256n))return false;
  if(['eth','ada','btc','hgn'].includes(a.kind))return a.id==='';
  if(a.kind==='erc20')return /^0x[0-9a-fA-F]{40}$/.test(a.id);
  if(a.kind==='erc721'||a.kind==='erc1155'){
    const m=a.id.match(/^0x[0-9a-fA-F]{40}:(0|[1-9][0-9]{0,77})$/);
    return !!m&&BigInt(m[1])<(1n<<256n)&&(a.kind!=='erc721'||a.amount==='1');
  }
  return a.kind==='native'&&/^[0-9a-fA-F]{56}\.(?:[0-9a-fA-F]{2}){0,32}$/.test(a.id)&&BigInt(a.amount)<(1n<<63n);
}
const headers={'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer'};
function reply(status,body){return new Response(JSON.stringify(body),{status,headers});}
async function body(req){
  if(Number(req.headers.get('content-length')||0)>16384)throw new SyntaxError('body too large');
  if(!req.body)throw new SyntaxError('missing body');
  const reader=req.body.getReader(),parts=[];let size=0;
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>16384){await reader.cancel();throw new SyntaxError('body too large');}parts.push(value);}
  const data=new Uint8Array(size);let offset=0;for(const part of parts){data.set(part,offset);offset+=part.length;}
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data));
}
function presentation(row,t){
  const reserved=!!row.reservation_id&&row.reservation_expires>t;
  return {id:row.id,visibility:row.public?'public':'private',...JSON.parse(row.offer),expires:row.expires,closed:!!row.closed,...(reserved?{reservationId:row.reservation_id}:{}),
    ...(row.owner_identity?{ownerIdentity:row.owner_identity}:{}),...(reserved&&row.reservation_identity?{reservationIdentity:row.reservation_identity}:{})};
}
// Signed identity statements (swap-ui/identity.mjs). The relay checks structure, size and that the ids inside belong to this
// row so garbage cannot be stored; it does NOT verify signatures and clients never trust it to: they verify locally.
const IDENTITY_MAX=8192,IDENTITY_FIELD=/^[0-9a-f]{64}$/;
async function inboxFingerprint(publicKey){const raw=Uint8Array.from(publicKey.match(/../g),x=>parseInt(x,16));return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),x=>x.toString(16).padStart(2,'0')).join('');}
async function identityError(blob,row,role,reservationId){
  if(typeof blob!=='string'||blob.length>IDENTITY_MAX)return 'invalid identity statement';
  let value;try{value=JSON.parse(blob);}catch{return 'invalid identity statement';}
  const st=value?.statement;
  if(keys(value)!=='proofs,statement'||!Array.isArray(value.proofs)||value.proofs.length<1||value.proofs.length>4||!value.proofs.every(p=>p&&typeof p==='object'&&!Array.isArray(p))||!st||typeof st!=='object'||st.version!==1||st.kind!=='hegemon.swap.identity'||st.role!==role)return 'invalid identity statement';
  if(st.offer!==row.id||st.reservation!==(role==='owner'?'':reservationId))return 'identity statement is for a different offer or reservation';
  if(typeof st.inbox!=='string'||!IDENTITY_FIELD.test(st.inbox))return 'invalid identity statement';
  const inbox=JSON.parse(row.offer).ownerPublicKey;
  if(role==='owner'&&(!inbox||st.inbox!==await inboxFingerprint(inbox)))return 'identity statement names a different inbox key';
  return null;
}
async function get(db,id){return db.prepare('SELECT * FROM offers WHERE id=?').bind(id).first();}
function participant(row,hash,t){if(!hash)return null;if(hash===row.owner_hash)return 'owner';return hash===row.reservation_hash&&row.reservation_expires>t?'taker':null;}
// Swap sessions outlive the offer listing and reservation. The relay stores opaque
// packets only; clients must authenticate and validate their contents themselves.
const SWAP_SESSION_LIFETIME=180*86400;
const sessionId=(offerId,reservationId)=>digest('hegemon.swap.session.v1:'+offerId+':'+reservationId);
function sessionParticipant(row,hash,t){if(!row||!hash||row.expires<=t)return null;if(hash===row.owner_hash)return 'owner';return hash===row.taker_hash?'taker':null;}
function sessionPresentation(row){return {id:row.id,offerId:row.offer_id,reservationId:row.reservation_id,offer:JSON.parse(row.offer_snapshot),created:row.created,expires:row.expires};}
async function sessionApi(req,db,id,op,hash,t,url){
  const row=await db.prepare('SELECT * FROM swap_sessions WHERE id=?').bind(id).first(),who=sessionParticipant(row,hash,t);
  if(!who)return reply(401,{error:'unauthorized'});
  if(req.method==='GET'&&!op&&url.searchParams.size===0)return reply(200,sessionPresentation(row));
  if(op==='packets'&&req.method==='GET'){
    const raw=url.searchParams.get('after')??'0';
    if(!/^(0|[1-9][0-9]{0,15})$/.test(raw)||url.searchParams.size>(url.searchParams.has('after')?1:0)||!Number.isSafeInteger(Number(raw)))return reply(400,{error:'invalid cursor'});
    const rows=await db.prepare(`SELECT id,sender,sequence,ciphertext,created FROM swap_packets
      WHERE session_id=? AND id>? ORDER BY id LIMIT 100`).bind(id,Number(raw)).all();
    return reply(200,{packets:rows.results});
  }
  if(op==='packets'&&req.method==='POST'&&url.searchParams.size===0){
    const data=await body(req);
    if(keys(data)!=='ciphertext,sequence'||!Number.isSafeInteger(data.sequence)||data.sequence<1||data.sequence>256||typeof data.ciphertext!=='string'||data.ciphertext.length>12000||!/^[A-Za-z0-9+/]+={0,2}$/.test(data.ciphertext))return reply(400,{error:'invalid packet'});
    const previous=await db.prepare('SELECT id,ciphertext FROM swap_packets WHERE session_id=? AND sender=? AND sequence=?').bind(id,who,data.sequence).first();
    if(previous)return previous.ciphertext===data.ciphertext?reply(200,{id:previous.id,duplicate:true}):reply(409,{error:'packet conflicts with an existing sequence'});
    const inserted=await db.prepare(`INSERT OR IGNORE INTO swap_packets(session_id,sender,sequence,ciphertext,created)
      SELECT ?,?,?,?,? WHERE EXISTS (SELECT 1 FROM swap_sessions WHERE id=? AND expires>? AND ${who==='owner'?'owner_hash':'taker_hash'}=?)
      AND ?=(SELECT COALESCE(MAX(sequence),0)+1 FROM swap_packets WHERE session_id=? AND sender=?) RETURNING id`)
      .bind(id,who,data.sequence,data.ciphertext,t,id,t,hash,data.sequence,id,who).first();
    if(inserted)return reply(201,{id:inserted.id,duplicate:false});
    const current=await db.prepare('SELECT id,ciphertext FROM swap_packets WHERE session_id=? AND sender=? AND sequence=?').bind(id,who,data.sequence).first();
    return current&&current.ciphertext===data.ciphertext?reply(200,{id:current.id,duplicate:true}):reply(409,{error:'packet sequence changed or is out of order'});
  }
  return reply(404,{error:'not found'});
}
async function quota(req,env,t){
  const ip=req.headers.get('CF-Connecting-IP');
  if(!ip)return false;
  const window=Math.floor(t/60),key=await digest(window+':'+ip),limit=req.method==='GET'?180:40;
  const row=await env.DB.prepare('INSERT INTO quotas(key,window,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1 WHERE count<? RETURNING count').bind(key,window,limit).first();
  return !!row;
}
const BITCOIN_API='https://blockstream.info/testnet4/api';
const BITCOIN_GENESIS='00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043';
async function bitcoinRead(path){
  const response=await fetch(BITCOIN_API+path,{headers:{accept:'application/json'},signal:AbortSignal.timeout(12000)});
  if(!response.ok||!response.body)throw Error('Bitcoin testnet provider unavailable');
  const reader=response.body.getReader(),chunks=[];let size=0;
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>1024*1024){await reader.cancel();throw Error('Bitcoin provider response too large');}chunks.push(value);}
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  return new TextDecoder().decode(bytes);
}
async function bitcoinEscrow(url){
  const txid=url.searchParams.get('txid'),voutText=url.searchParams.get('vout');
  if(!hex.test(txid||'')||!/^(0|[1-9][0-9]{0,4})$/.test(voutText||'')||url.searchParams.size!==2)return reply(400,{error:'invalid Bitcoin output'});
  const vout=Number(voutText);
  const [genesis,tipText,txText,outText]=await Promise.all([bitcoinRead('/block-height/0'),bitcoinRead('/blocks/tip/height'),bitcoinRead('/tx/'+txid),bitcoinRead('/tx/'+txid+'/outspend/'+vout)]);
  const tip=Number(tipText.trim()),tx=JSON.parse(txText),outspend=JSON.parse(outText),status=tx?.status;
  if(genesis.trim()!==BITCOIN_GENESIS||!Number.isSafeInteger(tip)||tip<0||tx?.txid!==txid||!Array.isArray(tx.vout)||vout>=tx.vout.length||typeof outspend.spent!=='boolean')throw Error('Bitcoin provider returned inconsistent data');
  const output=tx.vout[vout];
  if(!Number.isSafeInteger(output.value)||output.value<0||typeof output.scriptpubkey!=='string'||!/^[0-9a-f]*$/.test(output.scriptpubkey))throw Error('Invalid Bitcoin output');
  if(status?.confirmed!==true)return reply(200,{genesis:BITCOIN_GENESIS,txid,vout,tip,confirmed:false,spent:outspend.spent,amount_sats:output.value,script:output.scriptpubkey});
  const height=status.block_height,hash=status.block_hash;
  if(!Number.isSafeInteger(height)||height<0||height>tip||!hex.test(hash||''))throw Error('Invalid Bitcoin confirmation');
  const [canonical,again]=await Promise.all([bitcoinRead('/block-height/'+height),bitcoinRead('/tx/'+txid+'/outspend/'+vout)]);
  if(canonical.trim()!==hash||JSON.parse(again).spent!==outspend.spent)throw Error('Bitcoin chain or output changed');
  return reply(200,{genesis:BITCOIN_GENESIS,txid,vout,tip,confirmed:true,confirmations:tip-height+1,block_height:height,block_hash:hash,spent:outspend.spent,amount_sats:output.value,script:output.scriptpubkey});
}
const BITCOIN_ADDRESS=/^tb1q(?:[02-9ac-hj-np-z]{38}|[02-9ac-hj-np-z]{58})$/;
async function bitcoinUtxos(url){
  const address=url.searchParams.get('address');
  if(url.searchParams.size!==1||!BITCOIN_ADDRESS.test(address||''))return reply(400,{error:'invalid Bitcoin testnet address'});
  const [genesis,tipText,listText]=await Promise.all([bitcoinRead('/block-height/0'),bitcoinRead('/blocks/tip/height'),bitcoinRead('/address/'+address+'/utxo')]);
  const tip=Number(tipText.trim()),list=JSON.parse(listText);
  if(genesis.trim()!==BITCOIN_GENESIS||!Number.isSafeInteger(tip)||tip<0||!Array.isArray(list)||list.length>1000)throw Error('Bitcoin provider returned inconsistent data');
  const utxos=[];
  for(const item of list){
    if(!hex.test(item?.txid||'')||!Number.isSafeInteger(item.vout)||item.vout<0||!Number.isSafeInteger(item.value)||item.value<0||typeof item.status?.confirmed!=='boolean')throw Error('Bitcoin provider returned an invalid output');
    if(item.status.confirmed!==true)continue;
    const height=item.status.block_height;
    if(!Number.isSafeInteger(height)||height<0||height>tip||!hex.test(item.status.block_hash||''))throw Error('Invalid Bitcoin confirmation');
    utxos.push({txid:item.txid,vout:item.vout,amount_sats:item.value,confirmations:tip-height+1,block_hash:item.status.block_hash});
  }
  utxos.sort((a,b)=>b.amount_sats-a.amount_sats||(a.txid<b.txid?-1:a.txid>b.txid?1:a.vout-b.vout));
  return reply(200,{genesis:BITCOIN_GENESIS,address,tip,utxos:utxos.slice(0,100)});
}
async function bitcoinBroadcast(req){
  let data;try{data=await body(req);}catch{return reply(400,{error:'invalid request'});}
  if(keys(data)!=='tx'||typeof data.tx!=='string'||!/^(?:[0-9a-f]{2}){60,8000}$/.test(data.tx))return reply(400,{error:'invalid transaction'});
  const response=await fetch(BITCOIN_API+'/tx',{method:'POST',headers:{'content-type':'text/plain',accept:'text/plain'},body:data.tx,signal:AbortSignal.timeout(15000)});
  const text=(await response.text()).slice(0,300).trim();
  if(response.ok){if(!hex.test(text))throw Error('Bitcoin provider returned an invalid transaction id');return reply(200,{txid:text});}
  if(response.status>=400&&response.status<500)return reply(400,{error:'rejected by the Bitcoin network',reason:text.replace(/[^\x20-\x7e]/g,'?')});
  throw Error('Bitcoin provider unavailable');
}
const CARDANO_API='https://preview.koios.rest/api/v1';
async function cardanoRead(path,body){
  const response=await fetch(CARDANO_API+path,{method:body?'POST':'GET',headers:{accept:'application/json',...(body?{'content-type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(12000)});
  if(!response.ok||!response.body)throw Error('Cardano preview provider unavailable');
  const reader=response.body.getReader(),chunks=[];let size=0;
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>1024*1024){await reader.cancel();throw Error('Cardano response too large');}chunks.push(value);}
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  return JSON.parse(new TextDecoder().decode(bytes));
}
async function cardanoEscrow(url){
  const ref=url.searchParams.get('outref');
  if(typeof ref!=='string'||!/^[0-9a-f]{64}#(0|[1-9][0-9]{0,9})$/.test(ref)||url.searchParams.size!==1)return reply(400,{error:'invalid Cardano output'});
  const [txid,indexText]=ref.split('#'),index=Number(indexText);if(index>0xffffffff)return reply(400,{error:'invalid Cardano output'});
  const query={'_utxo_refs':[ref],'_extended':true},statusQuery={'_tx_hashes':[txid]};
  const [genesis,tip,status,rows]=await Promise.all([cardanoRead('/genesis'),cardanoRead('/tip'),cardanoRead('/tx_status',statusQuery),cardanoRead('/utxo_info',query)]);
  if(!Array.isArray(genesis)||genesis.length!==1||genesis[0]?.networkmagic!=='2'||genesis[0]?.networkid!=='Testnet'||genesis[0]?.systemstart!==1666656000||!Array.isArray(tip)||tip.length!==1||!Number.isSafeInteger(tip[0]?.abs_slot)||!Array.isArray(status)||status.length!==1||status[0]?.tx_hash!==txid||!Number.isSafeInteger(status[0]?.num_confirmations)||!Array.isArray(rows)||rows.length!==1)throw Error('Cardano provider returned inconsistent data');
  const row=rows[0];if(row.tx_hash!==txid||row.tx_index!==index||typeof row.is_spent!=='boolean')throw Error('Cardano provider returned a different output');
  const [again,againStatus]=await Promise.all([cardanoRead('/utxo_info',query),cardanoRead('/tx_status',statusQuery)]);
  if(!Array.isArray(again)||again.length!==1||JSON.stringify(again[0])!==JSON.stringify(row)||!Array.isArray(againStatus)||againStatus.length!==1||againStatus[0]?.tx_hash!==txid||!Number.isSafeInteger(againStatus[0]?.num_confirmations))throw Error('Cardano escrow changed during observation');
  return reply(200,{network:'preview',magic:2,system_start:1666656000,slot:tip[0].abs_slot,confirmations:Math.min(status[0].num_confirmations,againStatus[0].num_confirmations),output:row});
}

// Decimal prices from the provider become exact fractions so the page never does floating-point fee arithmetic.
function ratioOf(x){
  const text=typeof x==='number'?String(x):x;
  const m=typeof text==='string'?/^(\d{1,12})(?:\.(\d{1,18}))?(?:e(-?\d{1,3}))?$/i.exec(text):null;
  if(!m)throw Error('Invalid Cardano price');
  let digits=m[1]+(m[2]||''),scale=(m[2]||'').length-Number(m[3]||0);
  if(scale<0){digits+='0'.repeat(-scale);scale=0;}
  if(scale>40)throw Error('Invalid Cardano price');
  return [BigInt(digits).toString(),(10n**BigInt(scale)).toString()];
}
const decimalText=x=>{const n=typeof x==='string'?Number(x):x;if(!Number.isSafeInteger(n)||n<0)throw Error('Invalid Cardano parameter');return n;};
async function cardanoNetwork(){
  const [genesis,tip]=await Promise.all([cardanoRead('/genesis'),cardanoRead('/tip')]);
  if(!Array.isArray(genesis)||genesis.length!==1||genesis[0]?.networkmagic!=='2'||genesis[0]?.networkid!=='Testnet'||genesis[0]?.systemstart!==1666656000||!Array.isArray(tip)||tip.length!==1||!Number.isSafeInteger(tip[0]?.abs_slot)||!Number.isSafeInteger(tip[0]?.block_no)||!Number.isSafeInteger(tip[0]?.epoch_no))throw Error('Cardano provider returned inconsistent data');
  return {network:'preview',magic:2,system_start:1666656000,slot:tip[0].abs_slot,block:tip[0].block_no,epoch:tip[0].epoch_no};
}
async function cardanoParams(){
  const net=await cardanoNetwork(),rows=await cardanoRead('/epoch_params?_epoch_no='+net.epoch);
  if(!Array.isArray(rows)||rows.length!==1||rows[0]?.epoch_no!==net.epoch)throw Error('Cardano provider returned inconsistent data');
  const r=rows[0],model=r.cost_models?.PlutusV3;
  if(!Array.isArray(model)||model.length<200||model.length>1000||!model.every(Number.isSafeInteger))throw Error('Cardano provider returned an invalid cost model');
  return {...net,minFeeA:decimalText(r.min_fee_a),minFeeB:decimalText(r.min_fee_b),coinsPerUtxoByte:decimalText(r.coins_per_utxo_size),maxTxSize:decimalText(r.max_tx_size),priceMem:ratioOf(r.price_mem),priceStep:ratioOf(r.price_step),collateralPercent:decimalText(r.collateral_percent),maxCollateralInputs:decimalText(r.max_collateral_inputs),maxTxExMem:decimalText(r.max_tx_ex_mem),maxTxExSteps:decimalText(r.max_tx_ex_steps),costModelV3:model};
}
async function cardanoUtxos(url){
  const text=url.searchParams.get('refs');
  const refs=typeof text==='string'?text.split(','):[];
  if(url.searchParams.size!==1||refs.length<1||refs.length>24||new Set(refs).size!==refs.length||!refs.every(ref=>/^[0-9a-f]{64}#(0|[1-9][0-9]{0,9})$/.test(ref)&&Number(ref.split('#')[1])<=0xffffffff))return reply(400,{error:'invalid Cardano output list'});
  const [net,rows]=await Promise.all([cardanoNetwork(),cardanoRead('/utxo_info',{_utxo_refs:refs,_extended:true})]);
  if(!Array.isArray(rows)||rows.length>refs.length)throw Error('Cardano provider returned inconsistent data');
  const byRef=new Map();
  for(const row of rows){
    const ref=row?.tx_hash+'#'+row?.tx_index;
    if(!refs.includes(ref)||byRef.has(ref)||typeof row.address!=='string'||typeof row.is_spent!=='boolean'||typeof row.value!=='string'||!Array.isArray(row.asset_list))throw Error('Cardano provider returned a different output');
    byRef.set(ref,row);
  }
  return reply(200,{...net,outputs:refs.map(ref=>byRef.get(ref)??null)});
}
// ---- read proxies for the counterparty's spend (the page decodes and verifies; these only fetch)
async function bitcoinHead(url){
  if(url.searchParams.size!==0)return reply(400,{error:'invalid request'});
  const [genesis,tipText]=await Promise.all([bitcoinRead('/block-height/0'),bitcoinRead('/blocks/tip/height')]);
  const tip=Number(tipText.trim());
  if(genesis.trim()!==BITCOIN_GENESIS||!Number.isSafeInteger(tip)||tip<0)throw Error('Bitcoin provider returned inconsistent data');
  return reply(200,{genesis:BITCOIN_GENESIS,tip});
}
async function bitcoinSpend(url){
  const txid=url.searchParams.get('txid'),voutText=url.searchParams.get('vout');
  if(!hex.test(txid||'')||!/^(0|[1-9][0-9]{0,4})$/.test(voutText||'')||url.searchParams.size!==2)return reply(400,{error:'invalid Bitcoin output'});
  const vout=Number(voutText);
  const [genesis,tipText,txText,outText]=await Promise.all([bitcoinRead('/block-height/0'),bitcoinRead('/blocks/tip/height'),bitcoinRead('/tx/'+txid),bitcoinRead('/tx/'+txid+'/outspend/'+vout)]);
  const tip=Number(tipText.trim()),tx=JSON.parse(txText),outspend=JSON.parse(outText);
  if(genesis.trim()!==BITCOIN_GENESIS||!Number.isSafeInteger(tip)||tip<0||tx?.txid!==txid||!Array.isArray(tx.vout)||vout>=tx.vout.length||typeof outspend.spent!=='boolean')throw Error('Bitcoin provider returned inconsistent data');
  if(!outspend.spent)return reply(200,{genesis:BITCOIN_GENESIS,txid,vout,tip,spent:false});
  if(!hex.test(outspend.txid||'')||!Number.isSafeInteger(outspend.vin)||outspend.vin<0)throw Error('Bitcoin provider returned an invalid spend');
  const spend=JSON.parse(await bitcoinRead('/tx/'+outspend.txid)),input=Array.isArray(spend?.vin)?spend.vin[outspend.vin]:undefined;
  if(spend?.txid!==outspend.txid||input?.txid!==txid||input.vout!==vout||!Array.isArray(input.witness)||input.witness.length>20||!input.witness.every(w=>typeof w==='string'&&/^(?:[0-9a-f]{2})*$/.test(w)&&w.length<=20000))throw Error('Bitcoin provider returned a different spend');
  const status=spend.status;let confirmations=0,height,hash;
  if(status?.confirmed===true){
    height=status.block_height;hash=status.block_hash;
    if(!Number.isSafeInteger(height)||height<0||height>tip||!hex.test(hash||''))throw Error('Invalid Bitcoin confirmation');
    const [canonical,again]=await Promise.all([bitcoinRead('/block-height/'+height),bitcoinRead('/tx/'+txid+'/outspend/'+vout)]);
    if(canonical.trim()!==hash||JSON.parse(again).txid!==outspend.txid)throw Error('Bitcoin chain or output changed');
    confirmations=tip-height+1;
  }else if(JSON.parse(await bitcoinRead('/tx/'+txid+'/outspend/'+vout)).txid!==outspend.txid)throw Error('Bitcoin output changed');
  return reply(200,{genesis:BITCOIN_GENESIS,txid,vout,tip,spent:true,spend:{txid:outspend.txid,vin:outspend.vin,confirmed:confirmations>0,confirmations,...(confirmations>0?{block_height:height,block_hash:hash}:{}),witness:input.witness}});
}

const SEPOLIA_RPC='https://ethereum-sepolia-rpc.publicnode.com',SEPOLIA_BLOCKSCOUT='https://eth-sepolia.blockscout.com/api/v2';
const ESCROW_TOPICS={
  '0x0508a8b4117d9a7b3d8f5895f6413e61b4f9a2df35afbfb41e78d0ecfff1843f':'claimed','0xeddf608ef698454af2fb41c1df7b7e5154ff0d46969f895e0f39c7dfe7e6380a':'claimed',
  '0xd7dee2702d63ad89917b6a4da9981c90c4d24f8c2bdfd64c604ecae57d8d0651':'refunded','0x8616bbbbad963e4e65b1366f1d75dfb63f9e9704bbbf91fb01bec70849906cf7':'refunded'};
const EVENT_WINDOW=45000,EVENT_SCAN_BLOCKS=8*EVENT_WINDOW;
const SPENT_CALL='0x7ab71b7a3502d664db0bed48697e7443eff59e6af3c7c97d19d72b6a75aee66d';
async function limited(response,max){
  if(!response.ok||!response.body)throw Error('provider unavailable');
  const reader=response.body.getReader(),parts=[];let size=0;
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>max){await reader.cancel();throw Error('provider response too large');}parts.push(value);}
  const data=new Uint8Array(size);let offset=0;for(const part of parts){data.set(part,offset);offset+=part.length;}
  return JSON.parse(new TextDecoder().decode(data));
}
async function sepoliaRpc(method,params){
  const answer=await limited(await fetch(SEPOLIA_RPC,{method:'POST',headers:{'content-type':'application/json',accept:'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(12000)}),1024*1024);
  if(answer.error||!('result' in answer))throw Error('Sepolia provider error');
  return answer.result;
}
const quantity=v=>{if(typeof v!=='string'||!/^0x(?:0|[1-9a-f][0-9a-f]{0,14})$/.test(v))throw Error('Invalid Sepolia quantity');return Number(BigInt(v));};
function eventRow(row,contract){
  const topics=Array.isArray(row?.topics)?row.topics.map(t=>String(t).toLowerCase()):[],kind=ESCROW_TOPICS[topics[0]],txHash=String(row?.transactionHash??row?.transaction_hash??'').toLowerCase();
  const block=typeof row?.blockNumber==='string'?quantity(row.blockNumber):Number(row?.block_number),data=String(row?.data??'0x').toLowerCase();
  if(!kind||!/^0x[0-9a-f]{64}$/.test(txHash)||!Number.isSafeInteger(block)||block<0||!/^0x(?:[0-9a-f]{2})*$/.test(data)||data.length>2+64*8)return null;
  if(row.address!==undefined&&String(row.address?.hash??row.address).toLowerCase()!==contract)return null;
  return {kind,topic:topics[0],tx_hash:txHash,block_number:block,block_hash:typeof row.blockHash==='string'&&/^0x[0-9a-f]{64}$/.test(row.blockHash)?row.blockHash.toLowerCase():undefined,data};
}
async function sepoliaEvents(url){
  const contract=url.searchParams.get('contract'),fromText=url.searchParams.get('from_block')??'0';
  if(!/^0x[0-9a-f]{40}$/.test(contract||'')||!/^(0|[1-9][0-9]{0,9})$/.test(fromText)||[...url.searchParams.keys()].some(k=>!['contract','from_block'].includes(k)))return reply(400,{error:'invalid Sepolia escrow'});
  const [chain,tipHex]=await Promise.all([sepoliaRpc('eth_chainId',[]),sepoliaRpc('eth_blockNumber',[])]);
  if(chain!=='0xaa36a7')throw Error('Wrong Ethereum network');
  const tip=quantity(tipHex);
  const [spentRaw,code]=await Promise.all([sepoliaRpc('eth_call',[{to:contract,data:SPENT_CALL},'latest']),sepoliaRpc('eth_getCode',[contract,'latest'])]);
  if(typeof code!=='string'||code==='0x'||!/^0x[0-9a-f]{64}$/.test(spentRaw||''))return reply(200,{chain_id:11155111,contract,tip,deployed:false,spent:false,events:[]});
  const spent=BigInt(spentRaw)!==0n,scannedFrom=Math.max(Number(fromText),tip-EVENT_SCAN_BLOCKS+1,0);let rows,source='rpc';
  try{
    // Public RPC providers cap an eth_getLogs range (publicnode: 50000 blocks), so scan in bounded windows and never further
    // back than EVENT_SCAN_BLOCKS from the tip. A deployment block from the caller narrows the scan.
    rows=[];
    for(let a=scannedFrom;a<=tip;a+=EVENT_WINDOW){
      const part=await sepoliaRpc('eth_getLogs',[{address:contract,fromBlock:'0x'+a.toString(16),toBlock:'0x'+Math.min(a+EVENT_WINDOW-1,tip).toString(16),topics:[Object.keys(ESCROW_TOPICS)]}]);
      if(!Array.isArray(part))throw Error('bad logs');
      rows.push(...part);if(rows.length>50)throw Error('bad logs');
    }
  }catch{
    source='blockscout';
    const page=await limited(await fetch(SEPOLIA_BLOCKSCOUT+'/addresses/'+contract+'/logs',{headers:{accept:'application/json'},signal:AbortSignal.timeout(12000)}),1024*1024);
    rows=Array.isArray(page?.items)?page.items.slice(0,50):[];
  }
  const events=[];
  for(const row of rows){
    const item=eventRow(row,contract);if(!item||item.block_number<Number(fromText))continue;
    if(source==='rpc'){
      // The receipt must agree: same block, success status, and the log is really in it.
      const receipt=await sepoliaRpc('eth_getTransactionReceipt',[item.tx_hash]);
      if(receipt?.status!=='0x1'||String(receipt.blockHash).toLowerCase()!==item.block_hash||quantity(receipt.blockNumber)!==item.block_number||!receipt.logs?.some(l=>String(l.address).toLowerCase()===contract&&String(l.topics?.[0]).toLowerCase()===item.topic&&String(l.data).toLowerCase()===item.data))throw Error('Sepolia receipt disagrees with the event');
    }
    events.push({...item,confirmations:tip>=item.block_number?tip-item.block_number+1:0});
  }
  return reply(200,{chain_id:11155111,contract,tip,deployed:true,spent,source,scanned_from:source==='rpc'?scannedFrom:null,events});
}

// A read-only window onto Sepolia for the page's own verifiers. Fixed methods with strict parameter shapes; nothing that
// writes, signs or reveals the provider's account state.
const RPC_ADDRESS=/^0x[0-9a-f]{40}$/,RPC_HASH=/^0x[0-9a-f]{64}$/,RPC_QUANTITY=/^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/;
const RPC_BLOCK=v=>v==='latest'||RPC_QUANTITY.test(v);
const RPC_METHODS={
  eth_chainId:p=>p.length===0,
  eth_blockNumber:p=>p.length===0,
  eth_getBlockByNumber:p=>p.length===2&&RPC_BLOCK(p[0])&&p[1]===false,
  eth_getTransactionByHash:p=>p.length===1&&RPC_HASH.test(p[0]),
  eth_getTransactionReceipt:p=>p.length===1&&RPC_HASH.test(p[0]),
  eth_getCode:p=>p.length===2&&RPC_ADDRESS.test(p[0])&&RPC_BLOCK(p[1]),
  eth_getBalance:p=>p.length===2&&RPC_ADDRESS.test(p[0])&&RPC_BLOCK(p[1]),
  eth_call:p=>p.length===2&&p[0]&&typeof p[0]==='object'&&keys(p[0])==='data,to'&&RPC_ADDRESS.test(p[0].to)&&p[0].data==='0x7ab71b7a'&&RPC_BLOCK(p[1])
};
async function sepoliaProxy(req){
  let data;try{data=await body(req);}catch{return reply(400,{error:'invalid request'});}
  if(keys(data)!=='method,params'||typeof data.method!=='string'||!Object.hasOwn(RPC_METHODS,data.method)||!Array.isArray(data.params)||!RPC_METHODS[data.method](data.params))return reply(400,{error:'method or parameters not allowed'});
  const result=await sepoliaRpc(data.method,data.params);
  if(data.method==='eth_chainId'&&result!=='0xaa36a7')throw Error('Wrong Ethereum network');
  return reply(200,{result});
}

const CARDANO_HTLC='addr_test1wqmp4fms223lnjljntag8vk9frl0l8pygsp2pt75tv2llsgmwwmyv';
async function cardanoSpend(url){
  const ref=url.searchParams.get('outref');
  if(typeof ref!=='string'||!/^[0-9a-f]{64}#(0|[1-9][0-9]{0,9})$/.test(ref)||url.searchParams.size!==1||Number(ref.split('#')[1])>0xffffffff)return reply(400,{error:'invalid Cardano output'});
  const [txid]=ref.split('#');
  const [net,rows]=await Promise.all([cardanoNetwork(),cardanoRead('/utxo_info',{_utxo_refs:[ref],_extended:true})]);
  if(!Array.isArray(rows)||rows.length!==1||rows[0]?.tx_hash!==txid||`${rows[0].tx_hash}#${rows[0].tx_index}`!==ref||typeof rows[0].is_spent!=='boolean')throw Error('Cardano provider returned a different output');
  const row=rows[0];
  if(row.address!==CARDANO_HTLC)return reply(400,{error:'not an HTLC output'});
  if(!row.is_spent)return reply(200,{...net,outref:ref,spent:false});
  const pending=extra=>reply(200,{...net,outref:ref,spent:true,indexed:false,...extra});
  const created=Number.isSafeInteger(row.block_height)?row.block_height:0;
  const listed=await cardanoRead('/address_txs',{_addresses:[CARDANO_HTLC],_after_block_height:Math.max(0,created-1)});
  const candidates=Array.isArray(listed)?[...new Set(listed.map(r=>r?.tx_hash).filter(h=>typeof h==='string'&&hex.test(h)&&h!==txid))].slice(0,200):[];
  if(!candidates.length)return pending({});
  const info=await cardanoRead('/tx_info',{_tx_hashes:candidates,_inputs:true,_metadata:false,_assets:false,_withdrawals:false,_certs:false,_scripts:false,_bytecode:false});
  if(!Array.isArray(info)||new Set(info.map(i=>i?.tx_hash)).size!==candidates.length||!info.every(i=>candidates.includes(i?.tx_hash)))return pending({});
  const spender=info.find(i=>Array.isArray(i.inputs)&&i.inputs.some(x=>`${x?.tx_hash}#${x?.tx_index}`===ref));
  if(!spender)return pending({});
  const cbor=await cardanoRead('/tx_cbor',{_tx_hashes:[spender.tx_hash]});
  if(Array.isArray(cbor)&&cbor.length===0)return pending({spender:spender.tx_hash});
  if(!Array.isArray(cbor)||cbor.length!==1||cbor[0]?.tx_hash!==spender.tx_hash||cbor[0].valid_contract!==true||typeof cbor[0].cbor!=='string'||cbor[0].cbor.length>200000||!/^(?:[0-9a-f]{2})+$/.test(cbor[0].cbor))throw Error('Cardano provider returned an invalid spend');
  const height=spender.block_height;
  return reply(200,{...net,outref:ref,spent:true,indexed:true,spender:spender.tx_hash,confirmations:Number.isSafeInteger(height)&&net.block>=height?net.block-height+1:0,cbor:cbor[0].cbor});
}
async function api(req,env){
  const url=new URL(req.url),t=now(),db=env.DB,origin=req.headers.get('origin');
  if(origin&&origin!==url.origin)return reply(403,{error:'cross-origin request denied'});
  if(!await quota(req,env,t))return reply(429,{error:'request limit reached'});
  // Bound retention without a separate paid service. Messages survive offer
  // expiry for seven days, then up to 100 expired offers are pruned per pass.
  if(Math.random()<0.01){
    await db.batch([
      db.prepare('DELETE FROM quotas WHERE window<?').bind(Math.floor(t/60)-10),
      db.prepare('DELETE FROM messages WHERE offer_id IN (SELECT id FROM offers WHERE expires<? LIMIT 100)').bind(t-604800),
      db.prepare('DELETE FROM offers WHERE expires<? AND NOT EXISTS (SELECT 1 FROM messages WHERE offer_id=offers.id) AND id IN (SELECT id FROM offers WHERE expires<? LIMIT 100)').bind(t-604800,t-604800),
      db.prepare('DELETE FROM swap_packets WHERE session_id IN (SELECT id FROM swap_sessions WHERE expires<? LIMIT 100)').bind(t-604800),
      db.prepare('DELETE FROM swap_sessions WHERE expires<? AND NOT EXISTS (SELECT 1 FROM swap_packets WHERE session_id=swap_sessions.id) AND id IN (SELECT id FROM swap_sessions WHERE expires<? LIMIT 100)').bind(t-604800,t-604800)
    ]);
  }
  const match=url.pathname.match(/^\/offers\/([0-9a-f]{64})(?:\/(reserve|messages|close|identity|session))?$/);
  const sessionMatch=url.pathname.match(/^\/swap-sessions\/([0-9a-f]{64})(?:\/(packets))?$/);
  if(req.method==='GET'&&url.pathname==='/health')return reply(200,{status:'ok'});
  if(req.method==='GET'&&url.pathname==='/bitcoin-testnet4/escrow'){
    try{return await bitcoinEscrow(url);}catch{console.error('Bitcoin testnet provider unavailable or inconsistent');return reply(502,{error:'Bitcoin testnet service unavailable or inconsistent'});}
  }
  if(req.method==='GET'&&url.pathname==='/bitcoin-testnet4/utxos'){
    try{return await bitcoinUtxos(url);}catch{console.error('Bitcoin testnet provider unavailable or inconsistent');return reply(502,{error:'Bitcoin testnet service unavailable or inconsistent'});}
  }
  if(req.method==='POST'&&url.pathname==='/bitcoin-testnet4/broadcast'&&url.searchParams.size===0){
    try{return await bitcoinBroadcast(req);}catch{console.error('Bitcoin testnet broadcast unavailable or inconsistent');return reply(502,{error:'Bitcoin testnet service unavailable or inconsistent'});}
  }
  if(req.method==='GET'&&url.pathname==='/bitcoin-testnet4/head'){
    try{return await bitcoinHead(url);}catch{console.error('Bitcoin testnet provider unavailable or inconsistent');return reply(502,{error:'Bitcoin testnet service unavailable or inconsistent'});}
  }
  if(req.method==='GET'&&url.pathname==='/bitcoin-testnet4/spend'){
    try{return await bitcoinSpend(url);}catch{console.error('Bitcoin testnet provider unavailable or inconsistent');return reply(502,{error:'Bitcoin testnet service unavailable or inconsistent'});}
  }
  if(req.method==='GET'&&url.pathname==='/sepolia/escrow-events'){
    try{return await sepoliaEvents(url);}catch{console.error('Sepolia provider unavailable or inconsistent');return reply(502,{error:'Sepolia service unavailable or inconsistent'});}
  }
  if(req.method==='POST'&&url.pathname==='/sepolia/rpc'&&url.searchParams.size===0){
    try{return await sepoliaProxy(req);}catch{console.error('Sepolia provider unavailable or inconsistent');return reply(502,{error:'Sepolia service unavailable or inconsistent'});}
  }
  if(req.method==='GET'&&url.pathname==='/cardano-preview/spend'){
    try{return await cardanoSpend(url);}catch{console.error('Cardano preview provider unavailable or inconsistent');return reply(502,{error:'Cardano preview service unavailable or inconsistent'});}
  }
  if(req.method==='GET'&&url.pathname==='/cardano-preview/escrow'){
    try{return await cardanoEscrow(url);}catch{console.error('Cardano preview provider unavailable or inconsistent');return reply(502,{error:'Cardano preview service unavailable or inconsistent'});}
  }
  if(req.method==='GET'&&url.pathname==='/cardano-preview/params'&&url.searchParams.size===0){
    try{return reply(200,await cardanoParams());}catch{console.error('Cardano preview provider unavailable or inconsistent');return reply(502,{error:'Cardano preview service unavailable or inconsistent'});}
  }
  if(req.method==='GET'&&url.pathname==='/cardano-preview/utxos'){
    try{return await cardanoUtxos(url);}catch{console.error('Cardano preview provider unavailable or inconsistent');return reply(502,{error:'Cardano preview service unavailable or inconsistent'});}
  }
  if(req.method==='POST'&&url.pathname==='/offers'){
    const d=await body(req),k=keys(d);
    if(!['expires,give,receive,visibility','expires,give,ownerPublicKey,receive,visibility'].includes(k)||('ownerPublicKey'in d&&(typeof d.ownerPublicKey!=='string'||!/^04[0-9a-f]{128}$/.test(d.ownerPublicKey)))||!asset(d.give)||!asset(d.receive)||!['private','public'].includes(d.visibility)||!Number.isSafeInteger(d.expires)||d.expires<=t+60||d.expires>t+604800)return reply(400,{error:'invalid offer'});
    const id=random(),owner=random(),value=JSON.stringify({give:d.give,receive:d.receive,...(d.ownerPublicKey?{ownerPublicKey:d.ownerPublicKey}:{})});
    await db.prepare('INSERT INTO offers(id,owner_hash,public,offer,expires) VALUES(?,?,?,?,?)').bind(id,await digest(owner),d.visibility==='public'?1:0,value,d.expires).run();
    return reply(201,{id,ownerToken:owner});
  }
  if(req.method==='GET'&&url.pathname==='/offers'){
    const rows=await db.prepare('SELECT * FROM offers WHERE public=1 AND closed=0 AND expires>? ORDER BY rowid DESC LIMIT 100').bind(t).all();
    return reply(200,{offers:rows.results.map(x=>presentation(x,t))});
  }
  if(sessionMatch){const auth=req.headers.get('authorization')||'',secret=auth.startsWith('Bearer ')?auth.slice(7):'',hash=hex.test(secret)?await digest(secret):null;
    return sessionApi(req,db,sessionMatch[1],sessionMatch[2],hash,t,url);}
  if(!match)return reply(404,{error:'not found'});
  const [,id,op]=match;let row=await get(db,id);if(!row)return reply(404,{error:'not found'});
  if(req.method==='GET'&&!op)return reply(200,presentation(row,t));
  if(req.method==='POST'&&op==='reserve'){
    const secret=random(),reservationId=random(),expiry=Math.min(t+86400,row.expires);
    const result=await db.prepare('UPDATE offers SET reservation_hash=?,reservation_id=?,reservation_expires=?,reservation_identity=NULL WHERE id=? AND closed=0 AND expires>? AND (reservation_expires IS NULL OR reservation_expires<=?) RETURNING id').bind(await digest(secret),reservationId,expiry,id,t,t).first();
    if(!result)return reply(409,{error:row.closed||row.expires<=t?'offer unavailable':'already reserved'});
    return reply(201,{reservationToken:secret,reservationId,expires:expiry});
  }
  const auth=req.headers.get('authorization')||'',secret=auth.startsWith('Bearer ')?auth.slice(7):'',hash=hex.test(secret)?await digest(secret):null;
  const who=participant(row,hash,t);if(!who)return reply(401,{error:'unauthorized'});
  if(req.method==='POST'&&op==='session'&&url.searchParams.size===0){
    if(who!=='owner')return reply(403,{error:'owner only'});
    const data=await body(req);
    if(keys(data)!=='reservationId'||typeof data.reservationId!=='string'||!hex.test(data.reservationId))return reply(400,{error:'invalid reservation'});
    const sid=await sessionId(id,data.reservationId),existing=await db.prepare('SELECT * FROM swap_sessions WHERE id=?').bind(sid).first();
    if(existing)return sessionParticipant(existing,hash,t)==='owner'?reply(200,sessionPresentation(existing)):reply(401,{error:'unauthorized'});
    if(row.closed||row.expires<=t||row.reservation_id!==data.reservationId||row.reservation_expires<=t||!JSON.parse(row.offer).ownerPublicKey)return reply(409,{error:'active offer and reservation required'});
    const snapshot=JSON.stringify({...presentation(row,t)});
    const changes=await db.batch([
      db.prepare(`INSERT OR IGNORE INTO swap_sessions(id,offer_id,reservation_id,owner_hash,taker_hash,offer_snapshot,created,expires)
        SELECT ?,id,reservation_id,owner_hash,reservation_hash,?,?,? FROM offers
        WHERE id=? AND owner_hash=? AND closed=0 AND expires>? AND reservation_id=? AND reservation_expires>?`)
        .bind(sid,snapshot,t,t+SWAP_SESSION_LIFETIME,id,hash,t,data.reservationId,t),
      db.prepare(`UPDATE offers SET closed=1 WHERE id=? AND owner_hash=? AND EXISTS
        (SELECT 1 FROM swap_sessions WHERE id=? AND offer_id=offers.id AND reservation_id=?)`).bind(id,hash,sid,data.reservationId)
    ]);
    const created=await db.prepare('SELECT * FROM swap_sessions WHERE id=?').bind(sid).first();
    const inserted=Number(changes?.[0]?.meta?.changes??changes?.[0]?.changes??0)>0;
    return created&&sessionParticipant(created,hash,t)==='owner'?reply(inserted?201:200,sessionPresentation(created)):reply(409,{error:'offer or reservation changed'});
  }
  if(req.method==='POST'&&op==='close'){
    if(who!=='owner')return reply(403,{error:'owner only'});
    await db.prepare('UPDATE offers SET closed=1 WHERE id=? AND owner_hash=?').bind(id,hash).run();return reply(200,{closed:true});
  }
  if(op==='identity'&&req.method==='POST'){
    if(row.expires<=t||row.closed)return reply(409,{error:'offer unavailable'});
    const data=await body(req);
    if(keys(data)!==(who==='owner'?'identity':'identity,reservationId')||who==='taker'&&(typeof data.reservationId!=='string'||!hex.test(data.reservationId)))return reply(400,{error:'invalid identity request'});
    const problem=await identityError(data.identity,row,who,data.reservationId);
    if(problem)return reply(400,{error:problem});
    const result=who==='owner'
      ?await db.prepare('UPDATE offers SET owner_identity=? WHERE id=? AND owner_hash=? AND owner_identity IS NULL RETURNING id').bind(data.identity,id,hash).first()
      :await db.prepare('UPDATE offers SET reservation_identity=? WHERE id=? AND reservation_hash=? AND reservation_id=? AND reservation_expires>? AND reservation_identity IS NULL RETURNING id').bind(data.identity,id,hash,data.reservationId,t).first();
    if(!result){row=await get(db,id);if(!row||participant(row,hash,now())!==who)return reply(401,{error:'unauthorized'});return reply(409,{error:who==='taker'&&row.reservation_id!==data.reservationId?'reservation changed':'identity already published'});}
    return reply(201,{published:true});
  }
  if(op==='messages'&&req.method==='POST'){
    if(row.expires<=t)return reply(409,{error:'offer unavailable'});
    const data=await body(req),inbox=!!JSON.parse(row.offer).ownerPublicKey;
    if(keys(data)!==(inbox?'ciphertext,reservationId':'ciphertext')||typeof data.ciphertext!=='string'||!/^[A-Za-z0-9+/]+={0,2}$/.test(data.ciphertext)||data.ciphertext.length>8192||inbox&&(typeof data.reservationId!=='string'||!hex.test(data.reservationId)))return reply(400,{error:'invalid ciphertext or reservation'});
    if(inbox&&(!row.reservation_id||row.reservation_expires<=t||row.reservation_id!==data.reservationId))return reply(409,{error:'reservation changed'});
    const session=row.reservation_id;
    const result=await db.prepare(`INSERT INTO messages(offer_id,reservation_id,sender,payload,created)
      SELECT id,reservation_id,?,?,? FROM offers WHERE id=? AND expires>? AND reservation_id IS ?
      AND (owner_hash=? OR (reservation_hash=? AND reservation_expires>?))
      AND (SELECT count(*) FROM messages WHERE offer_id=? AND reservation_id IS ?)<100 RETURNING id`)
      .bind(who,data.ciphertext,t,id,t,session,hash,hash,t,id,session).first();
    if(!result){row=await get(db,id);if(!row||participant(row,hash,now())!==who)return reply(401,{error:'unauthorized'});if(row.reservation_id!==session||(inbox&&row.reservation_expires<=now()))return reply(409,{error:'reservation changed'});if(row.expires<=now())return reply(409,{error:'offer unavailable'});return reply(429,{error:'message limit reached'});}
    return reply(201,{id:result.id});
  }
  if(op==='messages'&&req.method==='GET'){
    const after=Number(url.searchParams.get('after')??'0');if(!Number.isSafeInteger(after)||after<0)return reply(400,{error:'invalid cursor'});
    // Recheck authorization and session in the query itself to avoid a race with replacement.
    const rows=await db.prepare(`SELECT m.id,m.sender,m.payload AS ciphertext,m.created FROM messages m JOIN offers o ON o.id=m.offer_id
      WHERE o.id=? AND m.reservation_id IS o.reservation_id AND m.id>? AND (o.owner_hash=? OR (o.reservation_hash=? AND o.reservation_expires>?)) ORDER BY m.id LIMIT 100`).bind(id,after,hash,hash,t).all();
    return reply(200,{messages:rows.results});
  }
  return reply(404,{error:'not found'});
}
export default {async fetch(req,env){
  try{
    const url=new URL(req.url);
    if(url.pathname==='/health'||url.pathname==='/offers'||url.pathname.startsWith('/offers/')||url.pathname.startsWith('/swap-sessions/')||url.pathname==='/bitcoin-testnet4/escrow'||url.pathname==='/bitcoin-testnet4/utxos'||url.pathname==='/bitcoin-testnet4/broadcast'||url.pathname==='/bitcoin-testnet4/spend'||url.pathname==='/bitcoin-testnet4/head'||url.pathname==='/sepolia/escrow-events'||url.pathname==='/sepolia/rpc'||url.pathname==='/cardano-preview/spend'||url.pathname==='/cardano-preview/escrow'||url.pathname==='/cardano-preview/params'||url.pathname==='/cardano-preview/utxos')return await api(req,env);
    if(req.method!=='GET'&&req.method!=='HEAD')return reply(404,{error:'not found'});
    // The hosted page is a file in the manifest (swap-ui/hosted.html, built by scripts/build_client_manifest.mjs), not a rewrite
    // of index.html at the edge, so the served bytes are reproducible. Only files in the manifest are served.
    const root=url.pathname==='/'||url.pathname==='/index.html';
    const path=root?'/'+HOSTED_ROOT:url.pathname;
    if(!SERVED.has(path.slice(1)))return reply(404,{error:'not found'});
    const result=await env.ASSETS.fetch(root?new Request(new URL(path,url),req):req),h=new Headers(result.headers);
    h.set('cache-control','no-store');h.set('x-content-type-options','nosniff');h.set('referrer-policy','no-referrer');
    h.set('content-security-policy',HOSTED_CSP);
    return new Response(result.body,{status:result.status,headers:h});
  }catch(error){if(error instanceof SyntaxError||error instanceof TypeError&&error.message.includes('encoded data'))return reply(400,{error:'invalid request body'});console.error('offer relay request failed');return reply(500,{error:'internal error'});}
}};
