/* Public testnet offer directory. Wallets and swap secrets stay with users. */
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
function presentation(row,t){return {id:row.id,visibility:row.public?'public':'private',...JSON.parse(row.offer),expires:row.expires,closed:!!row.closed,...(row.reservation_id&&row.reservation_expires>t?{reservationId:row.reservation_id}:{})};}
async function get(db,id){return db.prepare('SELECT * FROM offers WHERE id=?').bind(id).first();}
function participant(row,hash,t){if(!hash)return null;if(hash===row.owner_hash)return 'owner';return hash===row.reservation_hash&&row.reservation_expires>t?'taker':null;}
async function quota(req,env,t){
  const ip=req.headers.get('CF-Connecting-IP');
  if(!ip)return false;
  const window=Math.floor(t/60),key=await digest(window+':'+ip),limit=req.method==='GET'?180:40;
  const row=await env.DB.prepare('INSERT INTO quotas(key,window,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1 WHERE count<? RETURNING count').bind(key,window,limit).first();
  return !!row;
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
      db.prepare('DELETE FROM offers WHERE expires<? AND NOT EXISTS (SELECT 1 FROM messages WHERE offer_id=offers.id) AND id IN (SELECT id FROM offers WHERE expires<? LIMIT 100)').bind(t-604800,t-604800)
    ]);
  }
  const match=url.pathname.match(/^\/offers\/([0-9a-f]{64})(?:\/(reserve|messages|close))?$/);
  if(req.method==='GET'&&url.pathname==='/health')return reply(200,{status:'ok'});
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
  if(!match)return reply(404,{error:'not found'});
  const [,id,op]=match;let row=await get(db,id);if(!row)return reply(404,{error:'not found'});
  if(req.method==='GET'&&!op)return reply(200,presentation(row,t));
  if(req.method==='POST'&&op==='reserve'){
    const secret=random(),reservationId=random(),expiry=Math.min(t+86400,row.expires);
    const result=await db.prepare('UPDATE offers SET reservation_hash=?,reservation_id=?,reservation_expires=? WHERE id=? AND closed=0 AND expires>? AND (reservation_expires IS NULL OR reservation_expires<=?) RETURNING id').bind(await digest(secret),reservationId,expiry,id,t,t).first();
    if(!result)return reply(409,{error:row.closed||row.expires<=t?'offer unavailable':'already reserved'});
    return reply(201,{reservationToken:secret,reservationId,expires:expiry});
  }
  const auth=req.headers.get('authorization')||'',secret=auth.startsWith('Bearer ')?auth.slice(7):'',hash=hex.test(secret)?await digest(secret):null;
  const who=participant(row,hash,t);if(!who)return reply(401,{error:'unauthorized'});
  if(req.method==='POST'&&op==='close'){
    if(who!=='owner')return reply(403,{error:'owner only'});
    await db.prepare('UPDATE offers SET closed=1 WHERE id=? AND owner_hash=?').bind(id,hash).run();return reply(200,{closed:true});
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
    if(url.pathname==='/health'||url.pathname==='/offers'||url.pathname.startsWith('/offers/'))return await api(req,env);
    if(req.method!=='GET'&&req.method!=='HEAD')return reply(404,{error:'not found'});
    const result=await env.ASSETS.fetch(req),h=new Headers(result.headers);
    h.set('cache-control','no-store');h.set('x-content-type-options','nosniff');h.set('referrer-policy','no-referrer');
    h.set('content-security-policy',"default-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    let response=new Response(result.body,{status:result.status,headers:h});
    if(url.pathname==='/'||url.pathname==='/index.html'){
      const hidden=['wallet-title','verify-title','companion-title','ethereum-actions-title','bitcoin-title','bitcoin-actions-title','cardano-title','cardano-actions-title','hegemon-title','hegemon-actions-title','action-journal-title','vault-title','watch-title'];
      let rewrite=new HTMLRewriter()
        .on('title',{element(e){e.setInnerContent('Hegemon Swap · Testnet offer preview');}})
        .on('header .eyebrow',{element(e){e.setInnerContent('Hegemon · testnet offer preview');}})
        .on('main > aside',{element(e){e.setInnerContent('Testnet offer preview. Offers and messages do not lock assets or execute swaps. Wallet execution and recovery are still being built.');}})
        .on('#pair-check',{element(e){e.setAttribute('hidden','');}});
      for(const id of hidden)rewrite=rewrite.on(`section[aria-labelledby="${id}"]`,{element(e){e.setAttribute('hidden','');}});
      response=rewrite.transform(response);
    }
    return response;
  }catch(error){if(error instanceof SyntaxError||error instanceof TypeError&&error.message.includes('encoded data'))return reply(400,{error:'invalid request body'});console.error('offer relay request failed');return reply(500,{error:'internal error'});}
}};
