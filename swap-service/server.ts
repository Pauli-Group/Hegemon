/** Local prototype offer relay. It never signs or inspects chain transactions. */
import {createServer, type IncomingMessage, type ServerResponse} from 'node:http';
import {DatabaseSync} from 'node:sqlite';
import {createHash, randomBytes, timingSafeEqual} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {LOCAL_CSP,LOCAL_ROOT,SERVED_FILES} from './cloudflare/client-policy.mjs';
// Served files and the CSP come from the generated manifest policy (scripts/build_client_manifest.mjs), the same list the hosted Worker serves.
const SERVED=new Set(SERVED_FILES);

const db = new DatabaseSync(process.env.SWAP_DB ?? 'swap-offers.sqlite');
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS offers (id TEXT PRIMARY KEY, owner_hash TEXT NOT NULL, public INTEGER NOT NULL, offer TEXT NOT NULL, expires INTEGER NOT NULL, closed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS reservations (offer_id TEXT PRIMARY KEY REFERENCES offers(id), token_hash TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, offer_id TEXT NOT NULL REFERENCES offers(id), sender TEXT NOT NULL, payload TEXT NOT NULL, created INTEGER NOT NULL);`);
const reservationColumns=db.prepare('PRAGMA table_info(reservations)').all() as {name:string}[];
if(!reservationColumns.some(column=>column.name==='reservation_id'))db.exec('ALTER TABLE reservations ADD COLUMN reservation_id TEXT');
// P5 signed identity statements: additive columns only. A new reservation replaces its row, which clears the taker's identity.
if(!reservationColumns.some(column=>column.name==='identity'))db.exec('ALTER TABLE reservations ADD COLUMN identity TEXT');
if(!(db.prepare('PRAGMA table_info(offers)').all() as {name:string}[]).some(column=>column.name==='owner_identity'))db.exec('ALTER TABLE offers ADD COLUMN owner_identity TEXT');
const token=()=>randomBytes(32).toString('hex');
const digest=(s:string)=>createHash('sha256').update(s).digest('hex');
const equals=(a:string,b:string)=>a.length===b.length && timingSafeEqual(Buffer.from(a),Buffer.from(b));
const now=()=>Math.floor(Date.now()/1000);
const chains=new Set(['ethereum','cardano','bitcoin','hegemon']);
const kinds:Record<string,string[]>={ethereum:['eth','erc20','erc721','erc1155'],cardano:['ada','native'],bitcoin:['btc'],hegemon:['hgn']};
type Asset={chain:string,kind:string,id:string,amount:string};
function asset(v:unknown):v is Asset {
    if (!v || typeof v!=='object' || Array.isArray(v)) return false;
    const a=v as Record<string,unknown>;
    if (!(Object.keys(a).sort().join(',')==='amount,chain,id,kind' && typeof a.chain==='string' && chains.has(a.chain) && typeof a.kind==='string' && kinds[a.chain].includes(a.kind) && typeof a.id==='string' && typeof a.amount==='string' && /^[1-9][0-9]{0,77}$/.test(a.amount))) return false;
    if(BigInt(a.amount)>=(1n<<256n)) return false;
    if(['eth','ada','btc','hgn'].includes(a.kind)) return a.id==='';
    if(a.kind==='erc20') return /^0x[0-9a-fA-F]{40}$/.test(a.id);
    if(a.kind==='erc721' || a.kind==='erc1155') {
        const match=a.id.match(/^0x[0-9a-fA-F]{40}:(0|[1-9][0-9]{0,77})$/);
        return !!match && BigInt(match[1])<(1n<<256n) && (a.kind!=='erc721' || a.amount==='1');
    }
    if(a.kind==='native') return /^[0-9a-fA-F]{56}\.(?:[0-9a-fA-F]{2}){0,32}$/.test(a.id) && BigInt(a.amount)<(1n<<63n);
    return false;
}
async function body(req:IncomingMessage):Promise<any> {
    let text='';
    for await (const part of req) {text+=part.toString(); if (Buffer.byteLength(text)>16384) throw new Error('body too large');}
    return JSON.parse(text);
}
function reply(res:ServerResponse,status:number,value:unknown) {
    res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'});
    res.end(JSON.stringify(value));
}
function credentials(req:IncomingMessage) { const value=req.headers.authorization ?? ''; return value.startsWith('Bearer ') ? value.slice(7) : ''; }
function participant(id:string,secret:string):string|null {
    const offer=db.prepare('SELECT owner_hash FROM offers WHERE id=?').get(id) as {owner_hash:string}|undefined;
    if (!offer || !/^[0-9a-f]{64}$/.test(secret)) return null;
    const hash=digest(secret);
    if(equals(hash,offer.owner_hash)) return 'owner';
    const reservation=db.prepare('SELECT token_hash FROM reservations WHERE offer_id=? AND expires>?').get(id,now()) as {token_hash:string}|undefined;
    return reservation && equals(hash,reservation.token_hash) ? 'taker' : null;
}
function getOffer(id:string) {return db.prepare('SELECT id,public,offer,expires,closed,owner_identity FROM offers WHERE id=?').get(id) as {id:string,public:number,offer:string,expires:number,closed:number,owner_identity:string|null}|undefined;}
function present(row:NonNullable<ReturnType<typeof getOffer>>) {
    const active=db.prepare('SELECT reservation_id,identity FROM reservations WHERE offer_id=? AND expires>?').get(row.id,now()) as {reservation_id:string|null,identity:string|null}|undefined;
    return {id:row.id,visibility:row.public?'public':'private',...JSON.parse(row.offer),expires:row.expires,closed:!!row.closed,...(active?.reservation_id?{reservationId:active.reservation_id}:{}),
        ...(row.owner_identity?{ownerIdentity:row.owner_identity}:{}),...(active?.reservation_id&&active.identity?{reservationIdentity:active.identity}:{})};
}
// Signed identity statements (swap-ui/identity.mjs). Structure, size and ids only: the relay never verifies signatures and
// clients do not rely on it to. Mirrors swap-service/cloudflare/worker.mjs.
function identityError(blob:unknown,offer:{id:string,offer:string},role:'owner'|'taker',reservationId:string):string|null {
    if(typeof blob!=='string'||blob.length>8192) return 'invalid identity statement';
    let value:any;try{value=JSON.parse(blob);}catch{return 'invalid identity statement';}
    const st=value?.statement;
    if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='proofs,statement'||!Array.isArray(value.proofs)||value.proofs.length<1||value.proofs.length>4||!value.proofs.every((p:unknown)=>p&&typeof p==='object'&&!Array.isArray(p))||!st||typeof st!=='object'||st.version!==1||st.kind!=='hegemon.swap.identity'||st.role!==role) return 'invalid identity statement';
    if(st.offer!==offer.id||st.reservation!==(role==='owner'?'':reservationId)) return 'identity statement is for a different offer or reservation';
    if(typeof st.inbox!=='string'||!/^[0-9a-f]{64}$/.test(st.inbox)) return 'invalid identity statement';
    const inbox=JSON.parse(offer.offer).ownerPublicKey;
    if(role==='owner'&&(!inbox||st.inbox!==createHash('sha256').update(Buffer.from(inbox,'hex')).digest('hex'))) return 'identity statement names a different inbox key';
    return null;
}

const server=createServer(async (req,res)=>{
    try {
        const url=new URL(req.url ?? '/', 'http://localhost');
        if(req.method==='GET' && (url.pathname==='/' || SERVED.has(url.pathname.slice(1)))) {
            const file=url.pathname==='/'?LOCAL_ROOT:url.pathname.slice(1);
            const type=file.endsWith('.html')?'text/html':file.endsWith('.js')||file.endsWith('.mjs')?'text/javascript':file.endsWith('.json')?'application/json':'text/css';
            const content=readFileSync(new URL('../swap-ui/'+file,import.meta.url));
            res.writeHead(200,{'content-type':type+'; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer','content-security-policy':LOCAL_CSP});
            res.end(content);return;
        }
        const match=url.pathname.match(/^\/offers\/([0-9a-f]{64})(?:\/(reserve|messages|close|identity))?$/);
        if(req.method==='GET' && url.pathname==='/health') return reply(res,200,{status:'ok'});
        if(req.method==='POST' && url.pathname==='/offers') {
            const data=await body(req);
            if(!data || !['expires,give,receive,visibility','expires,give,ownerPublicKey,receive,visibility'].includes(Object.keys(data).sort().join(',')) || ('ownerPublicKey' in data && (typeof data.ownerPublicKey!=='string'||!/^04[0-9a-f]{128}$/.test(data.ownerPublicKey))) || !asset(data.give) || !asset(data.receive) || !['private','public'].includes(data.visibility) || !Number.isSafeInteger(data.expires) || data.expires<=now()+60 || data.expires>now()+604800) return reply(res,400,{error:'invalid offer'});
            const id=token(),owner=token();
            db.prepare('INSERT INTO offers(id,owner_hash,public,offer,expires) VALUES(?,?,?,?,?)').run(id,digest(owner),data.visibility==='public'?1:0,JSON.stringify({give:data.give,receive:data.receive,...(data.ownerPublicKey?{ownerPublicKey:data.ownerPublicKey}:{})}),data.expires);
            return reply(res,201,{id,ownerToken:owner});
        }
        if(req.method==='GET' && url.pathname==='/offers') {
            const rows=db.prepare('SELECT id,public,offer,expires,closed FROM offers WHERE public=1 AND closed=0 AND expires>? ORDER BY rowid DESC LIMIT 100').all(now()) as NonNullable<ReturnType<typeof getOffer>>[];
            return reply(res,200,{offers:rows.map(present)});
        }
        if (!match) return reply(res,404,{error:'not found'});
        const [,id,op]=match;
        const offer=getOffer(id);
        if(!offer) return reply(res,404,{error:'not found'});
        if(req.method==='GET' && !op) return reply(res,200,present(offer));
        if(req.method==='POST' && op==='reserve') {
            if(offer.closed || offer.expires<=now()) return reply(res,409,{error:'offer unavailable'});
            const secret=token(), reservationId=token(), expiry=Math.min(now()+86400,offer.expires);
            db.exec('BEGIN IMMEDIATE');
            try {
                db.prepare('DELETE FROM reservations WHERE offer_id=? AND expires<=?').run(id,now());
                const result=db.prepare('INSERT OR IGNORE INTO reservations(offer_id,token_hash,expires,reservation_id) VALUES(?,?,?,?)').run(id,digest(secret),expiry,reservationId);
                if(result.changes) db.prepare('DELETE FROM messages WHERE offer_id=?').run(id);
                db.exec('COMMIT');
                if(!result.changes) return reply(res,409,{error:'already reserved'});
            } catch(e) {db.exec('ROLLBACK');throw e;}
            return reply(res,201,{reservationToken:secret,reservationId,expires:expiry});
        }
        const who=participant(id,credentials(req));
        if(!who) return reply(res,401,{error:'unauthorized'});
        if(req.method==='POST' && op==='close') {
            if(who!=='owner') return reply(res,403,{error:'owner only'});
            db.prepare('UPDATE offers SET closed=1 WHERE id=?').run(id);
            return reply(res,200,{closed:true});
        }
        if(op==='identity' && req.method==='POST') {
            if(offer.expires<=now()||offer.closed) return reply(res,409,{error:'offer unavailable'});
            const data=await body(req);
            if(!data||Object.keys(data).sort().join(',')!==(who==='owner'?'identity':'identity,reservationId')||(who==='taker'&&(typeof data.reservationId!=='string'||!/^[0-9a-f]{64}$/.test(data.reservationId)))) return reply(res,400,{error:'invalid identity request'});
            const problem=identityError(data.identity,offer,who as 'owner'|'taker',data.reservationId);
            if(problem) return reply(res,400,{error:problem});
            db.exec('BEGIN IMMEDIATE');
            try {
                const current=participant(id,credentials(req));
                if(current!==who){db.exec('ROLLBACK');return reply(res,401,{error:'unauthorized'});}
                const result=who==='owner'
                    ?db.prepare('UPDATE offers SET owner_identity=? WHERE id=? AND owner_identity IS NULL').run(data.identity,id)
                    :db.prepare('UPDATE reservations SET identity=? WHERE offer_id=? AND reservation_id=? AND expires>? AND identity IS NULL').run(data.identity,id,data.reservationId,now());
                if(!result.changes){
                    const active=db.prepare('SELECT reservation_id FROM reservations WHERE offer_id=? AND expires>?').get(id,now()) as {reservation_id:string|null}|undefined;
                    db.exec('ROLLBACK');
                    return reply(res,409,{error:who==='taker'&&active?.reservation_id!==data.reservationId?'reservation changed':'identity already published'});
                }
                db.exec('COMMIT');return reply(res,201,{published:true});
            } catch(e) {db.exec('ROLLBACK');throw e;}
        }
        if(op==='messages' && req.method==='POST') {
            if(offer.expires<=now()) return reply(res,409,{error:'offer unavailable'});
            const data=await body(req);
            const inbox=!!JSON.parse(offer.offer).ownerPublicKey;
            if(!data || Object.keys(data).sort().join(',')!==(inbox?'ciphertext,reservationId':'ciphertext') || typeof data.ciphertext!=='string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(data.ciphertext) || data.ciphertext.length>8192 || inbox&&(typeof data.reservationId!=='string'||!/^[0-9a-f]{64}$/.test(data.reservationId))) return reply(res,400,{error:'invalid ciphertext or reservation'});
            db.exec('BEGIN IMMEDIATE');
            try {
                const current=participant(id,credentials(req));
                if(current!==who){db.exec('ROLLBACK');return reply(res,401,{error:'unauthorized'});}
                if(inbox){const active=db.prepare('SELECT reservation_id FROM reservations WHERE offer_id=? AND expires>?').get(id,now()) as {reservation_id:string|null}|undefined;
                    if(!active||active.reservation_id!==data.reservationId){db.exec('ROLLBACK');return reply(res,409,{error:'reservation changed'});}}
                if(offer.expires<=now()){db.exec('ROLLBACK');return reply(res,409,{error:'offer unavailable'});}
                const count=db.prepare('SELECT count(*) AS n FROM messages WHERE offer_id=?').get(id) as {n:number};
                if(count.n>=100){db.exec('ROLLBACK');return reply(res,429,{error:'message limit reached'});}
                const result=db.prepare('INSERT INTO messages(offer_id,sender,payload,created) VALUES(?,?,?,?)').run(id,who,data.ciphertext,now());
                db.exec('COMMIT');return reply(res,201,{id:Number(result.lastInsertRowid)});
            } catch(e) {db.exec('ROLLBACK');throw e;}
        }
        if(op==='messages' && req.method==='GET') {
            const after=Number(url.searchParams.get('after') ?? '0');
            if(!Number.isSafeInteger(after) || after<0) return reply(res,400,{error:'invalid cursor'});
            const messages=db.prepare('SELECT id,sender,payload AS ciphertext,created FROM messages WHERE offer_id=? AND id>? ORDER BY id LIMIT 100').all(id,after);
            return reply(res,200,{messages});
        }
        return reply(res,404,{error:'not found'});
    } catch(e) {
        if(e instanceof SyntaxError || (e instanceof Error && e.message==='body too large')) return reply(res,400,{error:'invalid request body'});
        console.error('request failed',e);
        return reply(res,500,{error:'internal error'});
    }
});
server.listen(Number(process.env.SWAP_PORT ?? '8787'),process.env.SWAP_HOST ?? '127.0.0.1',()=>console.log('swap offer relay listening'));
process.on('SIGTERM',()=>server.close(()=>{db.close();process.exit(0);}));
