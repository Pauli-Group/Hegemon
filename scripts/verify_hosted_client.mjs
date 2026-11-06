#!/usr/bin/env node
/* Compare a deployed swap page to what this checkout would serve.
 *
 *   node scripts/verify_hosted_client.mjs --base https://hegemon-swap-testnet.willdoyle422.workers.dev
 *   node scripts/verify_hosted_client.mjs --base http://127.0.0.1:8787 --profile local
 *   add --json for a machine-readable report. Exit status 1 if any check fails, 2 on usage errors.
 *
 * The expected manifest is rebuilt from the repository files, not read from the committed manifest, so a stale or edited
 * committed manifest is reported too. Run it from a checkout you verified (a signed tag or a commit hash you compared
 * through another channel) and, ideally, from a machine other than the one serving the page.
 *
 * What it can and cannot prove. It proves that, at the moment of the request, every file in the manifest, the page root,
 * the content security policy and the timing file are byte-for-byte what the repository builds, and that the page references
 * nothing outside the manifest. It cannot prove what a different client (another country, another time, a targeted user)
 * is served, and it cannot protect a user who loads the page without running it: their browser trusts whatever code the
 * first load returned. For real value, run the page from a verified checkout (`node swap-service/server.ts`).
 * See .agent/SWAP_RELAY_IDENTITY_EXECPLAN.md. */
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync,statSync} from 'node:fs';
import {join,resolve,relative,sep,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {build,REPO} from './build_client_manifest.mjs';

const sha256Hex=data=>createHash('sha256').update(data).digest('hex');
const API_PREFIXES=['/offers','/health','/bitcoin-testnet4/','/sepolia/','/cardano-preview/'];
const MAX_BYTES=8*1024*1024;

export const LIMITATION=[
 'This check shows what the server returned to this request. It cannot show what other users are served, and it does not protect',
 'anyone who loads the page without running a check: their browser runs whatever the first load returned. For real value, run the',
 'page from a verified checkout (node swap-service/server.ts) instead of loading it from a hosted address.'
].join(' ');

function listIgnored(repo,served){
 // Files that live in swap-ui/ but are deliberately not served (tests, fixtures, helpers), to probe that they are not.
 const ui=join(repo,'swap-ui'),out=[];
 const walk=dir=>{for(const entry of readdirSync(dir).sort()){
  const full=join(dir,entry),path=relative(ui,full).split(sep).join('/');
  if(statSync(full).isDirectory())walk(full);else if(!served.has(path)&&path!=='.assetsignore')out.push(path);
 }};
 walk(ui);
 return [...new Set([...out,'.assetsignore','server.ts','worker.mjs','schema.sql','wrangler.jsonc','package.json'])];
}
function references(path,text){
 const base=path.includes('/')?'/'+path.slice(0,path.lastIndexOf('/')+1):'/';
 const found=new Set(),add=value=>{
  if(value===''||value.startsWith('#'))return;
  if(/^[a-z][a-z0-9+.-]*:/i.test(value)||value.startsWith('//'))return found.add('EXTERNAL '+value);
  const url=new URL(value,'http://x'+base);found.add(url.pathname);
 };
 if(path.endsWith('.html')){
  for(const m of text.matchAll(/\b(?:src|href|action)="([^"]*)"/g))add(m[1]);
 }else{
  for(const m of text.matchAll(/\bfrom\s*['"](\.{0,2}\/[^'"]+)['"]/g))add(m[1]);
  for(const m of text.matchAll(/\bimport\(\s*['"](\.{0,2}\/[^'"]+)['"]\s*\)/g))add(m[1]);
  for(const m of text.matchAll(/\bfetch\(\s*['"](\/[^'"?]*)/g))add(m[1]);
 }
 return [...found];
}
const apiRoute=path=>API_PREFIXES.some(p=>path===p||path.startsWith(p.endsWith('/')?p:p+'/')||path===p.replace(/\/$/,''));

/** Verify `fetcher(path)` -> `{status, headers:{name:value}, bytes:Buffer}` against the repository. Returns `{ok, checks}`. */
export async function verifyClient({fetcher,profile='hosted',repo=REPO}){
 if(!['hosted','local'].includes(profile))throw Error('profile must be hosted or local');
 const checks=[],check=(name,ok,detail='')=>checks.push({name,ok:!!ok,detail});
 const {outputs,manifest}=build({repo}),expectedManifestText=outputs['swap-ui/client-manifest.json'];
 // 1. The committed generated files are what a fresh build produces.
 for(const [path,text] of Object.entries(outputs)){
  let onDisk='';try{onDisk=readFileSync(join(repo,path),'utf8');}catch{}
  check('repository: '+path+' is fresh',onDisk===text,onDisk===text?'':'differs from a fresh build; run scripts/build_client_manifest.mjs');
 }
 // 2. Every manifest file is served with exactly the expected bytes.
 const root=manifest.roots[profile],expected=new Map(),served=new Set(Object.keys(manifest.files));
 for(const [path,info] of Object.entries(manifest.files))expected.set(path,info.sha256);
 // In the hosted profile `/index.html` is the hosted root; in the local profile `/hosted.html` is just another file.
 if(profile==='hosted')expected.set('index.html',manifest.files['hosted.html'].sha256);
 expected.set('client-manifest.json',sha256Hex(expectedManifestText));
 const bodies=new Map(),headersByPath=new Map();
 const get=async path=>{
  try{const r=await fetcher(path);if(r.bytes.length>MAX_BYTES)throw Error('response too large');return r;}
  catch(e){return {status:0,headers:{},bytes:Buffer.alloc(0),error:e.message};}
 };
 for(const [path,hash] of [...expected].sort()){
  const r=await get('/'+path);bodies.set(path,r.bytes);headersByPath.set(path,r.headers);
  const got=r.status===200?sha256Hex(r.bytes):'';
  check('served file: /'+path,r.status===200&&got===hash,r.status!==200?'status '+r.status+(r.error?' ('+r.error+')':''):got===hash?'':'sha256 '+got+' differs from expected '+hash);
 }
 const rootResponse=await get('/'),rootHash=manifest.files[root].sha256;
 bodies.set('/',rootResponse.bytes);headersByPath.set('/',rootResponse.headers);
 check('served root: / is '+root,rootResponse.status===200&&sha256Hex(rootResponse.bytes)===rootHash,rootResponse.status!==200?'status '+rootResponse.status:'');
 // 3. Headers.
 const wantCsp=manifest.csp[profile];
 for(const path of ['/',...['app.js','style.css','client-manifest.json'].map(p=>'/'+p)]){
  const key=path==='/'?'/':path.slice(1),h=headersByPath.get(key)||{};
  check('header: content-security-policy on '+path,h['content-security-policy']===wantCsp,h['content-security-policy']===wantCsp?'':'got '+JSON.stringify(h['content-security-policy']));
  for(const [name,value] of Object.entries(manifest.headers))check('header: '+name+' on '+path,h[name]===value,h[name]===value?'':'got '+JSON.stringify(h[name]));
 }
 // 4. The timing file the page judges deadlines with is the repository's.
 const timing=readFileSync(join(repo,'config','swap','chain-timing.json'));
 const servedTiming=bodies.get('chain-timing.json')||Buffer.alloc(0);
 check('timing: /chain-timing.json equals config/swap/chain-timing.json',sha256Hex(servedTiming)===sha256Hex(timing));
 // 5. The page's own structure: one inline script (the import map, allowed by hash), no handlers, no inline style, no external origin.
 const html=(bodies.get('/')||Buffer.alloc(0)).toString('utf8');
 const inline=[...html.matchAll(/<script(?![^>]*\ssrc=)([^>]*)>([\s\S]*?)<\/script>/g)];
 const importMaps=inline.filter(m=>/type="importmap"/.test(m[1]));
 check('page: exactly one inline script and it is the import map',inline.length===1&&importMaps.length===1,'inline scripts: '+inline.length);
 check('page: import map hash matches the manifest and the CSP',importMaps.length===1&&('sha256-'+createHash('sha256').update(importMaps[0][2]).digest('base64'))===manifest.import_map.source&&wantCsp.includes("'"+manifest.import_map.source+"'"));
 check('page: no event-handler attributes or inline styles',!/\son[a-z]+\s*=|\sstyle\s*=|<style[\s>]/i.test(html));
 // 6. Everything the page references is in the manifest or is an API route.
 const unreferenced=[];
 for(const [path,data] of [['/',bodies.get('/')],...[...expected.keys()].filter(p=>/\.(mjs|js)$/.test(p)).map(p=>['/'+p,bodies.get(p)])]){
  if(!data)continue;
  const file=path==='/'?'index.html':path.slice(1);
  for(const ref of references(file,data.toString('utf8'))){
   if(ref.startsWith('EXTERNAL '))unreferenced.push(path+' -> '+ref);
   else if(!(served.has(ref.slice(1))||ref==='/'||apiRoute(ref)||ref==='/client-manifest.json'))unreferenced.push(path+' -> '+ref);
  }
 }
 check('references: nothing outside the manifest, no external origins',unreferenced.length===0,unreferenced.join('; '));
 // 7. Files that must not be served are not.
 for(const path of listIgnored(repo,new Set([...served,'client-manifest.json']))){
  const r=await get('/'+path);
  check('not served: /'+path,r.status!==200,r.status===200?'unexpectedly served':'');
 }
 return {ok:checks.every(c=>c.ok),checks,profile,files:expected.size};
}

async function main(){
 const args=process.argv.slice(2),option=name=>{const i=args.indexOf(name);return i<0?undefined:args[i+1];};
 const base=option('--base'),profile=option('--profile')||'hosted',repo=resolve(option('--repo')||REPO);
 if(!base||!/^https?:\/\//.test(base)||!['hosted','local'].includes(profile)){console.error('usage: verify_hosted_client.mjs --base URL [--profile hosted|local] [--repo DIR] [--json]');process.exit(2);}
 const fetcher=async path=>{
  const response=await fetch(new URL(path,base),{redirect:'manual',cache:'no-store',signal:AbortSignal.timeout(20000)});
  return {status:response.status,headers:Object.fromEntries(response.headers),bytes:Buffer.from(await response.arrayBuffer())};
 };
 const report=await verifyClient({fetcher,profile,repo});
 if(args.includes('--json'))console.log(JSON.stringify({base,...report,limitation:LIMITATION},null,1));
 else{
  for(const c of report.checks)if(!c.ok||args.includes('--verbose'))console.log((c.ok?'ok   ':'FAIL ')+c.name+(c.detail?' — '+c.detail:''));
  const failed=report.checks.filter(c=>!c.ok).length;
  console.log((failed?'FAILED':'OK')+': '+report.checks.length+' checks, '+failed+' failed ('+report.files+' files, profile '+profile+')\n'+LIMITATION);
 }
 process.exit(report.ok?0:1);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(e=>{console.error(e.message);process.exit(2);});
