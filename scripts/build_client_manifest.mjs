#!/usr/bin/env node
/* Reproducible integrity artifacts for the swap page. From the files in swap-ui/ this writes, deterministically:
 *
 *   swap-ui/index.html          its import map (integrity of every module) and the stylesheet and entry-script integrity
 *   swap-ui/hosted.html         index.html with the hosted-testnet edits applied (what the Worker serves for / and /index.html)
 *   swap-ui/client-manifest.json  SHA-256 and size of every served file, the CSP for each profile, the import map hash
 *   swap-service/cloudflare/client-policy.mjs  the CSP strings and served-file list the Worker and the local relay use
 *
 *   node scripts/build_client_manifest.mjs            write
 *   node scripts/build_client_manifest.mjs --check    exit 1 if any file differs from a fresh build; writes nothing
 *
 * The hosted page used to be produced at the edge with HTMLRewriter, whose output cannot be reproduced without the Cloudflare
 * runtime. The same edits are applied here instead, each checked to match exactly once, so the served bytes are a file whose
 * hash is in the manifest and there is no rewrite code left to trust. See .agent/SWAP_RELAY_IDENTITY_EXECPLAN.md. */
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,readdirSync,statSync,existsSync} from 'node:fs';
import {dirname,join,relative,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';

const here=dirname(fileURLToPath(import.meta.url));
export const REPO=resolve(here,'..');
const GENERATED=new Set(['hosted.html','client-manifest.json']);
const COMPANION='http://127.0.0.1:8788';

const sha256Hex=data=>createHash('sha256').update(data).digest('hex');
const sri=data=>'sha256-'+createHash('sha256').update(data).digest('base64');

// ---------------------------------------------------------------- which files are served
function ignoreMatcher(text){
 const rules=text.split('\n').map(l=>l.trim()).filter(l=>l&&!l.startsWith('#')).map(rule=>{
  if(rule.endsWith('/')){const dir=rule;return path=>path.startsWith(dir)||path.includes('/'+dir);}
  const pattern=new RegExp('^'+rule.replace(/[.+^${}()|[\]\\]/g,'\\$&').replace(/\*/g,'[^/]*')+'$');
  return rule.includes('/')?path=>pattern.test(path):path=>pattern.test(path.split('/').pop());
 });
 return path=>rules.some(rule=>rule(path));
}
export function servedFiles(ui){
 const ignored=ignoreMatcher(readFileSync(join(ui,'.assetsignore'),'utf8')),out=[];
 const walk=dir=>{for(const entry of readdirSync(dir).sort()){
  const full=join(dir,entry),path=relative(ui,full).split(sep).join('/'),info=statSync(full);
  if(info.isDirectory()){if(!ignored(path+'/'))walk(full);}else if(!ignored(path))out.push(path);
 }};
 walk(ui);
 return out.sort();
}

// ---------------------------------------------------------------- hosted page edits
const HOSTED_TITLE='Hegemon Swap · Testnet offer preview',HOSTED_EYEBROW='Hegemon · testnet offer preview';
const HOSTED_NOTE='Testnet preview. Creating or reserving an offer does not lock funds. Completing a swap still requires manual steps; Hegemon needs a local companion.';
const HOSTED_VAULT='Create a random secret and its public hashlock locally. Export the encrypted backup and protect its separate passphrase. This backup stores the secret only, not wallet keys or the complete swap.';
const REVEAL=['sepolia-section','sepolia-action-section','bitcoin-testnet-section','cardano-preview-section','cardano-wallet-section','bitcoin-wallet-section','observer-section','guided-section'];
const CONCEAL_IDS=['pair-check'];
const CONCEAL_LABELS=['verify-title','ethereum-actions-title','bitcoin-title','bitcoin-actions-title','cardano-title','cardano-actions-title','hegemon-title','hegemon-actions-title','watch-title'];
function once(html,pattern,replace,what){
 const matches=html.match(new RegExp(pattern.source,'g'))||[];
 if(matches.length!==1)throw Error('hosted edit "'+what+'" matched '+matches.length+' times, expected exactly 1');
 return html.replace(pattern,replace);
}
const escapeText=text=>text.replace(/&/g,'&amp;').replace(/</g,'&lt;');
/** Apply the hosted-testnet edits to index.html. Every edit must match exactly once. */
export function renderHosted(html){
 let out=html;
 out=once(out,/<html lang="en">/,'<html lang="en" data-hosted-testnet="">','html attribute');
 out=once(out,/<title>[^<]*<\/title>/,'<title>'+escapeText(HOSTED_TITLE)+'</title>','title');
 out=once(out,/(<header><p class="eyebrow">)[^<]*(<\/p>)/,'$1'+escapeText(HOSTED_EYEBROW)+'$2','header eyebrow');
 out=once(out,/(<aside role="note">)[\s\S]*?(<\/aside>)/,'$1'+escapeText(HOSTED_NOTE)+'$2','note');
 out=once(out,/(<p id="vault-description">)[^<]*(<\/p>)/,'$1'+escapeText(HOSTED_VAULT)+'$2','vault description');
 out=once(out,/(<p id="companion-copy">)[^<]*(<\/p>)/,'$1'+escapeText('Start the local companion on this computer, then enter its pairing code. If your browser asks to access this computer, allow it. Node status does not read a wallet. Offering HGN requires the wallet-status companion and a terminal unlock. The terminal and this page show progress while that wallet syncs. This browser remembers a successful pairing code and reconnects after a refresh. Forget pairing code removes it. The code is not sent to the swap relay. Creating a listing does not lock funds.')+'$2','companion description');
 out=once(out,/<div id="hosted-node-instructions" hidden>/,'<div id="hosted-node-instructions">','hosted node instructions');
 const reveal=id=>{out=once(out,new RegExp('<section id="'+id+'"([^>]*?) hidden>'),'<section id="'+id+'"$1>','reveal '+id);};
 const conceal=(pattern,what)=>{out=once(out,pattern,m=>/\shidden[\s>]/.test(m)?m:m.slice(0,-1)+' hidden>',what);};
 for(const id of REVEAL)reveal(id);
 for(const id of CONCEAL_IDS)conceal(new RegExp('<[a-z]+ id="'+id+'"[^>]*>'),'conceal '+id);
 for(const label of CONCEAL_LABELS)conceal(new RegExp('<section[^>]*aria-labelledby="'+label+'"[^>]*>'),'conceal '+label);
 return out;
}

// ---------------------------------------------------------------- build
function importMap(files,read){
 const integrity={};
 for(const path of files)if(/\.(mjs|js)$/.test(path))integrity['/'+path]=sri(read(path));
 return JSON.stringify({integrity});
}
function withIntegrity(html,map,css,entry){
 let out=html;
 const block='<!--importmap--><script type="importmap">'+map+'</script><!--/importmap-->';
 out=once(out,/<!--importmap-->[\s\S]*?<!--\/importmap-->/,()=>block,'import map block');
 out=once(out,/<link rel="stylesheet" href="\/style\.css"[^>]*>/,'<link rel="stylesheet" href="/style.css" integrity="'+css+'">','stylesheet integrity');
 out=once(out,/<script type="module" src="\/app\.js"[^>]*><\/script>/,'<script type="module" src="/app.js" integrity="'+entry+'"></script>','entry integrity');
 return out;
}
export function cspFor(profile,importMapSource){
 const connect="'self' "+COMPANION;
 return ["default-src 'self'","script-src 'self' '"+importMapSource+"'","style-src 'self'","connect-src "+connect,"object-src 'none'","frame-ancestors 'none'","base-uri 'none'","form-action 'self'"].join('; ');
}
/** Build every generated artifact from the sources under `ui`. Returns `{[repoRelativePath]: text}` and the manifest object. */
export function build({repo=REPO}={}){
 const ui=join(repo,'swap-ui'),files=servedFiles(ui).filter(path=>!GENERATED.has(path));
 const bytes=new Map(),read=path=>{if(!bytes.has(path))bytes.set(path,readFileSync(join(ui,path)));return bytes.get(path);};
 if(!files.includes('index.html'))throw Error('swap-ui/index.html is missing');
 const timing=readFileSync(join(repo,'config','swap','chain-timing.json'));
 if(!Buffer.from(read('chain-timing.json')).equals(timing))throw Error('swap-ui/chain-timing.json differs from config/swap/chain-timing.json');
 const map=importMap(files,read),mapHash=sri(Buffer.from(map));
 const indexHtml=withIntegrity(read('index.html').toString('utf8'),map,sri(read('style.css')),sri(read('app.js')));
 const hostedHtml=renderHosted(indexHtml);
 const text={'index.html':indexHtml,'hosted.html':hostedHtml};
 const all=[...files,'hosted.html'].sort(),entries={};
 for(const path of all){const data=path in text?Buffer.from(text[path]):read(path);entries[path]={sha256:sha256Hex(data),bytes:data.length};}
 const manifest={version:1,generated_by:'scripts/build_client_manifest.mjs',
  roots:{hosted:'hosted.html',local:'index.html'},import_map:{source:mapHash,modules:Object.keys(JSON.parse(map).integrity).length},
  csp:{hosted:cspFor('hosted',mapHash),local:cspFor('local',mapHash)},
  headers:{'x-content-type-options':'nosniff','referrer-policy':'no-referrer','cache-control':'no-store'},
  chain_timing_sha256:sha256Hex(timing),files:entries};
 const policy='// Generated by scripts/build_client_manifest.mjs from swap-ui/. Do not edit; rebuild instead.\n'+
  'export const HOSTED_CSP='+JSON.stringify(manifest.csp.hosted)+';\n'+
  'export const LOCAL_CSP='+JSON.stringify(manifest.csp.local)+';\n'+
  'export const HOSTED_ROOT='+JSON.stringify('hosted.html')+';\nexport const LOCAL_ROOT='+JSON.stringify('index.html')+';\n'+
  'export const SERVED_FILES='+JSON.stringify([...all,'client-manifest.json'].sort(),null,1)+';\n';
 return {outputs:{
  'swap-ui/index.html':text['index.html'],'swap-ui/hosted.html':text['hosted.html'],
  'swap-ui/client-manifest.json':JSON.stringify(manifest,null,1)+'\n','swap-service/cloudflare/client-policy.mjs':policy},manifest};
}
function main(){
 const check=process.argv.includes('--check'),{outputs}=build();
 const stale=Object.entries(outputs).filter(([path,text])=>!existsSync(join(REPO,path))||readFileSync(join(REPO,path),'utf8')!==text).map(([path])=>path);
 if(check){
  if(stale.length){console.error('generated files differ from a fresh build: '+stale.join(', ')+'\nRun: node scripts/build_client_manifest.mjs');process.exit(1);}
  console.log('client manifest and generated files match a fresh build');return;
 }
 for(const [path,text] of Object.entries(outputs))writeFileSync(join(REPO,path),text);
 console.log('wrote '+Object.keys(outputs).join(', ')+(stale.length?' (changed: '+stale.join(', ')+')':' (no changes)'));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main();
