/** Run the actual testnet Worker and an isolated local D1 without deploying.
 * This program never opens a wallet, starts a node, or reads .wrangler. */
import {createRequire} from 'node:module';
import {readFileSync,realpathSync,lstatSync,readdirSync,writeFileSync} from 'node:fs';
import {resolve,relative,sep} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=realpathSync(fileURLToPath(new URL('..',import.meta.url))),args=process.argv.slice(2),usage='Use: node scripts/run_swap_rehearsal.mjs --state /absolute/private/empty-directory [--port 8787]';
let stateArg=null,port=8787;
for(let i=0;i<args.length;i++){
 if(args[i]==='--state'&&stateArg===null&&args[i+1])stateArg=args[++i];
 else if(args[i]==='--port'&&args[i+1]&&/^[1-9][0-9]{0,4}$/.test(args[i+1]))port=Number(args[++i]);
 else throw Error(usage);
}
if(!stateArg||!stateArg.startsWith('/')||!Number.isInteger(port)||port<1||port>65535||port===8788)throw Error(usage);
process.umask(0o077);
const path=resolve(stateArg);
const info=lstatSync(path);if(info.isSymbolicLink()||!info.isDirectory()||process.getuid?.()!==info.uid||(info.mode&0o077)!==0)throw Error('The rehearsal state directory must be user-owned, private and not a symlink.');
const state=realpathSync(path),inside=relative(root,state);
if(inside===''||inside!== '..'&&!inside.startsWith('..'+sep))throw Error('Keep rehearsal state outside the repository.');
const marker=resolve(state,'.hegemon-swap-rehearsal'),tag='hegemon-swap-rehearsal-v1\n',names=readdirSync(state);
if(!names.includes('.hegemon-swap-rehearsal')){
 if(names.length)throw Error('Choose an empty private directory for rehearsal state.');
 writeFileSync(marker,tag,{flag:'wx',mode:0o600});
}else{
 const stamp=lstatSync(marker);if(stamp.isSymbolicLink()||!stamp.isFile()||stamp.uid!==info.uid||(stamp.mode&0o077)!==0||stamp.size!==tag.length||readFileSync(marker,'utf8')!==tag)throw Error('The rehearsal state marker is invalid.');
}
const require=createRequire(import.meta.url),modulePath=process.env.SWAP_MINIFLARE_MODULE;
if(!modulePath||!modulePath.startsWith('/'))throw Error('Set SWAP_MINIFLARE_MODULE to the absolute path of the Miniflare package from the pinned Wrangler installation.');
const {Miniflare,convertV4MiniflareOptions}=require(modulePath);
if(typeof Miniflare!=='function'||typeof convertV4MiniflareOptions!=='function')throw Error('Use the Miniflare package included with Wrangler 4.156.2.');
const {fetch:providerFetch,EnvHttpProxyAgent}=require(resolve(modulePath,'../undici'));
if(typeof providerFetch!=='function'||typeof EnvHttpProxyAgent!=='function')throw Error('The pinned Wrangler installation is missing its HTTP client.');
const agent=new EnvHttpProxyAgent(),providers=new Set(['blockstream.info','eth-sepolia.blockscout.com','ethereum-sepolia-rpc.publicnode.com','preview.koios.rest']);
const outbound=async request=>{
 const url=new URL(request.url);
 if(url.protocol!=='https:'||!providers.has(url.hostname)||url.port||url.username||url.password||!['GET','POST'].includes(request.method))return new Response('Provider not allowed',{status:403});
 const headers=new Headers();for(const name of ['accept','content-type']){const value=request.headers.get(name);if(value)headers.set(name,value);}
 const body=request.method==='GET'?undefined:await request.arrayBuffer();
 if(body&&body.byteLength>1024*1024)return new Response('Request too large',{status:413});
 const response=await providerFetch(url,{method:request.method,headers,body,redirect:'error',dispatcher:agent,signal:AbortSignal.any([request.signal,AbortSignal.timeout(20000)])});
 return new Response(response.body,{status:response.status,headers:response.headers});
};
const cloud=resolve(root,'swap-service/cloudflare'),assetsRoot=realpathSync(resolve(root,'swap-ui'));
const modules=['worker.mjs','client-policy.mjs'].map(name=>({type:'ESModule',path:resolve(cloud,name),contents:readFileSync(resolve(cloud,name),'utf8')}));
const assets=async request=>{
 const name=new URL(request.url).pathname.slice(1);
 if(!/^[A-Za-z0-9_./-]+$/.test(name)||name.includes('..'))return new Response('Not found',{status:404});
 try{
  const file=realpathSync(resolve(assetsRoot,name)),within=relative(assetsRoot,file);
  if(within===''||within==='..'||within.startsWith('..'+sep))return new Response('Not found',{status:404});
  const type=name.endsWith('.html')?'text/html':name.endsWith('.css')?'text/css':name.endsWith('.json')?'application/json':'text/javascript';
  return new Response(readFileSync(file),{headers:{'content-type':type+'; charset=utf-8'}});
 }catch{return new Response('Not found',{status:404});}
};
const options=convertV4MiniflareOptions({name:'hegemon-swap-local-rehearsal',modules,modulesRoot:cloud,compatibilityDate:'2026-10-01',host:'127.0.0.1',port,d1Databases:['DB'],serviceBindings:{ASSETS:assets},outboundService:outbound,logRequests:false,cf:false});
options.resourcePersistencePath=state;
const mf=new Miniflare(options);
try{
 const db=await mf.getD1Database('DB'),schema=readFileSync(resolve(cloud,'schema.sql'),'utf8').replace(/^\s*--.*$/gm,'');
 for(const statement of schema.split(';').map(value=>value.trim()).filter(Boolean))await db.prepare(statement).run();
 const ready=await mf.ready;
 if(ready.hostname!=='127.0.0.1'||Number(ready.port)!==port)throw Error('The rehearsal did not bind to the requested loopback address.');
 process.stdout.write(`Local testnet rehearsal: ${ready.origin}/\nRelay state: ${state}\nThe hosted site and remote database are not changed. Press Ctrl-C to stop.\n`);
 await new Promise(done=>{process.once('SIGINT',done);process.once('SIGTERM',done);});
}finally{await mf.dispose();await agent.close();}
