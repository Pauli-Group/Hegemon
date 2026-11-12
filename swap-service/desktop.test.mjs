import {test} from 'node:test';
import assert from 'node:assert/strict';
import {_electron} from 'playwright-core';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,chmod,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {createServer as createHttpServer} from 'node:http';
import {once} from 'node:events';

test('desktop opens isolated local offer board without a real node',{timeout:60000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-desktop-'));
 const probe=createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');const relayPort=probe.address().port;await new Promise(r=>probe.close(r));
 const bin=join(dir,'bin');await mkdir(bin);for(const name of ['hegemon-node','walletd']){const path=join(bin,name);await writeFile(path,'#!/bin/sh\nexit 0\n');await chmod(path,0o700);}
 const relay=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:String(relayPort)},stdio:'ignore'});
 // Change response bytes at the HTTP boundary; no renderer request interception.
 let tamper=false;
 const proxy=createHttpServer(async(req,res)=>{
  try{
   const response=await fetch('http://127.0.0.1:'+relayPort+req.url),headers=new Headers(response.headers);
   let body=Buffer.from(await response.arrayBuffer());
   if(req.url==='/'){
    // Model a relay update after the desktop was built: same map, new bytes/hash.
    const html=body.toString(),map=html.match(/(<script type="importmap">)([\s\S]*?)(<\/script>)/),updated=map[2]+'\n';
    const hash=text=>"'sha256-"+createHash('sha256').update(text).digest('base64')+"'";
    body=Buffer.from(html.replace(map[0],map[1]+updated+map[3]));
    headers.set('content-security-policy',headers.get('content-security-policy').replace(hash(map[2]),hash(updated)));
   }
   if(tamper&&req.url==='/offer-draft.mjs')body=Buffer.concat([body,Buffer.from('\nglobalThis.__tamperedDependency=true;\n')]);
   headers.delete('content-length');headers.delete('transfer-encoding');
   res.writeHead(response.status,Object.fromEntries(headers));res.end(body);
  }catch{res.writeHead(502);res.end();}
 });
 let application;
 try{
  proxy.listen(8787,'127.0.0.1');await once(proxy,'listening');
  let ready=false;for(let i=0;i<100;i++){try{if(relay.exitCode!==null)break;if((await fetch('http://127.0.0.1:8787/health')).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,50));}assert.ok(ready,'local relay did not start');
  const env={...process.env,HEGEMON_BIN_DIR:bin,HEGEMON_SEEDS:'',XDG_CONFIG_HOME:join(dir,'config')};delete env.GH_TOKEN;delete env.GITHUB_TOKEN;
  const displayArgs=process.env.DISPLAY?[]:['--headless','--ozone-platform=headless'];
  application=await _electron.launch({executablePath:resolve('hegemon-app/node_modules/electron/dist/electron'),args:['--no-sandbox','--disable-gpu','--disable-background-networking',...displayArgs,`--user-data-dir=${join(dir,'user-data')}`,resolve('hegemon-app/out/main/main.cjs')],env,timeout:30000});
  const main=await application.firstWindow();await main.getByRole('link',{name:/Swaps/}).click();
  const [board]=await Promise.all([application.waitForEvent('window'),main.getByRole('button',{name:'Open local offer board'}).click()]);
  await board.getByText('Offers and reservations do not lock assets.',{exact:false}).waitFor();
  await board.waitForFunction(()=>document.querySelectorAll('[name="give-type"] option').length>0);
  assert.equal(new URL(board.url()).origin,'http://127.0.0.1:8787');
  assert.equal(await board.evaluate(()=>typeof window.hegemon),'undefined');
  const errors=[];board.on('console',message=>{if(message.type()==='error')errors.push(message.text());});
  tamper=true;
  await board.reload();
  await board.waitForFunction(()=>document.readyState==='complete');
  assert.equal(await board.evaluate(()=>globalThis.__tamperedDependency===true),false);
  assert.ok(errors.some(message=>message.includes('integrity')&&message.includes('offer-draft.mjs')),'desktop must enforce the import map integrity');
  assert.equal(await board.locator('[name="give-type"] option').count(),0);
  tamper=false;await board.reload();
  await board.waitForFunction(()=>document.querySelectorAll('[name="give-type"] option').length>0);
  await board.close();
 }finally{
  if(application)await application.close();
  await new Promise(r=>proxy.close(r));
  if(relay.exitCode===null){relay.kill('SIGTERM');await once(relay,'exit');}
  await rm(dir,{recursive:true,force:true});
 }
});
