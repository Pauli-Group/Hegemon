import {test} from 'node:test';
import assert from 'node:assert/strict';
import {_electron} from 'playwright-core';
import {spawn} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,chmod,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';

test('desktop opens isolated local offer board without a real node',{timeout:60000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'swap-desktop-'));
 const probe=createServer();probe.listen(8787,'127.0.0.1');await once(probe,'listening');await new Promise(r=>probe.close(r));
 const bin=join(dir,'bin');await mkdir(bin);for(const name of ['hegemon-node','walletd']){const path=join(bin,name);await writeFile(path,'#!/bin/sh\nexit 0\n');await chmod(path,0o700);}
 const relay=spawn(process.execPath,[resolve('swap-service/server.ts')],{env:{...process.env,SWAP_DB:join(dir,'offers.db'),SWAP_PORT:'8787'},stdio:'ignore'});
 let application;
 try{
  let ready=false;for(let i=0;i<100;i++){try{if(relay.exitCode!==null)break;if((await fetch('http://127.0.0.1:8787/health')).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,50));}assert.ok(ready,'local relay did not start');
  const env={...process.env,HEGEMON_BIN_DIR:bin,HEGEMON_SEEDS:'',XDG_CONFIG_HOME:join(dir,'config')};delete env.GH_TOKEN;delete env.GITHUB_TOKEN;
  const displayArgs=process.env.DISPLAY?[]:['--headless','--ozone-platform=headless'];
  application=await _electron.launch({executablePath:resolve('hegemon-app/node_modules/electron/dist/electron'),args:['--no-sandbox','--disable-gpu','--disable-background-networking',...displayArgs,`--user-data-dir=${join(dir,'user-data')}`,resolve('hegemon-app/out/main/main.cjs')],env,timeout:30000});
  const main=await application.firstWindow();await main.getByRole('link',{name:/Swaps/}).click();
  const [board]=await Promise.all([application.waitForEvent('window'),main.getByRole('button',{name:'Open local offer board'}).click()]);
  await board.getByText('Offer board only.',{exact:false}).waitFor();
  assert.equal(new URL(board.url()).origin,'http://127.0.0.1:8787');
  assert.equal(await board.evaluate(()=>typeof window.hegemon),'undefined');
  await board.close();
 }finally{
  if(application)await application.close();
  if(relay.exitCode===null){relay.kill('SIGTERM');await once(relay,'exit');}
  await rm(dir,{recursive:true,force:true});
 }
});
