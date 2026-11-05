// Real Chromium interaction checks of the production component/hook. All node
// data here is an explicit test fixture; this never activates a native runtime.
import { createServer } from 'vite';
import react from '@vitejs/plugin-react';
import { mkdtemp, writeFile, readFile, rm, mkdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);
const fixture = await mkdtemp(resolve(root, '.reward-ux-check-'));
const profile = await mkdtemp(resolve(tmpdir(), 'hegemon-reward-browser-'));
const output =
  process.env.REWARD_UX_ARTIFACTS ?? resolve(tmpdir(), 'hegemon-reward-ux');
let server, browser, socket;
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
try {
  await mkdir(output, { recursive: true });
  await writeFile(
    resolve(fixture, 'index.html'),
    '<html><head><title>Reward UX test fixture</title></head><body><div id="root"></div><script type="module" src="./check.tsx"></script></body></html>',
  );
  await writeFile(
    resolve(fixture, 'check.tsx'),
    `
import React from 'react';import{createRoot}from'react-dom/client';
import{RewardWorkspace}from'../src/components/RewardWorkspace';import{useRewardAccounts}from'../src/lib/useRewardAccounts';
import{statusFixture,accountFixture}from'../tests/rewardFixtures';import vectors from'../../wallet/tests/fixtures/reward-addresses.json';import'../src/styles.css';
let current,delayIdentity=false,resolveIdentity,broken=false,changedChain=false;const calls=[];
const identity={accountAddress:vectors.accountTest,shieldedAddress:vectors.shieldedTest};
window.hegemon={node:{rewardRead:async(url,method,query)=>{calls.push(method);const s=statusFixture();if(changedChain)s.context.chain_id='09'.repeat(32);if(broken)s.supply.pending_account_atoms='1';if(method==='hegemon_rewardAccountsStatus')return s;if(method==='hegemon_rewardAccount')return{context:s.context,account:{...accountFixture(),address:query.address,is_treasury:false}};if(method==='hegemon_rewardAccountsGenesis')return{chain_id:s.context.chain_id,genesis_hash:s.context.genesis_hash,rows:[],total_rows:0,next_offset:null};throw Error('Unknown test read');}},wallet:{reward:async(_store,_token,method,params)=>{calls.push('reward.'+method);if(method==='identity'){if(delayIdentity){delayIdentity=false;return await new Promise(r=>resolveIdentity=()=>r(identity));}return identity;}if(method==='reviewDonation')return{kind:'treasury-donation-review',...params,submitted:false,proofPrepared:false};throw Error('Unexpected test wallet method '+method);}},clipboard:{writeText:async text=>{window.copied=text;}}};
function Harness(){const[token,setToken]=React.useState('test-unlock'),[url,setUrl]=React.useState('http://localhost:9944');const state=useRewardAccounts(url,null,'test-wallet',token);current={state,setToken,setUrl};return <main style={{padding:24,maxWidth:1200,margin:'0 auto'}}><p>Explicit UI test fixture · no native transactions</p><RewardWorkspace state={state} url={url} storePath="test-wallet" token={token}/></main>;}
createRoot(document.getElementById('root')).render(<Harness/>);
const wait=async(predicate)=>{for(let i=0;i<200;i++){if(predicate())return;await new Promise(r=>setTimeout(r,20));}throw Error('Timed out: '+predicate.toString());};
const check=(ok,message)=>{if(!ok)throw Error(message);};const button=text=>[...document.querySelectorAll('button')].find(b=>b.textContent.trim()===text);
const input=(label,value)=>{const el=[...document.querySelectorAll('label')].find(l=>l.textContent.includes(label))?.querySelector('input,textarea');check(el,'Missing field '+label);Object.getOwnPropertyDescriptor(el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value').set.call(el,value);el.dispatchEvent(new Event('input',{bubbles:true}));return el;};
window.rewardUxCheck=(async()=>{
 await wait(()=>current?.state.account);check(document.body.textContent.includes('Claimable next block'),'Missing boundary amount');check(document.body.textContent.includes('2881'),'Wrong boundary height');button('Copy reward account').click();await wait(()=>window.copied===identity.accountAddress);
 delayIdentity=true;current.state.refresh();await wait(()=>resolveIdentity);current.setToken(null);await wait(()=>!current.state.identity&&!current.state.loading);resolveIdentity();await new Promise(r=>setTimeout(r,100));check(!current.state.identity&&!current.state.account,'Stale unlocked response survived lock');
 current.setToken('new-unlock');await wait(()=>current.state.account);broken=true;current.state.refresh();await wait(()=>current.state.error);check(!current.state.status&&!current.state.account,'Invalid supply became a balance');broken=false;current.state.refresh();await wait(()=>current.state.account);
 changedChain=true;current.state.refresh();await wait(()=>current.state.error);check(current.state.mode==='accounts'&&!current.state.identity,'Changed network retained authority');changedChain=false;current.setUrl('http://localhost:9945');await wait(()=>current.state.account);
 button('Treasury').click();await wait(()=>button('Review donation'));check(button('Review donation').disabled,'Donation disclosure not required');input('Donation amount','1.23456789');input('Public memo','<img src=x onerror=window.injected=true>');await new Promise(r=>setTimeout(r,50));document.querySelector('input[type=checkbox]').click();await wait(()=>!button('Review donation').disabled);button('Review donation').click();await wait(()=>document.body.textContent.includes('Donation reviewed'));check(!window.injected&&!document.querySelector('img[src=x]'),'Memo interpreted as markup');check(document.body.textContent.includes('No funds moved'),'Donation review implied submission');
 input('Public memo','changed memo');await wait(()=>!document.body.textContent.includes('Prepared public package'));check(!document.querySelector('input[type=checkbox]').checked,'Changed memo retained disclosure approval');check(calls.every(m=>!m.toLowerCase().includes('submit')),'Unexpected submission');
 button('Genesis & supply').click();await wait(()=>button('Read genesis allocations'));button('Read genesis allocations').click();await wait(()=>document.body.textContent.includes('No genesis allocations.'));check(document.body.textContent.includes('Remaining mining issuance'),'Missing supply budget');
 button('Backup & recovery').click();await wait(()=>button('Recover keys to a separate wallet'));input('New passphrase','never-retain-on-lock');input('Confirm new passphrase','never-retain-on-lock');current.setToken(null);await wait(()=>[...document.querySelectorAll('input[type=password]')].every(i=>i.value===''));check(button('Recover keys to a separate wallet').disabled,'Locked wallet can recover private keys');
 current.setToken('new-unlock');await wait(()=>current.state.account);button('My rewards').click();await wait(()=>button('Copy reward account'));return{checks:12,calls:calls.length,success:true};})();
`,
  );
  server = await createServer({
    root,
    configFile: false,
    plugins: [react()],
    server: { host: '127.0.0.1', port: 0 },
    logLevel: 'error',
  });
  await server.listen();
  const port = server.httpServer.address().port;
  browser = spawn(
    process.env.CHROMIUM_PATH ?? '/usr/bin/chromium',
    [
      '--headless',
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      `--user-data-dir=${profile}`,
      '--remote-debugging-port=0',
      `http://127.0.0.1:${port}/${fixture.slice(root.length + 1)}/index.html`,
    ],
    { stdio: 'ignore' },
  );
  let debugPort;
  for (let i = 0; i < 200; i++) {
    try {
      debugPort = Number(
        (await readFile(resolve(profile, 'DevToolsActivePort'), 'utf8')).split(
          '\n',
        )[0],
      );
      break;
    } catch {
      await pause(50);
    }
  }
  if (!debugPort) throw Error('Chromium did not expose its debugging port');
  const targets = await (
    await fetch(`http://127.0.0.1:${debugPort}/json/list`)
  ).json();
  const target = targets.find((t) => t.type === 'page');
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r, j) => {
    socket.onopen = r;
    socket.onerror = j;
  });
  let next = 0;
  const pending = new Map();
  socket.onmessage = (e) => {
    const message = JSON.parse(e.data);
    if (message.id) {
      const p = pending.get(message.id);
      if (p) {
        pending.delete(message.id);
        message.error
          ? p.reject(Error(message.error.message))
          : p.resolve(message.result);
      }
    }
  };
  const cdp = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = ++next;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params }));
    });
  await cdp('Runtime.enable');
  await cdp('Page.enable');
  let result;
  for (let i = 0; i < 100; i++) {
    result = await cdp('Runtime.evaluate', {
      expression: 'window.rewardUxCheck',
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails)
      throw Error(JSON.stringify(result.exceptionDetails));
    if (result.result?.value) {
      break;
    }
    await pause(100);
  }
  if (!result?.result?.value?.success)
    throw Error('Browser interaction checks failed: ' + JSON.stringify(result));
  for (const [name, width, height] of [
    ['desktop', 1280, 1080],
    ['mobile', 390, 1000],
  ]) {
    await cdp('Emulation.setDeviceMetricsOverride', {
      width,
      height,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await pause(150);
    const layout = await cdp('Runtime.evaluate', {
      expression: 'document.documentElement.scrollWidth<=window.innerWidth',
      returnByValue: true,
    });
    if (!layout.result.value) throw Error('Horizontal overflow at ' + name);
    const shot = await cdp('Page.captureScreenshot', {
      format: 'png',
      captureBeyondViewport: true,
    });
    await writeFile(
      resolve(output, `${name}.png`),
      Buffer.from(shot.data, 'base64'),
    );
  }
  console.log(JSON.stringify({ ...result.result.value, artifacts: output }));
} finally {
  socket?.close();
  browser?.kill('SIGTERM');
  await server?.close();
  await pause(200);
  await rm(fixture, { recursive: true, force: true });
  await rm(profile, { recursive: true, force: true }).catch(() => {});
}
