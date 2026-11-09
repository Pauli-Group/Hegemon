import test from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {createHash} from 'node:crypto';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {HOSTED_CSP} from './cloudflare/client-policy.mjs';

const origin = 'https://hegemon-swap-testnet.willdoyle422.workers.dev';
const sleep = ms => new Promise(done => setTimeout(done, ms));

test('hosted page connects only on request to a read-only local Hegemon companion', {timeout: 60000}, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hegemon-hosted-node-test-'));
  const release = JSON.parse(await readFile('config/testnet/0.11/release.json', 'utf8'));
  const manifest = JSON.parse(await readFile('config/testnet/0.11/network-manifest.json', 'utf8'));
  const fields = ['schema','profile','genesis_timestamp_ms','pow_bits','rules_hash','launch_reference_rules_hash','funding_address','funding_subsidy_numerator','funding_subsidy_denominator'];
  const canonical = JSON.stringify(Object.fromEntries(fields.map(field => [field, manifest[field]])));
  const digest = '0x' + createHash('sha512').update('hegemon.native.network-manifest.sha512.v1\0' + canonical).digest('hex');
  const methods = ['chain_getBlockHash','chain_getBlockActionsChunk','hegemon_latestBlock','hegemon_nodeConfig','hegemon_privateSpendParameters','hegemon_submitAction'];
  const relation = 'b9d22c2f0cb49df519b34620c138d7f2d74fa135a76c7b526cd73a60bb5cd6ce' + 'c2f910dde83b1a848684e123d02ab0bbc8bdb384b1bcaff1b489fd8794c14685';
  const answers = {
    chain_getBlockHash: release.genesis_hash,
    hegemon_nodeConfig: {networkProfile:'pre-mainnet',chainId:release.chain_id,networkManifestDigest:digest,networkManifest:manifest},
    system_health: {isSyncing:false,peers:8}, rpc_methods:{methods}, chain_getHeader:{number:'0x21d3'},
    hegemon_privateSpendParameters:{relation_digest:relation,action_id:15,public_words:86,ciphertext_bytes:2608},
  };
  const rpc = createServer((req, res) => {
    let body='';req.on('data',chunk => body+=chunk);req.on('end',() => {
      const request=JSON.parse(body);res.writeHead(200,{'content-type':'application/json'});
      res.end(JSON.stringify({jsonrpc:'2.0',id:request.id,result:answers[request.method]}));
    });
  });
  rpc.listen(0, '127.0.0.1'); await once(rpc, 'listening');
  const startCompanion=()=>spawn('python3', ['scripts/local_swap_companion.py','--hosted-node-status',
    '--hegemon-rpc',`http://127.0.0.1:${rpc.address().port}`,'--token-file',join(directory,'token')], {stdio:['ignore','ignore','pipe']});
  let companion=startCompanion();
  let browser;
  try {
    let token;
    for (let i=0;i<200;i++) {
      try {
        token=(await readFile(join(directory,'token'),'utf8')).trim();
        const health=await fetch('http://127.0.0.1:8788/health',{headers:{origin,authorization:'Bearer '+token}});
        if(health.ok)break;
      } catch {}
      if(companion.exitCode!==null)throw Error('Local test companion stopped before becoming ready.');
      await sleep(25);
    }
    assert.match(token ?? '',/^[0-9a-f]{64}$/);
    const html=await readFile('swap-ui/hosted.html');
    browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox','--disable-background-networking']});
    const context=await browser.newContext({viewport:{width:390,height:844}});
    await context.route(origin+'/**',async route => {
      const path=new URL(route.request().url()).pathname;
      if(path==='/')return route.fulfill({status:200,body:html,headers:{'content-type':'text/html; charset=utf-8','content-security-policy':HOSTED_CSP}});
      if(path==='/offers')return route.fulfill({json:{offers:[]}});
      if(!/^\/[A-Za-z0-9_./-]+$/.test(path)||path.includes('..'))return route.fulfill({status:404,body:''});
      try {
        const data=await readFile(resolve('swap-ui'+path));
        const type=path.endsWith('.css')?'text/css':path.endsWith('.json')?'application/json':'text/javascript';
        return route.fulfill({status:200,body:data,headers:{'content-type':type}});
      } catch {return route.fulfill({status:404,body:''});}
    });
    const page=await context.newPage(), localRequests=[], browserErrors=[];
    page.on('console',message=>{if(message.type()==='error')browserErrors.push(message.text());});
    page.on('requestfailed',request=>browserErrors.push(request.failure()?.errorText||'request failed'));
    page.on('request',request=>{if(request.url().startsWith('http://127.0.0.1:8788/'))localRequests.push(request.url());});
    await page.goto(origin+'/');
    await page.waitForFunction(() => document.documentElement.dataset.journeyMode==='guided');
    assert.equal(localRequests.length,0,'the page does not contact the local companion without a user action');
    const indicator=page.locator('#companion-indicator');
    assert.equal(await indicator.getAttribute('data-state'),'disconnected');
    await indicator.click();
    assert.equal(await page.locator('#hosted-node-instructions').isVisible(),true);
    await page.getByText('How do I start the local companion?').click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true);
    await context.grantPermissions(['local-network-access'],{origin});
    await page.locator('#companion-token').fill('0'.repeat(64));
    await page.locator('#connect-companion').click();
    await page.locator('#companion-status.error').waitFor();
    await page.locator('#companion-token').fill(token);
    await page.locator('#connect-companion').click();
    try {await page.locator('#companion-status').getByText(/Hegemon node connected · block 8659/).waitFor({timeout:5000});}
    catch {throw Error('Node status did not connect: '+await page.locator('#companion-status').innerText()+'; browser errors: '+browserErrors.join(' | '));}
    assert.match(await page.locator('#companion-status').innerText(),/status check; Hegemon swaps are not ready/);
    assert.equal(await indicator.getAttribute('data-state'),'connected');
    await indicator.click();
    await page.locator('#companion-details[open]').waitFor();
    await page.waitForFunction(()=>document.getElementById('companion-details-status').textContent.includes('block 8659'));
    await page.locator('#companion-details button').click();
    companion.kill('SIGTERM');
    await once(companion,'exit');
    await page.evaluate(()=>window.dispatchEvent(new Event('focus')));
    await page.waitForFunction(()=>document.getElementById('companion-indicator').dataset.state==='disconnected');
    await indicator.click();
    assert.equal(await page.locator('#hosted-node-instructions').isVisible(),true);
    companion=startCompanion();
    for(let i=0;i<100;i++){
      try{if((await fetch('http://127.0.0.1:8788/health',{headers:{origin,authorization:'Bearer '+token}})).ok)break;}catch{}
      await sleep(25);
    }
    await page.evaluate(()=>window.dispatchEvent(new Event('focus')));
    await page.waitForFunction(()=>document.getElementById('companion-indicator').dataset.state==='connected');
    assert.equal(await page.locator('#companion-token').inputValue(),'');
    assert.equal(await page.evaluate(secret => JSON.stringify({...localStorage,...sessionStorage}).includes(secret),token),false);
    assert.equal(localRequests.some(url => url.includes(token)),false,'the pairing code never appears in a URL');
  } finally {
    await browser?.close();
    companion.kill('SIGTERM');if(companion.exitCode===null)await Promise.race([once(companion,'exit'),sleep(2000)]);
    await new Promise(done => rpc.close(done));
    await rm(directory,{recursive:true,force:true});
  }
});
