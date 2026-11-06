import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {spawn} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {chromium} from 'playwright-core';

async function port() { const s = createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening'); const n = s.address().port; await new Promise(r => s.close(r)); return n; }

test('Sepolia claim from an encrypted backup: one wallet request, and it fails safe on a wrong passphrase, near the deadline and on a wrong network', {timeout: 90000}, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sepolia-claim-')), n = await port(), base = `http://127.0.0.1:${n}`;
  const server = spawn(process.execPath, [resolve('swap-service/server.ts')], {env: {...process.env, SWAP_DB: join(dir, 'offers.db'), SWAP_PORT: String(n)}, stdio: 'ignore'});
  let browser;
  try {
    for (let i = 0; i < 100; i++) { try { if ((await fetch(base + '/health')).ok) break; } catch {} await new Promise(r => setTimeout(r, 50)); }
    browser = await chromium.launch({executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox']});
    const context = await browser.newContext();
    const claimant = '0x' + '2'.repeat(40), refundee = '0x' + '1'.repeat(40), HEAD = 1_800_000_000, EXPIRY = HEAD + 3600;
    await context.addInitScript(({claimant, HEAD}) => {
      window.sent = []; window.headTime = HEAD; window.chain = '0xaa36a7'; window.pageTerms = null;
      window.ethereum = {request: async ({method, params = []}) => {
        switch (method) {
          case 'eth_requestAccounts': case 'eth_accounts': return [claimant];
          case 'eth_chainId': return window.chain;
          case 'eth_blockNumber': return '0x100';
          case 'eth_getBlockByNumber':
            if (params[0] === '0x0') return {hash: '0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9'};
            return {number: params[0] === 'latest' ? '0x100' : params[0], timestamp: '0x' + window.headTime.toString(16), hash: '0x' + (params[0] === 'latest' ? 'b' : 'c').repeat(64)};
          case 'eth_getCode': {
            const module = await import('/ethereum-escrow.mjs'), template = await (await fetch('/ether-escrow-template.json')).json();
            return module.expectedEtherRuntime(template, window.pageTerms);
          }
          case 'eth_call': return '0x' + '0'.repeat(64);
          case 'eth_getBalance': return '0x64';
          case 'eth_sendTransaction': window.sent.push(params[0]); return '0x' + '9'.repeat(64);
          default: throw Error('unexpected ' + method);
        }
      }};
    }, {claimant, HEAD});
    const page = await context.newPage();
    page.on('dialog', dialog => dialog.accept());
    await page.goto(base);
    await page.evaluate(() => { document.getElementById('sepolia-action-section').hidden = false; });
    // Create the encrypted backup through the page, like a user would.
    await page.locator('#vault-create [name="label"]').fill('claim test');
    await page.locator('#vault-create [name="passphrase"]').fill('a long enough passphrase');
    await page.locator('#vault-create [name="confirm"]').fill('a long enough passphrase');
    await page.getByRole('button', {name: 'Create encrypted secret'}).click();
    await page.waitForFunction(() => document.getElementById('vault-backup').value.includes('hashlock'));
    const hashlock = JSON.parse(await page.locator('#vault-backup').inputValue()).envelope.hashlock;
    const terms = {amount: '100', hashlock: '0x' + hashlock, claimant, refundee, expiry: String(EXPIRY), contract: '0x' + '4'.repeat(40)};
    await page.evaluate(t => { window.pageTerms = {kind: 'eth', token: '', tokenId: '', ...t}; }, terms);
    await page.getByRole('button', {name: 'Connect Ethereum wallet'}).click();
    for (const [k, v] of Object.entries(terms)) await page.locator(`#sepolia-action-form [name="${k}"]`).fill(v);
    await page.locator('#sepolia-claim-backup').selectOption(hashlock);
    const claim = () => page.getByRole('button', {name: 'Claim with encrypted backup'}).click();
    const status = () => page.locator('#sepolia-action-status').innerText();
    const finished = () => page.waitForFunction(() => !document.getElementById('sepolia-claim').disabled && !/^Checking/.test(document.getElementById('sepolia-action-status').textContent));
    const sent = () => page.evaluate(() => window.sent.length);

    await page.locator('#sepolia-claim-passphrase').fill('the wrong passphrase!');
    await claim();
    await finished();
    assert.match(await status(), /Could not unlock encrypted backup/);
    assert.equal(await sent(), 0);

    await page.evaluate(h => { window.headTime = h; }, EXPIRY - 30);
    await page.locator('#sepolia-claim-passphrase').fill('a long enough passphrase');
    await claim();
    await finished();
    assert.match(await status(), /too close/i);
    assert.equal(await sent(), 0, 'no wallet request near the deadline');

    await page.evaluate(() => { window.headTime = 1_800_000_000; window.chain = '0x1'; });
    await page.locator('#sepolia-claim-passphrase').fill('a long enough passphrase');
    await claim();
    await finished();
    assert.match(await status(), /not connected to Ethereum Sepolia/);
    assert.equal(await sent(), 0, 'no wallet request on the wrong network');

    await page.evaluate(() => { window.chain = '0xaa36a7'; });
    await page.locator('#sepolia-claim-passphrase').fill('a long enough passphrase');
    await claim();
    await page.getByText('Transaction submitted. Check its receipt and confirmations.').waitFor();
    const requests = await page.evaluate(() => window.sent);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].to, terms.contract);
    assert.equal(requests[0].from, claimant);
    assert.match(requests[0].data, /^0xbd66528a[0-9a-f]{64}$/);
    const digest = await page.evaluate(async data => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(data.slice(10).match(/../g), x => parseInt(x, 16)))), b => b.toString(16).padStart(2, '0')).join(''), requests[0].data);
    assert.equal(digest, hashlock, 'the sent preimage hashes to the hashlock');
    await page.getByRole('button', {name: 'Export action records'}).click();
    await page.waitForFunction(() => { try { return JSON.parse(document.getElementById('action-journal-text').value).records.some(x => x.operation === 'claim' && x.state === 'completed'); } catch { return false; } });
    const journal = await page.locator('#action-journal-text').inputValue();
    assert.ok(!journal.includes(requests[0].data.slice(10)), 'the journal never holds the preimage');
  } finally { if (browser) await browser.close(); server.kill('SIGTERM'); await once(server, 'exit').catch(() => {}); await rm(dir, {recursive: true, force: true}); }
});
