import test from 'node:test';
import assert from 'node:assert/strict';
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import {readFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {HOSTED_CSP} from './cloudflare/client-policy.mjs';

async function port() {
  const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const value = server.address().port; await new Promise(done => server.close(done)); return value;
}

function snapshot(available, extra = {}) {
  return {available_atoms: available, reserved_atoms: '0', htlc_atoms: '0', immature_atoms: '0', synced_height: '14255', observed_height: '14255', observed_at: String(Date.now()), watch_only: false, ...extra};
}

async function mockCompanion(context, token, capabilities, balance) {
  await context.route('http://127.0.0.1:8788/**', route => {
    if (route.request().headers().authorization !== 'Bearer ' + token) return route.fulfill({status: 403, contentType: 'application/json', body: '{"error":"forbidden"}'});
    const path = new URL(route.request().url()).pathname;
    const current = typeof balance === 'function' ? balance() : balance;
    const body = path === '/health' ? {status: 'ok', capabilities}
      : path === '/hegemon/status' ? {network: 'v0.11 pre-mainnet', height: '14255', syncing: false, peers: 8, wallet_rpc_ready: true}
      : path === '/hegemon/unlock' ? {unlocked: true, balance: current}
      : path === '/hegemon/balance' ? current : null;
    if (!body) return route.fulfill({status: 404, contentType: 'application/json', body: '{"error":"not found"}'});
    return route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(body)});
  });
}

test('hosted HGN offers require a local wallet snapshot and other assets do not', {timeout: 90000}, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hegemon-hgn-gate-'));
  const n = await port(), base = `http://127.0.0.1:${n}`;
  const server = spawn(process.execPath, [resolve('swap-service/server.ts')], {env: {...process.env, SWAP_DB: join(directory, 'offers.db'), SWAP_PORT: String(n)}, stdio: 'ignore'});
  let browser;
  try {
    for (let i = 0; i < 100; i++) { try { if ((await fetch(base + '/health')).ok) break; } catch { /* retry */ } await new Promise(done => setTimeout(done, 50)); }
    const html = await readFile('swap-ui/hosted.html');
    browser = await chromium.launch({executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-gpu', '--disable-background-networking']});
    const statusOnly = await browser.newContext(), short = await browser.newContext(), funded = await browser.newContext();
    for (const context of [statusOnly, short, funded]) {
      await context.route(base + '/**', route => {
        const path = new URL(route.request().url()).pathname;
        if (path === '/') return route.fulfill({status: 200, body: html, headers: {'content-type': 'text/html; charset=utf-8', 'content-security-policy': HOSTED_CSP}});
        return route.continue();
      });
      await context.grantPermissions(['local-network-access'], {origin: base});
    }
    const statusToken = '11'.repeat(32), shortToken = '22'.repeat(32), fundedToken = '33'.repeat(32);
    await mockCompanion(statusOnly, statusToken, ['hegemon-public-status'], null);
    await mockCompanion(short, shortToken, ['hegemon-public-status', 'hegemon-public-balance'], () => snapshot('1000'));
    await mockCompanion(funded, fundedToken, ['hegemon-public-status', 'hegemon-public-balance'], () => snapshot('5000000'));

    const statusPage = await statusOnly.newPage();
    let statusPosts = 0;
    statusPage.on('request', request => { if (request.method() === 'POST' && request.url() === base + '/offers') statusPosts++; });
    await statusPage.goto(base);
    await statusPage.locator('#companion-indicator').click();
    await statusPage.locator('#companion-token').fill(statusToken);
    await statusPage.locator('#connect-companion').click();
    await statusPage.locator('#companion-status').getByText(/status check; Hegemon swaps are not ready/).waitFor();
    await statusPage.locator('#journey-back').click();
    await statusPage.getByRole('button', {name: /Create an offer/}).click();
    await statusPage.locator('#journey-give-type').selectOption('hegemon:hgn');
    await statusPage.locator('#journey-next').click();
    await statusPage.locator('#journey-give-amount').fill('0.001');
    assert.match(await statusPage.locator('#journey-hgn-available').innerText(), /wallet-status/);
    assert.equal(await statusPage.locator('#journey-next').isDisabled(), true);
    await statusPage.locator('#journey-next').evaluate(button => { button.disabled = false; button.click(); });
    assert.match(await statusPage.locator('#journey-create-status').innerText(), /wallet-status/);
    assert.equal(await statusPage.locator('#journey-give-amount').isVisible(), true);
    assert.equal(statusPosts, 0);

    const shortPage = await short.newPage();
    let shortPosts = 0;
    shortPage.on('request', request => { if (request.method() === 'POST' && request.url() === base + '/offers') shortPosts++; });
    await shortPage.goto(base);
    await shortPage.locator('#companion-indicator').click();
    await shortPage.locator('#companion-token').fill(shortToken);
    await shortPage.locator('#connect-companion').click();
    await shortPage.locator('#companion-status').getByText(/does not lock funds/).waitFor();
    await shortPage.locator('#journey-back').click();
    await shortPage.getByRole('button', {name: /Create an offer/}).click();
    await shortPage.locator('#journey-give-type').selectOption('hegemon:hgn');
    await shortPage.locator('#journey-next').click();
    await shortPage.locator('#journey-give-amount').fill('0.001');
    await shortPage.locator('#journey-hgn-unlock').click();
    await shortPage.locator('#journey-hgn-shortfall').getByText(/short/).waitFor();
    assert.match(await shortPage.locator('#journey-hgn-available').innerText(), /0\.00001 HGN/);
    assert.equal(await shortPage.locator('#journey-next').isDisabled(), true);
    await shortPage.locator('#journey-next').evaluate(button => { button.disabled = false; button.click(); });
    assert.match(await shortPage.locator('#journey-create-status').innerText(), /short/);
    assert.equal(shortPosts, 0);
    await shortPage.locator('#journey-mode').click();
    await shortPage.locator('#offer-form [name="give-type"]').selectOption('hegemon:hgn');
    await shortPage.locator('#offer-form [name="give-amount"]').fill('100000');
    await shortPage.locator('#offer-form [name="receive-type"]').selectOption('bitcoin:btc');
    await shortPage.locator('#offer-form [name="receive-amount"]').fill('1');
    await shortPage.locator('#offer-form button[type="submit"]').click();
    await shortPage.locator('#create-result.error').getByText(/short/).waitFor();
    assert.equal(shortPosts, 0);

    const fundedPage = await funded.newPage();
    let fundedPosts = 0;
    fundedPage.on('request', request => { if (request.method() === 'POST' && request.url() === base + '/offers') fundedPosts++; });
    await fundedPage.goto(base);
    await fundedPage.locator('#companion-indicator').click();
    await fundedPage.locator('#companion-token').fill(fundedToken);
    await fundedPage.locator('#connect-companion').click();
    await fundedPage.locator('#journey-back').click();
    await fundedPage.getByRole('button', {name: /Create an offer/}).click();
    await fundedPage.locator('#journey-give-type').selectOption('ethereum:eth');
    await fundedPage.locator('#journey-next').click();
    assert.equal(await fundedPage.locator('#journey-hgn-funds').isHidden(), true);
    await fundedPage.locator('#journey-back').click();
    await fundedPage.locator('#journey-give-type').selectOption('hegemon:hgn');
    await fundedPage.locator('#journey-next').click();
    await fundedPage.locator('#journey-give-amount').fill('0.001');
    await fundedPage.locator('#journey-hgn-unlock').click();
    await fundedPage.locator('#journey-create-status').getByText(/does not lock funds/).waitFor();
    assert.equal(await fundedPage.locator('#journey-next').isDisabled(), false);
    await fundedPage.locator('#journey-next').click();
    await fundedPage.locator('#journey-receive-type').selectOption('bitcoin:btc');
    await fundedPage.locator('#journey-next').click();
    await fundedPage.locator('#journey-receive-amount').fill('0.00000001');
    await fundedPage.locator('#journey-next').click();
    await fundedPage.locator('[name="journey-visibility"][value="private"]').check();
    await fundedPage.locator('#journey-next').click();
    await fundedPage.locator('#journey-lifetime').selectOption('86400');
    await fundedPage.locator('#journey-next').click();
    await fundedPage.locator('[name="journey-backup"][value="no"]').check();
    await fundedPage.locator('#journey-next').click();
    await fundedPage.locator('#journey-publish').click();
    await fundedPage.locator('#journey-created').waitFor({state: 'visible'});
    assert.equal(fundedPosts, 1);
    const id = (await fundedPage.locator('#journey-share-link').inputValue()).split('#')[1].split('.')[0];
    const offer = await (await fetch(base + '/offers/' + id)).json();
    assert.equal(offer.give.amount, '100000');
    assert.equal(offer.give.chain, 'hegemon');

    const stale = await browser.newContext();
    await stale.route(base + '/**', route => {
      const path = new URL(route.request().url()).pathname;
      if (path === '/') return route.fulfill({status: 200, body: html, headers: {'content-type': 'text/html; charset=utf-8', 'content-security-policy': HOSTED_CSP}});
      return route.continue();
    });
    await stale.grantPermissions(['local-network-access'], {origin: base});
    const staleToken = '44'.repeat(32);
    let balanceReads = 0, unlockPosts = 0;
    await stale.route('http://127.0.0.1:8788/**', route => {
      if (route.request().headers().authorization !== 'Bearer ' + staleToken) return route.fulfill({status: 403, contentType: 'application/json', body: '{"error":"forbidden"}'});
      const path = new URL(route.request().url()).pathname, method = route.request().method();
      if (path === '/hegemon/unlock' && method === 'POST') unlockPosts++;
      if (path === '/hegemon/balance' && method === 'GET') balanceReads++;
      const fresh = snapshot('5000000'), old = snapshot('5000000', {observed_at: String(Date.now() - 120000)});
      const body = path === '/health' ? {status: 'ok', capabilities: ['hegemon-public-status', 'hegemon-public-balance']}
        : path === '/hegemon/status' ? {network: 'v0.11 pre-mainnet', height: '14255', syncing: false, peers: 8, wallet_rpc_ready: true}
        : path === '/hegemon/wallet-activity' ? {phase: 'idle'}
        : path === '/hegemon/unlock' ? {unlocked: true, balance: old}
        : path === '/hegemon/balance' ? fresh : null;
      if (!body) return route.fulfill({status: 404, contentType: 'application/json', body: '{"error":"not found"}'});
      return route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(body)});
    });
    async function reachStaleAmount(page) {
      await page.goto(base);
      await page.locator('#companion-indicator').click();
      await page.locator('#companion-token').fill(staleToken);
      await page.locator('#connect-companion').click();
      await page.locator('#companion-status').getByText(/does not lock funds/).waitFor();
      await page.locator('#journey-back').click();
      await page.getByRole('button', {name: /Create an offer/}).click();
      await page.locator('#journey-give-type').selectOption('hegemon:hgn');
      await page.locator('#journey-next').click();
      await page.locator('#journey-give-amount').fill('0.001');
      await page.locator('#journey-hgn-unlock').click();
      await page.locator('#journey-hgn-shortfall').getByText(/stale/).waitFor();
      assert.equal(await page.locator('#journey-hgn-unlock').innerText(), 'Read balance again');
    }
    const rereadPage = await stale.newPage();
    await reachStaleAmount(rereadPage);
    const unlocksAfterFirst = unlockPosts, readsAfterFirst = balanceReads;
    assert.equal(unlocksAfterFirst, 1);
    assert.equal(readsAfterFirst, 0);
    await rereadPage.locator('#journey-hgn-unlock').click();
    await rereadPage.waitForFunction(() => !document.getElementById('journey-next').disabled && document.getElementById('journey-hgn-shortfall').textContent === '');
    assert.equal(unlockPosts, 1);
    assert.equal(balanceReads, 1);

    const continuePage = await stale.newPage();
    await reachStaleAmount(continuePage);
    const unlocksBeforeContinue = unlockPosts, readsBeforeContinue = balanceReads;
    await continuePage.locator('#journey-next').evaluate(button => { button.disabled = false; button.click(); });
    await continuePage.getByRole('heading', {name: 'What would you like in return?'}).waitFor();
    assert.equal(unlockPosts, unlocksBeforeContinue);
    assert.equal(balanceReads, readsBeforeContinue + 1);
  } finally {
    await browser?.close();
    server.kill('SIGTERM');
    await Promise.race([once(server, 'exit'), new Promise(done => setTimeout(done, 2000))]);
    await rm(directory, {recursive: true, force: true});
  }
});
