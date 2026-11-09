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

test('hosted guided flow creates one reviewed offer and opens it in a second browser', {timeout: 90000}, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hegemon-journey-test-'));
  const n = await port(), base = `http://127.0.0.1:${n}`;
  const server = spawn(process.execPath, [resolve('swap-service/server.ts')], {env: {...process.env, SWAP_DB: join(directory, 'offers.db'), SWAP_PORT: String(n)}, stdio: 'ignore'});
  let browser;
  try {
    for (let i = 0; i < 100; i++) { try { if ((await fetch(base + '/health')).ok) break; } catch {} await new Promise(done => setTimeout(done, 50)); }
    const html = await readFile('swap-ui/hosted.html');
    browser = await chromium.launch({executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox', '--disable-gpu', '--disable-background-networking']});
    const owner = await browser.newContext({viewport: {width: 390, height: 844}}), taker = await browser.newContext();
    for (const context of [owner, taker]) {
      await context.route(base + '/', route => route.fulfill({status: 200, body: html, headers: {'content-type': 'text/html; charset=utf-8', 'content-security-policy': HOSTED_CSP}}));
      await context.addInitScript(() => { window.walletCalls = 0; window.ethereum = {request: async () => { window.walletCalls++; throw Error('No wallet is needed to make an offer'); }}; });
    }
    const first = await owner.newPage(), second = await taker.newPage();
    let posts = 0;
    first.on('request', request => { if (request.method() === 'POST' && request.url() === base + '/offers') posts++; });
    await first.goto(base);
    assert.equal(await first.evaluate(() => document.documentElement.dataset.journeyMode), 'guided');
    assert.equal(await first.getByRole('heading', {name: 'What would you like to do?'}).isVisible(), true);
    assert.equal(await first.locator('#sepolia-form').isVisible(), false);
    assert.equal(await first.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'mobile page must not overflow horizontally');

    await first.getByRole('button', {name: /Create an offer/}).click();
    await first.locator('#journey-next').click();
    assert.match(await first.locator('#journey-create-status').innerText(), /choose an asset/i);
    assert.equal(posts, 0);
    await first.locator('#journey-give-type').selectOption('hegemon:hgn');
    await first.locator('#journey-next').click();
    await first.locator('#journey-give-amount').fill('0.001');
    assert.match(await first.locator('#journey-give-base').innerText(), /100000 atoms/);
    await first.locator('#journey-back').click();
    assert.equal(await first.locator('#journey-give-type').inputValue(), 'hegemon:hgn');
    await first.locator('#journey-next').click();
    assert.equal(await first.locator('#journey-give-amount').inputValue(), '0.001');
    await first.locator('#journey-next').click();
    await first.locator('#journey-receive-type').selectOption('bitcoin:btc');
    await first.locator('#journey-next').click();
    await first.locator('#journey-receive-amount').fill('0.00000001');
    await first.locator('#journey-next').click();
    await first.locator('[name="journey-visibility"][value="private"]').check();
    await first.locator('#journey-next').click();
    await first.locator('#journey-lifetime').selectOption('86400');
    await first.locator('#journey-next').click();
    await first.locator('[name="journey-backup"][value="yes"]').check();
    await first.locator('#journey-backup-passphrase').fill('a sufficiently long test phrase');
    await first.locator('#journey-backup-confirm').fill('a sufficiently long test phrase');
    await first.locator('#journey-next').click();
    assert.match(await first.locator('#journey-review').innerText(), /100000 atoms/);
    assert.match(await first.locator('#journey-review').innerText(), /1 satoshis/);
    assert.equal(posts, 0, 'drafting never publishes an offer');
    assert.equal(await first.evaluate(() => window.walletCalls), 0);
    await first.locator('#journey-publish').evaluate(button => { button.click(); button.click(); });
    await first.locator('#journey-created').waitFor({state: 'visible'});
    assert.equal(posts, 1, 'repeated confirmation must not publish twice');
    assert.equal(await first.evaluate(() => window.walletCalls), 0, 'offer creation never asks a wallet to sign');
    assert.equal(await first.locator('#journey-see-offer').isDisabled(), true, 'the selected one-time inbox backup must be acknowledged');
    assert.ok((await first.locator('#journey-backup-text').inputValue()).length > 100);
    await first.locator('#journey-backup-saved').check();
    const link = await first.locator('#journey-share-link').inputValue();
    const [id, key] = link.split('#')[1].split('.');
    const offer = await (await fetch(base + '/offers/' + id)).json();
    assert.deepEqual(offer.give, {chain: 'hegemon', kind: 'hgn', id: '', amount: '100000'});
    assert.deepEqual(offer.receive, {chain: 'bitcoin', kind: 'btc', id: '', amount: '1'});
    await first.locator('#journey-see-offer').click();
    assert.equal(await first.locator('#selected').isVisible(), true);
    assert.equal(await first.locator('#reserve').isVisible(), false, 'an owner should not be asked to reserve their own offer');

    const requested = [];
    second.on('request', request => requested.push(request.url()));
    second.on('dialog', dialog => dialog.accept());
    await second.goto(base);
    await second.getByRole('button', {name: /Open an offer link/}).click();
    await second.locator('#journey-open-link').fill('https://unrelated.example/#' + id + '.' + key);
    await second.locator('#journey-open-form button').click();
    assert.match(await second.locator('#journey-open-status').innerText(), /this site/);
    await second.locator('#journey-open-link').fill(link);
    await second.locator('#journey-open-form button').click();
    await second.locator('#selected').waitFor({state: 'visible'});
    assert.match(await second.locator('#details').innerText(), /0\.001 HGN/);
    assert.equal(requested.some(url => url.includes(key)), false, 'the private fragment must not be sent in a request URL');
    await second.locator('#reserve').click();
    await second.getByText('No funds have been locked.', {exact: false}).last().waitFor();
    assert.equal(await second.locator('#reserve').isVisible(), false);
    await second.locator('#journey-identity-next').click();
    await second.locator('#identity').waitFor({state: 'visible'});
    assert.match(await second.locator('#journey-context-copy').innerText(), /Hegemon addresses cannot yet be signed/);
    await second.evaluate(() => {
      window.journeyRefreshed = false;
      document.addEventListener('journey:offer-selected', () => { window.journeyRefreshed = true; }, {once: true});
      window.dispatchEvent(new Event('hashchange'));
    });
    await second.waitForFunction(() => window.journeyRefreshed);
    assert.equal(await second.locator('#identity').isVisible(), true, 'an offer refresh must not pull someone away from identity verification');
    await second.getByRole('button', {name: 'Continue to messages →'}).click();
    await second.locator('#chat').waitFor({state: 'visible'});
    await second.locator('#journey-mode').click();
    assert.equal(await second.evaluate(() => document.documentElement.dataset.journeyMode), 'advanced');
    assert.equal(await second.locator('#sepolia-section').isVisible(), true);
    await second.locator('#journey-mode').click();
    assert.equal(await second.evaluate(() => document.documentElement.dataset.journeyMode), 'guided');
    assert.equal(await second.locator('#sepolia-section').isVisible(), false);

    const resume = await browser.newPage({viewport: {width: 1280, height: 800}});
    await resume.route(base + '/', route => route.fulfill({status: 200, body: html, headers: {'content-type': 'text/html; charset=utf-8', 'content-security-policy': HOSTED_CSP}}));
    await resume.goto(base);
    await resume.getByRole('button', {name: /Continue a swap/}).click();
    assert.match(await resume.locator('#journey-context-copy').innerText(), /does not yet support token or NFT swaps/);
    assert.equal(await resume.locator('#guided-terms').isVisible(), true);
    assert.equal(await resume.locator('#guided-swap-status').isVisible(), false);
    assert.equal(await resume.locator('#guided-check').isVisible(), false);
    await resume.locator('#journey-guided-next').click();
    assert.match(await resume.locator('#journey-guided-terms-status').innerText(), /valid swap terms JSON/);
    const vectors = JSON.parse(await readFile('config/swap/flow-vectors.json', 'utf8'));
    await resume.locator('#guided-terms').fill(JSON.stringify(vectors.ids[0].terms));
    await resume.locator('#journey-guided-next').click();
    assert.equal(await resume.locator('#guided-terms').isVisible(), false);
    assert.equal(await resume.locator('#guided-swap-status').isVisible(), true);
    assert.equal(await resume.locator('#guided-check').isVisible(), true);
    await resume.locator('#journey-guided-previous').click();
    assert.equal(await resume.locator('#guided-terms').isVisible(), true);

    const publicMaker = await browser.newPage();
    await publicMaker.route(base + '/', route => route.fulfill({status: 200, body: html, headers: {'content-type': 'text/html; charset=utf-8', 'content-security-policy': HOSTED_CSP}}));
    await publicMaker.goto(base);
    await publicMaker.getByRole('button', {name: /Create an offer/}).click();
    await publicMaker.locator('#journey-give-type').selectOption('ethereum:eth');
    await publicMaker.locator('#journey-next').click();
    await publicMaker.locator('#journey-give-amount').fill('0.5');
    await publicMaker.locator('#journey-next').click();
    await publicMaker.locator('#journey-receive-type').selectOption('cardano:ada');
    await publicMaker.locator('#journey-next').click();
    await publicMaker.locator('#journey-receive-amount').fill('1.25');
    await publicMaker.locator('#journey-next').click();
    await publicMaker.locator('[name="journey-visibility"][value="public"]').check();
    await publicMaker.locator('#journey-next').click();
    await publicMaker.locator('#journey-lifetime').selectOption('3600');
    await publicMaker.locator('#journey-next').click();
    await publicMaker.locator('[name="journey-backup"][value="no"]').check();
    await publicMaker.locator('#journey-next').click();
    await publicMaker.locator('#journey-publish').click();
    await publicMaker.locator('#journey-created').waitFor({state: 'visible'});
    assert.equal(await publicMaker.locator('#journey-see-offer').isDisabled(), false);
    await publicMaker.locator('#journey-back').click();
    await publicMaker.getByRole('button', {name: /Explore public offers/}).click();
    assert.match(await publicMaker.locator('#board').innerText(), /0\.5 ETH \(500000000000000000 wei\)/);
    assert.match(await publicMaker.locator('#board').innerText(), /1\.25 ADA \(1250000 lovelace\)/);
  } finally {
    await browser?.close();
    server.kill('SIGTERM'); await Promise.race([once(server, 'exit'), new Promise(done => setTimeout(done, 2000))]);
    await rm(directory, {recursive: true, force: true});
  }
});
