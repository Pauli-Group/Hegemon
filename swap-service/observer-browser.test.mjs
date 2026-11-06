import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {spawn} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {chromium} from 'playwright-core';
import {sha256} from '../swap-ui/vendor/hash.mjs';
import {bitcoinWitnessScript, TESTNET4_GENESIS} from '../swap-ui/bitcoin-testnet-verifier.mjs';
import {fromHex, toHex} from '../swap-ui/cbor.mjs';

async function port() { const s = createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening'); const n = s.address().port; await new Promise(r => s.close(r)); return n; }
const preimage = '5a'.repeat(32), hashlock = toHex(sha256(fromHex(preimage)));
const btc = {txid: 'aa'.repeat(32), vout: 1, hashlock, claimant_key: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa', refund_key: '02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27', refund_height: 200000, amount_sats: 5000};
const contract = '0x' + 'ab'.repeat(20);

test('Observing a counterparty claim in the page: found, verified against the hashlock, saved encrypted; pending and bad data are not results', {timeout: 120000}, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'observer-')), n = await port(), base = `http://127.0.0.1:${n}`;
  const server = spawn(process.execPath, [resolve('swap-service/server.ts')], {env: {...process.env, SWAP_DB: join(dir, 'offers.db'), SWAP_PORT: String(n)}, stdio: 'ignore'});
  let browser;
  try {
    for (let i = 0; i < 100; i++) { try { if ((await fetch(base + '/health')).ok) break; } catch {} await new Promise(r => setTimeout(r, 50)); }
    browser = await chromium.launch({executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox']});
    const state = {btcWitness: ['30' + 'ab'.repeat(70), preimage, '01', bitcoinWitnessScript(btc)], btcConfirmations: 3, ethData: '0x' + preimage, ethSpent: true, ethEvents: true, cardano: {spent: true, indexed: false}};
    const context = await browser.newContext(), requests = [];
    await context.route('**/bitcoin-testnet4/spend?*', route => { requests.push(route.request().url()); route.fulfill({json: {genesis: TESTNET4_GENESIS, txid: btc.txid, vout: 1, tip: 1000, spent: true, spend: {txid: 'bb'.repeat(32), vin: 0, confirmed: state.btcConfirmations > 0, confirmations: state.btcConfirmations, witness: state.btcWitness}}}); });
    await context.route('**/sepolia/escrow-events?*', route => route.fulfill({json: {chain_id: 11155111, contract, tip: 100, deployed: true, spent: state.ethSpent, source: 'rpc',
      events: state.ethEvents ? [{kind: 'claimed', topic: '0x0508a8b4117d9a7b3d8f5895f6413e61b4f9a2df35afbfb41e78d0ecfff1843f', tx_hash: '0x' + 'cd'.repeat(32), block_number: 90, confirmations: 11, data: state.ethData}] : []}}));
    await context.route('**/cardano-preview/spend?*', route => route.fulfill({json: {network: 'preview', outref: new URL(route.request().url()).searchParams.get('outref'), ...state.cardano}}));
    const page = await context.newPage();
    await page.goto(base);
    await page.evaluate(() => { document.getElementById('observer-section').hidden = false; });
    const status = () => page.locator('#observer-status').innerText();
    const look = async () => {
      await page.evaluate(() => { const el = document.getElementById('observer-status'); el.textContent = ''; el.className = ''; });
      await page.locator('#observer-look').click();
      await page.waitForFunction(() => { const t = document.getElementById('observer-status').textContent; return t !== '' && t !== 'Reading the chain.'; });
    };
    const fill = async fields => { for (const [k, v] of Object.entries(fields)) await page.locator(`#observer-form [name="${k}"]`).fill(String(v)); };
    const vault = () => page.evaluate(async () => (await import('/vault-store.mjs')).listVault());

    // Bitcoin: a confirmed claim is found, shown without the secret, and saved only after the user sets a passphrase.
    await fill({hashlock, txid: btc.txid, vout: 1, claimant_key: btc.claimant_key, refund_key: btc.refund_key, refund_height: btc.refund_height});
    await look();
    assert.match(await status(), /Claim found and it hashes/);
    assert.equal((await page.locator('#observer-result').innerText()).includes(preimage), false, 'the result view never prints the secret');
    assert.equal(await page.locator('#observer-save-panel').isVisible(), true);
    await page.locator('#observer-passphrase').fill('a long enough passphrase');
    await page.locator('#observer-confirm').fill('a different passphrase!!');
    await page.locator('#observer-save').click();
    await page.waitForFunction(() => /passphrases/.test(document.getElementById('observer-status').textContent));
    assert.equal((await vault()).length, 0, 'mismatched passphrases save nothing');
    await page.locator('#observer-passphrase').fill('a long enough passphrase');
    await page.locator('#observer-confirm').fill('a long enough passphrase');
    await page.locator('#observer-save').click();
    await page.waitForFunction(() => /Encrypted backup saved/.test(document.getElementById('observer-status').textContent));
    const saved = await vault();
    assert.equal(saved.length, 1);
    assert.equal(saved[0].envelope.hashlock, hashlock);
    assert.equal(JSON.stringify(saved).includes(preimage), false, 'only ciphertext is stored');
    assert.equal(await page.locator('#observer-passphrase').inputValue(), '');
    const unlocked = await page.evaluate(async hash => { const {listVault} = await import('/vault-store.mjs'); const {unlockRecovery} = await import('/recovery.mjs'); const e = (await listVault())[0].envelope; return Array.from(await unlockRecovery(e, 'a long enough passphrase'), b => b.toString(16).padStart(2, '0')).join(''); }, hashlock);
    assert.equal(unlocked, preimage);

    // A shallow claim is reported as such; a witness that does not hash to the hashlock is an error.
    state.btcConfirmations = 0; await look();
    assert.match(await status(), /0 of 2 required confirmations/);
    state.btcConfirmations = 3; state.btcWitness = [state.btcWitness[0], '77'.repeat(32), '01', state.btcWitness[3]]; await look();
    assert.equal(await page.locator('#observer-status').getAttribute('class'), 'error');
    assert.match(await status(), /does not hash/);
    assert.equal(await page.locator('#observer-save-panel').isVisible(), false);

    // Ethereum: spent without a visible event is pending; with the event the secret is learned.
    await page.locator('#observer-form [name="chain"]').selectOption('ethereum');
    await fill({contract});
    state.ethEvents = false; await look();
    assert.match(await status(), /not visible yet/);
    assert.equal(await page.locator('#observer-save-panel').isVisible(), false);
    state.ethEvents = true; await look();
    assert.match(await status(), /Claim found/);
    state.ethData = '0x' + '77'.repeat(32); await look();
    assert.match(await status(), /does not hash/);

    // Cardano: an unindexed spend is pending, not "nothing happened".
    await page.locator('#observer-form [name="chain"]').selectOption('cardano');
    await fill({outref: 'ee'.repeat(32) + '#0'});
    await look();
    assert.match(await status(), /not indexed|has not indexed/);
    assert.match(await status(), /not evidence that nothing happened/);
    state.cardano = {spent: false};
    await look();
    assert.match(await status(), /No spend/);
  } finally {
    await browser?.close();
    server.kill();
    await rm(dir, {recursive: true, force: true});
  }
});
