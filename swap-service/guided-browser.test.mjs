import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {spawn} from 'node:child_process';
import {readFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {chromium} from 'playwright-core';
import {sha256} from '../swap-ui/vendor/hash.mjs';
import {expectedBitcoinScript, TESTNET4_GENESIS} from '../swap-ui/bitcoin-testnet-verifier.mjs';
import {PREVIEW_HTLC_ADDRESS} from '../swap-ui/cardano-preview-verifier.mjs';
import {fromHex, toHex} from '../swap-ui/cbor.mjs';
import {planWithMargin, swapId, termsDigest} from '../swap-ui/swap-flow.mjs';

async function port() { const s = createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening'); const n = s.address().port; await new Promise(r => s.close(r)); return n; }
const config = JSON.parse(await readFile(new URL('../swap-ui/chain-timing.json', import.meta.url), 'utf8'));
const hashlock = toHex(sha256(fromHex('5a'.repeat(32))));
const BTC = {initiator: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa', responder: '02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27'};
const ADA = {initiator: 'c5'.repeat(28), responder: '88'.repeat(28)};

test('Guided swap in the page: policy verdict, engine-equal decision, wallet form prefill without any wallet request, and every refusal', {timeout: 120000}, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'guided-')), n = await port(), base = `http://127.0.0.1:${n}`;
  const server = spawn(process.execPath, [resolve('swap-service/server.ts')], {env: {...process.env, SWAP_DB: join(dir, 'offers.db'), SWAP_PORT: String(n)}, stdio: 'ignore'});
  let browser;
  try {
    for (let i = 0; i < 100; i++) { try { if ((await fetch(base + '/health')).ok) break; } catch {} await new Promise(r => setTimeout(r, 50)); }
    browser = await chromium.launch({executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox']});
    const now = Math.floor(Date.now() / 1000), tip = 100_000;
    const plan = planWithMargin(config, 'bitcoin', 'cardano', {long: {observedAt: now, height: tip}, short: {observedAt: now, timestamp: now - 5}}, now);
    const terms = {version: 1, hashlock, legs: {
      long: {chain: 'bitcoin', amount: 60_000, refundee: BTC.initiator, claimant: BTC.responder, expiry: plan.long.expiry},
      short: {chain: 'cardano', amount: 5_000_000, refundee: ADA.responder, claimant: ADA.initiator, expiry: plan.short.expiry}}};
    const status = async extra => ({swap_id: await swapId(terms), role: 'initiator', state: 'long_funded', inflight: null, needs_human: null, terms_digest: await termsDigest(terms),
      escrows: {long: {txid: 'aa'.repeat(32), vout: 1}, short: {txid: 'cc'.repeat(32), vout: 0}}, txids: {}, ...extra});
    const script = await expectedBitcoinScript({txid: 'aa'.repeat(32), vout: 1, amount_sats: 60_000, hashlock, claimant_key: BTC.responder, refund_key: BTC.initiator, refund_height: terms.legs.long.expiry});
    const state = {shortValue: '5000000', walletCalls: 0};
    const context = await browser.newContext();
    await context.addInitScript(() => { window.ethereum = {request: () => { throw Error('wallet must not be contacted'); }}; });
    await context.route('**/bitcoin-testnet4/head', route => route.fulfill({json: {genesis: TESTNET4_GENESIS, tip}}));
    await context.route('**/bitcoin-testnet4/escrow?*', route => route.fulfill({json: {genesis: TESTNET4_GENESIS, txid: 'aa'.repeat(32), vout: 1, tip, confirmed: true, confirmations: 6, block_height: tip - 5, block_hash: 'b'.repeat(64), spent: false, amount_sats: 60_000, script}}));
    await context.route('**/cardano-preview/params', route => route.fulfill({json: {network: 'preview', magic: 2, system_start: 1666656000, slot: now - 1666656000 - 5}}));
    await context.route('**/cardano-preview/escrow?*', route => route.fulfill({json: {network: 'preview', magic: 2, system_start: 1666656000, slot: now - 1666656000 - 5, confirmations: 6, output: {tx_hash: 'cc'.repeat(32), tx_index: 0, address: PREVIEW_HTLC_ADDRESS, value: state.shortValue, asset_list: [], is_spent: false,
      inline_datum: {value: {constructor: 0, fields: [{bytes: hashlock}, {bytes: ADA.initiator}, {bytes: ADA.responder}, {int: terms.legs.short.expiry * 1000}]}}}}}));
    const page = await context.newPage();
    await page.goto(base);
    await page.evaluate(() => { document.getElementById('guided-section').hidden = false; });
    const check = async (t, s) => {
      await page.locator('#guided-terms').fill(JSON.stringify(t));
      await page.locator('#guided-swap-status').fill(JSON.stringify(s));
      await page.evaluate(() => { const el = document.getElementById('guided-status'); el.textContent = ''; el.className = ''; });
      await page.locator('#guided-check').click();
      await page.waitForFunction(() => { const t = document.getElementById('guided-status').textContent; return t !== '' && t !== 'Reading the chains.'; });
    };
    const text = id => page.locator('#' + id).innerText();

    // 1. Initiator, both escrows good: the engine would record the short leg as verified.
    await check(terms, await status());
    assert.match(await text('guided-headline'), /short_verified|short leg verified/i);
    assert.match(await text('guided-detail'), /Timelock policy: allows these terms/);
    assert.match(await text('guided-detail'), /short leg \(cardano\): verified, 6 confirmations/);
    assert.match(await text('guided-command'), /swap_engine_cli.py advance [0-9a-f]{16}/);
    assert.equal(await page.locator('#guided-sequence li[aria-current="step"]').innerText(), 'Long leg funded');
    assert.equal(await page.locator('#guided-fill').isHidden(), true);

    // 2. A contradicting short escrow is shown as a mismatch and the page does not move.
    state.shortValue = '4999999';
    await check(terms, await status());
    assert.match(await text('guided-detail'), /MISMATCH escrow differs from the terms in value/);
    assert.match(await text('guided-headline'), /Wait/);
    state.shortValue = '5000000';

    // 3. Ready to claim: the form is filled with the agreed terms, nothing is submitted, no wallet is touched, and no secret exists in the page.
    await check(terms, await status({state: 'short_verified'}));
    assert.match(await text('guided-headline'), /Stopped: the preimage/, 'without an encrypted backup the page says the claim cannot proceed');
    await page.evaluate(async hash => {
      const {encryptRecovery} = await import('/recovery.mjs'), {addVault} = await import('/vault-store.mjs');
      await addVault({label: 'guided', envelope: await encryptRecovery(Uint8Array.from({length: 32}, () => 0x5a), 'a long enough passphrase')});
    }, hashlock);
    await check(terms, await status({state: 'short_verified'}));
    assert.match(await text('guided-headline'), /claim the short leg on cardano/);
    assert.match(await text('guided-detail'), /Submit the claim within \d+s/);
    assert.equal(await page.locator('#cardano-wallet-section').isHidden(), true);
    await page.locator('#guided-fill').click();
    assert.equal(await page.locator('#cardano-wallet-section').isVisible(), true, 'the form the page filled is revealed');
    const value = name => page.locator(`#cardano-wallet-form [name="${name}"]`).inputValue();
    assert.deepEqual([await value('hashlock'), await value('claimant'), await value('refundee'), await value('lovelace'), await value('expiry_ms'), await value('outref')],
      [hashlock, ADA.initiator, ADA.responder, '5000000', String(terms.legs.short.expiry * 1000), 'cc'.repeat(32) + '#0']);
    assert.equal((await page.evaluate(async () => (await import('/action-journal.mjs')).listActions())).length, 0, 'filling a form writes no action record');

    // 4. An unsettled saved action for this swap is reported before anything else.
    await page.evaluate(async hash => (await import('/action-journal.mjs')).beginAction('cardano', 'claim', {operation: 'claim', hashlock: hash, claimant: 'c5'.repeat(28), refundee: '88'.repeat(28), expiry_ms: '1', expected_value: {lovelace: '1'}, outref: 'cc'.repeat(32) + '#0', fee_input: '01'.repeat(32) + '#0', collateral: '02'.repeat(32) + '#0'}), hashlock);
    await check(terms, await status({state: 'short_verified'}));
    assert.match(await text('guided-notes'), /pending or uncertain/);

    // 5. needs_human and inflight are shown and the page does not suggest an action.
    await check(terms, await status({state: 'short_claim_submitted', needs_human: 'claim not visible long after submission', inflight: {action: 'claim'}}));
    assert.match(await text('guided-notes'), /in flight/);
    assert.match(await text('guided-notes'), /stopped for a human/);
    assert.match(await text('guided-headline'), /Stopped/);

    // 6a. Terms the timelock policy rejects are reported as rejected, with the reason.
    const tight = {...terms, legs: {...terms.legs, short: {...terms.legs.short, expiry: terms.legs.long.expiry}}};
    await check(tight, {...(await status({state: 'terms_saved', escrows: {long: null, short: null}})), swap_id: await swapId(tight), terms_digest: await termsDigest(tight)});
    assert.match(await text('guided-detail'), /Timelock policy: rejects these terms\n\s+\w+/);

    // 6. A status for another swap, and a Hegemon leg, are refused or labelled.
    await check(terms, {...(await status()), swap_id: '0'.repeat(16)});
    assert.equal(await page.locator('#guided-status').getAttribute('class'), 'error');
    assert.match(await text('guided-status'), /different swap/);
    const hegemon = {...terms, legs: {...terms.legs, long: {chain: 'hegemon', amount: 5, refundee: 'shca1aaa', claimant: 'shca1bbb', expiry: 900_000}}};
    await check(hegemon, {...(await status({state: 'terms_saved', escrows: {long: null, short: null}})), swap_id: await swapId(hegemon), terms_digest: await termsDigest(hegemon)});
    assert.match(await text('guided-notes'), /Hegemon has no public testnet leg/);
  } finally {
    await browser?.close();
    server.kill();
    await rm(dir, {recursive: true, force: true});
  }
});
