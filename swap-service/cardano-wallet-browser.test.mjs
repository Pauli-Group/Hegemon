import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {chromium} from 'playwright-core';
import {blake2b, ed25519, sha256} from '../swap-ui/vendor/hash.mjs';
import * as ct from '../swap-ui/cardano-tx.mjs';
import {fromHex, spans, toHex} from '../swap-ui/cbor.mjs';
import {PREVIEW_HTLC_ADDRESS} from '../swap-ui/cardano-preview-verifier.mjs';
import {rowOf, softwareWallet} from './tools/cardano-bridge.mjs';

async function port() { const s = createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening'); const n = s.address().port; await new Promise(r => s.close(r)); return n; }

const script = JSON.parse(await readFile(new URL('../swap-ui/cardano-htlc-script.json', import.meta.url), 'utf8'));
const rawParams = JSON.parse(await readFile(new URL('../swap-ui/fixtures/cardano-preview-params.json', import.meta.url), 'utf8'));
ct.setPinnedScript(script);
const seeds = {alice: new Uint8Array(32).fill(3), bob: new Uint8Array(32).fill(4)};
const keyHash = seed => toHex(blake2b(ed25519.getPublicKey(seed), {dkLen: 28}));
const people = Object.fromEntries(Object.entries(seeds).map(([name, seed]) => [name, {seed, hash: keyHash(seed), address: ct.toBech32(new Uint8Array([0x60, ...fromHex(keyHash(seed))]))}]));
const ESCROW = 'ee'.repeat(32) + '#0';

test('Cardano wallet actions in the page: review before signing, journal first, and every wallet failure fails safe', {timeout: 150000}, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'cardano-wallet-')), n = await port(), base = `http://127.0.0.1:${n}`;
  const server = spawn(process.execPath, [resolve('swap-service/server.ts')], {env: {...process.env, SWAP_DB: join(dir, 'offers.db'), SWAP_PORT: String(n)}, stdio: 'ignore'});
  let browser;
  try {
    for (let i = 0; i < 100; i++) { try { if ((await fetch(base + '/health')).ok) break; } catch {} await new Promise(r => setTimeout(r, 50)); }
    browser = await chromium.launch({executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox']});
    const now = Math.floor(Date.now() / 1000), slot = now - 1666656000;
    const state = {owner: 'alice', network: 0, hideChain: false, declines: false, failSign: false, escrowSlot: slot, expiry: now + 86400};
    const utxosFor = owner => [
      {ref: '01'.repeat(32) + '#0', address: people[owner].address, lovelace: 50_000_000, assets: {}},
      {ref: '02'.repeat(32) + '#0', address: people[owner].address, lovelace: 6_000_000, assets: {}},
    ];
    const signed = [], calls = {sign: 0};
    const context = await browser.newContext();
    await context.exposeFunction('mockWallet', async (method, args) => {
      const wallet = softwareWallet({seed: people[state.owner].seed, address: people[state.owner].address, utxos: utxosFor(state.owner), collateral: [utxosFor(state.owner)[1].ref], declines: state.declines, failSign: state.failSign, onSubmit: hex => signed.push(hex)});
      if (method === 'getNetworkId') return state.network;
      if (method === 'signTx') calls.sign++;
      return wallet[method](...args);
    });
    await context.addInitScript(() => {
      const call = method => (...args) => window.mockWallet(method, args).catch(error => { throw Object.assign(new Error(String(error.message).replace(/^.*Error: /, '')), error.message.includes('declined') ? {code: 2, info: 'User declined'} : {}); });
      window.cardano = {mock: {name: 'Mock CIP-30', enable: async () => Object.fromEntries(['getNetworkId', 'getUtxos', 'getCollateral', 'getUsedAddresses', 'getUnusedAddresses', 'getChangeAddress', 'signTx', 'submitTx'].map(m => [m, call(m)]))}};
    });
    await context.route('**/cardano-preview/params', route => route.fulfill({json: {...rawParams, slot}}));
    await context.route('**/cardano-preview/utxos?*', route => {
      const refs = new URL(route.request().url()).searchParams.get('refs').split(',');
      const known = new Map(utxosFor(state.owner).map(u => [u.ref, rowOf(u)]));
      route.fulfill({json: {...rawParams, slot, outputs: refs.map(r => (state.hideChain ? null : known.get(r) ?? null))}});
    });
    let escrowTerms;
    await context.route('**/cardano-preview/escrow?*', route => {
      const t = ct.parseTerms(escrowTerms), datum = toHex(ct.datumBytes(t));
      route.fulfill({json: {network: 'preview', magic: 2, system_start: 1666656000, slot: state.escrowSlot, confirmations: 500, output: {tx_hash: ESCROW.split('#')[0], tx_index: 0, address: PREVIEW_HTLC_ADDRESS, value: escrowTerms.lovelace, is_spent: false, asset_list: [],
        inline_datum: {bytes: datum, value: {constructor: 0, fields: [{bytes: escrowTerms.hashlock}, {bytes: escrowTerms.claimant}, {bytes: escrowTerms.refundee}, {int: Number(escrowTerms.expiry_ms)}]}}}}});
    });
    const page = await context.newPage();
    await page.goto(base);
    await page.evaluate(() => { document.getElementById('cardano-wallet-section').hidden = false; });
    const connect = async () => { await page.locator('#cardano-wallet').selectOption('mock'); await page.locator('#connect-cardano').click(); await page.waitForFunction(() => /Cardano connected/.test(document.getElementById('wallet-status').textContent) || document.getElementById('wallet-status').className === 'error'); };
    const status = () => page.locator('#cardano-wallet-status').innerText();
    const journal = () => page.evaluate(async () => (await import('/action-journal.mjs')).listActions());
    const fill = async terms => { for (const [k, v] of Object.entries(terms)) await page.locator(`#cardano-wallet-form [name="${k}"]`).fill(v); };
    const settle = () => page.waitForFunction(() => !document.querySelector('#cardano-wallet-form button').disabled);
    const terms = (extra = {}) => ({lovelace: '10000000', assets: '', hashlock: toHex(sha256(fromHex('5a'.repeat(32)))), claimant: people.bob.hash, refundee: people.alice.hash, expiry_ms: String(state.expiry * 1000), ...extra});

    // 0. No wallet: nothing happens, no wallet call.
    await fill(terms());
    await page.locator('#cardano-fund').click();
    await page.waitForFunction(() => /Connect a Cardano/.test(document.getElementById('cardano-wallet-status').textContent));

    // 1. A wallet on another network (id 1) is not accepted as a connection.
    state.network = 1; await connect();
    await page.locator('#cardano-fund').click();
    await page.waitForFunction(() => /Connect a Cardano/.test(document.getElementById('cardano-wallet-status').textContent));
    assert.equal(calls.sign, 0);

    // 2. Network id 0 but the wallet's UTxOs are unknown to preview (a preprod wallet): refused before any signature request.
    state.network = 0; state.hideChain = true; await connect();
    await page.locator('#cardano-fund').click();
    await page.waitForFunction(() => /None of the wallet UTxOs exist on Cardano preview/.test(document.getElementById('cardano-wallet-status').textContent));
    assert.equal(calls.sign, 0);
    assert.equal((await journal()).length, 0);
    state.hideChain = false;

    // 3. Fund: the page shows what the transaction does and does not contact the wallet to sign until approved.
    await page.locator('#cardano-fund').click();
    await page.waitForFunction(() => !document.getElementById('cardano-confirm').hidden);
    const review = await page.locator('#cardano-confirm-text').innerText();
    assert.match(review, /Lock 10000000 lovelace/);
    assert.match(review, /Network fee \d+ lovelace/);
    assert.equal(calls.sign, 0, 'no signature has been requested before approval');
    assert.equal((await journal()).length, 0, 'the journal is written after approval and before the wallet request');
    await page.locator('#cardano-confirm-no').click(); await settle();
    assert.equal(calls.sign, 0); assert.equal((await journal()).length, 0);
    await page.locator('#cardano-fund').click();
    await page.waitForFunction(() => !document.getElementById('cardano-confirm').hidden);
    await page.locator('#cardano-confirm-yes').click();
    await page.waitForFunction(() => /Transaction submitted/.test(document.getElementById('cardano-wallet-status').textContent), null, {timeout: 20000});
    assert.equal(calls.sign, 1);
    let records = await journal();
    assert.equal(records.length, 1);
    assert.equal(records[0].state, 'completed'); assert.equal(records[0].operation, 'lock');
    const fundTx = ct.inspectTx(fromHex(signed.at(-1)));
    assert.equal(fundTx.outputs[0].value.lovelace, 10_000_000n);
    assert.deepEqual(fundTx.outputs[0].datum.bytes, ct.datumBytes(terms()));
    assert.equal(JSON.parse(await page.locator('#cardano-wallet-result').innerText()).txid, toHex(fundTx.bodyHash));

    // 4. A wallet that declines leaves no journal record and nothing submitted.
    const before = signed.length;
    state.declines = true;
    await page.locator('#cardano-fund').click();
    await page.waitForFunction(() => !document.getElementById('cardano-confirm').hidden);
    await page.locator('#cardano-confirm-yes').click();
    await page.waitForFunction(() => /declined/.test(document.getElementById('cardano-wallet-status').textContent));
    assert.equal(signed.length, before);
    assert.equal((await journal()).length, 1, 'the declined attempt was removed from the journal');
    state.declines = false;

    // 5. Claim from an encrypted backup. A wrong passphrase never reaches the wallet; the right one reveals the preimage once.
    await page.locator('#vault-create [name="label"]').fill('cardano claim test');
    await page.locator('#vault-create [name="passphrase"]').fill('a long enough passphrase');
    await page.locator('#vault-create [name="confirm"]').fill('a long enough passphrase');
    await page.getByRole('button', {name: 'Create encrypted secret'}).click();
    await page.waitForFunction(() => document.getElementById('vault-backup').value.includes('hashlock'));
    const hashlock = JSON.parse(await page.locator('#vault-backup').inputValue()).envelope.hashlock;
    state.owner = 'bob'; await connect();
    escrowTerms = terms({hashlock, outref: ESCROW});
    await fill(escrowTerms);
    await page.locator('#cardano-claim-backup').selectOption(hashlock);
    const signBefore = calls.sign;
    await page.locator('#cardano-claim-passphrase').fill('definitely the wrong passphrase');
    await page.locator('#cardano-claim').click();
    await page.waitForFunction(() => document.getElementById('cardano-wallet-status').className === 'error' && !document.querySelector('#cardano-wallet-form button').disabled);
    assert.equal(calls.sign, signBefore);
    await page.locator('#cardano-claim-passphrase').fill('a long enough passphrase');
    await page.locator('#cardano-claim').click();
    await page.waitForFunction(() => !document.getElementById('cardano-confirm').hidden);
    assert.match(await page.locator('#cardano-confirm-text').innerText(), /reveals the swap secret on chain/);
    assert.equal(calls.sign, signBefore, 'the secret stays in the page until the user approves');
    await page.locator('#cardano-confirm-yes').click();
    await page.waitForFunction(() => /Transaction submitted/.test(document.getElementById('cardano-wallet-status').textContent), null, {timeout: 20000});
    assert.equal(calls.sign, signBefore + 1);
    const claimTx = ct.inspectTx(fromHex(signed.at(-1)));
    const revealed = claimTx.redeemers[0].data.value[0];
    assert.equal(toHex(sha256(revealed)), hashlock, 'the redeemer carries the preimage of the agreed hashlock');
    assert.equal(claimTx.signers[0], people.bob.hash);
    assert.equal(claimTx.ttl, slot + 3600);
    records = await journal();
    assert.equal(records.find(r => r.operation === 'claim').state, 'completed');
    assert.equal(JSON.stringify(records).includes(toHex(revealed)), false, 'the journal never stores the preimage');

    // 6. A claim inside the deadline cutoff is refused by the verifier before anything reaches the wallet.
    state.expiry = now + 120;
    escrowTerms = terms({hashlock, outref: ESCROW});
    await fill(escrowTerms);
    await page.locator('#cardano-claim-passphrase').fill('a long enough passphrase');
    const afterClaim = calls.sign;
    await page.locator('#cardano-claim').click();
    await page.waitForFunction(() => document.getElementById('cardano-wallet-status').className === 'error' && !document.querySelector('#cardano-wallet-form button').disabled);
    assert.match(await status(), /too close|cutoff/);
    assert.equal(calls.sign, afterClaim);

    // 7. Refund after the deadline by the refundee.
    state.owner = 'alice'; await connect();
    state.expiry = now - 600; state.escrowSlot = slot;
    escrowTerms = terms({hashlock, outref: ESCROW});
    await fill(escrowTerms);
    await page.locator('#cardano-refund').click();
    await page.waitForFunction(() => !document.getElementById('cardano-confirm').hidden);
    assert.match(await page.locator('#cardano-confirm-text').innerText(), /Refund 10000000 lovelace/);
    await page.locator('#cardano-confirm-yes').click();
    await page.waitForFunction(() => /Transaction submitted/.test(document.getElementById('cardano-wallet-status').textContent), null, {timeout: 20000});
    const refundTx = ct.inspectTx(fromHex(signed.at(-1)));
    assert.equal(refundTx.start, state.expiry - 1666656000);
    assert.equal(refundTx.signers[0], people.alice.hash);
    assert.equal(spans(fromHex(signed.at(-1))).length, 4);
  } finally {
    await browser?.close();
    server.kill();
    await rm(dir, {recursive: true, force: true});
  }
});
