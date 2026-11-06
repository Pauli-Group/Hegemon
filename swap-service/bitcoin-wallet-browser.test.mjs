import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {spawn} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {chromium} from 'playwright-core';
import {Address, TEST_NETWORK, Transaction, p2wpkh, secp256k1, sha256} from '../swap-ui/vendor/btc-signer.mjs';
import {expectedBitcoinScript, TESTNET4_GENESIS} from '../swap-ui/bitcoin-testnet-verifier.mjs';

async function port() { const s = createServer(); s.listen(0, '127.0.0.1'); await once(s, 'listening'); const n = s.address().port; await new Promise(r => s.close(r)); return n; }
const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const unhex = s => Uint8Array.from(s.match(/../g) ?? [], x => parseInt(x, 16));
const priv = {claimant: new Uint8Array(32).fill(5), refunder: new Uint8Array(32).fill(6), wallet: new Uint8Array(32).fill(8)};
const pub = p => hex(secp256k1.getPublicKey(p, true));
const walletAddress = p2wpkh(secp256k1.getPublicKey(priv.wallet, true), TEST_NETWORK).address;
const destination = Address(TEST_NETWORK).encode({type: 'wpkh', hash: new Uint8Array(20).fill(4)});
const ESCROW_TXID = 'ee'.repeat(32);

/** What an external PSBT signer does: sign every input it holds the key for, using the library's own signer. */
function externalSign(base64, key) {
  const tx = Transaction.fromPSBT(Uint8Array.from(atob(base64), c => c.charCodeAt(0)));
  for (let i = 0; i < tx.inputsLength; i++) tx.signIdx(key, i);
  return Buffer.from(tx.toPSBT()).toString('base64');
}

test('Bitcoin PSBT actions in the page: export, external signature, re-check, broadcast, and every failure fails safe', {timeout: 150000}, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'bitcoin-wallet-')), n = await port(), base = `http://127.0.0.1:${n}`;
  const server = spawn(process.execPath, [resolve('swap-service/server.ts')], {env: {...process.env, SWAP_DB: join(dir, 'offers.db'), SWAP_PORT: String(n)}, stdio: 'ignore'});
  let browser;
  try {
    for (let i = 0; i < 100; i++) { try { if ((await fetch(base + '/health')).ok) break; } catch {} await new Promise(r => setTimeout(r, 50)); }
    browser = await chromium.launch({executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox']});
    const state = {tip: 100_000, spent: false, refundHeight: 105_000, broadcast: 'ok', broadcasts: [], escrowTerms: null};
    const context = await browser.newContext();
    await context.route('**/bitcoin-testnet4/escrow?*', async route => {
      const t = state.escrowTerms, url = new URL(route.request().url());
      assert.equal(url.searchParams.get('txid'), ESCROW_TXID);
      route.fulfill({json: {genesis: TESTNET4_GENESIS, txid: ESCROW_TXID, vout: 1, tip: state.tip, confirmed: true, confirmations: 10, block_height: state.tip - 9, block_hash: 'b'.repeat(64),
        spent: state.spent, amount_sats: t.amount_sats, script: await expectedBitcoinScript(t)}});
    });
    await context.route('**/bitcoin-testnet4/utxos?*', route => route.fulfill({json: {genesis: TESTNET4_GENESIS, address: new URL(route.request().url()).searchParams.get('address'), tip: state.tip,
      utxos: [{txid: '01'.repeat(32), vout: 0, amount_sats: 300_000, confirmations: 6, block_hash: 'b'.repeat(64)}]}}));
    await context.route('**/bitcoin-testnet4/broadcast', route => {
      const {tx} = route.request().postDataJSON();
      state.broadcasts.push(tx);
      const txid = Transaction.fromRaw(unhex(tx), {allowUnknownOutputs: true}).id;
      if (state.broadcast === 'ok') return route.fulfill({json: {txid}});
      if (state.broadcast === 'rejected') return route.fulfill({status: 400, json: {error: 'rejected by the Bitcoin network', reason: 'bad-txns-inputs-missingorspent'}});
      return route.abort('connectionreset');
    });
    const page = await context.newPage();
    await page.goto(base);
    await page.evaluate(() => { document.getElementById('bitcoin-wallet-section').hidden = false; });
    const status = () => page.locator('#bitcoin-wallet-status').innerText();
    const journal = () => page.evaluate(async () => (await import('/action-journal.mjs')).listActions());
    const fill = async terms => { for (const [k, v] of Object.entries(terms)) await page.locator(`#bitcoin-wallet-form [name="${k}"]`).fill(String(v)); };
    const build = async (op, terms) => {
      await page.locator('#bitcoin-wallet-form [name="operation"]').selectOption(op);
      await fill(terms);
      await click('#bitcoin-build');
    };
    const click = async selector => {
      await page.evaluate(() => { const el = document.getElementById('bitcoin-wallet-status'); el.textContent = ''; el.className = ''; });
      await page.locator(selector).click();
      await page.waitForFunction(() => { const t = document.getElementById('bitcoin-wallet-status').textContent; return t !== '' && !/^(Checking|Re-checking)/.test(t); });
    };
    const failed = async pattern => { assert.equal(await page.locator('#bitcoin-wallet-status').getAttribute('class'), 'error', await status()); assert.match(await status(), pattern); };
    const backupPhrase = 'a long enough passphrase';

    await page.locator('#vault-create [name="label"]').fill('bitcoin claim test');
    await page.locator('#vault-create [name="passphrase"]').fill(backupPhrase);
    await page.locator('#vault-create [name="confirm"]').fill(backupPhrase);
    await page.getByRole('button', {name: 'Create encrypted secret'}).click();
    await page.waitForFunction(() => document.getElementById('vault-backup').value.includes('hashlock'));
    const hashlock = JSON.parse(await page.locator('#vault-backup').inputValue()).envelope.hashlock;
    const agreed = (extra = {}) => ({hashlock, claimant_key: pub(priv.claimant), refund_key: pub(priv.refunder), refund_height: state.refundHeight, amount_sats: 60_000, ...extra});
    const spendForm = (extra = {}) => ({txid: ESCROW_TXID, vout: 1, address: destination, feerate: 2, ...agreed(extra)});
    state.escrowTerms = agreed();

    // 1. A claim too close to the refund height is refused before any record exists.
    state.refundHeight = state.tip + 3; state.escrowTerms = agreed();
    await build('claim', spendForm());
    await failed(/too close/);
    assert.equal((await journal()).length, 0);
    state.refundHeight = 105_000; state.escrowTerms = agreed();

    // 2. A normal claim: the PSBT is exported with a public record and no secret.
    await build('claim', spendForm());
    await page.waitForFunction(() => !document.getElementById('bitcoin-psbt-section').hidden);
    let records = await journal();
    assert.deepEqual(records.map(r => [r.chain, r.operation, r.state]), [['bitcoin', 'claim', 'pending']]);
    const exported = await page.locator('#bitcoin-psbt-out').inputValue();
    assert.match(await page.locator('#bitcoin-psbt-summary').innerText(), /Claim 60000 sats/);
    await page.locator('#bitcoin-claim-backup').selectOption(hashlock);

    // 3. A signature by the wrong role key, then a wrong passphrase: nothing is broadcast.
    await page.locator('#bitcoin-psbt-in').fill(externalSign(exported, priv.refunder));
    await page.locator('#bitcoin-claim-passphrase').fill(backupPhrase);
    await click('#bitcoin-broadcast');
    await failed(/claimant|signature|verify|key/i);
    await page.locator('#bitcoin-psbt-in').fill(externalSign(exported, priv.claimant));
    await page.locator('#bitcoin-claim-passphrase').fill('definitely the wrong passphrase');
    await click('#bitcoin-broadcast');
    await failed(/./);
    assert.equal(state.broadcasts.length, 0);

    // 4. The escrow is spent while the user was signing: refused, still nothing broadcast.
    state.spent = true;
    await page.locator('#bitcoin-claim-passphrase').fill(backupPhrase);
    await click('#bitcoin-broadcast');
    await failed(/spent/);
    assert.equal(state.broadcasts.length, 0);
    state.spent = false;

    // 5. A lost response: the record becomes uncertain and the page names the txid to look up.
    state.broadcast = 'lost';
    await page.locator('#bitcoin-claim-passphrase').fill(backupPhrase);
    await click('#bitcoin-broadcast');
    await failed(/may have been accepted/);
    assert.equal(state.broadcasts.length, 1);
    assert.deepEqual((await journal()).map(r => r.state), ['uncertain']);

    // 6. Rebuild, sign, broadcast successfully: the witness carries the preimage of the agreed hashlock.
    state.broadcast = 'ok';
    await build('claim', spendForm());
    await page.locator('#bitcoin-claim-backup').selectOption(hashlock);
    await page.locator('#bitcoin-psbt-in').fill(externalSign(await page.locator('#bitcoin-psbt-out').inputValue(), priv.claimant));
    await page.locator('#bitcoin-claim-passphrase').fill(backupPhrase);
    await click('#bitcoin-broadcast');
    await page.waitForFunction(() => /Broadcast/.test(document.getElementById('bitcoin-wallet-status').textContent));
    const sent = Transaction.fromRaw(unhex(state.broadcasts.at(-1)));
    assert.equal(hex(sha256(sent.getInput(0).finalScriptWitness[1])), hashlock);
    assert.equal(sent.getInput(0).finalScriptWitness.length, 4);
    const result = JSON.parse(await page.locator('#bitcoin-wallet-result').innerText());
    assert.equal(result.state, 'submitted');
    assert.equal(result.txid, sent.id);
    records = await journal();
    assert.deepEqual(records.map(r => r.state).sort(), ['completed', 'uncertain']);
    assert.equal(JSON.stringify(records).includes(hex(sent.getInput(0).finalScriptWitness[1])), false, 'the journal never stores the preimage');
    assert.equal(await page.locator('#bitcoin-claim-passphrase').inputValue(), '', 'the passphrase field is cleared');

    // 7. A refund is refused before the height and works after it, with nLockTime set.
    state.tip = 104_990; state.broadcasts = [];
    await build('refund', spendForm());
    await failed(/not valid yet/);
    state.tip = 105_000; state.escrowTerms = agreed();
    await build('refund', spendForm());
    await page.locator('#bitcoin-psbt-in').fill(externalSign(await page.locator('#bitcoin-psbt-out').inputValue(), priv.refunder));
    await click('#bitcoin-broadcast');
    await page.waitForFunction(() => /Broadcast/.test(document.getElementById('bitcoin-wallet-status').textContent));
    assert.equal(Transaction.fromRaw(unhex(state.broadcasts.at(-1))).lockTime, 105_000);

    // 8. A rejection is not uncertain: the record is removed.
    state.broadcast = 'rejected'; const before = (await journal()).length;
    await build('refund', spendForm());
    await page.locator('#bitcoin-psbt-in').fill(externalSign(await page.locator('#bitcoin-psbt-out').inputValue(), priv.refunder));
    await click('#bitcoin-broadcast');
    await failed(/rejected/);
    assert.equal((await journal()).length, before, 'the pending record of a rejected broadcast is removed');
    state.broadcast = 'ok';

    // 9. Fund from a wallet address; finalize-only does not broadcast and shows the raw transaction.
    state.broadcasts = [];
    await build('fund', {address: walletAddress, feerate: 2, ...agreed()});
    assert.match(await page.locator('#bitcoin-psbt-summary').innerText(), /Lock 60000 sats/);
    await page.locator('#bitcoin-psbt-in').fill(externalSign(await page.locator('#bitcoin-psbt-out').inputValue(), priv.wallet));
    await click('#bitcoin-finalize');
    await page.waitForFunction(() => /not broadcast by this page/.test(document.getElementById('bitcoin-wallet-status').textContent));
    assert.equal(state.broadcasts.length, 0);
    const raw = JSON.parse(await page.locator('#bitcoin-wallet-result').innerText()).raw_transaction;
    const funding = Transaction.fromRaw(unhex(raw), {allowUnknownOutputs: true});
    assert.equal(funding.getOutput(0).amount, 60_000n);
    assert.equal(hex(funding.getOutput(0).script), (await expectedBitcoinScript(agreed())));
  } finally {
    await browser?.close();
    server.kill();
    await rm(dir, {recursive: true, force: true});
  }
});
