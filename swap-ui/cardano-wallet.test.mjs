import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {blake2b, ed25519, sha256} from './vendor/hash.mjs';
import * as ct from './cardano-tx.mjs';
import {cardanoWalletAction, WalletError, parseWalletUtxo} from './cardano-wallet.mjs';
import {softwareWallet, rowOf} from '../swap-service/tools/cardano-bridge.mjs';
import {fromHex, toHex} from './cbor.mjs';

const here = new URL('.', import.meta.url);
ct.setPinnedScript(JSON.parse(fs.readFileSync(new URL('cardano-htlc-script.json', here), 'utf8')));
const units = JSON.parse(fs.readFileSync(new URL('cardano-htlc-script.json', here), 'utf8')).executionUnits;
const rawParams = JSON.parse(fs.readFileSync(new URL('fixtures/cardano-preview-params.json', here), 'utf8'));

const seedAlice = new Uint8Array(32).fill(3), seedBob = new Uint8Array(32).fill(4);
const hashOf = seed => toHex(blake2b(ed25519.getPublicKey(seed), {dkLen: 28}));
const addr = seed => ct.toBech32(new Uint8Array([0x60, ...fromHex(hashOf(seed))]));
const alice = {seed: seedAlice, hash: hashOf(seedAlice), address: addr(seedAlice)}, bob = {seed: seedBob, hash: hashOf(seedBob), address: addr(seedBob)};
const preimage = '5a'.repeat(32), hashlock = toHex(sha256(fromHex(preimage)));
const now = 1_667_000_000, slot = now - 1666656000, expiry = now + 7200;
const ESCROW = 'ee'.repeat(32) + '#0';
const u = (n, lovelace, owner, assets = {}) => ({ref: n.toString(16).padStart(64, '0') + '#0', address: owner.address, lovelace, assets});
const terms = (extra = {}) => ({hashlock, claimant: bob.hash, refundee: alice.hash, expiry_ms: String(expiry * 1000), lovelace: '10000000', assets: '', ...extra});

function world(opts = {}) {
  const owner = opts.owner ?? alice;
  const utxos = opts.utxos ?? [u(1, 40_000_000, owner), u(2, 6_000_000, owner)];
  const rows = new Map(utxos.map(x => [x.ref, rowOf(x)]));
  if (opts.escrowRow !== false) rows.set(ESCROW, rowOf({ref: ESCROW, address: 'addr_test1wqmp4fms223lnjljntag8vk9frl0l8pygsp2pt75tv2llsgmwwmyv', lovelace: 10_000_000}));
  const events = [], submitted = [];
  const journal = {
    records: [],
    async begin(chain, op, req) { if (opts.journalFails) throw Error('storage unavailable'); events.push('journal'); this.records.push({state: 'pending', chain, op, req}); return String(this.records.length - 1); },
    async finish(id, receipt) { this.records[id].state = 'completed'; this.records[id].receipt = receipt; },
    async uncertain(id) { this.records[id].state = 'uncertain'; },
    async remove(id) { this.records[id].state = 'removed'; },
  };
  const wallet = softwareWallet({seed: owner.seed, address: owner.address, utxos, collateral: opts.collateral ?? [utxos[1]?.ref], onSubmit: hex => submitted.push(hex), ...(opts.wallet ?? {})});
  const original = wallet.signTx;
  wallet.signTx = async (...args) => { events.push('sign'); return original(...args); };
  let reads = 0;
  const read = {
    params: async () => ({...rawParams, slot: opts.staleSecond && reads++ > 0 ? slot - 100 : slot, validitySlots: undefined}),
    utxos: async refs => ({slot, outputs: refs.map(r => (opts.hideChain ? null : rows.get(r) ?? null)).map((row, i) => (row && opts.mutateRow ? opts.mutateRow(row, i) : row))}),
  };
  const call = (op, extra = {}) => cardanoWalletAction({
    op, terms: terms(op === 'fund' ? {} : {outref: ESCROW}), preimage: op === 'claim' ? preimage : undefined, api: wallet, read, journal, budget: units,
    verifyEscrow: async () => ({slot}), confirm: async summary => { events.push('confirm'); return opts.decline ? false : (assert.ok(summary.lines.length >= 2), true); },
    nowSeconds: () => now, ...extra,
  });
  return {call, journal, events, submitted, wallet, read};
}
const refused = (promise, code) => assert.rejects(promise, error => { assert.ok(error instanceof WalletError, String(error)); assert.equal(error.code, code, error.message); return true; });

test('fund, claim and refund run end to end through a CIP-30 wallet, journal first', async () => {
  const f = world();
  const fund = await f.call('fund');
  assert.equal(fund.state, 'submitted');
  assert.deepEqual(f.events, ['confirm', 'journal', 'sign']);
  assert.equal(f.journal.records[0].state, 'completed');
  assert.equal(f.journal.records[0].op, 'lock');
  assert.equal(f.journal.records[0].receipt.txid, fund.txid);
  assert.match(fund.lines[0], /Lock 10000000 lovelace/);
  const c = world({owner: bob});
  const claim = await c.call('claim');
  assert.match(claim.lines[0], /reveals the swap secret/);
  assert.equal(c.journal.records[0].req.outref, ESCROW);
  assert.match(c.journal.records[0].req.fee_input, /^[0-9a-f]{64}#0$/);
  assert.equal(JSON.stringify(c.journal.records[0]).includes(preimage), false, 'the journal never holds the preimage');
  const r = world({}), refundTerms = terms({outref: ESCROW, expiry_ms: String((now - 100) * 1000)});
  const refund = await r.call('refund', {terms: refundTerms, nowSeconds: () => now});
  assert.equal(refund.state, 'submitted');
});

test('the signed transaction the wallet submits is the checked one with only the wallet witness added', async () => {
  const f = world();
  const result = await f.call('fund');
  const signed = ct.inspectTx(fromHex(f.submitted[0]));
  assert.equal(toHex(signed.bodyHash), result.txid);
  assert.equal(signed.vkeys.length, 1);
});

test('wrong network id, unknown UTxOs and mismatched values are refused before any wallet signature request', async () => {
  for (const [opts, code] of [[{wallet: {networkId: 1}}, 'wrong-network'], [{hideChain: true}, 'wrong-network'], [{mutateRow: row => ({...row, value: '1'})}, 'wrong-network'], [{mutateRow: row => ({...row, address: 'addr_test1other'})}, 'wrong-network']]) {
    const f = world(opts);
    await refused(f.call('fund'), code);
    assert.ok(!f.events.includes('sign') && !f.events.includes('journal'), JSON.stringify(opts));
    assert.equal(f.submitted.length, 0);
  }
});

test('a wallet that does not hold the named key is refused', async () => {
  const f = world({owner: bob});  // bob's wallet, but alice is the refundee
  await refused(f.call('fund'), 'wrong-key');
  const g = world({owner: alice});
  await refused(g.call('claim'), 'wrong-key');
  assert.equal(g.events.length, 0);
});

test('declining in the page, in the wallet, or losing the wallet connection fails safe', async () => {
  const page = world({decline: true});
  await refused(page.call('fund'), 'declined-locally');
  assert.deepEqual(page.events, ['confirm']);
  const wallet = world({wallet: {declines: true}});
  await refused(wallet.call('fund'), 'declined');
  assert.equal(wallet.journal.records[0].state, 'removed');
  assert.equal(wallet.submitted.length, 0);
  const lost = world({wallet: {failSign: true}});
  await refused(lost.call('fund'), 'sign-failed');
  assert.equal(lost.journal.records[0].state, 'uncertain');
  assert.equal(lost.submitted.length, 0);
});

test('if the journal cannot be written the wallet is never contacted', async () => {
  const f = world({journalFails: true});
  await assert.rejects(f.call('fund'), /storage unavailable/);
  assert.ok(!f.events.includes('sign'));
});

test('a lost submit response leaves an uncertain record and a known transaction id', async () => {
  const f = world({wallet: {failSubmit: true}});
  const result = await f.call('fund');
  assert.equal(result.state, 'uncertain');
  assert.match(result.txid, /^[0-9a-f]{64}$/);
  assert.equal(f.journal.records[0].state, 'uncertain');
  assert.match(result.message, /look it up/);
});

test('a wallet witness that does not verify, or a different submitted id, is never accepted', async () => {
  const f = world({wallet: {tamper: w => { const copy = w.slice(); copy[copy.length - 3] ^= 1; return copy; }}});
  await assert.rejects(f.call('fund'), /does not verify|malformed/);
  assert.equal(f.submitted.length, 0);
  const g = world();
  g.wallet.submitTx = async () => '00'.repeat(32);
  await refused(g.call('fund'), 'txid-mismatch');
  assert.equal(g.journal.records[0].state, 'uncertain');
});

test('the claim cutoff and a stale chain head refuse before the wallet is asked', async () => {
  const late = world({owner: bob});
  await refused(late.call('claim', {cutoffSeconds: now - 1}), 'claim-cutoff');
  assert.equal(late.events.length, 0);
  const stale = world({owner: bob, staleSecond: true});
  await refused(stale.call('claim'), 'stale-head');
  assert.ok(!stale.events.includes('sign'));
  assert.equal(stale.journal.records[0].state, 'removed');
  const closeToExpiry = world({owner: bob});
  await assert.rejects(closeToExpiry.call('claim', {terms: terms({outref: ESCROW, expiry_ms: String((now + 10) * 1000)})}), /too close/);
  assert.ok(!closeToExpiry.events.includes('sign'));
});

test('a delayed approval, changed escrow or rejected final swap check never submits a Cardano action', async () => {
  const beforeSign = world({owner: bob});
  await refused(beforeSign.call('claim', {verifyBeforeSign: async () => { throw Error('The other leg changed.'); }}), 'swap-check');
  assert.equal(beforeSign.events.includes('sign'), false, 'the claim secret must not reach the wallet after a failed swap check');
  assert.equal(beforeSign.journal.records[0].state, 'removed');
  assert.equal(beforeSign.submitted.length, 0);
  let clock = now;
  const delayed = world({owner: bob}), sign = delayed.wallet.signTx;
  delayed.wallet.signTx = async (...args) => { const witness = await sign(...args); clock = now + 20; return witness; };
  await refused(delayed.call('claim', {cutoffSeconds: now + 10, nowSeconds: () => clock}), 'claim-cutoff');
  assert.equal(delayed.submitted.length, 0);
  assert.equal(delayed.journal.records[0].state, 'uncertain');

  const changed = world({owner: bob});
  let checks = 0;
  await refused(changed.call('claim', {verifyEscrow: async () => { if (++checks === 2) throw Error('Escrow changed.'); return {slot}; }}), 'swap-check');
  assert.equal(changed.submitted.length, 0);
  assert.equal(changed.journal.records[0].state, 'uncertain');

  const funding = world();
  await refused(funding.call('fund', {verifyBeforeSubmit: async () => { throw Error('The other leg is no longer safe.'); }}), 'swap-check');
  assert.equal(funding.submitted.length, 0);
  assert.equal(funding.journal.records[0].state, 'uncertain');

  const advancing = world({owner: bob}), original = advancing.read.params;
  let reads = 0;
  advancing.read.params = async () => { const params = await original(); return {...params, slot: ++reads === 4 ? expiry - 1666656000 : slot}; };
  await refused(advancing.call('claim'), 'claim-cutoff');
  assert.equal(advancing.submitted.length, 0);
  assert.equal(advancing.journal.records[0].state, 'uncertain');

  const slowHead = world({owner: bob}), originalHead = slowHead.read.params;
  let headReads = 0, headClock = now;
  slowHead.read.params = async () => { const params = await originalHead(); if (++headReads === 4) headClock = now + 20; return params; };
  await refused(slowHead.call('claim', {cutoffSeconds: now + 10, nowSeconds: () => headClock}), 'claim-cutoff');
  assert.equal(slowHead.submitted.length, 0);
  assert.equal(slowHead.journal.records[0].state, 'uncertain');

  const invalid = world();
  await refused(invalid.call('fund', {verifyBeforeSubmit: true}), 'swap-check');
  assert.equal(invalid.events.length, 0);
});

test('escrow that fails verification, and a wallet with no fee UTxO, stop the claim', async () => {
  const f = world({owner: bob});
  await assert.rejects(f.call('claim', {verifyEscrow: async () => { throw Error('Cardano escrow is spent or does not match the validator.'); }}), /spent or does not match/);
  assert.equal(f.events.length, 0);
  const only = world({owner: bob, utxos: [u(2, 6_000_000, bob)], collateral: [u(2, 6_000_000, bob).ref]});
  await refused(only.call('claim'), 'no-fee-input');
  assert.ok(!only.events.includes('sign'));
});

test('parseWalletUtxo rejects malformed wallet data', () => {
  assert.throws(() => parseWalletUtxo('80'), /malformed/);
  assert.throws(() => parseWalletUtxo('zz'), /Invalid|hex/i);
});
