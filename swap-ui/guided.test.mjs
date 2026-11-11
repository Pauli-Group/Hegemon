import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {blake2b, sha256} from './vendor/hash.mjs';
import {Tag, encode, fromHex, toHex} from './cbor.mjs';
import {bitcoinWitnessScript, expectedBitcoinScript, TESTNET4_GENESIS} from './bitcoin-testnet-verifier.mjs';
import {PREVIEW_HTLC_ADDRESS} from './cardano-preview-verifier.mjs';
import {expectedEtherRuntime} from './ethereum-escrow.mjs';
import {TRANSITIONS, planWithMargin, swapId, termsDigest} from './swap-flow.mjs';
import {SEQUENCE, SIDE_STATES, buildObservation, explainDecision, openActions, parseSwap, prefillFor, review, sequenceView, waitingView} from './guided.mjs';

test('guided waiting messages distinguish action, counterparty, network and unreadable chain', () => {
  const record = {role: 'initiator', state: 'long_funded', escrows: {long: {}, short: null}};
  const obs = {errors: {}};
  assert.equal(waitingView({record, decision: {kind: 'wait'}, obs}).actor, 'The other person');
  assert.equal(waitingView({record: {...record, escrows: {...record.escrows, short: {}}}, decision: {kind: 'wait'}, obs}).actor, 'The network');
  assert.equal(waitingView({record, decision: {kind: 'wait'}, obs: {errors: {short: 'unavailable'}}}).actor, 'Unknown');
  assert.equal(waitingView({record, decision: {kind: 'act', action: 'claim'}, obs}).title, 'Claim the escrow you are owed');
  assert.equal(waitingView({record, decision: {kind: 'move'}, obs}).title, 'Update the local swap record');
  assert.equal(waitingView({record: {...record, state: 'refund_submitted'}, decision: {kind: 'wait'}, obs}).actor, 'The network');
});

const config = JSON.parse(fs.readFileSync(new URL('chain-timing.json', import.meta.url), 'utf8'));
const template = JSON.parse(fs.readFileSync(new URL('ether-escrow-template.json', import.meta.url), 'utf8'));
const NOW = 1_800_000_000, preimage = '5a'.repeat(32), hashlock = toHex(sha256(fromHex(preimage)));
const BTC = {initiator: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa', responder: '02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27'};
const ADA = {initiator: 'c5'.repeat(28), responder: '88'.repeat(28)};
const ETH = {initiator: '0x' + 'a1'.repeat(20), responder: '0x' + 'b2'.repeat(20)};

const plan = planWithMargin(config, 'bitcoin', 'cardano', {long: {observedAt: NOW, height: 100_000}, short: {observedAt: NOW, timestamp: NOW - 5}}, NOW);
const terms = () => ({version: 1, hashlock, legs: {
  long: {chain: 'bitcoin', amount: 60_000, refundee: BTC.initiator, claimant: BTC.responder, expiry: plan.long.expiry},
  short: {chain: 'cardano', amount: 5_000_000, refundee: ADA.responder, claimant: ADA.initiator, expiry: plan.short.expiry}}});
const status = async (t, extra = {}) => ({swap_id: await swapId(t), role: 'initiator', state: 'long_funded', inflight: null, needs_human: null,
  escrows: {long: {txid: 'aa'.repeat(32), vout: 1}, short: {txid: 'cc'.repeat(32), vout: 0}}, txids: {}, terms_digest: await termsDigest(t), ...extra});
const text = value => JSON.stringify(value);

const datum = t => ({value: {constructor: 0, fields: [{bytes: t.hashlock}, {bytes: t.legs.short.claimant}, {bytes: t.legs.short.refundee}, {int: t.legs.short.expiry * 1000}]}});
async function readers(t, over = {}) {
  const long = t.legs.long, script = await expectedBitcoinScript({txid: 'aa'.repeat(32), vout: 1, amount_sats: long.amount, hashlock: t.hashlock, claimant_key: long.claimant, refund_key: long.refundee, refund_height: long.expiry});
  return {
    bitcoin: {head: async () => ({genesis: TESTNET4_GENESIS, tip: 100_000}),
      escrow: async (txid, vout) => ({genesis: TESTNET4_GENESIS, txid, vout, tip: 100_000, confirmed: true, confirmations: 6, spent: false, amount_sats: long.amount, script}),
      spend: async (txid, vout) => ({genesis: TESTNET4_GENESIS, txid, vout, tip: 100_000, spent: false}), ...over.bitcoin},
    cardano: {params: async () => ({system_start: 1666656000, slot: NOW - 1666656000 - 5}),
      escrow: async outref => ({network: 'preview', slot: 1, confirmations: 6, output: {tx_hash: outref.split('#')[0], tx_index: 0, address: PREVIEW_HTLC_ADDRESS, value: String(t.legs.short.amount), asset_list: [], is_spent: false, inline_datum: datum(t)}}),
      spend: async outref => ({network: 'preview', outref, spent: false}), ...over.cardano},
  };
}

test('swap inputs: the status must belong to the terms; unknown states, roles and escrow references are refused', async () => {
  const t = terms();
  const ok = await parseSwap({termsText: text(t), statusText: text(await status(t))});
  assert.equal(ok.id, await swapId(t));
  assert.equal(ok.record.submitted && Object.keys(ok.record.submitted).length, 0);
  const other = {...t, legs: {...t.legs, long: {...t.legs.long, amount: 61_000}}};
  await assert.rejects(parseSwap({termsText: text(other), statusText: text(await status(t))}), /different swap/);
  await assert.rejects(parseSwap({termsText: text(t), statusText: text({...await status(t), terms_digest: '00'.repeat(32)})}), /different terms/);
  await assert.rejects(parseSwap({termsText: text(t), statusText: text(await status(t, {state: 'flying'}))}), /unknown state/);
  await assert.rejects(parseSwap({termsText: text(t), statusText: text(await status(t, {role: 'observer'}))}), /role/);
  await assert.rejects(parseSwap({termsText: text(t), statusText: text(await status(t, {escrows: {long: {txid: 'zz', vout: 1}}}))}), /not a Bitcoin output/);
  await assert.rejects(parseSwap({termsText: '{', statusText: '{}'}), /not valid JSON/);
});

test('the happy-path sequences are real engine transitions', () => {
  const known = new Set(TRANSITIONS.map(([role, from, to]) => `${role}:${from}>${to}`));
  for (const [role, path] of Object.entries(SEQUENCE)) for (let i = 0; i + 1 < path.length; i++) assert.ok(known.has(`${role}:${path[i]}>${path[i + 1]}`), `${role} ${path[i]} to ${path[i + 1]}`);
  assert.deepEqual(sequenceView({role: 'responder', state: 'short_funded'}), {path: SEQUENCE.responder, index: 3, side: null});
  assert.equal(sequenceView({role: 'initiator', state: 'refunded'}).side, 'refunded');
  assert.ok(SIDE_STATES.every(s => TRANSITIONS.some(row => row[2] === s)));
});

test('initiator with both escrows confirmed and matching: the page reaches the same verdict as the engine and names the next step', async () => {
  const t = terms(), r = await readers(t);
  const out = await review({termsText: text(t), statusText: text(await status(t)), config, now: NOW, readers: r, template, hasSecret: true});
  assert.equal(out.view.decision.kind, 'move');
  assert.equal(out.view.decision.to, 'short_verified');
  assert.equal(out.policy.ok, true);
  assert.ok(out.policy.metrics.gapSeconds > 0, 'the P1 verdict and its measured gap are returned for display');
  assert.match(out.view.next.text, /swap_engine_cli.py advance/);
  assert.deepEqual(out.obs.legs.short, {found: true, verified: true, confirmations: 6, problem: null, spent: null, spend_confirmations: 0, spend_txid: null, preimage: null});
});

test('a contradicting escrow is a problem, never a pass; unindexed spends and outages make a leg unreadable', async () => {
  const t = terms();
  const wrongValue = await readers(t, {cardano: {escrow: async outref => ({network: 'preview', slot: 1, confirmations: 6, output: {tx_hash: outref.split('#')[0], tx_index: 0, address: PREVIEW_HTLC_ADDRESS, value: '4999999', asset_list: [], is_spent: false, inline_datum: datum(t)}})}});
  let out = await review({termsText: text(t), statusText: text(await status(t)), config, now: NOW, readers: wrongValue, template, hasSecret: true});
  assert.match(out.obs.legs.short.problem, /value/);
  assert.equal(out.view.decision.kind, 'wait');
  assert.match(out.view.decision.why, /contradicts the terms/);
  const wrongDatum = await readers(t, {cardano: {escrow: async outref => ({network: 'preview', slot: 1, confirmations: 6, output: {tx_hash: outref.split('#')[0], tx_index: 0, address: PREVIEW_HTLC_ADDRESS, value: String(t.legs.short.amount), asset_list: [], is_spent: false, inline_datum: {value: {constructor: 0, fields: [{bytes: t.hashlock}, {bytes: ADA.responder}, {bytes: ADA.initiator}, {int: t.legs.short.expiry * 1000}]}}}})}});
  out = await review({termsText: text(t), statusText: text(await status(t)), config, now: NOW, readers: wrongDatum, template, hasSecret: true});
  assert.match(out.obs.legs.short.problem, /datum terms/, 'swapped claimant and refundee are caught');
  const unindexed = await readers(t, {bitcoin: {escrow: async (txid, vout) => ({...(await (await readers(t)).bitcoin.escrow(txid, vout)), spent: true})}});
  out = await review({termsText: text(t), statusText: text(await status(t)), config, now: NOW, readers: unindexed, template, hasSecret: true});
  assert.equal(out.obs.legs.long, null, 'spent but not indexed is unreadable, not unspent');
  assert.match(out.obs.errors.long, /not indexed yet/);
  assert.equal(out.view.decision.kind, 'wait');
  const down = await readers(t, {cardano: {params: async () => { throw Error('provider down'); }}});
  out = await review({termsText: text(t), statusText: text(await status(t)), config, now: NOW, readers: down, template, hasSecret: true});
  assert.equal(out.obs.heads.short, null);
  assert.match(out.obs.errors.short, /provider down/);
  assert.equal(out.view.decision.kind, 'wait');
});

test('each field of an escrow is checked: Bitcoin script and amount, Cardano address, and unconfirmed depth is zero', async () => {
  const t = terms(), base = await readers(t), obsOf = async over => (await buildObservation({terms: t, record: (await parseSwap({termsText: text(t), statusText: text(await status(t))})).record, now: NOW, readers: await readers(t, over), template, hasSecret: true})).legs;
  const snapshot = await base.bitcoin.escrow('aa'.repeat(32), 1);
  assert.match((await obsOf({bitcoin: {escrow: async () => ({...snapshot, script: '0020' + '00'.repeat(32)})}})).long.problem, /script/);
  assert.match((await obsOf({bitcoin: {escrow: async () => ({...snapshot, amount_sats: snapshot.amount_sats + 1})}})).long.problem, /amount/);
  const shallow = await obsOf({bitcoin: {escrow: async () => ({...snapshot, confirmed: false, confirmations: 7})}});
  assert.equal(shallow.long.confirmations, 0, 'an unconfirmed output has no depth, whatever the provider says');
  const row = (await base.cardano.escrow('cc'.repeat(32) + '#0')).output;
  assert.match((await obsOf({cardano: {escrow: async () => ({network: 'preview', confirmations: 6, output: {...row, address: 'addr_test1other'}})}})).short.problem, /script address/);
  assert.match((await obsOf({cardano: {escrow: async () => ({network: 'preview', confirmations: 6, output: {...row, asset_list: [{policy_id: 'aa'.repeat(28), asset_name: '', quantity: '1'}]}})}})).short.problem, /value/);
});

test('a claim whose last safe submission time has passed is refused even if the decision says act', async () => {
  const t = terms(), record = {role: 'initiator', state: 'short_verified', escrows: {long: {txid: 'aa'.repeat(32), vout: 1}, short: {txid: 'cc'.repeat(32), vout: 0}}};
  const heads = {long: {observedAt: NOW, height: 100_000}, short: {observedAt: NOW, timestamp: t.legs.short.expiry - 5}};
  const view = explainDecision({decision: {kind: 'act', action: 'claim', leg: 'short', to: 'short_claim_submitted', why: 'x'}, record, terms: t, obs: {errors: {}, heads, now: NOW}, config, id: 'abc'});
  assert.match(view.headline, /Do not claim now/);
  assert.equal(view.next.type, 'wait');
  assert.equal(view.prefill, undefined);
});

test('a claimed short leg gives the responder the preimage; a refund gives none', async () => {
  const t = terms(), ref = {txid: 'cc'.repeat(32), vout: 0};
  const body = encode(new Map([[0, [[fromHex(ref.txid), 0]]], [2, 200000]]));
  const tx = redeemer => new Uint8Array([0x84, ...body, ...encode(new Map([[5, new Map([[[0, 0], [redeemer, [1, 2]]]])]])), 0xf5, 0xf6]);
  const txid = toHex(blake2b(body, {dkLen: 32}));
  const spent = redeemer => ({cardano: {escrow: async outref => ({network: 'preview', slot: 1, confirmations: 9, output: {tx_hash: ref.txid, tx_index: 0, address: PREVIEW_HTLC_ADDRESS, value: String(t.legs.short.amount), asset_list: [], is_spent: true, inline_datum: datum(t)}}),
    params: async () => ({system_start: 1666656000, slot: NOW - 1666656000 - 5}), spend: async outref => ({network: 'preview', outref, spent: true, indexed: true, spender: txid, confirmations: 4, cbor: toHex(tx(redeemer))})}});
  const record = {state: 'short_funded', role: 'responder'};
  const claimed = await review({termsText: text(t), statusText: text(await status(t, record)), config, now: NOW, readers: await readers(t, spent(new Tag(121, [fromHex(preimage)]))), template, hasSecret: false});
  assert.equal(claimed.obs.legs.short.spent, 'claimed');
  assert.equal(claimed.obs.legs.short.preimage, preimage);
  assert.equal(claimed.view.decision.kind, 'move');
  assert.equal(claimed.view.decision.to, 'preimage_known');
  const refunded = await review({termsText: text(t), statusText: text(await status(t, record)), config, now: NOW, readers: await readers(t, spent(new Tag(122, []))), template, hasSecret: false});
  assert.equal(refunded.obs.legs.short.spent, 'refunded');
  assert.equal(refunded.obs.legs.short.preimage, null);
  assert.equal(refunded.view.decision.to, 'refunded');
});

test('Ethereum legs are read through a read-only provider and verified by creation transaction, funder, amount and runtime code', async () => {
  const eth = {version: 1, hashlock, legs: {
    long: {chain: 'ethereum', amount: 1_000_000_000_000_000, refundee: ETH.initiator, claimant: ETH.responder, expiry: NOW + 60_000},
    short: {chain: 'cardano', amount: 5_000_000, refundee: ADA.responder, claimant: ADA.initiator, expiry: NOW + 30_000}}};
  const contract = '0x' + 'cd'.repeat(20), txid = 'ef'.repeat(32), runtime = expectedEtherRuntime(template, {hashlock: '0x' + hashlock, claimant: ETH.responder, refundee: ETH.initiator, expiry: String(eth.legs.long.expiry), amount: String(eth.legs.long.amount)});
  const chain = {code: runtime, from: ETH.initiator, value: '0x' + BigInt(eth.legs.long.amount).toString(16), to: null, status: '0x1', events: [], spentFlag: false};
  const provider = {request: async ({method, params}) => ({
    eth_getTransactionReceipt: {blockNumber: '0x64', status: chain.status, contractAddress: contract},
    eth_getTransactionByHash: {hash: '0x' + txid, from: chain.from, to: chain.to, value: chain.value},
    eth_blockNumber: '0x69', eth_getCode: chain.code, eth_getBlockByNumber: {timestamp: '0x' + NOW.toString(16)}}[method])};
  const r = await readers(terms()); r.ethereum = {provider, events: async (address, from) => ({chain_id: 11155111, contract: address, deployed: true, spent: chain.spentFlag, events: chain.events})};
  const record = await status(eth, {escrows: {long: {txid}, short: null}});
  const look = async () => (await buildObservation({terms: eth, record: (await parseSwap({termsText: text(eth), statusText: text(record)})).record, now: NOW, readers: r, template, hasSecret: true})).legs.long;
  assert.deepEqual([(await look()).found, (await look()).verified, (await look()).confirmations], [true, true, 6]);
  chain.code = '0x6001'; assert.match((await look()).problem, /runtime code/); chain.code = runtime;
  chain.from = ETH.responder; assert.match((await look()).problem, /funder/); chain.from = ETH.initiator;
  chain.value = '0x1'; assert.match((await look()).problem, /amount/); chain.value = '0x' + BigInt(eth.legs.long.amount).toString(16);
  chain.to = contract; assert.match((await look()).problem, /creation/); chain.to = null;
  chain.spentFlag = true; chain.events = [];
  assert.equal((await buildObservation({terms: eth, record: (await parseSwap({termsText: text(eth), statusText: text(record)})).record, now: NOW, readers: r, template, hasSecret: true})).legs.long, null, 'a spent contract with no visible event is unreadable');
  chain.events = [{kind: 'claimed', tx_hash: '0x' + 'ab'.repeat(32), block_number: 105, confirmations: 3, data: '0x' + preimage}];
  const claimed = await look();
  assert.deepEqual([claimed.spent, claimed.preimage, claimed.spend_confirmations], ['claimed', preimage, 3]);
  assert.equal(claimed.contract, contract);
  const refundPrefill = prefillFor({action: 'refund', leg: 'long'}, eth, {escrows: {long: {txid}, short: null}}, {legs: {long: claimed}});
  assert.equal(refundPrefill.fields.contract, contract, 'a later Ethereum claim or refund form is filled with the derived contract address');
});

test('Hegemon without a companion is labelled as requiring a local companion and never produces a head', async () => {
  const t = {...terms(), legs: {long: {chain: 'hegemon', amount: 5, refundee: 'shca1aaa', claimant: 'shca1bbb', expiry: 900_000}, short: terms().legs.short}};
  const out = await review({termsText: text(t), statusText: text(await status(t, {escrows: {long: null, short: null}, state: 'terms_saved'})), config, now: NOW, readers: await readers(terms()), template, hasSecret: true});
  assert.equal(out.obs.heads.long, null);
  assert.match(out.obs.errors.long, /local companion/);
  assert.equal(out.view.decision.kind, 'wait');
  assert.ok(out.view.notes.some(n => /local companion/.test(n)));
});

test('Hegemon with a companion reader produces a height head', async () => {
  const t = {...terms(), legs: {long: {chain: 'hegemon', amount: 5, refundee: 'shca1aaa', claimant: 'shca1bbb', expiry: 900_000}, short: terms().legs.short}};
  const r = await readers(terms());
  r.hegemon = {head: async () => ({height: 11246}), escrow: async () => null};
  const out = await review({termsText: text(t), statusText: text(await status(t, {escrows: {long: null, short: null}, state: 'terms_saved'})), config, now: NOW, readers: r, template, hasSecret: true});
  assert.deepEqual(out.obs.heads.long, {observedAt: NOW, height: 11246});
  assert.equal(out.obs.errors.long, undefined);
});

test('an act decision prefills the matching wallet form and a claim reports its last safe submission time; outside the gate it refuses', async () => {
  const t = terms(), r = await readers(t);
  const out = await review({termsText: text(t), statusText: text(await status(t, {state: 'short_verified'})), config, now: NOW, readers: r, template, hasSecret: true});
  assert.equal(out.view.decision.kind, 'act');
  assert.equal(out.view.decision.action, 'claim');
  assert.equal(out.view.prefill.section, 'cardano-wallet-section');
  assert.deepEqual(out.view.prefill.fields, {lovelace: 5_000_000, hashlock, claimant: ADA.initiator, refundee: ADA.responder, expiry_ms: t.legs.short.expiry * 1000, outref: 'cc'.repeat(32) + '#0'});
  assert.ok(out.view.claimGate.ok && out.view.claimGate.submitBySeconds > 0);
  assert.match(out.view.headline, /claim the short leg on cardano/);
  const late = await readers(t, {cardano: {params: async () => ({system_start: 1666656000, slot: t.legs.short.expiry - 1666656000 - 30})}});
  const closed = await review({termsText: text(t), statusText: text(await status(t, {state: 'short_verified'})), config, now: NOW, readers: late, template, hasSecret: true});
  assert.notEqual(closed.view.decision.kind, 'act', 'with the short leg about to expire the engine does not claim');
  const noSecret = await review({termsText: text(t), statusText: text(await status(t, {state: 'short_verified'})), config, now: NOW, readers: r, template, hasSecret: false});
  assert.equal(noSecret.view.decision.kind, 'halt');
  assert.match(noSecret.view.headline, /preimage/);
});

test('prefill covers every hosted chain and is empty for Hegemon; inflight and needs_human are surfaced first', async () => {
  const t = terms(), record = {role: 'initiator', state: 'terms_saved', escrows: {long: null, short: null}};
  assert.equal(prefillFor({action: 'fund', leg: 'long'}, t, record).fields.refund_key, BTC.initiator);
  assert.equal(prefillFor({action: 'fund', leg: 'long'}, t, record).operation, 'fund');
  const eth = {...t, legs: {...t.legs, long: {...t.legs.long, chain: 'ethereum', refundee: ETH.initiator, claimant: ETH.responder}}};
  assert.equal(prefillFor({action: 'fund', leg: 'long'}, eth, record).form, 'sepolia-action-form');
  assert.equal(prefillFor({action: 'fund', leg: 'long'}, {...t, legs: {...t.legs, long: {...t.legs.long, chain: 'hegemon'}}}, record), null);
  const view = explainDecision({decision: {kind: 'wait', why: 'x', detail: {}}, record: {...record, inflight: {action: 'fund'}, needs_human: 'check the chain'}, terms: t, obs: {errors: {}, heads: {}, now: NOW}, config, id: 'abc'});
  assert.match(view.notes[0], /in flight/);
  assert.match(view.notes[1], /stopped for a human/);
  const halted = explainDecision({decision: {kind: 'halt', why: 'bad', state: null, detail: {}}, record, terms: t, obs: {errors: {}, heads: {}, now: NOW}, config, id: 'abc'});
  assert.equal(halted.next.type, 'human');
});

test('pending and uncertain action records for the swap are reported; completed ones and other hashlocks are not', () => {
  const t = terms();
  const rec = (chain, state, hashlockValue) => ({chain, state, request: {hashlock: hashlockValue}});
  const open = openActions([rec('bitcoin', 'pending', hashlock), rec('cardano', 'uncertain', hashlock), rec('cardano', 'completed', hashlock), rec('bitcoin', 'pending', 'ee'.repeat(32)), rec('ethereum', 'pending', hashlock)], t);
  assert.deepEqual(open.map(r => r.state), ['pending', 'uncertain']);
});
