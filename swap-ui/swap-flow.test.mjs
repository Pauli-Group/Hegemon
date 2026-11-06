import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {TRANSITIONS, canonicalJson, claimGate, decide, explain, planWithMargin, swapId, termsDigest, validateTerms} from './swap-flow.mjs';
import {validateTiming} from './timelock-policy.mjs';

const read = path => JSON.parse(readFileSync(new URL(path, import.meta.url)));
const vectors = read('../config/swap/flow-vectors.json');
const config = validateTiming(read('./chain-timing.json'));

// Messages differ in wording between the two implementations; the contract is the structured part.
const normalize = decision => {
  const copy = JSON.parse(JSON.stringify(decision));
  delete copy.reasons;
  return copy;
};

test('transition table equals the engine table', () => {
  assert.deepEqual(TRANSITIONS, vectors.transitions);
  assert.ok(explain('initiator').length > 0 && explain('responder').length > 0);
});

test('decide matches every Python vector', () => {
  assert.ok(vectors.decide.length > 300, 'vector set unexpectedly small');
  const failures = [];
  for (const [index, item] of vectors.decide.entries()) {
    const got = normalize(decide(structuredClone(item.record), item.terms, item.obs, config, item.now));
    const want = normalize(item.decision);
    try { assert.deepEqual(got, want); } catch { failures.push({index, got, want}); }
  }
  assert.deepEqual(failures.slice(0, 2), [], failures.length + ' decide vectors diverge');
});

test('decide covers every decision kind and every transition of both roles', () => {
  const kinds = new Set(vectors.decide.map(item => item.decision.kind));
  for (const kind of ['move', 'act', 'wait', 'abort', 'halt', 'terminal']) assert.ok(kinds.has(kind), kind);
  const seen = new Set(vectors.decide.filter(item => item.decision.to).map(item => `${item.record.role}:${item.record.state}>${item.decision.to}`));
  for (const [role, from, to] of TRANSITIONS) {
    if (to === 'aborted') {
      assert.ok(vectors.decide.some(item => item.record.role === role && item.record.state === from && item.decision.kind === 'abort'), `${role} ${from} has no abort vector`);
    } else {
      assert.ok(seen.has(`${role}:${from}>${to}`), `${role} ${from} > ${to} has no vector`);
    }
  }
});

test('claimGate matches every Python vector and refuses inside the cutoff', () => {
  assert.ok(vectors.claim_gate.length > 100);
  const seen = new Set();
  for (const item of vectors.claim_gate) {
    assert.deepEqual(claimGate(item.role, item.terms, item.heads, config, item.now), item.gate);
    for (const reason of item.gate.reasons) seen.add(reason);
  }
  for (const reason of ['claim-closed', 'inside-claim-cutoff', 'policy-rejects-claim', 'chain-head-unavailable']) assert.ok(seen.has(reason), reason);
  assert.ok(vectors.claim_gate.some(item => item.gate.ok));
});

test('planWithMargin matches every Python plan vector', () => {
  for (const item of vectors.plan) {
    if (item.error) {
      assert.throws(() => planWithMargin(config, item.long_chain, item.short_chain, item.heads, item.now, item.margin), /No compliant plan/, `${item.long_chain}/${item.short_chain}`);
    } else {
      const got = planWithMargin(config, item.long_chain, item.short_chain, item.heads, item.now, item.margin);
      assert.deepEqual({long: got.long, short: got.short, marginSeconds: got.marginSeconds, ok: got.verdict.ok}, item.plan, `${item.long_chain}/${item.short_chain}`);
    }
  }
});

test('swap id and canonical form match Python', async () => {
  for (const item of vectors.ids) {
    assert.equal(canonicalJson(item.terms), item.canonical);
    assert.equal(await swapId(item.terms), item.id);
    assert.equal((await termsDigest(item.terms)).slice(0, 16), item.id);
  }
});

test('terms validation rejects malformed terms', () => {
  const good = structuredClone(vectors.ids[0].terms);
  assert.equal(validateTerms(good), good);
  const bad = mutate => { const t = structuredClone(good); mutate(t); return t; };
  for (const mutate of [
    t => { t.version = 2; },
    t => { t.hashlock = 'AB'.repeat(32); },
    t => { delete t.legs.short; },
    t => { t.legs.long.amount = 0; },
    t => { t.legs.long.expiry = 1.5; },
    t => { t.legs.long.claimant = t.legs.long.refundee; },
    t => { t.legs.long.refundee = '0xAB' + '11'.repeat(19); },
    t => { t.legs.short.chain = 'dogecoin'; },
    t => { t.extra = 1; t.legs.long.extra = 1; },
  ]) assert.throws(() => validateTerms(bad(mutate)));
  const same = structuredClone(good);
  same.legs.short.chain = 'ethereum';
  same.legs.short.refundee = '0x' + '88'.repeat(20);
  same.legs.short.claimant = '0x' + '99'.repeat(20);
  assert.throws(() => validateTerms(same), /cross identities/);
});
