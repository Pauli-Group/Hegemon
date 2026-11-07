import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync, mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, dirname} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import * as policy from './timelock-policy.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, '../config/swap/timelock-vectors.json'), 'utf8'));
const realConfig = JSON.parse(readFileSync(join(here, '../config/swap/chain-timing.json'), 'utf8'));
const clone = value => JSON.parse(JSON.stringify(value));

/** Run every shared vector against a policy module; returns a list of failure strings. */
export function runVectors(mod, data = vectors) {
  const failures = [];
  const config = data.config;
  try { mod.validateTiming(clone(config)); } catch (error) { failures.push('config: ' + error.message); return failures; }
  for (const c of data.cases) {
    let verdict;
    try { verdict = mod.checkOrdered(config, {long: c.long, short: c.short, heads: c.heads, now: c.now}); } catch (error) { failures.push(c.name + ': threw ' + error.message); continue; }
    const codes = verdict.reasons.map(r => r.code);
    if (verdict.ok !== c.expect.ok) failures.push(c.name + ': ok ' + verdict.ok);
    if (JSON.stringify(codes) !== JSON.stringify(c.expect.codes)) failures.push(c.name + ': codes ' + codes);
    for (const [key, value] of Object.entries(c.expect.metrics)) {
      if (verdict.metrics[key] !== value) failures.push(c.name + ': ' + key + ' ' + verdict.metrics[key] + ' != ' + value);
    }
  }
  for (const r of data.requirements || []) {
    const got = mod.legRequirements(config, r.chain);
    if (JSON.stringify(got) !== JSON.stringify(r.expect)) failures.push('requirements ' + r.chain + ': ' + JSON.stringify(got));
  }
  for (const p of data.plans) {
    let plan;
    try { plan = mod.planTimeouts(config, p); } catch (error) { failures.push(p.name + ': threw ' + error.message); continue; }
    if (!plan.verdict.ok) failures.push(p.name + ': plan not ok ' + plan.verdict.reasons.map(r => r.code));
    if (p.expect && (plan.long.expiry !== p.expect.long || plan.short.expiry !== p.expect.short)) failures.push(p.name + ': expiries ' + plan.long.expiry + ',' + plan.short.expiry);
  }
  return failures;
}

test('shared vectors pass', () => {
  assert.deepEqual(runVectors(policy), []);
});

test('pair judgement is independent of argument order and names the long leg', () => {
  const c = vectors.cases[0];
  const forward = policy.checkPair(vectors.config, {a: c.long, b: c.short, heads: {a: c.heads.long, b: c.heads.short}, now: c.now});
  const reverse = policy.checkPair(vectors.config, {a: c.short, b: c.long, heads: {a: c.heads.short, b: c.heads.long}, now: c.now});
  assert.equal(forward.ok, true); assert.equal(forward.long, 'a');
  assert.equal(reverse.ok, true); assert.equal(reverse.long, 'b');
  assert.deepEqual(forward.metrics, reverse.metrics);
});

test('both real and test configs validate; invalid configs are rejected precisely', () => {
  policy.validateTiming(clone(realConfig));
  const bad = clone(vectors.config); bad.chains.slow.fastFactor = 1.5;
  assert.throws(() => policy.validateTiming(bad), /slow\.fastFactor/);
  const noWindow = clone(vectors.config); delete noWindow.chains.slow.windows['1'];
  assert.throws(() => policy.validateTiming(noWindow), /1-block entry/);
  const inverted = clone(vectors.config); inverted.chains.slow.windows['6'] = {min: 9, max: 3};
  assert.throws(() => policy.validateTiming(inverted), /windows\[6\]/);
  const lowGap = clone(vectors.config); lowGap.policy.gapFactor = 0.5;
  assert.throws(() => policy.validateTiming(lowGap), /gapFactor/);
});

test('the hosted copy of the timing config is byte-identical to the canonical one', () => {
  assert.equal(readFileSync(join(here, 'chain-timing.json'), 'utf8'), readFileSync(join(here, '../config/swap/chain-timing.json'), 'utf8'),
    'run: cp config/swap/chain-timing.json swap-ui/chain-timing.json');
});

test('real config: Hegemon tables and lock minimum reflect measured behavior', () => {
  const heg = realConfig.chains.hegemon;
  assert.equal(heg.minLockBlocks, 14);
  // The relation's 14-block minimum is not a wall-clock guarantee: the fast bound for 14 blocks is far below an hour.
  assert.ok(policy.fastSeconds(heg, 14) < 3600);
  assert.ok(policy.slowSeconds(heg, 14) > policy.fastSeconds(heg, 14));
});

// ---- Property tests --------------------------------------------------------
function prng(seed) { let s = seed >>> 0; return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 2 ** 32; }; }
function tableOf(gaps, sizes) {
  const times = [0]; for (const g of gaps) times.push(times.at(-1) + g);
  const windows = {};
  for (const k of sizes) {
    const spans = []; for (let i = 0; i + k < times.length; i++) spans.push(times[i + k] - times[i]);
    windows[k] = {min: Math.min(...spans), max: Math.max(...spans)};
  }
  return {windows, times};
}

test('property: bounds from a chain\'s own table contain every observed span (adversarial gap patterns)', () => {
  const rnd = prng(7);
  const sizes = [1, 2, 3, 6, 12, 24];
  for (let trial = 0; trial < 200; trial++) {
    const mode = trial % 4;
    const gaps = Array.from({length: 120}, (_, i) => {
      if (mode === 0) return Math.floor(-Math.log(1 - rnd()) * 600);          // memoryless
      if (mode === 1) return rnd() < 0.15 ? 1 : 1500 + Math.floor(rnd() * 600); // bursts then slow
      if (mode === 2) return Math.floor(rnd() * 2) * 3000;                      // bimodal, zeros allowed
      return Math.floor(Math.floor(i / 10) % 2 ? rnd() * 5 : rnd() * 2400);     // alternating regimes
    });
    const {windows, times} = tableOf(gaps, sizes);
    const chain = {kind: 'height', windows, slowFactor: 1, fastFactor: 1, outageAllowanceSeconds: 0};
    for (let n = 1; n <= 60; n++) {
      for (let i = 0; i + n < times.length; i++) {
        const span = times[i + n] - times[i];
        assert.ok(policy.slowSeconds(chain, n) >= span, `slow bound ${policy.slowSeconds(chain, n)} < span ${span} for n=${n} trial ${trial}`);
        assert.ok(policy.fastSeconds(chain, n) <= span, `fast bound ${policy.fastSeconds(chain, n)} > span ${span} for n=${n} trial ${trial}`);
      }
    }
  }
});

test('property: bounds are monotone in n and fast never exceeds slow', () => {
  for (const name of ['bitcoin', 'hegemon']) {
    const c = realConfig.chains[name]; let ps = 0, pf = 0;
    for (let n = 0; n <= 1000; n++) {
      const s = policy.slowSeconds(c, n), f = policy.fastSeconds(c, n);
      assert.ok(s >= ps && f >= pf && f <= s, `${name} n=${n}`); ps = s; pf = f;
    }
  }
});

test('property: planTimeouts is compliant and minimal on every chain combination and random heads', () => {
  const rnd = prng(11);
  const names = Object.keys(realConfig.chains);
  for (let trial = 0; trial < 120; trial++) {
    const longChain = names[Math.floor(rnd() * names.length)], shortChain = names[Math.floor(rnd() * names.length)];
    const now = 1_790_000_000 + Math.floor(rnd() * 1e6);
    const head = chain => realConfig.chains[chain].kind === 'height'
      ? {observedAt: now, height: 1000 + Math.floor(rnd() * 100000)} : {observedAt: now, timestamp: now - Math.floor(rnd() * 100)};
    const heads = {long: head(longChain), short: head(shortChain)};
    const plan = policy.planTimeouts(realConfig, {longChain, shortChain, heads, now});
    // A pair may be refused only because the worst-case lock horizon is too long (Bitcoin testnet4 variance); never for a gap or claim window.
    assert.deepEqual(plan.verdict.reasons.filter(r => r.code !== 'horizon-too-long'), [], `${longChain}/${shortChain}`);
    // Minimality of the long expiry (unless pinned by the Hegemon lock minimum).
    const lc = realConfig.chains[longChain];
    const floor = lc.minLockBlocks ? heads.long.height + lc.minLockBlocks + lc.providerLagBlocks + policy.proveBlocks(lc) + 1 : 0;
    if (plan.long.expiry > floor) {
      const lower = policy.checkOrdered(realConfig, {long: {chain: longChain, expiry: plan.long.expiry - 1}, short: plan.short, heads, now});
      assert.ok(lower.reasons.some(r => r.code === 'insufficient-gap'), `${longChain}/${shortChain}: long expiry not minimal`);
    }
  }
});

test('property: raising the long expiry never turns an acceptable gap into an unacceptable one', () => {
  const rnd = prng(23);
  const c = vectors.cases[0];
  for (let trial = 0; trial < 100; trial++) {
    const expiry = c.long.expiry - 200 + Math.floor(rnd() * 800);
    const a = policy.checkOrdered(vectors.config, {long: {...c.long, expiry}, short: c.short, heads: c.heads, now: c.now});
    const b = policy.checkOrdered(vectors.config, {long: {...c.long, expiry: expiry + 1 + Math.floor(rnd() * 50)}, short: c.short, heads: c.heads, now: c.now});
    const gapOk = v => !v.reasons.some(r => r.code === 'insufficient-gap');
    if (gapOk(a)) assert.ok(gapOk(b));
  }
});

test('real config: documented examples', () => {
  // Hegemon long leg, Ethereum short leg, using real heads.
  const now = 1_793_935_000;
  const heads = {long: {observedAt: now, height: 10062}, short: {observedAt: now, timestamp: now - 10}};
  const plan = policy.planTimeouts(realConfig, {longChain: 'hegemon', shortChain: 'ethereum', heads, now});
  assert.ok(plan.verdict.ok);
  assert.ok(plan.long.expiry - 10062 >= 14, 'respects the relation minimum lock window');
});

// ---- Mutation tests --------------------------------------------------------
const source = readFileSync(join(here, 'timelock-policy.mjs'), 'utf8');
const mutations = [
  ['gap uses first refund of the short leg', 'const gap = lw.firstRefund - sw.lastClaim;', 'const gap = lw.firstRefund - sw.firstRefund;'],
  ['gap comparison becomes inclusive of shortfall', 'gap < gapRequired', 'gap < gapRequired - 1'],
  ['gap comparison off by one the other way', 'gap < gapRequired', 'gap <= gapRequired'],
  ['claim window comparison weakened', 'sw.firstRefund < claimRequired', 'sw.firstRefund < claimRequired - 1'],
  ['slow bound uses min window', 'best = Math.min(best, Math.ceil(n / k) * w.max)', 'best = Math.min(best, Math.floor(n / k) * w.max)'],
  ['fast bound ignores window tables', 'best = Math.max(best, Math.floor(n / k) * w.min)', 'best = Math.max(best, n * w.min)'],
  ['refund offset dropped', 'leg.expiry + c.refundOffsetBlocks - trueHead', 'leg.expiry - trueHead'],
  ['provider lag ignored', 'const trueHead = head.height + c.providerLagBlocks;', 'const trueHead = head.height;'],
  ['outage allowance dropped', 'Math.ceil(best * c.slowFactor) + c.outageAllowanceSeconds', 'Math.ceil(best * c.slowFactor)'],
  ['clock skew sign flipped on refund', 'leg.expiry - c.clockSkewSeconds - now', 'leg.expiry + c.clockSkewSeconds - now'],
  ['safety floor removed', 'Math.max(Math.ceil(base * p.gapFactor), base + p.gapFloorSeconds)', 'Math.ceil(base * p.gapFactor)'],
  ['stale head allowed', 'Math.abs(now - head.observedAt) > config.policy.maxObservationAgeSeconds', 'false'],
  ['clock drift allowed', 'drift < -c.clockSkewSeconds || drift > c.maxHeadAgeSeconds + c.clockSkewSeconds', 'false'],
  ['horizon unchecked', 'horizon > config.policy.maxHorizonSeconds', 'false'],
  ['expired short leg ignored', 'if (sw.expired) reasons.push', 'if (false) reasons.push'],
  ['confirmation depth ignored', 'return isHeight(c) ? slowSeconds(c, depth) : c.inclusionSeconds + (depth - 1) * c.slowBlockSeconds;', 'return isHeight(c) ? slowSeconds(c, 1) : c.inclusionSeconds;'],
  ['prove time ignored', 'return inclusionSeconds(c) + (c.proveSeconds || 0);', 'return inclusionSeconds(c);'],
  ['requirement blocks ignore provider lag', 'fastSeconds(c, d + c.refundOffsetBlocks - c.providerLagBlocks)', 'fastSeconds(c, d + c.refundOffsetBlocks)'],
  ['requirement window ignores reaction time', 'scale(config, actionSeconds(c) + config.policy.reactionSeconds);\n  const out', 'scale(config, actionSeconds(c));\n  const out'],
  ['plan skips lock minimum', 'floorOf = (c, head) => (isHeight(c) && c.minLockBlocks ?', 'floorOf = (c, head) => (false && c.minLockBlocks ?'],
  ['lock floor ignores proving blocks', 'c.providerLagBlocks + proveBlocks(c) + 1', 'c.providerLagBlocks + 1'],
  ['proving blocks use the slow bound', 'if (fastSeconds(c, mid) <= seconds) lo = mid;', 'if (slowSeconds(c, mid) <= seconds) lo = mid;'],
];

test('mutation: every rule in the policy is pinned by a shared vector or property', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'timelock-mutation-'));
  const survivors = [];
  for (const [index, [name, from, to]] of mutations.entries()) {
    assert.ok(source.includes(from), `mutation target missing for "${name}"`);
    const file = join(dir, `m${index}.mjs`);
    writeFileSync(file, source.replace(from, to));
    const mod = await import(pathToFileURL(file).href);
    if (runVectors(mod).length === 0) survivors.push(name);
  }
  assert.deepEqual(survivors, []);
});
