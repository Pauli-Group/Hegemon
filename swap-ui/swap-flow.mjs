/** Display-side port of the two-party swap state machine (scripts/swap_engine/engine.py).
 *
 * The page never signs for the engine and never writes engine state. This module only
 * answers "given this record and these observations, what would the engine do and why",
 * so the guided view can show the same decision a CLI `advance` would take. Python is the
 * source of truth: config/swap/flow-vectors.json is generated from it
 * (scripts/swap_engine/ui_vectors.py) and swap-flow.test.mjs fails if this file diverges.
 */
import {actionSeconds, checkOrdered, confirmSeconds, fastSeconds, legWindow, planTimeouts} from './timelock-policy.mjs';

export const LONG = 'long', SHORT = 'short';
export const TERMINAL = ['done', 'refunded', 'aborted', 'failed'];
const TRANSIENT_CODES = ['head-stale', 'clock-drift'];
const HEX64 = /^[0-9a-f]{64}$/;

/** [role, from, to, trigger]; must equal engine.TRANSITIONS (checked against the vectors). */
export const TRANSITIONS = [
  ['initiator', 'terms_saved', 'long_fund_submitted', 'policy ok on fresh heads: fund the long leg'],
  ['initiator', 'terms_saved', 'aborted', 'policy deterministically fails; nothing is funded'],
  ['initiator', 'long_fund_submitted', 'long_funded', 'long escrow confirmed and matches terms'],
  ['initiator', 'long_funded', 'long_fund_submitted', 'long escrow disappears (reorg); wait, never fund twice'],
  ['initiator', 'long_funded', 'short_verified', 'short escrow confirmed, matches terms, unspent, policy and claim cutoff ok'],
  ['initiator', 'long_funded', 'refund_submitted', 'long leg refund is due'],
  ['initiator', 'short_verified', 'short_claim_submitted', 'claim the short leg with the preimage'],
  ['initiator', 'short_verified', 'long_funded', 'short leg no longer safe to claim'],
  ['initiator', 'short_claim_submitted', 'done', 'claim confirmed'],
  ['initiator', 'short_claim_submitted', 'long_funded', 'short leg refunded before the claim landed'],
  ['initiator', 'refund_submitted', 'refunded', 'refund confirmed'],
  ['responder', 'terms_saved', 'long_verified', 'long escrow confirmed, matches terms, unspent, policy ok'],
  ['responder', 'terms_saved', 'aborted', 'policy fails or long escrow contradicts terms; nothing is funded'],
  ['responder', 'long_verified', 'short_fund_submitted', 'long still verified and policy ok: fund the short leg'],
  ['responder', 'long_verified', 'aborted', 'policy or long escrow no longer acceptable; nothing is funded'],
  ['responder', 'short_fund_submitted', 'short_funded', 'short escrow confirmed and matches terms'],
  ['responder', 'short_funded', 'short_fund_submitted', 'short escrow disappears (reorg); wait, never fund twice'],
  ['responder', 'short_funded', 'preimage_known', 'initiator claim observed; preimage stored'],
  ['responder', 'short_funded', 'refund_submitted', 'short leg refund is due'],
  ['responder', 'preimage_known', 'long_claim_submitted', 'claim the long leg with the learned preimage'],
  ['responder', 'preimage_known', 'failed', 'long leg was refunded before the claim'],
  ['responder', 'long_claim_submitted', 'done', 'claim confirmed'],
  ['responder', 'long_claim_submitted', 'failed', 'long leg refunded before the claim landed'],
  ['responder', 'refund_submitted', 'refunded', 'refund confirmed'],
];

export function explain(role) {
  return TRANSITIONS.filter(row => row[0] === role).map(([, from, to, when]) => [from, to, when]);
}

export const ownLeg = role => role === 'initiator' ? LONG : SHORT;
export const otherLeg = role => role === 'initiator' ? SHORT : LONG;

// ---------------------------------------------------------------- terms and identity

/** Per-chain identity formats from the P2 schema. */
const IDENTITY = {
  bitcoin: /^(02|03)[0-9a-f]{64}$/,
  ethereum: /^0x[0-9a-f]{40}$/,
  cardano: /^[0-9a-f]{56}$/,
};

function isPositiveInteger(value) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

/** Same rules as store.validate_terms plus the identity formats the adapters use. Amounts and
 * expiries are plain JSON integers; amounts above 2^53 are not accepted in the page. */
export function validateTerms(terms) {
  if (!terms || typeof terms !== 'object' || Array.isArray(terms) || terms.version !== 1 || !HEX64.test(String(terms.hashlock))) {
    throw Error('Terms need version 1 and a 64-hex hashlock.');
  }
  const legs = terms.legs;
  if (!legs || typeof legs !== 'object' || Object.keys(legs).sort().join() !== 'long,short') throw Error('Terms need a long and a short leg.');
  for (const name of [LONG, SHORT]) {
    const leg = legs[name];
    if (!leg || typeof leg !== 'object' || Object.keys(leg).sort().join() !== 'amount,chain,claimant,expiry,refundee') {
      throw Error(`The ${name} leg needs chain, amount, refundee, claimant and expiry.`);
    }
    if (!['bitcoin', 'ethereum', 'cardano', 'hegemon'].includes(leg.chain)) throw Error(`The ${name} leg names an unknown chain.`);
    if (!isPositiveInteger(leg.amount)) throw Error(`The ${name} leg amount must be a positive integer in the chain base unit.`);
    if (!isPositiveInteger(leg.expiry)) throw Error(`The ${name} leg expiry must be a positive integer.`);
    if (typeof leg.refundee !== 'string' || typeof leg.claimant !== 'string') throw Error(`The ${name} leg has a malformed identity.`);
    if (leg.refundee === leg.claimant) throw Error(`The ${name} leg must name different refundee and claimant.`);
    const format = IDENTITY[leg.chain];
    if (format && (!format.test(leg.refundee) || !format.test(leg.claimant))) throw Error(`The ${name} leg identities do not match the ${leg.chain} format.`);
  }
  if (legs.long.chain === legs.short.chain
    && (legs.long.refundee !== legs.short.claimant || legs.short.refundee !== legs.long.claimant)) {
    throw Error('Same-chain legs must cross identities.');
  }
  return terms;
}

/** Sorted keys, no spaces, like Python's json.dumps(sort_keys=True, separators=(',', ':')). */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
}

export async function termsDigest(terms) {
  const bytes = new TextEncoder().encode(canonicalJson(terms));
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
}

/** The swap id: the first 16 hex characters of the SHA-256 of the canonical terms. */
export async function swapId(terms) {
  return (await termsDigest(validateTerms(terms))).slice(0, 16);
}

/** `legs.long|short` as `{chain, expiry}` for the policy. */
export function policyLegs(terms) {
  return {
    long: {chain: terms.legs.long.chain, expiry: terms.legs.long.expiry},
    short: {chain: terms.legs.short.chain, expiry: terms.legs.short.expiry},
  };
}

// ---------------------------------------------------------------- decisions

const wait = (why, detail = {}) => ({kind: 'wait', why, detail});
const move = (to, why, extra = {}) => ({kind: 'move', to, why, ...extra});
const act = (action, leg, to, why) => ({kind: 'act', action, leg, to, why});
const halt = (why, state = null, detail = {}) => ({kind: 'halt', why, state, detail});

export function refundDue(config, leg, head) {
  const chain = config.chains[leg.chain];
  return chain.kind === 'height' ? head.height >= leg.expiry + chain.refundOffsetBlocks : head.timestamp >= leg.expiry;
}

/** Time chains refuse a claim at or after the deadline; height chains do not. */
export function claimBlockedByChain(config, leg, head) {
  const chain = config.chains[leg.chain];
  return chain.kind === 'height' ? false : head.timestamp >= leg.expiry;
}

function verdictOf(terms, obs, config, now) {
  const heads = obs.heads;
  if (heads.long == null || heads.short == null) return null;
  return checkOrdered(config, {long: policyLegs(terms).long, short: policyLegs(terms).short, heads: {long: heads.long, short: heads.short}, now});
}

function policyGate(terms, obs, config, now) {
  const verdict = verdictOf(terms, obs, config, now);
  if (verdict === null) return wait('chain head unavailable', {errors: obs.errors});
  if (verdict.ok) return null;
  const codes = verdict.reasons.map(item => item.code);
  if (codes.every(code => TRANSIENT_CODES.includes(code))) return wait('policy needs a fresher observation: ' + codes.join(', '), {codes});
  return {kind: 'abort', why: 'timelock policy rejects these terms: ' + codes.join(', '), codes, reasons: verdict.reasons};
}

const legReady = (observation, need) => observation != null && observation.found && observation.verified && observation.confirmations >= need;

function stalled(record, config, terms, key, leg, now) {
  const entry = record.submitted[key];
  if (entry === undefined || entry === null) return false;
  const chain = config.chains[terms.legs[leg].chain];
  const limit = confirmSeconds(chain) + actionSeconds(chain) + config.policy.reactionSeconds;
  return now - entry.at > limit;
}

/** The initiator's gate before revealing the preimage: policy ok and the short leg still has
 * at least one action time before it can be refunded. Also the gate the page applies to a
 * hosted claim of the short leg. */
export function claimOk(terms, obs, config, now) {
  const verdict = verdictOf(terms, obs, config, now);
  if (verdict === null || !verdict.ok) return false;
  const short = policyLegs(terms).short;
  const window = legWindow(config, short, obs.heads.short, now);
  return window.firstRefund >= actionSeconds(config.chains[short.chain]);
}

/** May a hosted page submit this participant's claim now? Same rules as engine.claim_gate. The claimed
 * leg is the other leg. `submitBySeconds` is the time left to submit before the last safe moment (negative
 * means the cutoff has passed). The initiator's claim also needs the engine's own gate (`claimOk`). */
export function claimGate(role, terms, heads, config, now) {
  const name = otherLeg(role), leg = terms.legs[name], head = heads[name];
  if (head == null) return {ok: false, reasons: ['chain-head-unavailable'], submitBySeconds: null};
  const chain = config.chains[leg.chain];
  const window = legWindow(config, {chain: leg.chain, expiry: leg.expiry}, head, now);
  const reasons = [];
  if (window.expired || refundDue(config, leg, head) || claimBlockedByChain(config, leg, head)) reasons.push('claim-closed');
  const submitBySeconds = window.lastClaim - actionSeconds(chain);
  if (submitBySeconds < 0) reasons.push('inside-claim-cutoff');
  if (role === 'initiator' && !claimOk(terms, {heads}, config, now)) reasons.push('policy-rejects-claim');
  return {ok: reasons.length === 0, reasons, submitBySeconds};
}

/** Pure: what the engine would do next. Mirrors engine.decide step for step. */
export function decide(record, terms, obs, config, now) {
  const {role, state} = record;
  if (TERMINAL.includes(state)) return {kind: 'terminal', why: state};
  if (record.needs_human) return halt('needs a human: ' + record.needs_human);
  const own = ownLeg(role), other = otherLeg(role), legs = terms.legs, heads = obs.heads;
  const ownObs = obs.legs[own], otherObs = obs.legs[other];
  const needOwn = config.chains[legs[own].chain].confirmations;
  const needOther = config.chains[legs[other].chain].confirmations;

  const ownRefundStep = () => {
    const head = heads[own];
    if (head != null && refundDue(config, legs[own], head)) return act('refund', own, 'refund_submitted', 'the refund deadline has passed');
    return null;
  };
  const ownFundingConfirmed = confirmedState => {
    if (ownObs == null) return wait('own leg unreadable', {errors: obs.errors});
    if (ownObs.problem) return halt('the escrow we funded does not match the terms: ' + ownObs.problem);
    if (legReady(ownObs, needOwn)) return move(confirmedState, 'own escrow confirmed');
    if (!ownObs.found && heads[own] != null && refundDue(config, legs[own], heads[own])) {
      return halt('funding transaction not seen by the deadline; check the chain, then resolve');
    }
    if (!ownObs.found && stalled(record, config, terms, 'fund', own, now)) {
      return halt('funding transaction not visible long after submission; check the chain, then resolve');
    }
    return wait('waiting for own escrow confirmations', {have: ownObs.confirmations, need: needOwn});
  };
  const ownRefundProgress = () => {
    if (ownObs == null) return wait('own leg unreadable', {errors: obs.errors});
    if (ownObs.spent === 'refunded' && ownObs.spend_confirmations >= needOwn) return move('refunded', 'refund confirmed');
    if (ownObs.spent === 'claimed') return halt('our escrow was claimed while we were refunding it; inspect the chain');
    if (ownObs.spent == null && stalled(record, config, terms, 'refund', own, now)) {
      return halt('refund not visible long after submission; check the chain, then resolve');
    }
    return wait('waiting for refund confirmations');
  };

  if (role === 'initiator') {
    if (state === 'terms_saved') {
      const gate = policyGate(terms, obs, config, now);
      return gate === null ? act('fund', LONG, 'long_fund_submitted', 'policy allows funding the long leg') : gate;
    }
    if (state === 'long_fund_submitted') return ownFundingConfirmed('long_funded');
    if (state === 'long_funded' || state === 'short_verified') {
      if (ownObs == null) return wait('own leg unreadable', {errors: obs.errors});
      if (!ownObs.found) return move('long_fund_submitted', 'long escrow no longer visible; waiting, never funding twice');
      if (ownObs.spent === 'refunded') return move('refunded', 'long leg already refunded');
      if (ownObs.spent === 'claimed') return halt('long leg was claimed before we claimed the short leg; the preimage may have leaked');
      if (state === 'long_funded') {
        const refund = ownRefundStep();
        if (refund) return refund;
        if (otherObs == null || record.escrows.short == null) {
          return wait(record.escrows.short == null ? 'waiting for the responder to fund the short leg' : 'short leg unreadable', {errors: obs.errors});
        }
        if (otherObs.problem) return wait('short leg contradicts the terms: ' + otherObs.problem);
        if (!legReady(otherObs, needOther)) return wait('short leg not yet confirmed and verified', {have: otherObs.confirmations, need: needOther});
        if (otherObs.spent != null) return wait('short leg already spent');
        if (!claimOk(terms, obs, config, now)) return wait('policy or claim cutoff does not allow claiming the short leg');
        return move('short_verified', 'short leg verified; policy and claim cutoff ok');
      }
      if (heads[own] != null && refundDue(config, legs[own], heads[own])) return move('long_funded', 'long leg refund due; not claiming');
      if (otherObs == null) return wait('short leg unreadable', {errors: obs.errors});
      if (!legReady(otherObs, needOther) || otherObs.spent != null || !claimOk(terms, obs, config, now)) {
        return move('long_funded', 'short leg no longer safe to claim');
      }
      if (!obs.preimage_available) return halt('the preimage file is missing or does not match the hashlock');
      return act('claim', SHORT, 'short_claim_submitted', 'claiming the short leg reveals the preimage');
    }
    if (state === 'short_claim_submitted') {
      if (otherObs == null) return wait('short leg unreadable', {errors: obs.errors});
      if (otherObs.spent === 'claimed' && otherObs.spend_confirmations >= needOther) return move('done', 'short claim confirmed');
      if (otherObs.spent === 'refunded') return move('long_funded', 'short leg was refunded before our claim landed');
      if (otherObs.spent == null && stalled(record, config, terms, 'claim', other, now)) {
        return halt('claim not visible long after submission; check the chain, then resolve');
      }
      return wait('waiting for the claim to confirm');
    }
    if (state === 'refund_submitted') return ownRefundProgress();
  } else {
    if (state === 'terms_saved' || state === 'long_verified') {
      if (otherObs == null || record.escrows.long == null) {
        return wait(record.escrows.long == null ? 'waiting for the initiator long leg' : 'long leg unreadable', {errors: obs.errors});
      }
      if (otherObs.problem) return {kind: 'abort', why: 'long escrow contradicts the terms: ' + otherObs.problem, codes: ['escrow-mismatch']};
      const gate = policyGate(terms, obs, config, now);
      if (gate !== null) return gate;
      if (!legReady(otherObs, needOther) || otherObs.spent != null) {
        return wait('long leg not yet confirmed, verified and unspent', {have: otherObs.confirmations, need: needOther});
      }
      if (state === 'terms_saved') return move('long_verified', 'long leg verified; policy ok');
      return act('fund', SHORT, 'short_fund_submitted', 'long leg verified and policy ok: fund the short leg');
    }
    if (state === 'short_fund_submitted') return ownFundingConfirmed('short_funded');
    if (state === 'short_funded') {
      if (ownObs == null) return wait('own leg unreadable', {errors: obs.errors});
      if (!ownObs.found) return move('short_fund_submitted', 'short escrow no longer visible; waiting, never funding twice');
      if (ownObs.spent === 'claimed') {
        if (ownObs.preimage == null) return wait('short leg claimed but the preimage is not readable yet');
        return move('preimage_known', 'initiator claim observed', {learn_preimage: ownObs.preimage});
      }
      if (ownObs.spent === 'refunded') return move('refunded', 'short leg already refunded');
      const refund = ownRefundStep();
      if (refund) return refund;
      return wait('waiting for the initiator to claim or the deadline');
    }
    if (state === 'preimage_known' || state === 'long_claim_submitted') {
      if (otherObs == null) return wait('long leg unreadable', {errors: obs.errors});
      if (state === 'long_claim_submitted') {
        if (otherObs.spent === 'claimed' && otherObs.spend_confirmations >= needOther) return move('done', 'long claim confirmed');
        if (otherObs.spent === 'refunded') return move('failed', 'long leg was refunded before our claim landed');
        if (otherObs.spent == null && stalled(record, config, terms, 'claim', other, now)) {
          return halt('claim not visible long after submission; check the chain, then resolve');
        }
        return wait('waiting for the claim to confirm');
      }
      if (otherObs.spent === 'refunded') return move('failed', 'long leg was refunded before we could claim it');
      if (otherObs.spent === 'claimed') return move('done', 'long leg already claimed');
      if (heads[other] != null && claimBlockedByChain(config, legs[other], heads[other])) {
        return move('failed', 'long leg deadline passed on a chain that refuses late claims');
      }
      if (heads[other] == null) return wait('long chain head unavailable', {errors: obs.errors});
      if (!obs.preimage_available) return halt('the learned preimage file is missing or does not match the hashlock');
      return act('claim', LONG, 'long_claim_submitted', 'preimage is public: claim the long leg');
    }
    if (state === 'refund_submitted') return ownRefundProgress();
  }
  return halt('unknown state ' + state);
}

// ---------------------------------------------------------------- planning with margin

const CORNERS = [[0, 0], [1, 1], [1, 0], [0, 1]];
const MAX_ROUNDS = 400;

/** Most blocks the measured windows allow in `seconds` (inverse of fastSeconds). */
export function maxBlocksIn(chain, seconds) {
  if (seconds <= 0) return 0;
  let lo = 0, hi = 1;
  while (fastSeconds(chain, hi) <= seconds && hi < 10_000_000) hi *= 2;
  while (lo < hi) {
    const mid = Math.floor((lo + hi + 1) / 2);
    if (fastSeconds(chain, mid) <= seconds) lo = mid; else hi = mid - 1;
  }
  return lo;
}

/** Python round() is banker's rounding; JS Math.round is not. Fractions here are 0 or 1, so both agree. */
function project(config, chainName, head, seconds, fraction) {
  const chain = config.chains[chainName];
  if (chain.kind === 'height') {
    return {observedAt: head.observedAt + seconds, height: head.height + Math.round(maxBlocksIn(chain, seconds) * fraction)};
  }
  return {observedAt: head.observedAt + seconds, timestamp: head.timestamp + seconds};
}

function defaultMargin(config, longChain) {
  return confirmSeconds(config.chains[longChain]) + config.policy.reactionSeconds;
}

function sampleTimes(config, chainNames, margin) {
  const times = new Set([0, margin]);
  for (const name of chainNames) {
    const chain = config.chains[name];
    if (chain.kind !== 'height') continue;
    for (let n = 1; n <= maxBlocksIn(chain, margin); n++) {
      const seconds = fastSeconds(chain, n);
      if (seconds >= 0 && seconds <= margin) times.add(seconds);
    }
  }
  return [...times].sort((a, b) => a - b);
}

function verdictFailures(config, long, short, heads, now, margin) {
  const failures = [];
  for (const seconds of sampleTimes(config, [long.chain, short.chain], margin)) {
    for (const [fLong, fShort] of CORNERS) {
      const projected = {long: project(config, long.chain, heads.long, seconds, fLong), short: project(config, short.chain, heads.short, seconds, fShort)};
      const verdict = checkOrdered(config, {long, short, heads: projected, now: now + seconds});
      if (!verdict.ok) failures.push({seconds, fractions: [fLong, fShort], reasons: verdict.reasons});
    }
  }
  return failures;
}

function bump(config, leg, amountSeconds) {
  const chain = config.chains[leg.chain];
  if (chain.kind === 'height') {
    const mean = Math.trunc(Number((chain.measurement || {}).mean_seconds) || 600);
    return leg.expiry + Math.max(1, Math.floor(amountSeconds / Math.max(1, mean)));
  }
  return leg.expiry + Math.max(60, amountSeconds);
}

/** Expiries that stay compliant for `marginSeconds` (default: confirm the long leg plus a reaction).
 * `heads` is {long, short}. Throws when the pair cannot be planned. */
export function planWithMargin(config, longChain, shortChain, heads, now, marginSeconds = null) {
  const margin = marginSeconds === null ? defaultMargin(config, longChain) : marginSeconds;
  const base = planTimeouts(config, {longChain, shortChain, heads, now});
  const long = {...base.long}, short = {...base.short};
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const failures = verdictFailures(config, long, short, heads, now, margin);
    if (!failures.length) {
      return {long, short, verdict: checkOrdered(config, {long, short, heads, now}), marginSeconds: margin};
    }
    const codes = {};
    for (const failure of failures) for (const item of failure.reasons) codes[item.code] = item;
    if (['horizon-too-long', 'bad-input', 'leg-expired', 'head-stale', 'clock-drift'].some(code => code in codes)) {
      throw Error('No compliant plan: ' + Object.keys(codes).sort().join(', '));
    }
    if ('claim-window-too-short' in codes) {
      const need = codes['claim-window-too-short'].detail;
      short.expiry = bump(config, short, need.needSeconds - need.haveSeconds);
    }
    if ('insufficient-gap' in codes) {
      const need = codes['insufficient-gap'].detail;
      long.expiry = bump(config, long, need.needSeconds - need.haveSeconds);
    }
  }
  throw Error('No compliant plan found within the search limit');
}
