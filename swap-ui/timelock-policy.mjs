/** Cross-chain deadline policy for the four-chain HTLC swap.
 *
 * Pure functions over a config object (config/swap/chain-timing.json) so the
 * browser, Node tests and the Python mirror (scripts/swap_engine/timelock_policy.py)
 * produce identical verdicts from the shared vectors in
 * config/swap/timelock-vectors.json. Every number is integer seconds.
 *
 * Vocabulary. The long leg is funded first by the party who knows the preimage
 * and is refundable later. The short leg is funded second and is claimed first;
 * claiming it reveals the preimage. Safety needs the preimage to reach the owner
 * of the long leg while that leg is still claimable:
 *   firstRefund(long) - lastClaim(short) >= observe + react + claim-on-long.
 * A height deadline is turned into wall-clock bounds from measured windows: the
 * refund side uses the FASTEST plausible block production, the claim side the
 * SLOWEST. This is a testnet policy, not a real-funds guarantee.
 */
const INT = Number.isSafeInteger;
const reason = (code, message, detail = {}) => ({ code, message, detail });

function chainOf(config, name) {
  const c = config && config.chains && config.chains[name];
  if (!c) throw new Error(`Unknown chain for timelock policy: ${name}`);
  return c;
}
const isHeight = c => c.kind === 'height';

/** Validate a config object. Throws with a precise message; returns the config. */
export function validateTiming(config) {
  const p = config && config.policy;
  const need = (ok, text) => { if (!ok) throw new Error(`Invalid chain-timing config: ${text}`); };
  need(p && typeof p === 'object', 'policy missing');
  for (const key of ['reactionSeconds', 'gapFloorSeconds', 'maxHorizonSeconds', 'maxObservationAgeSeconds', 'minShortWindowSeconds']) {
    need(INT(p[key]) && p[key] >= 0, `policy.${key} must be a non-negative integer`);
  }
  need(typeof p.gapFactor === 'number' && p.gapFactor >= 1, 'policy.gapFactor must be >= 1');
  need(config.chains && typeof config.chains === 'object', 'chains missing');
  for (const [name, c] of Object.entries(config.chains)) {
    need(c.kind === 'height' || c.kind === 'time', `${name}.kind must be height or time`);
    need(INT(c.confirmations) && c.confirmations >= 1, `${name}.confirmations must be >= 1`);
    need(INT(c.clockSkewSeconds) && c.clockSkewSeconds >= 0, `${name}.clockSkewSeconds must be a non-negative integer`);
    need(c.proveSeconds === undefined || (INT(c.proveSeconds) && c.proveSeconds >= 0), `${name}.proveSeconds invalid`);
    if (c.kind === 'time') {
      for (const key of ['inclusionSeconds', 'slowBlockSeconds', 'maxHeadAgeSeconds']) need(INT(c[key]) && c[key] > 0, `${name}.${key} must be a positive integer`);
      continue;
    }
    need(typeof c.slowFactor === 'number' && c.slowFactor >= 1, `${name}.slowFactor must be >= 1`);
    need(typeof c.fastFactor === 'number' && c.fastFactor > 0 && c.fastFactor <= 1, `${name}.fastFactor must be in (0,1]`);
    need(INT(c.outageAllowanceSeconds) && c.outageAllowanceSeconds >= 0, `${name}.outageAllowanceSeconds invalid`);
    need(INT(c.providerLagBlocks) && c.providerLagBlocks >= 0, `${name}.providerLagBlocks invalid`);
    need(INT(c.refundOffsetBlocks) && c.refundOffsetBlocks >= 0, `${name}.refundOffsetBlocks invalid`);
    need(c.windows && c.windows['1'], `${name}.windows needs a 1-block entry`);
    for (const [k, w] of Object.entries(c.windows)) {
      need(INT(Number(k)) && Number(k) >= 1 && INT(w.min) && INT(w.max) && w.min >= 0 && w.max >= w.min, `${name}.windows[${k}] invalid`);
    }
  }
  return config;
}

function windowList(c) {
  return Object.entries(c.windows).map(([k, w]) => [Number(k), w]);
}

/** Wall-clock seconds by which `n` blocks have surely been produced (upper bound). */
export function slowSeconds(c, n) {
  if (n <= 0) return 0;
  let best = Infinity;
  for (const [k, w] of windowList(c)) best = Math.min(best, Math.ceil(n / k) * w.max);
  return Math.ceil(best * c.slowFactor) + c.outageAllowanceSeconds;
}

/** Wall-clock seconds before which `n` blocks have surely not been produced (lower bound). */
export function fastSeconds(c, n) {
  if (n <= 0) return 0;
  let best = 0;
  for (const [k, w] of windowList(c)) best = Math.max(best, Math.floor(n / k) * w.min);
  return Math.floor(best * c.fastFactor);
}

/** Seconds for a submitted transaction to be included in a block. */
export function inclusionSeconds(c) {
  return isHeight(c) ? slowSeconds(c, 1) : c.inclusionSeconds;
}

/** Seconds from submission until an event is `depth` blocks deep (default: required confirmations). */
export function confirmSeconds(c, depth = c.confirmations) {
  return isHeight(c) ? slowSeconds(c, depth) : c.inclusionSeconds + (depth - 1) * c.slowBlockSeconds;
}

/** Seconds to build, prove and land a claim or refund after deciding to act. */
export function actionSeconds(c) {
  return inclusionSeconds(c) + (c.proveSeconds || 0);
}

function scale(config, base) {
  const p = config.policy;
  return Math.max(Math.ceil(base * p.gapFactor), base + p.gapFloorSeconds);
}

/** Seconds (from `now`) at which each leg first allows a refund and last safely allows a claim. */
export function legWindow(config, leg, head, now) {
  const c = chainOf(config, leg.chain);
  if (isHeight(c)) {
    const trueHead = head.height + c.providerLagBlocks; // provider may be behind; assume it is
    const firstRefund = fastSeconds(c, leg.expiry + c.refundOffsetBlocks - trueHead);
    const lastClaim = slowSeconds(c, leg.expiry - head.height);
    const lockUpperBound = slowSeconds(c, leg.expiry + c.refundOffsetBlocks - head.height);
    return { firstRefund, lastClaim, lockUpperBound, expired: head.height >= leg.expiry };
  }
  const firstRefund = leg.expiry - c.clockSkewSeconds - now;
  const lastClaim = leg.expiry - 1 + c.clockSkewSeconds - now;
  return { firstRefund, lastClaim, lockUpperBound: leg.expiry + c.clockSkewSeconds - now, expired: firstRefund <= 0 };
}

/** Per-leg minimums a verifier can enforce without knowing the counterparty leg: the
 * required confirmations and the shortest remaining time (and, for height chains,
 * blocks from the observed head to the deadline) that still leaves a claimant the
 * policy's claim window. This is a floor; `checkPair` is the actual safety rule. */
export function legRequirements(config, chainName) {
  const c = chainOf(config, chainName);
  const minClaimWindowSeconds = scale(config, actionSeconds(c) + config.policy.reactionSeconds);
  const out = { confirmations: c.confirmations, minClaimWindowSeconds };
  if (isHeight(c)) {
    let lo = 0, hi = 20_000_000;
    const enough = d => fastSeconds(c, d + c.refundOffsetBlocks - c.providerLagBlocks) >= minClaimWindowSeconds;
    while (lo < hi) { const mid = Math.floor((lo + hi) / 2); if (enough(mid)) hi = mid; else lo = mid + 1; }
    out.minBlocksToExpiry = lo;
  }
  return out;
}

function checkInputs(config, role, leg, head, now, reasons) {
  if (!leg || typeof leg.chain !== 'string' || !config.chains[leg.chain] || !INT(leg.expiry) || leg.expiry <= 0) {
    reasons.push(reason('bad-input', `The ${role} leg needs a known chain and a positive integer expiry.`, { role }));
    return false;
  }
  const c = config.chains[leg.chain];
  if (!head || !INT(head.observedAt)) {
    reasons.push(reason('bad-input', `The ${role} leg needs a chain head observation time.`, { role }));
    return false;
  }
  if (Math.abs(now - head.observedAt) > config.policy.maxObservationAgeSeconds) {
    reasons.push(reason('head-stale', `The ${role} chain head was observed too long ago; refresh it.`, { role, ageSeconds: Math.abs(now - head.observedAt) }));
    return false;
  }
  if (isHeight(c)) {
    if (!INT(head.height) || head.height < 0) {
      reasons.push(reason('bad-input', `The ${role} chain head needs an integer height.`, { role }));
      return false;
    }
    return true;
  }
  if (!INT(head.timestamp)) {
    reasons.push(reason('bad-input', `The ${role} chain head needs a block timestamp.`, { role }));
    return false;
  }
  const drift = now - head.timestamp;
  if (drift < -c.clockSkewSeconds || drift > c.maxHeadAgeSeconds + c.clockSkewSeconds) {
    reasons.push(reason('clock-drift', `This device's clock and the ${role} chain's latest block disagree by ${drift} seconds.`, { role, driftSeconds: drift }));
    return false;
  }
  return true;
}

/** Judge one ordering: `long` is refundable later than `short`. */
export function checkOrdered(config, { long, short, heads, now }) {
  const reasons = [];
  const okLong = checkInputs(config, 'long', long, heads && heads.long, now, reasons);
  const okShort = checkInputs(config, 'short', short, heads && heads.short, now, reasons);
  if (!okLong || !okShort) return { ok: false, reasons, metrics: {} };
  const cl = config.chains[long.chain];
  const cs = config.chains[short.chain];
  const lw = legWindow(config, long, heads.long, now);
  const sw = legWindow(config, short, heads.short, now);
  if (lw.expired) reasons.push(reason('leg-expired', 'The long leg has already reached its deadline.', { role: 'long' }));
  if (sw.expired) reasons.push(reason('leg-expired', 'The short leg has already reached its deadline.', { role: 'short' }));

  const claimRequired = scale(config, actionSeconds(cs) + config.policy.reactionSeconds);
  const gapBase = confirmSeconds(cs) + config.policy.reactionSeconds + actionSeconds(cl);
  const gapRequired = scale(config, gapBase);
  const gap = lw.firstRefund - sw.lastClaim;
  const metrics = {
    longFirstRefundIn: lw.firstRefund, shortFirstRefundIn: sw.firstRefund, shortLastClaimIn: sw.lastClaim,
    gapSeconds: gap, gapRequiredSeconds: gapRequired, shortClaimWindowSeconds: sw.firstRefund,
    shortClaimRequiredSeconds: claimRequired,
    longLockUpperSeconds: lw.lockUpperBound, shortLockUpperSeconds: sw.lockUpperBound,
  };
  if (!sw.expired && sw.firstRefund < claimRequired) {
    reasons.push(reason('claim-window-too-short', `Only ${Math.max(0, sw.firstRefund)} seconds are left to claim the short leg; at least ${claimRequired} are needed.`, { role: 'short', haveSeconds: sw.firstRefund, needSeconds: claimRequired }));
  }
  if (!lw.expired && !sw.expired && gap < gapRequired) {
    reasons.push(reason('insufficient-gap', `The long leg becomes refundable only ${gap} seconds after the short leg's last safe claim; at least ${gapRequired} are needed.`, { haveSeconds: gap, needSeconds: gapRequired }));
  }
  const horizon = Math.max(lw.lockUpperBound, sw.lockUpperBound);
  if (horizon > config.policy.maxHorizonSeconds) {
    reasons.push(reason('horizon-too-long', `Funds could stay locked for up to ${horizon} seconds; the limit is ${config.policy.maxHorizonSeconds}.`, { horizonSeconds: horizon, limitSeconds: config.policy.maxHorizonSeconds }));
  }
  return { ok: reasons.length === 0, reasons, metrics };
}

/** Judge a pair without knowing roles: try both orderings and report the better one.
 * `a` and `b` are `{chain, expiry}`; `heads` is `{a, b}`; expiry is integer seconds
 * for time chains (Cardano ms / 1000) and a block height for height chains. */
export function checkPair(config, { a, b, heads, now }) {
  const first = checkOrdered(config, { long: a, short: b, heads: heads && { long: heads.a, short: heads.b }, now });
  const second = checkOrdered(config, { long: b, short: a, heads: heads && { long: heads.b, short: heads.a }, now });
  const score = v => (v.metrics.gapSeconds === undefined ? -Infinity : v.metrics.gapSeconds - v.metrics.gapRequiredSeconds);
  const pick = (first.ok && !second.ok) ? [first, 'a'] : (second.ok && !first.ok) ? [second, 'b']
    : score(first) >= score(second) ? [first, 'a'] : [second, 'b'];
  return { ...pick[0], long: pick[1] };
}

function smallestExpiry(config, leg, head, now, predicate) {
  const c = config.chains[leg.chain];
  let lo = isHeight(c) ? head.height + 1 : now + 1;
  let hi = lo + 20_000_000;
  if (!predicate(hi)) throw new Error('No expiry within search range satisfies the timelock policy.');
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (predicate(mid)) hi = mid; else lo = mid + 1;
  }
  return lo;
}

/** Recommend the smallest compliant expiries for a new swap. Returns native expiries
 * (block height or integer seconds) and the verdict of the recommendation. */
export function planTimeouts(config, { longChain, shortChain, heads, now }) {
  const cl = chainOf(config, longChain);
  const cs = chainOf(config, shortChain);
  const longHead = heads.long;
  const shortHead = heads.short;
  const shortNeed = Math.max(config.policy.minShortWindowSeconds,
    confirmSeconds(cl) + config.policy.reactionSeconds + confirmSeconds(cs)
      + scale(config, actionSeconds(cs) + config.policy.reactionSeconds));
  const floorOf = (c, head) => (isHeight(c) && c.minLockBlocks ? head.height + c.minLockBlocks + c.providerLagBlocks + 1 : 0);
  const shortProbe = { chain: shortChain };
  let shortExpiry = smallestExpiry(config, shortProbe, shortHead, now,
    e => legWindow(config, { chain: shortChain, expiry: e }, shortHead, now).firstRefund >= shortNeed);
  shortExpiry = Math.max(shortExpiry, floorOf(cs, shortHead));
  const sw = legWindow(config, { chain: shortChain, expiry: shortExpiry }, shortHead, now);
  const gapRequired = scale(config, confirmSeconds(cs) + config.policy.reactionSeconds + actionSeconds(cl));
  const longNeed = sw.lastClaim + gapRequired;
  let longExpiry = smallestExpiry(config, { chain: longChain }, longHead, now,
    e => legWindow(config, { chain: longChain, expiry: e }, longHead, now).firstRefund >= longNeed);
  longExpiry = Math.max(longExpiry, floorOf(cl, longHead));
  const long = { chain: longChain, expiry: longExpiry };
  const short = { chain: shortChain, expiry: shortExpiry };
  return { long, short, verdict: checkOrdered(config, { long, short, heads, now }) };
}
