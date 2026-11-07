"""Swap planning with margin for the time the parties need to act.

`timelock_policy.plan_timeouts` returns the smallest expiries that satisfy the
policy at one instant. Because the height-to-time bounds are step functions
(measured windows), the smallest expiry sits exactly on a step edge: one block
later the bound loosens, and a check that passed at planning time fails when the
counterparty verifies the long leg minutes afterwards. The simulated swaps showed
this for Bitcoin long legs: a plan valid at t=0 was rejected at t=1200 s with
`insufficient-gap`. `plan_with_margin` therefore only accepts expiries for which
the verdict stays ok at the worst moments inside a margin (the instants a block-count
threshold is crossed) and for the corner cases of how many blocks each chain produced
(none, or as many as the fastest measured windows allow).
"""
try:
    from swap_engine import timelock_policy as policy
except ImportError:
    import timelock_policy as policy

MAX_ROUNDS = 400


def max_blocks_in(chain, seconds):
    """Most blocks the measured windows allow in `seconds` (inverse of fast_seconds)."""
    if seconds <= 0:
        return 0
    lo, hi = 0, 1
    while policy.fast_seconds(chain, hi) <= seconds and hi < 10_000_000:
        hi *= 2
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if policy.fast_seconds(chain, mid) <= seconds:
            lo = mid
        else:
            hi = mid - 1
    return lo


def project(config, chain_name, head, seconds, fraction):
    """Head after `seconds`; `fraction` in [0, 1] picks how many of the possible blocks were produced."""
    chain = config['chains'][chain_name]
    if chain['kind'] == 'height':
        blocks = round(max_blocks_in(chain, seconds) * fraction)
        return {'observedAt': head['observedAt'] + seconds, 'height': head['height'] + blocks}
    return {'observedAt': head['observedAt'] + seconds, 'timestamp': head['timestamp'] + seconds}


def default_margin(config, long_chain, short_chain=None):
    """Time for the long leg to confirm, the responder to react, and, when the short leg's chain needs a proof
    (`proveSeconds`, Hegemon), for the responder to prove and confirm the short leg before the initiator can claim.

    The first two alone were the whole margin until a local Bitcoin/Hegemon swap found the initiator unable to claim:
    the proof and two Hegemon blocks of confirmation ate the gap the plan had left."""
    margin = policy.confirm_seconds(config['chains'][long_chain]) + config['policy']['reactionSeconds']
    if short_chain is not None:
        short = config['chains'][short_chain]
        if short.get('proveSeconds'):
            margin += short['proveSeconds'] + policy.confirm_seconds(short)
    return margin


def sample_times(config, chain_names, margin):
    """Moments to check inside [0, margin].

    Between two block-count thresholds the gap between the legs only improves (the short leg's time
    remaining shrinks linearly while the long leg's bound is constant), so the worst moments are the
    instants a threshold is crossed: the times at which one more block becomes possible under the
    fastest measured windows. Time chains contribute no thresholds.
    """
    times = {0, margin}
    for name in chain_names:
        chain = config['chains'][name]
        if chain['kind'] != 'height':
            continue
        for n in range(1, max_blocks_in(chain, margin) + 1):
            seconds = policy.fast_seconds(chain, n)
            if 0 <= seconds <= margin:
                times.add(seconds)
    return sorted(times)


CORNERS = ((0.0, 0.0), (1.0, 1.0), (1.0, 0.0), (0.0, 1.0))


def verdicts(config, long, short, heads, now, margin):
    """Check ordered legs at the worst moments and at the four corner head advances; return failures.

    A height chain's remaining-time bounds are monotone in blocks produced (the long leg's earliest
    refund is smallest when the most blocks were produced; the short leg's latest claim is largest
    when the fewest were), so the corners bound every intermediate block count. The unit test
    checks that claim on random intermediate counts rather than assuming it.
    """
    failures = []
    for seconds in sample_times(config, (long['chain'], short['chain']), margin):
        for f_long, f_short in CORNERS:
            projected = {'long': project(config, long['chain'], heads['long'], seconds, f_long),
                         'short': project(config, short['chain'], heads['short'], seconds, f_short)}
            verdict = policy.check_ordered(config, long, short, projected, now + seconds)
            if not verdict['ok']:
                failures.append({'seconds': seconds, 'fractions': (f_long, f_short), 'reasons': verdict['reasons']})
    return failures


def _bump(config, leg, amount_seconds):
    chain = config['chains'][leg['chain']]
    if chain['kind'] == 'height':
        mean = int((chain.get('measurement') or {}).get('mean_seconds') or 0)
        if mean:
            return leg['expiry'] + max(1, amount_seconds // max(1, mean))
        # No measured mean (a local fixture): the most blocks the fastest windows allow in that time, which cannot
        # overshoot. A 600 second guess advanced a 3 second regtest chain one block per round and ran out of rounds.
        return leg['expiry'] + max(1, max_blocks_in(chain, amount_seconds))
    return leg['expiry'] + max(60, amount_seconds)


def plan_with_margin(config, long_chain, short_chain, heads, now, margin_seconds=None):
    """Expiries that stay compliant for `margin_seconds` (default: confirm the long leg plus a reaction).

    `heads` is {'long': head, 'short': head}. Raises ValueError if the pair cannot be planned,
    for example when the safe horizon exceeds the policy limit.
    """
    margin = default_margin(config, long_chain, short_chain) if margin_seconds is None else margin_seconds
    base = policy.plan_timeouts(config, long_chain, short_chain, heads, now)
    long = dict(base['long'])
    short = dict(base['short'])
    for _ in range(MAX_ROUNDS):
        failures = verdicts(config, long, short, heads, now, margin)
        if not failures:
            final = policy.check_ordered(config, long, short, heads, now)
            return {'long': long, 'short': short, 'verdict': final, 'marginSeconds': margin}
        codes = {item['code']: item for failure in failures for item in failure['reasons']}
        if 'horizon-too-long' in codes or 'bad-input' in codes or 'leg-expired' in codes or 'head-stale' in codes or 'clock-drift' in codes:
            raise ValueError('No compliant plan: ' + ', '.join(sorted(codes)))
        if 'claim-window-too-short' in codes:
            need = codes['claim-window-too-short']['detail']
            short['expiry'] = _bump(config, short, need['needSeconds'] - need['haveSeconds'])
        if 'insufficient-gap' in codes:
            need = codes['insufficient-gap']['detail']
            long['expiry'] = _bump(config, long, need['needSeconds'] - need['haveSeconds'])
    raise ValueError('No compliant plan found within the search limit')
