"""Cross-chain deadline policy for the four-chain HTLC swap (Python mirror).

Mirror of swap-ui/timelock-policy.mjs. Both implementations read
config/swap/chain-timing.json and must reproduce every case in
config/swap/timelock-vectors.json bit for bit. Inputs and outputs use the same
camelCase keys as the JavaScript so the vectors are shared without translation.
All numbers are integer seconds. Read the module docstring of the JavaScript file
for the safety argument; this is a testnet policy, not a real-funds guarantee.
"""
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / 'config' / 'swap' / 'chain-timing.json'
VECTORS_PATH = ROOT / 'config' / 'swap' / 'timelock-vectors.json'


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and abs(value) <= 2**53 - 1


def _reason(code, message, **detail):
    return {'code': code, 'message': message, 'detail': detail}


def load_timing(path=CONFIG_PATH):
    return validate_timing(json.loads(Path(path).read_text()))


def _chain(config, name):
    chain = (config.get('chains') or {}).get(name)
    if chain is None:
        raise ValueError(f'Unknown chain for timelock policy: {name}')
    return chain


def _is_height(chain):
    return chain['kind'] == 'height'


def validate_timing(config):
    def need(ok, text):
        if not ok:
            raise ValueError(f'Invalid chain-timing config: {text}')

    policy = config.get('policy')
    need(isinstance(policy, dict), 'policy missing')
    for key in ('reactionSeconds', 'gapFloorSeconds', 'maxHorizonSeconds', 'maxObservationAgeSeconds', 'minShortWindowSeconds'):
        need(_is_int(policy.get(key)) and policy[key] >= 0, f'policy.{key} must be a non-negative integer')
    need(isinstance(policy.get('gapFactor'), (int, float)) and policy['gapFactor'] >= 1, 'policy.gapFactor must be >= 1')
    need(isinstance(config.get('chains'), dict), 'chains missing')
    for name, chain in config['chains'].items():
        need(chain.get('kind') in ('height', 'time'), f'{name}.kind must be height or time')
        need(_is_int(chain.get('confirmations')) and chain['confirmations'] >= 1, f'{name}.confirmations must be >= 1')
        need(_is_int(chain.get('clockSkewSeconds')) and chain['clockSkewSeconds'] >= 0, f'{name}.clockSkewSeconds must be a non-negative integer')
        need('proveSeconds' not in chain or (_is_int(chain['proveSeconds']) and chain['proveSeconds'] >= 0), f'{name}.proveSeconds invalid')
        if chain['kind'] == 'time':
            for key in ('inclusionSeconds', 'slowBlockSeconds', 'maxHeadAgeSeconds'):
                need(_is_int(chain.get(key)) and chain[key] > 0, f'{name}.{key} must be a positive integer')
            continue
        need(isinstance(chain.get('slowFactor'), (int, float)) and chain['slowFactor'] >= 1, f'{name}.slowFactor must be >= 1')
        need(isinstance(chain.get('fastFactor'), (int, float)) and 0 < chain['fastFactor'] <= 1, f'{name}.fastFactor must be in (0,1]')
        need(_is_int(chain.get('outageAllowanceSeconds')) and chain['outageAllowanceSeconds'] >= 0, f'{name}.outageAllowanceSeconds invalid')
        need(_is_int(chain.get('providerLagBlocks')) and chain['providerLagBlocks'] >= 0, f'{name}.providerLagBlocks invalid')
        need(_is_int(chain.get('refundOffsetBlocks')) and chain['refundOffsetBlocks'] >= 0, f'{name}.refundOffsetBlocks invalid')
        need(isinstance(chain.get('windows'), dict) and '1' in chain['windows'], f'{name}.windows needs a 1-block entry')
        for k, w in chain['windows'].items():
            need(k.isdigit() and int(k) >= 1 and _is_int(w.get('min')) and _is_int(w.get('max')) and 0 <= w['min'] <= w['max'], f'{name}.windows[{k}] invalid')
    return config


def _windows(chain):
    return [(int(k), w) for k, w in chain['windows'].items()]


def slow_seconds(chain, n):
    if n <= 0:
        return 0
    best = min(-(-n // k) * w['max'] for k, w in _windows(chain))
    return math.ceil(best * chain['slowFactor']) + chain['outageAllowanceSeconds']


def fast_seconds(chain, n):
    if n <= 0:
        return 0
    best = max([0] + [(n // k) * w['min'] for k, w in _windows(chain)])
    return math.floor(best * chain['fastFactor'])


def blocks_during(chain, seconds):
    """Most blocks a height chain can add within `seconds`, from the fast side of the measured windows."""
    if not _is_height(chain) or seconds <= 0:
        return 0
    lo, hi = 0, 1_000_000
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if fast_seconds(chain, mid) <= seconds:
            lo = mid
        else:
            hi = mid - 1
    return lo


def prove_blocks(chain):
    """Blocks that can pass while the wallet proves an action (zero for chains without proving)."""
    return blocks_during(chain, chain.get('proveSeconds', 0))


def lock_floor(chain, head_height):
    """Smallest expiry height a new lock may carry: the chain's minimum lock window, the provider lag and
    the blocks that can pass while the lock is proved, so the lock still has its window when it lands."""
    return head_height + chain['minLockBlocks'] + chain['providerLagBlocks'] + prove_blocks(chain) + 1


def lock_window_shortfall(config, leg, head):
    """None when a lock for `leg` can still be made; otherwise a reason the engine must not fund it.

    The private-spend wallet refuses a timeout below its tip plus the minimum lock window. The check here
    adds the provider lag and the proving time, using the same margins the planner used, so a swap that sat
    too long between planning and funding is refused by policy rather than by the wallet.
    """
    chain = _chain(config, leg['chain'])
    if not _is_height(chain) or not chain.get('minLockBlocks'):
        return None
    need = lock_floor(chain, head['height'])
    if leg['expiry'] >= need:
        return None
    return _reason('lock-window-short', f"The {leg['chain']} lock must expire at height {need} or later; this one expires at {leg['expiry']}.",
                   haveExpiry=leg['expiry'], needExpiry=need)


def inclusion_seconds(chain):
    return slow_seconds(chain, 1) if _is_height(chain) else chain['inclusionSeconds']


def confirm_seconds(chain, depth=None):
    depth = chain['confirmations'] if depth is None else depth
    if _is_height(chain):
        return slow_seconds(chain, depth)
    return chain['inclusionSeconds'] + (depth - 1) * chain['slowBlockSeconds']


def action_seconds(chain):
    return inclusion_seconds(chain) + chain.get('proveSeconds', 0)


def _scale(config, base):
    policy = config['policy']
    return max(math.ceil(base * policy['gapFactor']), base + policy['gapFloorSeconds'])


def leg_window(config, leg, head, now):
    chain = _chain(config, leg['chain'])
    if _is_height(chain):
        true_head = head['height'] + chain['providerLagBlocks']
        return {
            'firstRefund': fast_seconds(chain, leg['expiry'] + chain['refundOffsetBlocks'] - true_head),
            'lastClaim': slow_seconds(chain, leg['expiry'] - head['height']),
            'lockUpperBound': slow_seconds(chain, leg['expiry'] + chain['refundOffsetBlocks'] - head['height']),
            'expired': head['height'] >= leg['expiry'],
        }
    first_refund = leg['expiry'] - chain['clockSkewSeconds'] - now
    return {
        'firstRefund': first_refund,
        'lastClaim': leg['expiry'] - 1 + chain['clockSkewSeconds'] - now,
        'lockUpperBound': leg['expiry'] + chain['clockSkewSeconds'] - now,
        'expired': first_refund <= 0,
    }


def leg_requirements(config, chain_name):
    """Per-leg minimums a verifier can enforce without the counterparty leg (a floor;
    check_pair is the actual safety rule). See legRequirements in the JavaScript."""
    chain = _chain(config, chain_name)
    window = _scale(config, action_seconds(chain) + config['policy']['reactionSeconds'])
    out = {'confirmations': chain['confirmations'], 'minClaimWindowSeconds': window}
    if _is_height(chain):
        lo, hi = 0, 20_000_000
        while lo < hi:
            mid = (lo + hi) // 2
            if fast_seconds(chain, mid + chain['refundOffsetBlocks'] - chain['providerLagBlocks']) >= window:
                hi = mid
            else:
                lo = mid + 1
        out['minBlocksToExpiry'] = lo
    return out


def _check_inputs(config, role, leg, head, now, reasons):
    chains = config['chains']
    if not isinstance(leg, dict) or not isinstance(leg.get('chain'), str) or leg['chain'] not in chains \
            or not _is_int(leg.get('expiry')) or leg['expiry'] <= 0:
        reasons.append(_reason('bad-input', f'The {role} leg needs a known chain and a positive integer expiry.', role=role))
        return False
    chain = chains[leg['chain']]
    if not isinstance(head, dict) or not _is_int(head.get('observedAt')):
        reasons.append(_reason('bad-input', f'The {role} leg needs a chain head observation time.', role=role))
        return False
    if abs(now - head['observedAt']) > config['policy']['maxObservationAgeSeconds']:
        reasons.append(_reason('head-stale', f'The {role} chain head was observed too long ago; refresh it.', role=role, ageSeconds=abs(now - head['observedAt'])))
        return False
    if _is_height(chain):
        if not _is_int(head.get('height')) or head['height'] < 0:
            reasons.append(_reason('bad-input', f'The {role} chain head needs an integer height.', role=role))
            return False
        return True
    if not _is_int(head.get('timestamp')):
        reasons.append(_reason('bad-input', f'The {role} chain head needs a block timestamp.', role=role))
        return False
    drift = now - head['timestamp']
    if drift < -chain['clockSkewSeconds'] or drift > chain['maxHeadAgeSeconds'] + chain['clockSkewSeconds']:
        reasons.append(_reason('clock-drift', f"This device's clock and the {role} chain's latest block disagree by {drift} seconds.", role=role, driftSeconds=drift))
        return False
    return True


def check_ordered(config, long, short, heads, now):
    """Judge one ordering: `long` is refundable later than `short`."""
    reasons = []
    heads = heads or {}
    ok_long = _check_inputs(config, 'long', long, heads.get('long'), now, reasons)
    ok_short = _check_inputs(config, 'short', short, heads.get('short'), now, reasons)
    if not ok_long or not ok_short:
        return {'ok': False, 'reasons': reasons, 'metrics': {}}
    cl = config['chains'][long['chain']]
    cs = config['chains'][short['chain']]
    lw = leg_window(config, long, heads['long'], now)
    sw = leg_window(config, short, heads['short'], now)
    if lw['expired']:
        reasons.append(_reason('leg-expired', 'The long leg has already reached its deadline.', role='long'))
    if sw['expired']:
        reasons.append(_reason('leg-expired', 'The short leg has already reached its deadline.', role='short'))
    policy = config['policy']
    claim_required = _scale(config, action_seconds(cs) + policy['reactionSeconds'])
    gap_required = _scale(config, confirm_seconds(cs) + policy['reactionSeconds'] + action_seconds(cl))
    gap = lw['firstRefund'] - sw['lastClaim']
    metrics = {
        'longFirstRefundIn': lw['firstRefund'], 'shortFirstRefundIn': sw['firstRefund'],
        'shortLastClaimIn': sw['lastClaim'], 'gapSeconds': gap, 'gapRequiredSeconds': gap_required,
        'shortClaimWindowSeconds': sw['firstRefund'], 'shortClaimRequiredSeconds': claim_required,
        'longLockUpperSeconds': lw['lockUpperBound'], 'shortLockUpperSeconds': sw['lockUpperBound'],
    }
    if not sw['expired'] and sw['firstRefund'] < claim_required:
        reasons.append(_reason(
            'claim-window-too-short',
            f"Only {max(0, sw['firstRefund'])} seconds are left to claim the short leg; at least {claim_required} are needed.",
            role='short', haveSeconds=sw['firstRefund'], needSeconds=claim_required))
    if not lw['expired'] and not sw['expired'] and gap < gap_required:
        reasons.append(_reason(
            'insufficient-gap',
            f"The long leg becomes refundable only {gap} seconds after the short leg's last safe claim; at least {gap_required} are needed.",
            haveSeconds=gap, needSeconds=gap_required))
    horizon = max(lw['lockUpperBound'], sw['lockUpperBound'])
    if horizon > policy['maxHorizonSeconds']:
        reasons.append(_reason(
            'horizon-too-long',
            f"Funds could stay locked for up to {horizon} seconds; the limit is {policy['maxHorizonSeconds']}.",
            horizonSeconds=horizon, limitSeconds=policy['maxHorizonSeconds']))
    return {'ok': not reasons, 'reasons': reasons, 'metrics': metrics}


def check_pair(config, a, b, heads, now):
    """Judge a pair without knowing roles: try both orderings and report the better one."""
    heads = heads or {}
    first = check_ordered(config, a, b, {'long': heads.get('a'), 'short': heads.get('b')}, now)
    second = check_ordered(config, b, a, {'long': heads.get('b'), 'short': heads.get('a')}, now)

    def score(verdict):
        m = verdict['metrics']
        return -math.inf if 'gapSeconds' not in m else m['gapSeconds'] - m['gapRequiredSeconds']

    if first['ok'] and not second['ok']:
        pick, side = first, 'a'
    elif second['ok'] and not first['ok']:
        pick, side = second, 'b'
    elif score(first) >= score(second):
        pick, side = first, 'a'
    else:
        pick, side = second, 'b'
    return {**pick, 'long': side}


def _smallest_expiry(config, chain_name, head, now, predicate):
    chain = config['chains'][chain_name]
    lo = head['height'] + 1 if _is_height(chain) else now + 1
    hi = lo + 20_000_000
    if not predicate(hi):
        raise ValueError('No expiry within search range satisfies the timelock policy.')
    while lo < hi:
        mid = (lo + hi) // 2
        if predicate(mid):
            hi = mid
        else:
            lo = mid + 1
    return lo


def plan_timeouts(config, long_chain, short_chain, heads, now):
    """Smallest compliant expiries for a new swap, with the verdict of that plan."""
    cl = _chain(config, long_chain)
    cs = _chain(config, short_chain)
    long_head, short_head = heads['long'], heads['short']
    policy = config['policy']
    short_need = max(
        policy['minShortWindowSeconds'],
        confirm_seconds(cl) + policy['reactionSeconds'] + confirm_seconds(cs)
        + _scale(config, action_seconds(cs) + policy['reactionSeconds']))

    def floor_of(chain, head):
        if _is_height(chain) and chain.get('minLockBlocks'):
            return lock_floor(chain, head['height'])
        return 0

    short_expiry = _smallest_expiry(
        config, short_chain, short_head, now,
        lambda e: leg_window(config, {'chain': short_chain, 'expiry': e}, short_head, now)['firstRefund'] >= short_need)
    short_expiry = max(short_expiry, floor_of(cs, short_head))
    sw = leg_window(config, {'chain': short_chain, 'expiry': short_expiry}, short_head, now)
    gap_required = _scale(config, confirm_seconds(cs) + policy['reactionSeconds'] + action_seconds(cl))
    long_need = sw['lastClaim'] + gap_required
    long_expiry = _smallest_expiry(
        config, long_chain, long_head, now,
        lambda e: leg_window(config, {'chain': long_chain, 'expiry': e}, long_head, now)['firstRefund'] >= long_need)
    long_expiry = max(long_expiry, floor_of(cl, long_head))
    long = {'chain': long_chain, 'expiry': long_expiry}
    short = {'chain': short_chain, 'expiry': short_expiry}
    return {'long': long, 'short': short, 'verdict': check_ordered(config, long, short, heads, now)}
