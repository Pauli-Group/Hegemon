"""Generate config/swap/flow-vectors.json: the contract between the Python engine and the page.

The hosted page (swap-ui/swap-flow.mjs) re-implements only the pure functions `decide`, `explain`
and `plan_with_margin` so it can show what the engine would do. This module records what the Python
implementations answer for a deterministic, coverage-guided set of inputs; swap-ui/swap-flow.test.mjs
replays them against the JavaScript, and test_ui_vectors.py fails when the checked-in file is stale.

    cd scripts && PYTHONPATH=.:$HOME/.local/opt/hegemon-swap-python python3 -m swap_engine.ui_vectors [--check]
"""
import json
import random
import sys
from pathlib import Path

from swap_engine import engine, planner, store
from swap_engine import timelock_policy as policy
from swap_engine.adapter import empty_observation

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'config' / 'swap' / 'flow-vectors.json'
NOW = 1_800_000_000
HASHLOCK = 'ab' * 32
SEED = 20261106
PER_SIGNATURE = 4
PAIRS = [('ethereum', 'cardano'), ('bitcoin', 'ethereum'), ('cardano', 'bitcoin'), ('hegemon', 'ethereum')]
STATES = {
    'initiator': ['terms_saved', 'long_fund_submitted', 'long_funded', 'short_verified', 'short_claim_submitted', 'refund_submitted', 'done', 'aborted'],
    'responder': ['terms_saved', 'long_verified', 'short_fund_submitted', 'short_funded', 'preimage_known', 'long_claim_submitted', 'refund_submitted', 'failed'],
}
SECRET = 'cd' * 32


def head(config, chain, base, offset=0):
    if config['chains'][chain]['kind'] == 'height':
        return {'observedAt': NOW, 'height': base + offset}
    return {'observedAt': NOW, 'timestamp': NOW - 5 + offset}


def heads_at(config, terms, advance):
    """Chain heads at `now`; `advance` moves a leg's head to or past its deadline."""
    out = {}
    for name in ('long', 'short'):
        leg = terms['legs'][name]
        chain = config['chains'][leg['chain']]
        if advance == name or advance == 'both':
            out[name] = ({'observedAt': NOW, 'height': leg['expiry'] + chain['refundOffsetBlocks']} if chain['kind'] == 'height'
                         else {'observedAt': NOW, 'timestamp': leg['expiry']})
        else:
            base = leg['expiry'] - 400 if chain['kind'] == 'height' else None
            out[name] = ({'observedAt': NOW, 'height': base} if chain['kind'] == 'height' else {'observedAt': NOW, 'timestamp': NOW - 5})
    return out


def planned_terms(config, long_chain, short_chain, tighten=False):
    heads = {'long': head(config, long_chain, 150_000), 'short': head(config, short_chain, 150_000)}
    plan = planner.plan_with_margin(config, long_chain, short_chain, heads, NOW)
    long_expiry, short_expiry = plan['long']['expiry'], plan['short']['expiry']
    if tighten:
        long_expiry = short_expiry + 5
    terms = {'version': 1, 'hashlock': HASHLOCK, 'legs': {
        'long': {'chain': long_chain, 'amount': 5, 'refundee': 'a', 'claimant': 'b', 'expiry': long_expiry},
        'short': {'chain': short_chain, 'amount': 7, 'refundee': 'b', 'claimant': 'a', 'expiry': short_expiry}}}
    return terms, heads


def leg_variants(confirmations_needed):
    base = empty_observation()
    ready = {**base, 'found': True, 'verified': True, 'confirmations': confirmations_needed}
    return [
        None,
        base,
        {**base, 'found': True, 'confirmations': 1},
        {**base, 'found': True, 'verified': True, 'confirmations': 1},
        ready,
        {**base, 'found': True, 'verified': False, 'confirmations': confirmations_needed, 'problem': 'value differs'},
        {**ready, 'spent': 'claimed', 'spend_confirmations': confirmations_needed, 'spend_txid': 'f' * 64, 'preimage': SECRET},
        {**ready, 'spent': 'claimed', 'spend_confirmations': 0, 'spend_txid': 'f' * 64, 'preimage': SECRET},
        {**ready, 'spent': 'claimed', 'spend_confirmations': confirmations_needed, 'spend_txid': 'f' * 64, 'preimage': None},
        {**ready, 'spent': 'refunded', 'spend_confirmations': confirmations_needed, 'spend_txid': 'e' * 64},
        {**ready, 'spent': 'refunded', 'spend_confirmations': 0, 'spend_txid': 'e' * 64},
    ]


def signature(decision):
    return (decision['kind'], decision.get('to'), decision.get('action'), decision['why'].split(':')[0][:60])


def decide_cases(config):
    rng = random.Random(SEED)
    candidates = []
    for long_chain, short_chain in PAIRS:
        for tighten in (False, True):
            terms, base_heads = planned_terms(config, long_chain, short_chain, tighten)
            need = {name: config['chains'][terms['legs'][name]['chain']]['confirmations'] for name in ('long', 'short')}
            for role, states in STATES.items():
                for state in states:
                    for own_obs in leg_variants(need['long' if role == 'initiator' else 'short']):
                        for other_obs in leg_variants(need['short' if role == 'initiator' else 'long']):
                            candidates.append((terms, role, state, own_obs, other_obs))
    rng.shuffle(candidates)
    counts = {}
    cases = []
    for terms, role, state, own_obs, other_obs in candidates:
        own, other = ('long', 'short') if role == 'initiator' else ('short', 'long')
        legs = {own: own_obs, other: other_obs}
        for advance in (None, 'long', 'short'):
            for preimage in (True, False):
                for flags in (None, 'needs_human'):
                    heads = heads_at(config, terms, advance)
                    record = {'role': role, 'state': state, 'needs_human': 'check the chain' if flags else None, 'inflight': None,
                              'escrows': {'long': {'txid': 'L'}, 'short': {'txid': 'S'}}, 'txids': {},
                              'submitted': {'fund': {'at': NOW - 100000}, 'claim': {'at': NOW - 100000}, 'refund': {'at': NOW - 100000}}
                              if advance == 'short' else {}}
                    if state in ('terms_saved',) and own_obs is None and other_obs is None:
                        record['escrows'] = {'long': None, 'short': None}
                    obs = {'now': NOW, 'heads': heads, 'legs': legs, 'errors': {}, 'preimage_available': preimage}
                    decision = engine.decide(record, terms, obs, config, NOW)
                    key = (role, state) + signature(decision)
                    if counts.get(key, 0) >= PER_SIGNATURE:
                        continue
                    counts[key] = counts.get(key, 0) + 1
                    cases.append({'record': record, 'terms': terms, 'obs': obs, 'now': NOW, 'decision': decision})
        if len(cases) > 6000:
            break
    return cases


def claim_gate_cases(config):
    """Heads for the claimed leg are placed at chosen distances from its deadline so every cutoff is crossed."""
    cases = []
    for long_chain, short_chain in PAIRS:
        for tighten in (False, True):
            terms, _ = planned_terms(config, long_chain, short_chain, tighten)
            for role in ('initiator', 'responder'):
                claimed = 'short' if role == 'initiator' else 'long'
                leg = terms['legs'][claimed]
                kind = config['chains'][leg['chain']]['kind']
                for advance in (None, 'long', 'short', 'both'):
                    for near in (None, 0, 1, 10, 30, 60, 120, 400, 1500, 6000):
                        heads = heads_at(config, terms, advance)
                        if near is not None and advance is None:
                            heads[claimed] = ({'observedAt': NOW, 'height': leg['expiry'] - near // 10} if kind == 'height'
                                              else {'observedAt': NOW, 'timestamp': leg['expiry'] - near})
                        for missing in (False, True):
                            use = {**heads, claimed: None} if missing else heads
                            if missing and (near is not None or advance is not None):
                                continue
                            cases.append({'role': role, 'terms': terms, 'heads': use, 'now': NOW, 'gate': engine.claim_gate(role, terms, use, config, NOW)})
    seen, unique = set(), []
    for case in cases:
        key = json.dumps([case['role'], case['terms'], case['heads']], sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(case)
    return unique


def plan_cases(config):
    out = []
    for long_chain, short_chain in [('ethereum', 'cardano'), ('cardano', 'ethereum'), ('bitcoin', 'ethereum'), ('ethereum', 'bitcoin'),
                                    ('bitcoin', 'cardano'), ('cardano', 'bitcoin'), ('hegemon', 'ethereum'), ('ethereum', 'hegemon'),
                                    ('bitcoin', 'bitcoin'), ('ethereum', 'ethereum'), ('hegemon', 'bitcoin')]:
        for base, margin in ((150_000, None), (123_457, None), (150_000, 3600)):
            heads = {'long': head(policy_config(), long_chain, base), 'short': head(policy_config(), short_chain, base // 3)}
            case = {'long_chain': long_chain, 'short_chain': short_chain, 'heads': heads, 'now': NOW, 'margin': margin}
            try:
                result = planner.plan_with_margin(policy_config(), long_chain, short_chain, heads, NOW, margin)
                case['plan'] = {'long': result['long'], 'short': result['short'], 'marginSeconds': result['marginSeconds'], 'ok': result['verdict']['ok']}
            except ValueError as error:
                case['error'] = str(error)
            out.append(case)
    return out


_CONFIG = None


def policy_config():
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = policy.load_timing()
    return _CONFIG


def id_cases():
    cases = []
    for terms in (
        {'version': 1, 'hashlock': HASHLOCK, 'legs': {
            'long': {'chain': 'ethereum', 'amount': 5, 'refundee': '0x' + '11' * 20, 'claimant': '0x' + '22' * 20, 'expiry': NOW + 7200},
            'short': {'chain': 'cardano', 'amount': 7, 'refundee': '33' * 28, 'claimant': '44' * 28, 'expiry': NOW + 3700}}},
        {'version': 1, 'hashlock': '00' * 32, 'legs': {
            'long': {'chain': 'bitcoin', 'amount': 50000, 'refundee': '02' + '55' * 32, 'claimant': '03' + '66' * 32, 'expiry': 159999},
            'short': {'chain': 'ethereum', 'amount': 10**15, 'refundee': '0x' + '77' * 20, 'claimant': '0x' + '88' * 20, 'expiry': NOW + 3700}}},
    ):
        cases.append({'terms': terms, 'id': store.terms_digest(terms)[:16], 'canonical': store.canonical(terms).decode()})
    return cases


def build():
    config = policy_config()
    return {
        'version': 1,
        'generated_by': 'scripts/swap_engine/ui_vectors.py',
        'transitions': [list(row) for row in engine.TRANSITIONS],
        'ids': id_cases(),
        'decide': decide_cases(config),
        'claim_gate': claim_gate_cases(config),
        'plan': plan_cases(config),
    }


def dump(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n'


def main(argv):
    text = dump(build())
    if '--check' in argv:
        if not PATH.exists() or PATH.read_text() != text:
            print('config/swap/flow-vectors.json is stale; regenerate it with this module', file=sys.stderr)
            return 1
        print('flow vectors are current')
        return 0
    PATH.write_text(text)
    print(f'wrote {PATH} ({len(text)} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
