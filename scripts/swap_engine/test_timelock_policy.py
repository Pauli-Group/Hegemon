#!/usr/bin/env python3
"""Tests for the Python mirror of the cross-chain deadline policy.

Runs the same shared vectors as swap-ui/timelock-policy.test.mjs, so the two
implementations cannot diverge, plus soundness properties and mutation tests.
"""
import copy
import json
import random
import types
import unittest
from pathlib import Path

from swap_engine import timelock_policy as policy

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / 'config/swap/timelock-vectors.json').read_text())
REAL = json.loads((ROOT / 'config/swap/chain-timing.json').read_text())
SOURCE = Path(policy.__file__).read_text()


def run_vectors(module, data=VECTORS):
    failures = []
    config = data['config']
    try:
        module.validate_timing(copy.deepcopy(config))
    except ValueError as error:
        return [f'config: {error}']
    for case in data['cases']:
        try:
            verdict = module.check_ordered(config, case['long'], case['short'], case['heads'], case['now'])
        except Exception as error:  # noqa: BLE001 - report any divergence as a failure string
            failures.append(f"{case['name']}: raised {error}")
            continue
        codes = [r['code'] for r in verdict['reasons']]
        expect = case['expect']
        if verdict['ok'] != expect['ok']:
            failures.append(f"{case['name']}: ok {verdict['ok']}")
        if codes != expect['codes']:
            failures.append(f"{case['name']}: codes {codes}")
        for key, value in expect['metrics'].items():
            if verdict['metrics'].get(key) != value:
                failures.append(f"{case['name']}: {key} {verdict['metrics'].get(key)} != {value}")
    for req in data.get('requirements', []):
        got = module.leg_requirements(config, req['chain'])
        if got != req['expect']:
            failures.append(f"requirements {req['chain']}: {got}")
    for plan_case in data['plans']:
        try:
            plan = module.plan_timeouts(config, plan_case['longChain'], plan_case['shortChain'], plan_case['heads'], plan_case['now'])
        except Exception as error:  # noqa: BLE001
            failures.append(f"{plan_case['name']}: raised {error}")
            continue
        if not plan['verdict']['ok']:
            failures.append(f"{plan_case['name']}: plan not ok")
        expect = plan_case.get('expect')
        if expect and (plan['long']['expiry'], plan['short']['expiry']) != (expect['long'], expect['short']):
            failures.append(f"{plan_case['name']}: expiries {plan['long']['expiry']},{plan['short']['expiry']}")
    return failures


def mutated(source_text):
    module = types.ModuleType('mutant')
    module.__file__ = policy.__file__
    exec(compile(source_text, 'mutant', 'exec'), module.__dict__)  # noqa: S102 - test-only mutation of our own source
    return module


class SharedVectorTests(unittest.TestCase):
    def test_shared_vectors_pass(self):
        self.assertEqual(run_vectors(policy), [])

    def test_pair_judgement_is_independent_of_argument_order(self):
        case = VECTORS['cases'][0]
        forward = policy.check_pair(VECTORS['config'], case['long'], case['short'], {'a': case['heads']['long'], 'b': case['heads']['short']}, case['now'])
        reverse = policy.check_pair(VECTORS['config'], case['short'], case['long'], {'a': case['heads']['short'], 'b': case['heads']['long']}, case['now'])
        self.assertTrue(forward['ok'] and reverse['ok'])
        self.assertEqual((forward['long'], reverse['long']), ('a', 'b'))
        self.assertEqual(forward['metrics'], reverse['metrics'])

    def test_configs_validate_and_bad_configs_are_rejected(self):
        policy.validate_timing(copy.deepcopy(REAL))
        bad = copy.deepcopy(VECTORS['config'])
        bad['chains']['slow']['fastFactor'] = 1.5
        with self.assertRaisesRegex(ValueError, r'slow\.fastFactor'):
            policy.validate_timing(bad)
        no_window = copy.deepcopy(VECTORS['config'])
        del no_window['chains']['slow']['windows']['1']
        with self.assertRaisesRegex(ValueError, '1-block entry'):
            policy.validate_timing(no_window)

    def test_hosted_copy_of_config_is_byte_identical(self):
        self.assertEqual((ROOT / 'swap-ui/chain-timing.json').read_bytes(), (ROOT / 'config/swap/chain-timing.json').read_bytes(),
                         'run: cp config/swap/chain-timing.json swap-ui/chain-timing.json')


class PropertyTests(unittest.TestCase):
    def test_bounds_from_own_table_contain_every_observed_span(self):
        rnd = random.Random(7)
        sizes = [1, 2, 3, 6, 12, 24]
        for trial in range(60):
            mode = trial % 4
            gaps = []
            for i in range(120):
                if mode == 0:
                    gaps.append(int(rnd.expovariate(1 / 600)))
                elif mode == 1:
                    gaps.append(1 if rnd.random() < 0.15 else 1500 + rnd.randrange(600))
                elif mode == 2:
                    gaps.append(rnd.randrange(2) * 3000)
                else:
                    gaps.append(rnd.randrange(5) if (i // 10) % 2 else rnd.randrange(2400))
            times = [0]
            for gap in gaps:
                times.append(times[-1] + gap)
            windows = {}
            for k in sizes:
                spans = [times[i + k] - times[i] for i in range(len(times) - k)]
                windows[str(k)] = {'min': min(spans), 'max': max(spans)}
            chain = {'kind': 'height', 'windows': windows, 'slowFactor': 1, 'fastFactor': 1, 'outageAllowanceSeconds': 0}
            for n in range(1, 61):
                for i in range(len(times) - n):
                    span = times[i + n] - times[i]
                    self.assertGreaterEqual(policy.slow_seconds(chain, n), span)
                    self.assertLessEqual(policy.fast_seconds(chain, n), span)

    def test_plans_are_compliant_on_every_chain_combination(self):
        rnd = random.Random(11)
        names = list(REAL['chains'])
        for _ in range(60):
            long_chain, short_chain = rnd.choice(names), rnd.choice(names)
            now = 1_790_000_000 + rnd.randrange(1_000_000)

            def head(name):
                if REAL['chains'][name]['kind'] == 'height':
                    return {'observedAt': now, 'height': 1000 + rnd.randrange(100000)}
                return {'observedAt': now, 'timestamp': now - rnd.randrange(100)}

            heads = {'long': head(long_chain), 'short': head(short_chain)}
            plan = policy.plan_timeouts(REAL, long_chain, short_chain, heads, now)
            codes = {r['code'] for r in plan['verdict']['reasons']}
            self.assertLessEqual(codes, {'horizon-too-long'}, f'{long_chain}/{short_chain}')


class MutationTests(unittest.TestCase):
    MUTATIONS = [
        ('gap uses first refund of the short leg', "gap = lw['firstRefund'] - sw['lastClaim']", "gap = lw['firstRefund'] - sw['firstRefund']"),
        ('gap comparison weakened', 'gap < gap_required', 'gap < gap_required - 1'),
        ('gap comparison off by one the other way', 'gap < gap_required', 'gap <= gap_required'),
        ('claim window comparison weakened', "sw['firstRefund'] < claim_required", "sw['firstRefund'] < claim_required - 1"),
        ('slow bound rounds down', "best = min(-(-n // k) * w['max']", "best = min((n // k) * w['max']"),
        ('fast bound ignores window tables', "(n // k) * w['min']", "n * w['min']"),
        ('refund offset dropped', "leg['expiry'] + chain['refundOffsetBlocks'] - true_head", "leg['expiry'] - true_head"),
        ('provider lag ignored', "true_head = head['height'] + chain['providerLagBlocks']", "true_head = head['height']"),
        ('outage allowance dropped', "math.ceil(best * chain['slowFactor']) + chain['outageAllowanceSeconds']", "math.ceil(best * chain['slowFactor'])"),
        ('clock skew sign flipped on refund', "leg['expiry'] - chain['clockSkewSeconds'] - now", "leg['expiry'] + chain['clockSkewSeconds'] - now"),
        ('safety floor removed', "max(math.ceil(base * policy['gapFactor']), base + policy['gapFloorSeconds'])", "math.ceil(base * policy['gapFactor'])"),
        ('stale head allowed', "abs(now - head['observedAt']) > config['policy']['maxObservationAgeSeconds']", 'False'),
        ('clock drift allowed', "drift < -chain['clockSkewSeconds'] or drift > chain['maxHeadAgeSeconds'] + chain['clockSkewSeconds']", 'False'),
        ('horizon unchecked', "horizon > policy['maxHorizonSeconds']", 'False'),
        ('expired short leg ignored', "if sw['expired']:\n        reasons.append", "if False:\n        reasons.append"),
        ('confirmation depth ignored', "return slow_seconds(chain, depth)", 'return slow_seconds(chain, 1)'),
        ('prove time ignored', "return inclusion_seconds(chain) + chain.get('proveSeconds', 0)", 'return inclusion_seconds(chain)'),
        ('requirement blocks ignore provider lag', "mid + chain['refundOffsetBlocks'] - chain['providerLagBlocks']", "mid + chain['refundOffsetBlocks']"),
        ('requirement window ignores reaction time', "window = _scale(config, action_seconds(chain) + config['policy']['reactionSeconds'])", 'window = _scale(config, action_seconds(chain))'),
        ('plan skips lock minimum', "if _is_height(chain) and chain.get('minLockBlocks'):", "if False and chain.get('minLockBlocks'):"),
    ]

    def test_every_rule_is_pinned_by_a_shared_vector(self):
        survivors = []
        for name, old, new in self.MUTATIONS:
            self.assertIn(old, SOURCE, f'mutation target missing: {name}')
            if not run_vectors(mutated(SOURCE.replace(old, new, 1))):
                survivors.append(name)
        self.assertEqual(survivors, [])


if __name__ == '__main__':
    unittest.main()
