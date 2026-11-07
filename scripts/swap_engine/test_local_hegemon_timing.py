"""Timing of the local Hegemon fixture: the Erlang windows, the plans they give, and the post-run window check."""
import unittest

from swap_engine import local_world as world, planner
from swap_engine import timelock_policy as policy
from swap_engine.adapters.hegemon_local import LocalHegemonProfile


class ErlangWindows(unittest.TestCase):
    def test_windows_are_monotone_and_bracket_the_mean(self):
        previous = None
        for n, window in sorted(((int(n), w) for n, w in world.hegemon_timing()['windows'].items())):
            self.assertLess(window['min'], world.HEGEMON_MEAN_SECONDS * n)
            self.assertGreater(window['max'], world.HEGEMON_MEAN_SECONDS * n if n > 1 else 0)
            if previous:
                self.assertGreaterEqual(window['min'], previous['min'])
                self.assertGreaterEqual(window['max'], previous['max'])
            previous = window

    def test_tail_probability_matches_the_definition(self):
        for n in (1, 6, 48):
            window = world.erlang_window(n)
            below = world._erlang_cdf(n, window['min'] + 1, 60)
            above = 1 - world._erlang_cdf(n, window['max'] - 1, 60)
            self.assertAlmostEqual(above, world.HEGEMON_TAIL, delta=world.HEGEMON_TAIL * 0.1)
            self.assertLessEqual(world._erlang_cdf(n, window['min'], 60), world.HEGEMON_TAIL * 1.01)
            self.assertGreaterEqual(below, 0)

    def test_every_hegemon_pair_has_a_compliant_plan(self):
        now = 1_800_000_000
        config = world.local_timing(('hegemon', 'ethereum', 'bitcoin', 'cardano'))
        policy.validate_timing(config)
        for long_chain, short_chain in (('hegemon', 'ethereum'), ('ethereum', 'hegemon'), ('hegemon', 'bitcoin'), ('bitcoin', 'hegemon'),
                                        ('hegemon', 'cardano'), ('cardano', 'hegemon')):
            heads = {}
            for leg, name in (('long', long_chain), ('short', short_chain)):
                heads[leg] = {'observedAt': now, 'height': 200} if config['chains'][name]['kind'] == 'height' else {'observedAt': now, 'timestamp': now}
            plan = planner.plan_with_margin(config, long_chain, short_chain, heads, now, None)
            self.assertTrue(plan['verdict']['ok'], (long_chain, short_chain))
            for leg in ('long', 'short'):
                if plan[leg]['chain'] == 'hegemon':
                    self.assertGreaterEqual(plan[leg]['expiry'] - 200, config['chains']['hegemon']['minLockBlocks'])

    def test_a_hegemon_leg_never_plans_inside_the_proving_floor(self):
        config = world.local_timing(('hegemon', 'ethereum'))
        chain = config['chains']['hegemon']
        floor = policy.lock_floor(chain, 0)
        self.assertGreater(floor, chain['minLockBlocks'])
        self.assertEqual(floor, chain['minLockBlocks'] + chain['providerLagBlocks'] + policy.prove_blocks(chain) + 1)


class SpanCheck(unittest.TestCase):
    class Stub(LocalHegemonProfile):
        def __init__(self, times, start):
            self._times = times
            self.start_height = start

        def block_times(self):
            return self._times

    TIMING = {'windows': {'1': {'min': 1, 'max': 100}, '3': {'min': 30, 'max': 250}}}

    def test_blocks_inside_the_windows_pass_and_the_idle_gap_before_the_first_block_is_ignored(self):
        times = {10: 0.0, 11: 90_000.0, 12: 90_060.0, 13: 90_120.0, 14: 90_180.0}
        self.assertEqual(self.Stub(times, 10).spans_within_windows(self.TIMING), [])

    def test_a_slow_or_fast_span_is_reported(self):
        times = {10: 0.0, 11: 60.0, 12: 400.0, 13: 460.0, 14: 460.2}
        problems = self.Stub(times, 9).spans_within_windows(self.TIMING)
        self.assertTrue(any('1 blocks from 11' in p for p in problems), problems)
        self.assertTrue(any('3 blocks from 11' in p or '3 blocks from 10' in p for p in problems), problems)
        self.assertTrue(any('1 blocks from 13' in p for p in problems), problems)


if __name__ == '__main__':
    unittest.main()
