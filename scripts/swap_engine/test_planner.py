import itertools
import random
import unittest

from swap_engine import planner, timelock_policy as policy

CONFIG = policy.load_timing()
NOW = 1_800_000_000
CHAINS = ('bitcoin', 'hegemon', 'ethereum', 'cardano')


def head(chain, height=1000, now=NOW):
    if CONFIG['chains'][chain]['kind'] == 'height':
        return {'observedAt': now, 'height': height}
    return {'observedAt': now, 'timestamp': now - 5}


class PlannerTests(unittest.TestCase):
    def test_max_blocks_inverts_fast_seconds(self):
        for name in ('bitcoin', 'hegemon'):
            chain = CONFIG['chains'][name]
            for seconds in (0, 1, 600, 3600, 86400, 400000):
                n = planner.max_blocks_in(chain, seconds)
                self.assertLessEqual(policy.fast_seconds(chain, n), seconds)
                self.assertGreater(policy.fast_seconds(chain, n + 1), seconds if seconds else -1)

    def test_every_plannable_pair_stays_ok_at_random_future_moments(self):
        rng = random.Random(7)
        for long_chain, short_chain in itertools.product(CHAINS, CHAINS):
            heads = {'long': head(long_chain), 'short': head(short_chain)}
            try:
                plan = planner.plan_with_margin(CONFIG, long_chain, short_chain, heads, NOW)
            except ValueError as error:
                self.assertEqual((long_chain, short_chain), ('bitcoin', 'bitcoin'), str(error))
                self.assertIn('horizon-too-long', str(error))
                continue
            self.assertTrue(plan['verdict']['ok'])
            base = policy.plan_timeouts(CONFIG, long_chain, short_chain, heads, NOW)
            self.assertGreaterEqual(plan['long']['expiry'], base['long']['expiry'])
            self.assertGreaterEqual(plan['short']['expiry'], base['short']['expiry'])
            for _ in range(400):
                seconds = rng.randint(0, plan['marginSeconds'])
                projected = {}
                for key, name in (('long', long_chain), ('short', short_chain)):
                    projected[key] = planner.project(CONFIG, name, heads[key], seconds, rng.random())
                verdict = policy.check_ordered(CONFIG, plan['long'], plan['short'], projected, NOW + seconds)
                self.assertTrue(verdict['ok'], (long_chain, short_chain, seconds, verdict['reasons']))

    def test_margin_covers_proving_and_confirming_a_short_hegemon_leg(self):
        """A local Bitcoin/Hegemon swap refused to claim because the responder's proof and two Hegemon blocks had
        used the gap the plan left; the default margin now includes them whenever the short chain needs a proof."""
        hegemon = CONFIG['chains']['hegemon']
        extra = hegemon['proveSeconds'] + policy.confirm_seconds(hegemon)
        for long_chain in ('bitcoin', 'ethereum', 'cardano'):
            plain = planner.default_margin(CONFIG, long_chain)
            self.assertEqual(planner.default_margin(CONFIG, long_chain, 'hegemon'), plain + extra)
            self.assertEqual(planner.default_margin(CONFIG, long_chain, 'bitcoin' if long_chain != 'bitcoin' else 'ethereum'), plain)
            heads = {'long': head(long_chain), 'short': head('hegemon')}
            plan = planner.plan_with_margin(CONFIG, long_chain, 'hegemon', heads, NOW)
            self.assertEqual(plan['marginSeconds'], plain + extra)
            # the slowest the responder can be: a full margin of real time with the fastest blocks on the long leg
            projected = {'long': planner.project(CONFIG, long_chain, heads['long'], plan['marginSeconds'], 1.0),
                         'short': planner.project(CONFIG, 'hegemon', heads['short'], plan['marginSeconds'], 0.0)}
            self.assertTrue(policy.check_ordered(CONFIG, plan['long'], plan['short'], projected, NOW + plan['marginSeconds'])['ok'])

    def test_bump_without_a_measured_mean_uses_the_fastest_windows(self):
        """A local fixture has no `measurement`; guessing 600 s per block moved a 3 second chain one block per round."""
        chain = {'kind': 'height', 'slowFactor': 1.0, 'fastFactor': 1.0, 'windows': {'1': {'min': 3, 'max': 9}, '96': {'min': 280, 'max': 320}}}
        leg = {'chain': 'fixture', 'expiry': 1000}
        config = {'chains': {'fixture': chain}}
        bumped = planner._bump(config, leg, 900)
        self.assertGreater(bumped - 1000, 100)
        self.assertLessEqual(policy.fast_seconds(chain, bumped - 1000), 900)
        measured = {'chains': {'fixture': {**chain, 'measurement': {'mean_seconds': 600}}}}
        self.assertEqual(planner._bump(measured, leg, 1800), 1003)

    def test_plain_plan_can_fail_inside_the_margin(self):
        """The reason the planner exists: plan_timeouts alone is valid only at one instant."""
        heads = {'long': head('bitcoin'), 'short': head('ethereum')}
        base = policy.plan_timeouts(CONFIG, 'bitcoin', 'ethereum', heads, NOW)
        failures = planner.verdicts(CONFIG, base['long'], base['short'], heads, NOW, planner.default_margin(CONFIG, 'bitcoin'))
        self.assertTrue(failures)
        self.assertIn('insufficient-gap', {r['code'] for f in failures for r in f['reasons']})

    def test_horizon_error_is_reported(self):
        heads = {'long': head('bitcoin'), 'short': head('bitcoin')}
        with self.assertRaisesRegex(ValueError, 'horizon-too-long'):
            planner.plan_with_margin(CONFIG, 'bitcoin', 'bitcoin', heads, NOW)


if __name__ == '__main__':
    unittest.main()
