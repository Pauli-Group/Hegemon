"""Engine swaps on a real local Hegemon chain. Opt in: HEGEMON_LOCAL_CHAINS=1 HEGEMON_LOCAL_HEGEMON=1.

Needs the development node and wallet and the chain template (`python3 -m swap_engine.adapters.hegemon_local
build-template`) in addition to the tools `test_local_chains` needs. Happy swaps take minutes; every refund or
late-claim scenario waits for a Hegemon deadline and takes hours, so they run only with HEGEMON_LOCAL_HEGEMON_SLOW=1
(and in parallel worlds with `python3 -m swap_engine.local_hegemon`, which is how the recorded results were made).
"""
import os
import unittest

from swap_engine.local_hegemon import run_scenario

FAST = os.environ.get('HEGEMON_LOCAL_CHAINS') == '1' and os.environ.get('HEGEMON_LOCAL_HEGEMON') == '1'
SLOW = FAST and os.environ.get('HEGEMON_LOCAL_HEGEMON_SLOW') == '1'
PAIRS = (('hegemon', 'ethereum'), ('ethereum', 'hegemon'), ('hegemon', 'bitcoin'), ('bitcoin', 'hegemon'),
         ('hegemon', 'cardano'), ('cardano', 'hegemon'))


class HegemonHappy(unittest.TestCase):
    pass


def _happy(long_chain, short_chain):
    @unittest.skipUnless(FAST, 'set HEGEMON_LOCAL_CHAINS=1 and HEGEMON_LOCAL_HEGEMON=1')
    def test(self):
        result = run_scenario('happy', long_chain, short_chain)
        self.assertTrue(result['ok'], result)
    return test


for _long, _short in PAIRS:
    setattr(HegemonHappy, f'test_{_long}_{_short}', _happy(_long, _short))


@unittest.skipUnless(SLOW, 'set HEGEMON_LOCAL_HEGEMON_SLOW=1 (each scenario takes hours)')
class HegemonFailures(unittest.TestCase):
    def check(self, scenario, long_chain, short_chain):
        result = run_scenario(scenario, long_chain, short_chain)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['window_problems'], [])
        self.assertEqual(result['hegemon_peers'], 0)

    def test_no_counterparty_hegemon_long(self):
        self.check('no_counterparty', 'hegemon', 'ethereum')

    def test_both_refund_ethereum_long(self):
        self.check('both_refund', 'ethereum', 'hegemon')

    def test_both_refund_hegemon_long(self):
        self.check('both_refund', 'hegemon', 'ethereum')

    def test_late_claim_ethereum_long(self):
        self.check('late_claim', 'ethereum', 'hegemon')


if __name__ == '__main__':
    unittest.main()
