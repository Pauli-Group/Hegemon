"""Two-party swaps through the engine on real local chains: Anvil, bitcoind regtest and a Cardano cluster.

Slow (minutes) and needs the chain tools (see scripts/swap_engine/tools.py), so it runs only when
HEGEMON_LOCAL_CHAINS=1. Each swap is planned by the production planner against a scaled timing config
(local_world.local_timing) and funded, verified, claimed or refunded by the production adapters.
"""
import itertools
import os
import unittest

from swap_engine.tools import find_tool

CHAINS = ('bitcoin', 'ethereum', 'cardano')
TOOLS = all(find_tool(name) for name in ('anvil', 'bitcoind', 'cardano-node', 'cardano-cli', 'aiken'))


@unittest.skipUnless(os.environ.get('HEGEMON_LOCAL_CHAINS') == '1' and TOOLS, 'set HEGEMON_LOCAL_CHAINS=1 with the chain tools installed')
class LocalChains(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from swap_engine.local_world import LocalWorld
        cls.world = LocalWorld(CHAINS)

    @classmethod
    def tearDownClass(cls):
        cls.world.close()

    def swap(self, long_chain, short_chain, tag):
        from swap_engine.local_world import LocalSwap
        swap = LocalSwap(self.world, long_chain, short_chain, tag)
        swap.verbose = bool(os.environ.get('HEGEMON_LOCAL_VERBOSE'))
        return swap

    def finish(self, swap, before, outcome, states):
        problems = swap.expected_after(before, outcome)
        self.assertEqual(problems, [], (states, swap.log[-6:]))

    def test_happy_path_for_every_ordered_pair(self):
        for long_chain, short_chain in itertools.product(CHAINS, CHAINS):
            with self.subTest(long=long_chain, short=short_chain):
                try:
                    swap = self.swap(long_chain, short_chain, f'h-{long_chain[:3]}-{short_chain[:3]}')
                except ValueError as error:
                    # The planner refuses a pair it cannot make safe; that is the correct outcome, not a failure.
                    self.assertIn('No compliant plan', str(error))
                    self.assertEqual((long_chain, short_chain), ('bitcoin', 'bitcoin'))
                    continue
                before = swap.balances()
                states = swap.run(timeout=420)
                self.assertEqual({k: v[0] for k, v in states.items()}, {'initiator': 'done', 'responder': 'done'}, swap.log[-8:])
                self.finish(swap, before, 'swapped', states)

    def test_responder_never_funds_so_the_initiator_refunds(self):
        swap = self.swap('ethereum', 'cardano', 'r1')
        before = swap.balances()
        states = swap.run(timeout=600, roles=('initiator',))
        self.assertEqual(states['initiator'][0], 'refunded', swap.log[-6:])
        self.assertEqual(states['responder'][0], 'terms_saved')
        self.finish(swap, before, 'unchanged', states)

    def test_initiator_vanishes_after_long_funding_so_both_refund(self):
        swap = self.swap('bitcoin', 'ethereum', 'r2')
        before = swap.balances()
        swap.run(timeout=300, roles=('initiator', 'responder'), until=lambda s: s.states()['responder'][0] == 'short_fund_submitted')
        states = swap.run(timeout=600, roles=('responder',))  # the initiator is gone
        self.assertEqual(states['responder'][0], 'refunded', swap.log[-6:])
        states = swap.run(timeout=600, roles=('initiator',))  # the initiator comes back after both expiries
        self.assertEqual(states['initiator'][0], 'refunded', swap.log[-6:])
        self.finish(swap, before, 'unchanged', states)

    def test_initiator_vanishes_after_funding_on_cardano_long(self):
        swap = self.swap('cardano', 'bitcoin', 'r3')
        before = swap.balances()
        swap.run(timeout=300, roles=('initiator', 'responder'), until=lambda s: s.states()['responder'][0] == 'short_fund_submitted')
        states = swap.run(timeout=600, roles=('responder',))
        self.assertEqual(states['responder'][0], 'refunded', swap.log[-6:])
        states = swap.run(timeout=600, roles=('initiator',))
        self.assertEqual(states['initiator'][0], 'refunded', swap.log[-6:])
        self.finish(swap, before, 'unchanged', states)


if __name__ == '__main__':
    unittest.main()
