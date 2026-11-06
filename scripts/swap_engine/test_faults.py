"""Simulated-chain scenarios: every chain pair, provider faults, reorgs, lost responses, and
a process kill at every crash point."""
import itertools
import os
import random
import tempfile
import unittest
from pathlib import Path

from swap_engine import engine, sim, timelock_policy as policy

CONFIG = policy.load_timing()
PREIMAGE = bytes(range(1, 33))
CHAINS = ('bitcoin', 'hegemon', 'ethereum', 'cardano')
DONE = ('done', 'done')
# fsync on a RAM disk keeps the crash sweep fast; override with SWAP_TEST_TMP to test real disk behavior.
TMP_BASE = os.environ.get('SWAP_TEST_TMP') or ('/dev/shm' if os.path.isdir('/dev/shm') else None)


def initiator_finished(harness):
    return harness.states()['initiator'][0] in ('done', 'refunded', 'aborted', 'failed')


class Scenario:
    def __init__(self, long_chain='ethereum', short_chain='cardano', hook=None, amounts=(1000, 2000)):
        names = sorted({long_chain, short_chain})
        self.world = sim.make_world(names)
        self.terms = sim.plan_terms(self.world, CONFIG, long_chain, short_chain, PREIMAGE, amounts)
        self.tmp = tempfile.TemporaryDirectory(dir=TMP_BASE)
        os.chmod(self.tmp.name, 0o700)
        long_leg, short_leg = self.terms['legs']['long'], self.terms['legs']['short']
        self.world.chains[long_chain].credit(long_leg['refundee'], 10 ** 6)
        self.world.chains[short_chain].credit(short_leg['refundee'], 10 ** 6)
        self.harness = sim.Harness(self.tmp.name, self.world, self.terms, CONFIG, PREIMAGE, hook)

    def run(self, **kwargs):
        kwargs.setdefault('seconds_per_step', 120)
        kwargs.setdefault('max_steps', 4000)
        return self.harness.run(**kwargs)

    def outcome(self, states=None):
        states = states or self.harness.states()
        return states['initiator'][0], states['responder'][0]

    def balance(self, role, leg):
        terms = self.terms['legs'][leg]
        chain = self.world.chains[terms['chain']]
        identity = terms['refundee'] if (role == 'alice') == (leg == 'long') else terms['claimant']
        return chain.state['balances'].get(identity, 0)

    def close(self):
        self.tmp.cleanup()


class EveryPair(unittest.TestCase):
    def test_happy_path_for_every_ordered_pair(self):
        unplannable = []
        for long_chain, short_chain in itertools.product(CHAINS, CHAINS):
            with self.subTest(long=long_chain, short=short_chain):
                try:
                    s = Scenario(long_chain, short_chain)
                except ValueError as error:
                    # Recorded finding: Bitcoin with Bitcoin cannot be planned inside the 30-day horizon.
                    self.assertIn('horizon-too-long', str(error))
                    unplannable.append((long_chain, short_chain))
                    continue
                self.addCleanup(s.close)
                states = s.run(seconds_per_step=300)
                self.assertEqual(s.outcome(states), DONE, s.harness.log[-6:])
                self.assertEqual(s.harness.check_safety(), [])
                # Alice paid the long amount and received the short amount; Bob the reverse.
                same = long_chain == short_chain
                self.assertEqual(s.balance('alice', 'short'), 2000 + (10 ** 6 - 1000 if same else 0))
                self.assertEqual(s.balance('bob', 'long'), 1000 + (10 ** 6 - 2000 if same else 0))
        self.assertEqual(unplannable, [('bitcoin', 'bitcoin')])


class Refunds(unittest.TestCase):
    def test_responder_never_shows_up_initiator_refunds(self):
        for long_chain, short_chain in (('ethereum', 'cardano'), ('bitcoin', 'ethereum'), ('hegemon', 'cardano')):
            with self.subTest(long=long_chain, short=short_chain):
                s = Scenario(long_chain, short_chain)
                self.addCleanup(s.close)
                states = s.run(seconds_per_step=600, active=lambda i, h: ('initiator',), until=initiator_finished)
                self.assertEqual(states['initiator'][0], 'refunded', s.harness.log[-4:])
                self.assertEqual(s.harness.check_safety(), [])
                self.assertEqual(s.balance('alice', 'long'), 10 ** 6)

    def test_initiator_goes_dark_responder_refunds_then_initiator_refunds(self):
        for long_chain, short_chain in (('ethereum', 'cardano'), ('cardano', 'ethereum'), ('bitcoin', 'hegemon')):
            with self.subTest(long=long_chain, short=short_chain):
                s = Scenario(long_chain, short_chain)
                self.addCleanup(s.close)
                gone = {'on': False}

                def active(index, harness):
                    if harness.states()['responder'][0] in ('short_fund_submitted', 'short_funded'):
                        gone['on'] = True
                    return ('responder',) if gone['on'] else ('initiator', 'responder')

                states = s.run(seconds_per_step=600, active=active, max_steps=6000,
                               until=lambda h: h.states()['responder'][0] in ('refunded', 'done'))
                self.assertEqual(s.outcome(states)[1], 'refunded', s.harness.log[-4:])
                # Alice comes back after both deadlines: she must refund and never claim the spent short leg.
                gone['on'] = False
                states = s.run(seconds_per_step=600, max_steps=3000)
                self.assertEqual(s.outcome(states), ('refunded', 'refunded'), s.harness.log[-6:])
                self.assertEqual(s.harness.check_safety(), [])


class LastMoment(unittest.TestCase):
    def test_initiator_delay_sweep_never_hurts_the_responder(self):
        """The initiator sleeps for D seconds after the responder funds, then resumes. For every D
        the swap must end both done or both refunded, never the initiator claiming while the
        responder loses the long leg."""
        base = Scenario('ethereum', 'cardano')
        short_window = base.terms['legs']['short']['expiry'] - base.world.now
        base.close()
        outcomes = set()
        for delay in range(0, short_window + 1800, 240):
            s = Scenario('ethereum', 'cardano')
            self.addCleanup(s.close)
            resume = {'at': None}

            def active(index, harness, resume=resume, delay=delay):
                if resume['at'] is None and harness.states()['responder'][0] in ('short_fund_submitted', 'short_funded'):
                    resume['at'] = harness.world.now + delay
                if resume['at'] is not None and harness.world.now < resume['at']:
                    return ('responder',)
                return ('initiator', 'responder')

            states = s.run(seconds_per_step=60, active=active, max_steps=4000)
            outcome = s.outcome(states)
            outcomes.add(outcome)
            self.assertEqual(s.harness.check_safety(), [], (delay, outcome))
            self.assertIn(outcome, (DONE, ('refunded', 'refunded')), (delay, outcome, s.harness.log[-6:]))
        self.assertEqual(outcomes, {DONE, ('refunded', 'refunded')})

    def test_claim_cutoff_refuses_the_claim_not_the_chain(self):
        s = Scenario('ethereum', 'cardano')
        self.addCleanup(s.close)
        cutoff = policy.action_seconds(CONFIG['chains']['cardano'])
        skew = CONFIG['chains']['cardano']['clockSkewSeconds']
        short_expiry = s.terms['legs']['short']['expiry']
        responder_started = {'on': False}

        def active(index, harness):
            if harness.states()['responder'][0] in ('short_fund_submitted', 'short_funded'):
                responder_started['on'] = True
            return ('responder',) if responder_started['on'] else ('initiator', 'responder')

        s.run(seconds_per_step=20, active=active, max_steps=400, until=lambda h: h.states()['responder'][0] == 'short_funded')
        # The initiator wakes up one second inside the cutoff: it must refuse to reveal the preimage.
        s.world.tick(short_expiry - skew - cutoff + 1 - s.world.now)
        s.harness.exchange()
        result = s.harness.step(s.harness.alice)
        self.assertEqual(result['status'], 'waiting', result)
        self.assertEqual([b for b in s.world.chains['cardano'].broadcasts if b[0] == 'claim'], [])
        # One second earlier it was allowed (policy gate and cutoff both ok on a fresh world).


class Faults(unittest.TestCase):
    def test_provider_rate_limits_do_not_change_the_outcome(self):
        s = Scenario()
        self.addCleanup(s.close)
        for index in range(0, 30, 3):
            pass

        def before(index, harness):
            if index % 4 == 0:
                for chain in harness.world.chains.values():
                    chain.fail_reads = 3

        states = s.run(seconds_per_step=60, before_step=before)
        self.assertEqual(s.outcome(states), DONE)
        self.assertEqual(s.harness.check_safety(), [])

    def test_lagging_provider_never_causes_a_second_fund(self):
        s = Scenario()
        self.addCleanup(s.close)
        for chain in s.world.chains.values():
            chain.lag = 3
        states = s.run(seconds_per_step=60)
        self.assertEqual(s.outcome(states), DONE)
        self.assertEqual(s.world.chains['ethereum'].fund_count, 1)
        self.assertEqual(s.world.chains['cardano'].fund_count, 1)

    def test_lost_response_after_broadcast_is_adopted_from_the_journal(self):
        s = Scenario()
        self.addCleanup(s.close)
        s.world.chains['ethereum'].lose_next_response = True
        result = s.harness.step(s.harness.alice)
        self.assertEqual(result['status'], 'recovered', result)
        self.assertEqual(result['error'], 'TimeoutError')
        states = s.run(seconds_per_step=60)
        self.assertEqual(s.outcome(states), DONE)
        self.assertEqual(s.world.chains['ethereum'].fund_count, 1)

    def test_broadcast_that_never_left_stays_inflight_until_a_human_resolves_it(self):
        s = Scenario()
        self.addCleanup(s.close)
        s.world.chains['ethereum'].drop_next_broadcast = True
        first = s.harness.step(s.harness.alice)
        self.assertEqual(first['status'], 'inflight')
        for _ in range(5):
            s.world.tick(60)
            again = s.harness.step(s.harness.alice)
            self.assertEqual(again['status'], 'inflight')  # blocked, and no second signature
        self.assertEqual(len(s.world.chains['ethereum'].mempool), 0)
        self.assertEqual(s.world.chains['ethereum'].fund_count, 1)
        self.assertEqual(s.harness.settle_inflight(), [('initiator', 'abandon')])
        states = s.run(seconds_per_step=60)
        self.assertEqual(s.outcome(states), DONE)
        self.assertEqual(len(s.world.chains['ethereum'].state['escrows']), 1)

    def test_refusal_before_signing_clears_the_marker_and_is_retried_later(self):
        s = Scenario()
        self.addCleanup(s.close)
        chain = s.world.chains['ethereum']
        identity = s.terms['legs']['long']['refundee']
        saved = chain.balances[identity]
        chain.balances[identity] = 0
        chain._replay()
        result = s.harness.step(s.harness.alice)
        self.assertEqual(result['status'], 'refused')
        self.assertEqual(s.harness.states()['initiator'], ('terms_saved', False, None))
        chain.balances[identity] = saved
        chain._replay()
        states = s.run(seconds_per_step=60)
        self.assertEqual(s.outcome(states), DONE)

    def test_funding_reorged_back_to_mempool_recovers_without_a_second_fund(self):
        s = Scenario()
        self.addCleanup(s.close)
        chain = s.world.chains['ethereum']
        done = {'flag': False}

        def before(index, harness):
            record_state = harness.states()['initiator'][0]
            if record_state == 'long_funded' and not done['flag']:
                done['flag'] = True
                txid = harness.alice.store and next(iter(chain.state['escrows']))
                chain.unconfirm(txid)

        states = s.run(seconds_per_step=60, before_step=before)
        self.assertEqual(s.outcome(states), DONE)
        self.assertTrue(done['flag'])
        self.assertEqual(chain.fund_count, 1)
        self.assertEqual(s.harness.check_safety(), [])

    def test_funding_dropped_by_a_reorg_waits_then_needs_a_human_but_never_funds_twice(self):
        s = Scenario()
        self.addCleanup(s.close)
        chain = s.world.chains['ethereum']
        done = {'flag': False}

        def before(index, harness):
            if harness.states()['initiator'][0] == 'long_funded' and not done['flag']:
                done['flag'] = True
                chain.drop(next(iter(chain.state['escrows'])))

        states = s.run(seconds_per_step=600, before_step=before, max_steps=400)
        self.assertEqual(states['initiator'][2] is not None, True, states)
        self.assertEqual(chain.fund_count, 1)
        self.assertEqual(s.harness.check_safety(), [])

    def test_claim_dropped_before_confirmation_is_not_resent_automatically(self):
        s = Scenario()
        self.addCleanup(s.close)
        cardano = s.world.chains['cardano']
        flag = {'dropped': False}

        def before(index, harness):
            if not flag['dropped'] and any(tx['kind'] == 'claim' for tx in cardano.mempool):
                flag['dropped'] = True
                cardano.drop(next(tx['id'] for tx in cardano.mempool if tx['kind'] == 'claim'))

        states = s.run(seconds_per_step=60, before_step=before, max_steps=900)
        self.assertTrue(flag['dropped'])
        claims = [b for b in cardano.broadcasts if b[0] == 'claim']
        self.assertEqual(len(claims), 1)  # the engine did not resend
        self.assertIsNotNone(states['initiator'][2])  # a human is asked to look
        self.assertEqual(s.harness.check_safety(), [])

    def test_preimage_seen_in_the_mempool_lets_the_responder_claim_before_confirmation(self):
        s = Scenario('ethereum', 'bitcoin')
        self.addCleanup(s.close)
        bitcoin = s.world.chains['bitcoin']
        seen = {'ok': False}

        def before(index, harness):
            if any(tx['kind'] == 'claim' for tx in bitcoin.mempool):
                # still unconfirmed: the responder may already hold the preimage
                state = harness.states()['responder'][0]
                if state in ('preimage_known', 'long_claim_submitted'):
                    seen['ok'] = True

        states = s.run(seconds_per_step=60, before_step=before, max_steps=3000)
        self.assertEqual(s.outcome(states), DONE)
        self.assertTrue(seen['ok'], 'responder never acted on an unconfirmed claim')

    def test_responder_aborts_when_the_long_leg_contradicts_the_terms(self):
        s = Scenario()
        self.addCleanup(s.close)
        terms = s.terms['legs']['long']
        chain = s.world.chains['ethereum']
        # A forged escrow with the wrong expiry, announced as the long leg.
        forged = {'id': 'f' * 64, 'kind': 'fund', 'sender': terms['refundee'], 'amount': terms['amount'], 'hashlock': s.terms['hashlock'],
                  'claimant': terms['claimant'], 'refundee': terms['refundee'], 'expiry': terms['expiry'] + 99999}
        chain.submit(forged)
        engine_receive = engine.receive
        with s.harness.bob.store.locked(s.harness.swap_id) as swap:
            engine_receive(swap, 'long', {'txid': forged['id']}, s.world.now)
        for _ in range(3):
            s.world.tick(120)
            s.harness.step(s.harness.bob)
        self.assertEqual(s.harness.states()['responder'][0], 'aborted')
        self.assertEqual(s.world.chains['cardano'].fund_count, 0)

    def test_a_lying_provider_cannot_plant_a_preimage(self):
        from unittest import mock
        real = sim.SimAdapter.inspect

        def lying(self, leg, escrow):
            value = real(self, leg, escrow)
            if value['preimage'] is not None:
                value['preimage'] = 'ee' * 32
            return value

        s = Scenario()
        self.addCleanup(s.close)
        with mock.patch.object(sim.SimAdapter, 'inspect', lying):
            s.run(seconds_per_step=60, max_steps=120)
        states = s.harness.states()
        self.assertEqual(states['responder'][0], 'short_funded')  # never believed the bogus preimage
        directory = Path(s.tmp.name) / 'bob' / s.harness.swap_id
        self.assertFalse((directory / 'learned-preimage').exists())

    def test_wrong_wallet_is_refused_before_anything_happens(self):
        s = Scenario()
        self.addCleanup(s.close)
        s.harness.alice.identities = {'long': 'mallory@ethereum', 'short': s.harness.alice.identities['short']}
        with self.assertRaises(engine.IdentityMismatch):
            with s.harness.alice.store.locked(s.harness.swap_id) as swap:
                engine.advance(swap, s.harness.alice.adapters(s.terms), CONFIG, s.world.now)


class CrashEverywhere(unittest.TestCase):
    """Kill a participant at every numbered crash point of a full swap and resume."""

    def crash_run(self, points, long_chain='ethereum', short_chain='cardano'):
        hook = sim.CrashHook(points)
        s = Scenario(long_chain, short_chain, hook=hook)
        self.addCleanup(s.close)
        states = s.run(seconds_per_step=120, human=True, max_steps=3000)
        return s, states, hook

    def test_single_crash_at_every_point(self):
        baseline = Scenario(hook=sim.CrashHook())
        self.addCleanup(baseline.close)
        baseline.run(seconds_per_step=120, human=True)
        total = baseline.harness.hook.count
        self.assertGreater(total, 40)
        kinds = set()
        for point in range(1, total + 1):
            s, states, hook = self.crash_run(point)
            name = hook.names[point - 1] if point <= len(hook.names) else None
            kinds.add(name)
            self.assertEqual(s.harness.crashes, 1, (point, name))
            self.assertEqual(s.outcome(states), DONE, (point, name, s.harness.log[-8:]))
            self.assertEqual(s.harness.check_safety(), [], (point, name))
            self.assertEqual(len(s.world.chains['ethereum'].state['escrows']), 1, (point, name))
            self.assertEqual(len(s.world.chains['cardano'].state['escrows']), 1, (point, name))
        self.assertTrue({'store:save:before', 'store:save:after', 'adapter:after-journal', 'adapter:after-broadcast',
                         'engine:before-write', 'engine:after-write', 'store:secret:before', 'store:secret:after'} <= kinds, kinds)

    def test_two_crashes_sampled(self):
        baseline = Scenario(hook=sim.CrashHook())
        self.addCleanup(baseline.close)
        baseline.run(seconds_per_step=120, human=True)
        total = baseline.harness.hook.count
        rng = random.Random(20261105)
        for _ in range(60):
            a, b = sorted(rng.sample(range(1, total + 1), 2))
            s, states, hook = self.crash_run({a, b})
            self.assertEqual(s.outcome(states), DONE, (a, b, s.harness.log[-8:]))
            self.assertEqual(s.harness.check_safety(), [], (a, b))

    def test_crashes_during_a_refund_path(self):
        baseline = Scenario(hook=sim.CrashHook())
        self.addCleanup(baseline.close)
        baseline.run(seconds_per_step=300, human=True, active=lambda i, h: ('initiator',), until=initiator_finished)
        total = baseline.harness.hook.count
        for point in range(1, total + 1):
            hook = sim.CrashHook(point)
            s = Scenario(hook=hook)
            self.addCleanup(s.close)
            states = s.run(seconds_per_step=300, human=True, active=lambda i, h: ('initiator',), until=initiator_finished)
            self.assertEqual(states['initiator'][0], 'refunded', (point, s.harness.log[-5:]))
            self.assertEqual(s.harness.check_safety(), [], point)
            self.assertEqual(s.balance('alice', 'long'), 10 ** 6, point)


if __name__ == '__main__':
    unittest.main()
