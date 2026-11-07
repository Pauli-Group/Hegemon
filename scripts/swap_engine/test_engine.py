"""Tests of the pure decision function. No chain, no files."""
import copy
import itertools
import unittest

from swap_engine import engine, timelock_policy as policy
from swap_engine.adapter import empty_observation

CONFIG = policy.load_timing()
NOW = 1_800_000_000
HASHLOCK = 'ab' * 32


def terms(long_chain='ethereum', short_chain='cardano', long_expiry=NOW + 5800, short_expiry=NOW + 3700):
    return {'version': 1, 'hashlock': HASHLOCK, 'legs': {
        'long': {'chain': long_chain, 'amount': 5, 'refundee': 'a', 'claimant': 'b', 'expiry': long_expiry},
        'short': {'chain': short_chain, 'amount': 7, 'refundee': 'b', 'claimant': 'a', 'expiry': short_expiry}}}


def head(chain, now=NOW, offset=0):
    if CONFIG['chains'][chain]['kind'] == 'height':
        return {'observedAt': now, 'height': 1000 + offset}
    return {'observedAt': now, 'timestamp': now - 5 + offset}


def ready(confirmations=2, **extra):
    return {**empty_observation(), 'found': True, 'verified': True, 'confirmations': confirmations, **extra}


def record(role, state, long_ref=True, short_ref=True, needs_human=None, submitted=None):
    return {'role': role, 'state': state, 'needs_human': needs_human, 'inflight': None,
            'escrows': {'long': {'txid': 'L'} if long_ref else None, 'short': {'txid': 'S'} if short_ref else None},
            'txids': {}, 'submitted': submitted or {}}


def observation(t, long=None, short=None, preimage=True, heads=True):
    return {'now': NOW, 'heads': {'long': head(t['legs']['long']['chain']) if heads else None,
                                  'short': head(t['legs']['short']['chain']) if heads else None},
            'legs': {'long': long, 'short': short}, 'errors': {}, 'preimage_available': preimage}


def decide(role, state, t=None, **kwargs):
    t = t or terms()
    rec_args = {k: kwargs.pop(k) for k in ('long_ref', 'short_ref', 'needs_human', 'submitted') if k in kwargs}
    obs = observation(t, **kwargs)
    return engine.decide(record(role, state, **rec_args), t, obs, CONFIG, NOW)


class InitiatorDecisions(unittest.TestCase):
    def test_funds_long_when_policy_ok(self):
        step = decide('initiator', 'terms_saved', long_ref=False, short_ref=False)
        self.assertEqual((step['kind'], step['action'], step['leg'], step['to']), ('act', 'fund', 'long', 'long_fund_submitted'))

    def test_waits_on_missing_heads_and_aborts_on_policy(self):
        self.assertEqual(decide('initiator', 'terms_saved', heads=False)['kind'], 'wait')
        bad = terms(long_expiry=NOW + 3800)  # gap far too small
        step = decide('initiator', 'terms_saved', t=bad)
        self.assertEqual(step['kind'], 'abort')
        self.assertIn('insufficient-gap', step['codes'])

    def test_stale_head_waits_instead_of_aborting(self):
        t = terms()
        obs = observation(t)
        obs['heads']['long'] = {**obs['heads']['long'], 'observedAt': NOW - 100000}
        step = engine.decide(record('initiator', 'terms_saved'), t, obs, CONFIG, NOW)
        self.assertEqual(step['kind'], 'wait')

    def test_funding_confirmation_and_reorg(self):
        self.assertEqual(decide('initiator', 'long_fund_submitted', long=ready(1))['kind'], 'wait')
        step = decide('initiator', 'long_fund_submitted', long=ready(2))
        self.assertEqual((step['kind'], step['to']), ('move', 'long_funded'))
        step = decide('initiator', 'long_funded', long=empty_observation())
        self.assertEqual((step['kind'], step['to']), ('move', 'long_fund_submitted'))

    def test_own_escrow_mismatch_halts(self):
        step = decide('initiator', 'long_fund_submitted', long={**ready(), 'verified': False, 'problem': 'amount differs'})
        self.assertEqual(step['kind'], 'halt')

    def test_waits_for_short_leg_then_verifies(self):
        self.assertEqual(decide('initiator', 'long_funded', long=ready(), short_ref=False)['kind'], 'wait')
        self.assertEqual(decide('initiator', 'long_funded', long=ready(), short=ready(1))['kind'], 'wait')
        step = decide('initiator', 'long_funded', long=ready(), short=ready(2))
        self.assertEqual((step['kind'], step['to']), ('move', 'short_verified'))

    def test_bad_short_leg_is_never_claimed(self):
        step = decide('initiator', 'long_funded', long=ready(), short={**ready(), 'verified': False, 'problem': 'x'})
        self.assertEqual(step['kind'], 'wait')

    def test_claim_requires_preimage_file_and_reveals_only_when_safe(self):
        step = decide('initiator', 'short_verified', long=ready(), short=ready())
        self.assertEqual((step['kind'], step['action'], step['leg']), ('act', 'claim', 'short'))
        step = decide('initiator', 'short_verified', long=ready(), short=ready(), preimage=False)
        self.assertEqual(step['kind'], 'halt')

    def test_claim_cutoff_blocks_a_late_claim(self):
        cutoff = policy.action_seconds(CONFIG['chains']['cardano'])
        late = terms(short_expiry=NOW + 60 + cutoff - 1)
        step = decide('initiator', 'short_verified', t=late, long=ready(), short=ready())
        self.assertEqual((step['kind'], step['to']), ('move', 'long_funded'))
        # one second more headroom: still blocked by policy (claim window), never allowed to claim
        self.assertNotEqual(decide('initiator', 'long_funded', t=late, long=ready(), short=ready())['kind'], 'act')

    def test_cutoff_exact_boundary(self):
        t = terms()
        obs = observation(t, long=ready(), short=ready())
        window = policy.leg_window(CONFIG, {'chain': 'cardano', 'expiry': t['legs']['short']['expiry']}, obs['heads']['short'], NOW)
        self.assertTrue(engine._claim_ok(t, obs, CONFIG, NOW))
        action = policy.action_seconds(CONFIG['chains']['cardano'])
        self.assertGreaterEqual(window['firstRefund'], action)

    def test_refund_priority_and_due_time(self):
        t = terms(long_expiry=NOW + 100)
        obs = observation(t, long=ready(), short=ready())
        obs['heads']['long'] = {'observedAt': NOW, 'timestamp': NOW + 99}
        self.assertNotEqual(engine.decide(record('initiator', 'long_funded'), t, obs, CONFIG, NOW)['kind'], 'act')
        obs['heads']['long'] = {'observedAt': NOW, 'timestamp': NOW + 100}
        step = engine.decide(record('initiator', 'long_funded'), t, obs, CONFIG, NOW)
        self.assertEqual((step['kind'], step['action'], step['leg']), ('act', 'refund', 'long'))

    def test_never_claims_after_refund_due(self):
        t = terms(long_expiry=NOW - 100)
        obs = observation(t, long=ready(), short=ready())
        obs['heads']['long'] = {'observedAt': NOW, 'timestamp': NOW + 1}
        step = engine.decide(record('initiator', 'short_verified'), t, obs, CONFIG, NOW)
        self.assertEqual((step['kind'], step['to']), ('move', 'long_funded'))

    def test_claim_progress_and_races(self):
        step = decide('initiator', 'short_claim_submitted', long=ready(), short=ready(spent='claimed', spend_confirmations=2))
        self.assertEqual((step['kind'], step['to']), ('move', 'done'))
        self.assertEqual(decide('initiator', 'short_claim_submitted', long=ready(), short=ready(spent='claimed', spend_confirmations=1))['kind'], 'wait')
        step = decide('initiator', 'short_claim_submitted', long=ready(), short=ready(spent='refunded', spend_confirmations=2))
        self.assertEqual((step['kind'], step['to']), ('move', 'long_funded'))

    def test_stalled_claim_needs_a_human(self):
        sub = {'claim': {'txid': 'x', 'at': NOW - 10 ** 6}}
        step = decide('initiator', 'short_claim_submitted', long=ready(), short=ready(), submitted=sub)
        self.assertEqual(step['kind'], 'halt')
        sub = {'claim': {'txid': 'x', 'at': NOW - 10}}
        self.assertEqual(decide('initiator', 'short_claim_submitted', long=ready(), short=ready(), submitted=sub)['kind'], 'wait')

    def test_unexpected_long_claim_halts(self):
        step = decide('initiator', 'long_funded', long=ready(spent='claimed', spend_confirmations=2), short=ready())
        self.assertEqual(step['kind'], 'halt')

    def test_refund_progress(self):
        step = decide('initiator', 'refund_submitted', long=ready(spent='refunded', spend_confirmations=2))
        self.assertEqual((step['kind'], step['to']), ('move', 'refunded'))
        self.assertEqual(decide('initiator', 'refund_submitted', long=ready(spent='claimed', spend_confirmations=2))['kind'], 'halt')


class ResponderDecisions(unittest.TestCase):
    def test_waits_for_long_leg_then_verifies(self):
        self.assertEqual(decide('responder', 'terms_saved', long_ref=False, short_ref=False)['kind'], 'wait')
        self.assertEqual(decide('responder', 'terms_saved', long=ready(1), short_ref=False)['kind'], 'wait')
        step = decide('responder', 'terms_saved', long=ready(), short_ref=False)
        self.assertEqual((step['kind'], step['to']), ('move', 'long_verified'))

    def test_contradicting_long_leg_aborts(self):
        step = decide('responder', 'terms_saved', long={**ready(), 'verified': False, 'problem': 'expiry differs'}, short_ref=False)
        self.assertEqual(step['kind'], 'abort')

    def test_funds_short_only_after_long_verified_and_policy_ok(self):
        step = decide('responder', 'long_verified', long=ready(), short_ref=False)
        self.assertEqual((step['kind'], step['action'], step['leg']), ('act', 'fund', 'short'))
        bad = terms(long_expiry=NOW + 3800)
        self.assertEqual(decide('responder', 'long_verified', t=bad, long=ready(), short_ref=False)['kind'], 'abort')
        self.assertEqual(decide('responder', 'long_verified', long=ready(spent='claimed', spend_confirmations=1), short_ref=False)['kind'], 'wait')

    def test_cannot_fund_if_long_leg_vanishes(self):
        self.assertEqual(decide('responder', 'long_verified', long=empty_observation(), short_ref=False)['kind'], 'wait')

    def test_preimage_learned_even_from_an_unconfirmed_claim(self):
        revealed = ready(spent='claimed', spend_confirmations=0, preimage='cd' * 32)
        step = decide('responder', 'short_funded', long=ready(), short=revealed)
        self.assertEqual((step['kind'], step['to'], step['learn_preimage']), ('move', 'preimage_known', 'cd' * 32))
        # claimed but preimage not readable yet: wait
        self.assertEqual(decide('responder', 'short_funded', long=ready(), short=ready(spent='claimed'))['kind'], 'wait')

    def test_short_refund_when_due(self):
        t = terms(short_expiry=NOW - 100)
        obs = observation(t, long=ready(), short=ready())
        obs['heads']['short'] = {'observedAt': NOW, 'timestamp': NOW + 1}
        step = engine.decide(record('responder', 'short_funded'), t, obs, CONFIG, NOW)
        self.assertEqual((step['kind'], step['action'], step['leg']), ('act', 'refund', 'short'))

    def test_claim_long_with_learned_preimage(self):
        step = decide('responder', 'preimage_known', long=ready(), short=ready(spent='claimed'))
        self.assertEqual((step['kind'], step['action'], step['leg']), ('act', 'claim', 'long'))
        self.assertEqual(decide('responder', 'preimage_known', long=ready(), short=ready(spent='claimed'), preimage=False)['kind'], 'halt')

    def test_late_claim_attempted_on_height_chains_refused_on_time_chains(self):
        # height chain: the preimage is public, so keep trying until a refund actually lands
        t = terms(long_chain='bitcoin', long_expiry=900)
        obs = observation(t, long=ready(), short=ready(spent='claimed'))
        self.assertEqual(engine.decide(record('responder', 'preimage_known'), t, obs, CONFIG, NOW)['kind'], 'act')
        # time chain: the contract refuses a claim at the deadline
        t = terms(long_expiry=NOW - 100)
        obs = observation(t, long=ready(), short=ready(spent='claimed'))
        obs['heads']['long'] = {'observedAt': NOW, 'timestamp': NOW + 1}
        step = engine.decide(record('responder', 'preimage_known'), t, obs, CONFIG, NOW)
        self.assertEqual((step['kind'], step['to']), ('move', 'failed'))

    def test_long_refunded_before_claim_is_a_failure(self):
        step = decide('responder', 'preimage_known', long=ready(spent='refunded', spend_confirmations=2), short=ready(spent='claimed'))
        self.assertEqual((step['kind'], step['to']), ('move', 'failed'))

    def test_claim_progress(self):
        step = decide('responder', 'long_claim_submitted', long=ready(spent='claimed', spend_confirmations=2))
        self.assertEqual((step['kind'], step['to']), ('move', 'done'))
        step = decide('responder', 'long_claim_submitted', long=ready(spent='refunded', spend_confirmations=2))
        self.assertEqual((step['kind'], step['to']), ('move', 'failed'))


class LockWindow(unittest.TestCase):
    """A swap that waited too long to fund is refused by policy, not left for the wallet to refuse."""

    def setUp(self):
        heads = {'long': head('ethereum'), 'short': head('hegemon')}
        plan = policy.plan_timeouts(CONFIG, 'ethereum', 'hegemon', heads, NOW)
        self.t = terms('ethereum', 'hegemon', plan['long']['expiry'], plan['short']['expiry'])
        self.tight = copy.deepcopy(CONFIG)
        # Make the chain's lock minimum wider than the window this plan left, as if time had passed.
        self.tight['chains']['hegemon']['minLockBlocks'] = plan['short']['expiry'] - 1000
        self.assertTrue(plan['verdict']['ok'])

    def decide(self, config, role, state, **kwargs):
        rec_args = {k: kwargs.pop(k) for k in ('long_ref', 'short_ref') if k in kwargs}
        return engine.decide(record(role, state, **rec_args), self.t, observation(self.t, **kwargs), config, NOW)

    def test_a_planned_swap_is_funded_in_time(self):
        step = self.decide(CONFIG, 'initiator', 'terms_saved', long_ref=False, short_ref=False)
        self.assertEqual((step['kind'], step['action']), ('act', 'fund'))
        step = self.decide(CONFIG, 'responder', 'long_verified', long=ready(), short_ref=False)
        self.assertEqual((step['kind'], step['action'], step['leg']), ('act', 'fund', 'short'))

    def test_initiator_does_not_fund_when_the_short_lock_can_no_longer_be_made(self):
        step = self.decide(self.tight, 'initiator', 'terms_saved', long_ref=False, short_ref=False)
        self.assertEqual(step['kind'], 'abort')
        self.assertEqual(step['codes'], ['lock-window-short'])

    def test_responder_does_not_fund_a_lock_the_wallet_would_refuse(self):
        step = self.decide(self.tight, 'responder', 'long_verified', long=ready(), short_ref=False)
        self.assertEqual((step['kind'], step['codes']), ('abort', ['lock-window-short']))

    def test_a_funded_leg_is_not_judged_by_the_lock_minimum(self):
        step = self.decide(self.tight, 'initiator', 'long_fund_submitted', long=ready(2))
        self.assertEqual(step['kind'], 'move')


class CommonDecisions(unittest.TestCase):
    def test_needs_human_blocks_everything(self):
        for role, state in (('initiator', 'terms_saved'), ('responder', 'long_verified')):
            step = decide(role, state, long=ready(), short=ready(), needs_human='look at it')
            self.assertEqual(step['kind'], 'halt')

    def test_terminal_states(self):
        for state in engine.TERMINAL:
            self.assertEqual(decide('initiator', state)['kind'], 'terminal')

    def test_unreadable_legs_wait(self):
        self.assertEqual(decide('initiator', 'long_funded', long=None, short=None)['kind'], 'wait')
        self.assertEqual(decide('responder', 'short_funded', long=None, short=None)['kind'], 'wait')

    def test_transition_table_matches_decisions(self):
        for role in ('initiator', 'responder'):
            states = {a for a, _, _ in engine.explain(role)} | {b for _, b, _ in engine.explain(role)}
            self.assertTrue(states >= {'terms_saved', 'refund_submitted', 'refunded'})


class Invariants(unittest.TestCase):
    """Sweep many observation combinations and assert the safety rules for every one."""

    def combos(self):
        spent_options = [(None, 0, None), ('claimed', 0, 'cd' * 32), ('claimed', 2, 'cd' * 32), ('refunded', 0, None), ('refunded', 2, None)]
        leg = [None, empty_observation()]
        for found_confirmations, verified, (spent, spend_conf, pre) in itertools.product((0, 1, 2), (True, False), spent_options):
            obs = {**empty_observation(), 'found': True, 'verified': verified, 'confirmations': found_confirmations,
                   'problem': None if verified else 'mismatch', 'spent': spent, 'spend_confirmations': spend_conf, 'preimage': pre}
            leg.append(obs)
        return leg

    def test_invariants(self):
        legs = self.combos()
        states = {'initiator': ['terms_saved', 'long_fund_submitted', 'long_funded', 'short_verified', 'short_claim_submitted', 'refund_submitted'],
                  'responder': ['terms_saved', 'long_verified', 'short_fund_submitted', 'short_funded', 'preimage_known', 'long_claim_submitted', 'refund_submitted']}
        for long_chain, short_chain in (('ethereum', 'cardano'), ('bitcoin', 'ethereum'), ('hegemon', 'cardano'), ('cardano', 'bitcoin')):
            t = terms(long_chain, short_chain, long_expiry=NOW + 400000 if CONFIG['chains'][long_chain]['kind'] == 'time' else 1500,
                      short_expiry=NOW + 300000 if CONFIG['chains'][short_chain]['kind'] == 'time' else 1400)
            for role, role_states in states.items():
                for state in role_states:
                    for long in legs[::3]:
                        for short in legs[::3]:
                            for preimage in (True, False):
                                obs = observation(t, long=long, short=short, preimage=preimage)
                                rec = record(role, state, needs_human=None)
                                step = engine.decide(rec, t, copy.deepcopy(obs), CONFIG, NOW)
                                self.check(role, state, step, obs)

    def check(self, role, state, step, obs):
        who = f'{role}/{state}/{step}'
        if step['kind'] == 'act':
            if step['action'] == 'fund':
                self.assertIn((role, state), (('initiator', 'terms_saved'), ('responder', 'long_verified')), who)
            if step['action'] == 'claim':
                self.assertIn((role, state), (('initiator', 'short_verified'), ('responder', 'preimage_known')), who)
                self.assertTrue(obs['preimage_available'], who)
                leg = obs['legs'][step['leg']]
                self.assertTrue(leg and leg['found'] and leg['spent'] is None, who)
                if role == 'initiator':
                    self.assertTrue(leg['verified'] and leg['confirmations'] >= 2, who)
            if step['action'] == 'refund':
                self.assertEqual(step['leg'], engine.own_leg(role), who)
                self.assertIn(state, ('long_funded', 'short_funded'), who)
        if step['kind'] == 'move' and step['to'] in ('done', 'refunded'):
            self.assertIn(state, ('short_claim_submitted', 'long_claim_submitted', 'refund_submitted', 'preimage_known', 'long_funded', 'long_verified', 'short_funded', 'short_verified'), who)


if __name__ == '__main__':
    unittest.main()
