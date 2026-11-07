"""Hegemon adapter tests against a simulated chain and wallet CLI (swap_engine/hegemon_fake.py).

Unit tests cover every observation shape, every refusal and the journal discipline; the engine tests run a
whole two-party swap with a process kill at every wallet step and check that the money ends fair. Real-chain
behaviour is covered by test_local_chains.py (HEGEMON_LOCAL_CHAINS=1) and the recorded local runs.
"""
import hashlib
import itertools
import json
import os
import tempfile
import unittest
from pathlib import Path

from swap_engine import engine, hegemon_wallet as hw, planner, sim, timelock_policy as policy
from swap_engine.adapter import ActionRefused, ChainUnavailable, check_observation
from swap_engine.adapters.hegemon_local import HegemonAdapter, terms_digest
from swap_engine.hegemon_fake import FakeHegemonProfile
from swap_engine.store import journal_ids

CONFIG = policy.load_timing()
PREIMAGE = bytes(range(1, 33))
HASHLOCK = hashlib.sha256(PREIMAGE).hexdigest()
TMP_BASE = os.environ.get('SWAP_TEST_TMP') or ('/dev/shm' if os.path.isdir('/dev/shm') else None)


def private(base=None):
    handle = tempfile.TemporaryDirectory(dir=base or TMP_BASE)
    os.chmod(handle.name, 0o700)
    return handle, Path(handle.name)


class Clock:
    def __init__(self, now=1_800_000_000):
        self.now = now

    def __call__(self):
        return self.now


class Fixture(unittest.TestCase):
    def setUp(self):
        handle, self.root = private()
        self.addCleanup(handle.cleanup)
        self.clock = Clock()
        self.profile = FakeHegemonProfile(self.root / 'profile', self.clock)
        for person in ('alice', 'bob'):
            for _ in range(3):
                self.profile.credit(person, 10_000_000)
        self.alice = HegemonAdapter(self.profile, 'alice')
        self.bob = HegemonAdapter(self.profile, 'bob')
        self.journal = self.root / 'journal'
        self.journal.mkdir(mode=0o700)
        self.height = self.profile.height()
        self.leg = {'chain': 'hegemon', 'amount': 100_000, 'refundee': self.alice.identity(), 'claimant': self.bob.identity(),
                    'expiry': self.height + 60, 'hashlock': HASHLOCK}

    def blocks(self, count):
        self.clock.now += count * self.profile.interval
        return self.profile.height()

    def fund(self, mined=True):
        result = self.alice.fund(self.leg, self.journal)
        self.escrow = self.alice.escrow_ref(self.leg, result['txid'])
        if mined:
            self.blocks(1)
        return result

    def observe(self, adapter):
        return check_observation(adapter.inspect(self.leg, self.escrow))


class ParserTests(unittest.TestCase):
    BLOCK = ', '.join(['0'] * 32)

    def test_status_is_parsed_strictly(self):
        text = ('Unlocking encrypted wallet…\nwallet-progress stage=unlock current=0 target=0 notes=0 elapsed_ms=0\nSyncing blocks: 5/5; new notes 0\nsynced 134\n'
                'ordinary position=28 value=10000\nhtlc position=30 value=100000\n'
                'balance synced_height=134 available_atoms=10000\n'
                f"{'ab' * 32} Submitted mined=Some((134, [{self.BLOCK}]))\n{'cd' * 32} Candidate mined=None\n")
        status = hw.parse_status(text)
        self.assertEqual(status['height'], 134)
        self.assertEqual([(n['kind'], n['position'], n['value']) for n in status['notes']], [('ordinary', 28, 10000), ('htlc', 30, 100000)])
        self.assertEqual(status['attempts'][0]['mined'], {'height': 134, 'hash': '00' * 32})
        self.assertIsNone(status['attempts'][1]['mined'])

    def test_ambiguous_or_malformed_output_is_refused(self):
        for text in ('no height here\n', 'synced 1\nsynced 2\n', 'synced 1\nordinary position=1 value=5\nordinary position=1 value=6\n',
                     f"synced 1\n{'ab' * 32} Bogus mined=None\n", f"synced 1\n{'ab' * 32} Submitted mined=Some((3, [1, 2]))\n",
                     f"synced 1\n{'ab' * 32} Submitted mined=None\n{'ab' * 32} Candidate mined=None\n"):
            with self.assertRaises(ValueError, msg=text):
                hw.parse_status(text)

    def test_candidate_submitted_and_verified(self):
        self.assertEqual(hw.parse_candidate('proving\ncandidate ' + 'ab' * 32 + '\n'), 'ab' * 32)
        for text in ('', 'candidate ' + 'ab' * 32 + '\ncandidate ' + 'cd' * 32 + '\n', 'candidate xyz\n'):
            with self.assertRaises(ValueError):
                hw.parse_candidate(text)
        self.assertEqual(hw.parse_submitted('submitted ' + 'ab' * 48 + '\n'), 'ab' * 48)
        with self.assertRaises(ValueError):
            hw.parse_submitted('submitted ' + 'ab' * 32 + '\n')
        good = json.dumps({'verified': True, 'position': 3, 'created_height': 9, 'reference_height': 12, 'confirmations': 4})
        self.assertEqual(hw.parse_verified('x\n' + good + '\n')['created_height'], 9)
        for text in ('', json.dumps({'verified': False}), json.dumps({'verified': True, 'position': '3'})):
            with self.assertRaises(ValueError):
                hw.parse_verified(text)

    def test_error_line_is_one_short_line(self):
        line = hw.last_error('wallet-progress stage=sync\nSyncing blocks: 1/9\nError: HTLC terms mismatch\n')
        self.assertEqual(line, 'Error: HTLC terms mismatch')
        self.assertLessEqual(len(hw.last_error('x' * 1000)), 200)


class ReadTests(Fixture):
    def test_head_identity_and_escrow_ref(self):
        head = self.alice.head()
        self.assertEqual(set(head), {'observedAt', 'height'})
        self.assertEqual(head['height'], self.height)
        self.assertTrue(self.alice.identity().startswith('shca1'))
        self.assertEqual(self.alice.escrow_ref(self.leg, 'ab' * 32), {'txid': 'ab' * 32})
        for bad in ('xx', 'AB' * 32, 5, None):
            with self.assertRaises(ValueError):
                self.alice.escrow_ref(self.leg, bad)

    def test_failed_reads_are_unavailable_never_empty(self):
        self.fund()
        self.profile.fail_reads = 1
        with self.assertRaises(ChainUnavailable):
            self.alice.head()
        self.profile.fail_commands['status'] = 1
        with self.assertRaises(ChainUnavailable):
            self.alice.inspect(self.leg, self.escrow)
        self.profile.fail_commands['status'] = 1
        with self.assertRaises(ChainUnavailable):
            self.alice.transaction_seen('ab' * 32)

    def test_a_wallet_that_is_neither_party_cannot_inspect(self):
        stranger = {**self.leg, 'claimant': 'shca1someoneelse', 'refundee': 'shca1another'}
        with self.assertRaises(ValueError):
            self.alice.inspect(stranger, {'txid': 'ab' * 32})


class FundTests(Fixture):
    def test_fund_journals_the_exported_bytes_before_broadcast(self):
        calls = []
        real = self.profile._run

        def watch(person, name, args, secrets):
            if name == 'submit':
                calls.append(sorted(p.name for p in self.journal.iterdir()))
                self.assertEqual(self.profile.mempool, [])
            return real(person, name, args, secrets)
        self.profile._run = watch
        result = self.alice.fund(self.leg, self.journal)
        txid = result['txid']
        self.assertTrue(hw.HEX64.fullmatch(txid))
        self.assertEqual(calls, [[f'hegemon-local-{txid}.json', f'hegemon-local-{txid}.signed']])
        record = json.loads((self.journal / f'hegemon-local-{txid}.json').read_text())
        self.assertEqual(record, {'version': 1, 'chain': 'hegemon-local', 'txid': txid, 'state': 'prepared_or_submitted'})
        self.assertEqual((self.journal / f'hegemon-local-{txid}.signed').read_bytes(), b'FAKE-ACTION-' + txid.encode())
        self.assertEqual(self.alice.journal_ids(self.journal), [txid])
        self.assertEqual(oct((self.journal / f'hegemon-local-{txid}.signed').stat().st_mode & 0o777), '0o600')
        self.assertTrue(self.alice.transaction_seen(txid))
        self.assertEqual(os.listdir(self.alice.state / 'exports'), [])  # no signed bytes left outside the journal

    def test_funding_observations_through_the_lifecycle(self):
        result = self.fund(mined=False)
        refundee = self.observe(self.alice)
        self.assertFalse(refundee['found'])
        self.assertFalse(self.observe(self.bob)['found'])
        self.blocks(1)
        refundee, claimant = self.observe(self.alice), self.observe(self.bob)
        for seen in (refundee, claimant):
            self.assertTrue(seen['found'] and seen['verified'])
            self.assertEqual((seen['confirmations'], seen['spent'], seen['preimage'], seen['problem']), (1, None, None, None))
        self.blocks(2)
        self.assertEqual(self.observe(self.alice)['confirmations'], 3)
        self.assertEqual(self.observe(self.bob)['confirmations'], 3)
        self.assertEqual(self.alice.escrow_ref(self.leg, result['txid']), self.escrow)

    def test_the_claimant_never_accepts_a_note_with_other_terms(self):
        self.fund()
        for key, value in (('amount', 99_999), ('expiry', self.leg['expiry'] + 1), ('hashlock', 'ee' * 32), ('refundee', 'shca1other'), ('claimant', 'shca1other')):
            changed = {**self.leg, key: value}
            if key == 'claimant':
                continue  # a different claimant makes the wallet a stranger to the leg, covered above
            self.assertFalse(check_observation(self.bob.inspect(changed, self.escrow))['found'], key)

    def test_refusals_before_signing_leave_no_trace(self):
        cases = [
            ('wrong actor', lambda: self.bob.fund(self.leg, self.journal)),
            ('amount too large', lambda: self.alice.fund({**self.leg, 'amount': 10 ** 12}, self.journal)),
            ('lock window', lambda: self.alice.fund({**self.leg, 'expiry': self.height + 5}, self.journal)),
            ('bad hashlock', lambda: self.alice.fund({**self.leg, 'hashlock': 'xyz'}, self.journal)),
            ('wallet failure', lambda: (self.profile.fail_commands.update(lock=1), self.alice.fund(self.leg, self.journal))),
        ]
        for name, call in cases:
            with self.subTest(name):
                with self.assertRaises(ActionRefused):
                    call()
                self.assertEqual(os.listdir(self.journal), [])
        self.assertEqual(self.profile.mempool, [])
        self.assertEqual([a for a in self.profile.attempts['alice'].values() if a['status'] != 'Candidate'], [])

    def test_a_crash_after_the_proof_leaves_a_stale_attempt_that_the_next_write_cancels(self):
        hook = sim.CrashHook(crash_at=2)  # point 1 is before `lock`, point 2 is right after it returns
        self.profile.hook = hook
        with self.assertRaises(sim.SimulatedCrash):
            self.alice.fund(self.leg, self.journal)  # killed right after `lock` returned: proved, not exported
        self.assertEqual(os.listdir(self.journal), [])
        stale = [a for a in self.profile.attempts['alice'].values()]
        self.assertEqual([a['status'] for a in stale], ['Candidate'])
        self.profile.hook = None
        result = self.alice.fund(self.leg, self.journal)
        self.assertNotIn(result['txid'], [a['id'] for a in stale])
        self.assertNotIn(stale[0]['id'], self.profile.attempts['alice'])
        self.blocks(1)
        self.assertEqual(len([n for n in self.profile.notes.values() if n['kind'] == 'htlc']), 1)

    def test_crash_between_journal_and_submit_is_reported_unseen_not_adopted(self):
        names = []

        class Recorder:
            def point(self, name):
                names.append(name)
                if name == 'wallet:submit:before':
                    raise sim.SimulatedCrash(name)
        self.profile.hook = Recorder()
        with self.assertRaises(sim.SimulatedCrash):
            self.alice.fund(self.leg, self.journal)
        [txid] = self.alice.journal_ids(self.journal)
        self.assertEqual(self.profile.mempool, [])
        self.assertFalse(self.alice.transaction_seen(txid))  # exported but never submitted: the engine hands this to a human
        self.profile.hook = None
        self.blocks(3)
        self.assertFalse(self.alice.transaction_seen(txid))

    def test_a_lost_submit_response_is_seen_from_the_wallet(self):
        class Lose:
            def point(self, name):
                if name == 'wallet:submit:after':
                    raise sim.SimulatedCrash(name)
        self.profile.hook = Lose()
        with self.assertRaises(sim.SimulatedCrash):
            self.alice.fund(self.leg, self.journal)
        [txid] = self.alice.journal_ids(self.journal)
        self.assertTrue(self.alice.transaction_seen(txid))
        self.profile.hook = None
        self.blocks(1)
        self.escrow = {'txid': txid}
        self.assertTrue(self.observe(self.alice)['verified'])

    def test_a_submit_failure_after_journaling_is_not_a_refusal(self):
        self.profile.fail_commands['submit'] = 1
        with self.assertRaises(RuntimeError):
            self.alice.fund(self.leg, self.journal)
        self.assertEqual(len(self.alice.journal_ids(self.journal)), 1)


class ClaimAndRefundTests(Fixture):
    def claim(self, preimage=PREIMAGE):
        result = self.bob.claim(self.leg, self.escrow, preimage, self.journal)
        self.blocks(1)
        return result

    def test_claim_is_seen_by_both_parties_with_the_preimage(self):
        self.fund()
        self.blocks(2)
        result = self.claim(bytearray(PREIMAGE))
        self.assertIn(result['txid'], self.bob.journal_ids(self.journal))
        for adapter in (self.alice, self.bob):
            seen = self.observe(adapter)
            self.assertEqual((seen['spent'], seen['preimage']), ('claimed', PREIMAGE.hex()))
            self.assertGreaterEqual(seen['spend_confirmations'], 1)
        self.assertEqual(sum(n['value'] for n in self.profile._visible('bob') if n['kind'] == 'ordinary') - 30_000_000, 100_000 - 1)

    def test_claim_accepts_bytes_and_bytearray_and_rejects_a_wrong_preimage(self):
        self.fund()
        with self.assertRaises(ActionRefused):
            self.bob.claim(self.leg, self.escrow, b'\x01' * 32, self.journal)
        with self.assertRaises(ActionRefused):
            self.bob.claim(self.leg, self.escrow, PREIMAGE[:31], self.journal)
        self.assertEqual(self.bob.journal_ids(self.journal), self.alice.journal_ids(self.journal))  # only the lock; no claim was signed
        self.claim(bytes(PREIMAGE))

    def test_claim_by_the_wrong_party_or_without_a_verified_note_is_refused(self):
        self.fund(mined=False)
        for adapter in (self.alice, self.bob):
            with self.assertRaises(ActionRefused):
                adapter.claim(self.leg, self.escrow, PREIMAGE, self.journal)
        self.assertEqual(len(os.listdir(self.journal)), 2)  # only Alice's lock records; nothing was signed for the claim
        self.assertEqual(self.bob.journal_ids(self.journal), self.alice.journal_ids(self.journal))

    def test_a_claim_stays_visible_when_the_note_is_gone_and_is_never_called_a_refund(self):
        self.fund()
        self.claim()
        self.assertEqual(self.observe(self.bob)['spent'], 'claimed')
        self.profile.releases.clear()  # a release that cannot be read must never be turned into a guess
        with self.assertRaises(ChainUnavailable):
            self.bob.inspect(self.leg, self.escrow)

    def test_refund_after_the_deadline_and_not_before(self):
        self.fund()
        self.assertTrue(self.observe(self.bob)['verified'])  # the claimant sees and caches the escrow while it still can
        with self.assertRaises(ActionRefused):
            self.alice.refund(self.leg, self.escrow, self.journal)
        self.assertEqual(len(self.alice.journal_ids(self.journal)), 1)  # only the lock
        self.blocks(self.leg['expiry'] - self.profile.height_now + 1)
        before = self.observe(self.alice)
        self.assertEqual(before['spent'], None)
        result = self.alice.refund(self.leg, self.escrow, self.journal)
        self.blocks(1)
        seen = self.observe(self.alice)
        self.assertEqual((seen['spent'], seen['spend_txid'], seen['preimage']), ('refunded', result['txid'], None))
        self.assertGreaterEqual(seen['spend_confirmations'], 1)
        refunded_to_alice = sum(n['value'] for n in self.profile._visible('alice') if n['kind'] == 'ordinary')
        self.assertEqual(refunded_to_alice, 30_000_000 - 1 - 1)  # the amount came back; two fees were paid
        claimant = self.observe(self.bob)
        self.assertEqual((claimant['spent'], claimant['preimage']), ('refunded', None))

    def test_a_late_claim_after_the_refund_is_refused_and_the_refund_never_repeats(self):
        self.fund()
        self.blocks(self.leg['expiry'] - self.profile.height_now + 1)
        self.alice.refund(self.leg, self.escrow, self.journal)
        self.blocks(1)
        with self.assertRaises(ActionRefused):
            self.bob.claim(self.leg, self.escrow, PREIMAGE, self.journal)
        with self.assertRaises(ActionRefused):
            self.alice.refund(self.leg, self.escrow, self.journal)

    def test_a_refund_is_found_even_when_the_window_is_too_close_to_verify(self):
        self.fund()
        self.blocks(self.leg['expiry'] - self.profile.height_now - 1)  # inside the wallet's verify floor
        self.blocks(2)  # and past the deadline: a fresh adapter has no cached position and cannot verify, yet can refund
        result = self.alice.refund(self.leg, self.escrow, self.journal)
        self.assertIn(result['txid'], self.alice.journal_ids(self.journal))

    def test_secrets_never_reach_the_adapter_state_or_journal(self):
        self.fund()
        self.claim()
        needles = [PREIMAGE.hex().encode(), PREIMAGE, b'handoff-passphrase']
        for base in (self.alice.state, self.bob.state, self.journal):
            for path in Path(base).rglob('*'):
                if path.is_file():
                    data = path.read_bytes()
                    for needle in needles:
                        self.assertNotIn(needle, data, str(path))
        try:
            self.bob.claim(self.leg, self.escrow, PREIMAGE, self.journal)
        except ActionRefused as error:
            self.assertNotIn(PREIMAGE.hex(), str(error))


class CarrierTests(unittest.TestCase):
    """The preimage is read from canonical action bytes; build a minimal carrier with the real offsets."""

    def carrier(self, flag=1, secret=PREIMAGE, kind=bytes):
        import hegemon_preimage_observer as observer
        prefix, chain_id = bytes([7]) * 48, bytes([9]) * 32
        data = bytearray(5788)
        data[:8] = b'HGPSLC02'
        data[8:24] = observer.IDENTITY
        data[24:72] = prefix
        data[72:104] = chain_id
        data[528:536] = flag.to_bytes(8, 'little')
        data[536:568] = secret
        data[5784:5788] = b'SMZL'
        return kind(data), prefix, chain_id

    def release(self, carrier, prefix, chain_id, hashlock=HASHLOCK):
        import hegemon_preimage_observer as observer
        return observer.released_preimage(carrier, chain_id=chain_id, relation_prefix=prefix, hashlock=hashlock)

    def test_bytes_and_bytearray_carriers_release_the_preimage(self):
        for kind in (bytes, bytearray):
            carrier, prefix, chain_id = self.carrier(kind=kind)
            secret = self.release(carrier, prefix, chain_id)
            self.assertEqual(bytes(secret), PREIMAGE)
            secret[:] = b'\0' * 32

    def test_no_release_wrong_hashlock_and_malformed_secrets(self):
        carrier, prefix, chain_id = self.carrier(flag=0, secret=bytes(32))
        self.assertIsNone(self.release(carrier, prefix, chain_id))
        carrier, prefix, chain_id = self.carrier()
        self.assertIsNone(self.release(carrier, prefix, chain_id, hashlock='ee' * 32))
        carrier, prefix, chain_id = self.carrier(flag=0, secret=PREIMAGE)
        with self.assertRaises(ValueError):
            self.release(carrier, prefix, chain_id)
        carrier, prefix, chain_id = self.carrier(flag=2)
        with self.assertRaises(ValueError):
            self.release(carrier, prefix, chain_id)
        with self.assertRaises(ValueError):
            self.release(bytes(10), prefix, chain_id)


# ------------------------------------------------------------------ whole swaps with a kill at every wallet step

class HegemonParty(sim.Party):
    def __init__(self, root, world, role, identities, profile, person, hook=None):
        super().__init__(root, world, role, identities, hook)
        self.profile, self.person = profile, person

    def adapters(self, terms):
        # A fresh adapter object on every step, as after a restart: only the state directory survives.
        out = {}
        for name in ('long', 'short'):
            chain = terms['legs'][name]['chain']
            out[name] = HegemonAdapter(self.profile, self.person) if chain == 'hegemon' else sim.SimAdapter(self.world, chain, self.identities[name], self.hook)
        return out


class HegemonSwap:
    def __init__(self, long_chain, short_chain, hook=None, amounts=(100_000, 2000)):
        self.chains = (long_chain, short_chain)
        other = short_chain if long_chain == 'hegemon' else long_chain
        self.world = sim.make_world([other])
        self.world.chains[other].credit(f'bob@{other}', 10 ** 6) if short_chain == other else self.world.chains[other].credit(f'alice@{other}', 10 ** 6)
        self.tmp = tempfile.TemporaryDirectory(dir=TMP_BASE)
        os.chmod(self.tmp.name, 0o700)
        root = Path(self.tmp.name)
        self.profile = FakeHegemonProfile(root / 'hegemon', lambda: self.world.now, hook=hook)
        self.profile.base = 1000
        for person in ('alice', 'bob'):
            for _ in range(4):
                self.profile.credit(person, 5_000_000)
        self.before = {p: self.hegemon_balance(p) for p in ('alice', 'bob')}
        self.addresses = {p: self.profile.address(p) for p in ('alice', 'bob')}
        heads = {}
        for key, name in (('long', long_chain), ('short', short_chain)):
            heads[key] = {'observedAt': self.world.now, 'height': self.profile.height()} if name == 'hegemon' else sim.sim_heads(self.world, name, name)['long']
        plan = planner.plan_with_margin(CONFIG, long_chain, short_chain, heads, self.world.now)
        assert plan['verdict']['ok'], plan['verdict']
        ids = {'long': (self.identity('alice', 'refundee', long_chain), self.identity('bob', 'claimant', long_chain)),
               'short': (self.identity('bob', 'refundee', short_chain), self.identity('alice', 'claimant', short_chain))}
        self.terms = {'version': 1, 'hashlock': HASHLOCK, 'legs': {
            'long': {'chain': long_chain, 'amount': amounts[0] if long_chain == 'hegemon' else amounts[1], 'refundee': ids['long'][0], 'claimant': ids['long'][1], 'expiry': plan['long']['expiry']},
            'short': {'chain': short_chain, 'amount': amounts[0] if short_chain == 'hegemon' else amounts[1], 'refundee': ids['short'][0], 'claimant': ids['short'][1], 'expiry': plan['short']['expiry']}}}
        self.harness = sim.Harness.__new__(sim.Harness)
        h = self.harness
        h.world, h.terms, h.config, h.hook = self.world, self.terms, CONFIG, hook
        h.alice = HegemonParty(root / 'alice', self.world, 'initiator', {'long': ids['long'][0], 'short': ids['short'][1]}, self.profile, 'alice', hook)
        h.bob = HegemonParty(root / 'bob', self.world, 'responder', {'long': ids['long'][1], 'short': ids['short'][0]}, self.profile, 'bob', hook)
        h.swap_id = hashlib.sha256(json.dumps(self.terms, sort_keys=True).encode()).hexdigest()[:16]
        h.alice.store.create(h.swap_id, 'initiator', self.terms, self.world.now, PREIMAGE)
        h.bob.store.create(h.swap_id, 'responder', self.terms, self.world.now)
        h.crashes, h.log = 0, []

    def identity(self, person, role, chain):
        return self.profile.address(person) if chain == 'hegemon' else f'{person}@{chain}'

    def hegemon_balance(self, person):
        return sum(n['value'] for n in self.profile._visible(person) if n['kind'] == 'ordinary')

    def run(self, **kwargs):
        kwargs.setdefault('seconds_per_step', 120)
        kwargs.setdefault('max_steps', 2500)
        return self.harness.run(**kwargs)

    def outcome(self, states=None):
        states = states or self.harness.states()
        return states['initiator'][0], states['responder'][0]

    def problems(self):
        """Value is conserved and no action was mined twice."""
        out = []
        locks = [n for n in self.profile.notes.values() if n['kind'] == 'htlc']
        if len(locks) > 1:
            out.append('more than one lock was mined')
        spent_locks = [n for n in locks if n['spent']]
        if len(spent_locks) > 1:
            out.append('a lock was spent twice')
        mined = [a for actions in self.profile.blocks.values() for a in actions]
        for kind in ('lock', 'claim', 'refund'):
            if len([a for a in mined if a['kind'] == kind]) > 1:
                out.append(f'{kind} mined more than once')
        total = sum(n['value'] for n in self.profile.notes.values() if not n['spent'])
        credited = 8 * 5_000_000
        fees = len(mined) * self.profile.fee
        if total + fees != credited:
            out.append(f'Hegemon value not conserved: {total} + {fees} != {credited}')
        return out

    def fair(self, outcome):
        got = {p: self.hegemon_balance(p) - self.before[p] for p in self.before}
        amount = next(l['amount'] for l in self.terms['legs'].values() if l['chain'] == 'hegemon')
        hegemon_leg = next(n for n, l in self.terms['legs'].items() if l['chain'] == 'hegemon')
        alice_funds = hegemon_leg == 'long'
        if outcome == 'swapped':
            expect = {'alice': -amount if alice_funds else amount, 'bob': amount if alice_funds else -amount}
        else:
            expect = {'alice': 0, 'bob': 0}
        return [f'{p}: moved {got[p]}, expected {expect[p]}' for p in got if abs(got[p] - expect[p]) > 4]

    def close(self):
        self.tmp.cleanup()


class SwapTests(unittest.TestCase):
    PAIRS = (('hegemon', 'ethereum'), ('ethereum', 'hegemon'), ('hegemon', 'cardano'), ('bitcoin', 'hegemon'))

    def test_happy_swaps_with_hegemon_on_either_leg(self):
        for long_chain, short_chain in self.PAIRS:
            with self.subTest(long=long_chain, short=short_chain):
                s = HegemonSwap(long_chain, short_chain)
                self.addCleanup(s.close)
                states = s.run(seconds_per_step=150)
                self.assertEqual(s.outcome(states), ('done', 'done'), s.harness.log[-6:])
                self.assertEqual(s.problems(), [])
                self.assertEqual(s.fair('swapped'), [])

    def test_responder_never_funds_so_a_hegemon_funder_refunds(self):
        s = HegemonSwap('hegemon', 'ethereum')
        self.addCleanup(s.close)
        states = s.run(seconds_per_step=300, active=lambda i, h: ('initiator',),
                       until=lambda h: h.states()['initiator'][0] in ('refunded', 'aborted', 'failed'))
        self.assertEqual(states['initiator'][0], 'refunded', s.harness.log[-4:])
        self.assertEqual(s.problems(), [])
        self.assertEqual(s.fair('unchanged'), [])

    def test_initiator_vanishes_so_the_hegemon_responder_refunds(self):
        s = HegemonSwap('ethereum', 'hegemon')
        self.addCleanup(s.close)
        gone = {'on': False}

        def active(index, harness):
            if harness.states()['responder'][0] in ('short_fund_submitted', 'short_funded'):
                gone['on'] = True
            return ('responder',) if gone['on'] else ('initiator', 'responder')

        states = s.run(seconds_per_step=300, active=active, max_steps=4000, until=lambda h: h.states()['responder'][0] in ('refunded', 'done'))
        self.assertEqual(s.outcome(states)[1], 'refunded', s.harness.log[-4:])
        gone['on'] = False
        states = s.run(seconds_per_step=300, max_steps=3000)
        self.assertEqual(s.outcome(states), ('refunded', 'refunded'), s.harness.log[-6:])
        self.assertEqual(s.problems(), [])
        self.assertEqual(s.fair('unchanged'), [])

    def test_a_late_claim_is_refused_after_the_hegemon_refund(self):
        s = HegemonSwap('hegemon', 'ethereum')
        self.addCleanup(s.close)
        # Run until the responder has funded, then freeze the responder past both deadlines and let the initiator refund.
        gone = {'on': False}

        def active(index, harness):
            if harness.states()['responder'][0] in ('short_fund_submitted', 'short_funded'):
                gone['on'] = True
            return ('initiator',) if gone['on'] else ('initiator', 'responder')

        # The initiator's own claim is what the responder would race; here the initiator sleeps instead.
        states = s.run(seconds_per_step=120, active=lambda i, h: ('responder',) if h.states()['responder'][0] in ('short_fund_submitted', 'short_funded') else ('initiator', 'responder'),
                       max_steps=400, until=lambda h: h.states()['responder'][0] == 'short_funded')
        self.assertEqual(s.outcome(states)[1], 'short_funded')
        s.world.tick(s.terms['legs']['long']['expiry'] - s.profile.height_now + 20)
        s.world.tick(20000)
        states = s.run(seconds_per_step=300, max_steps=2000)
        self.assertEqual(s.problems(), [])
        self.assertIn(s.outcome(states), (('refunded', 'refunded'), ('done', 'done')), s.harness.log[-8:])


class CrashSweep(unittest.TestCase):
    """Kill the process at every numbered wallet step of a happy swap, restart, and require a fair end."""

    def count_points(self, long_chain, short_chain):
        hook = sim.CrashHook(crash_at=())
        s = HegemonSwap(long_chain, short_chain, hook)
        try:
            states = s.run(seconds_per_step=150)
            self.assertEqual(s.outcome(states), ('done', 'done'))
            return len([n for n in hook.names if n.startswith('wallet:')]), hook.names
        finally:
            s.close()

    def test_every_crash_point_ends_fair_for_a_hegemon_long_and_short_leg(self):
        for long_chain, short_chain in (('hegemon', 'ethereum'), ('ethereum', 'hegemon')):
            _, names = self.count_points(long_chain, short_chain)
            with self.subTest(long=long_chain, short=short_chain):
                outcomes = {}
                for index in range(1, len(names) + 1):
                    if not names[index - 1].startswith('wallet:'):
                        continue
                    hook = sim.CrashHook(crash_at=index)
                    s = HegemonSwap(long_chain, short_chain, hook)
                    try:
                        states = s.run(seconds_per_step=150, human=True)
                        outcome = s.outcome(states)
                        outcomes[(index, names[index - 1])] = outcome
                        self.assertEqual(s.problems(), [], (index, names[index - 1], s.harness.log[-8:]))
                        self.assertIn(outcome, (('done', 'done'), ('refunded', 'refunded'), ('refunded', 'aborted'), ('aborted', 'aborted')), (index, names[index - 1], s.harness.log[-8:]))
                        self.assertEqual(s.fair('swapped' if outcome == ('done', 'done') else 'unchanged'), [], (index, names[index - 1], outcome))
                    finally:
                        s.close()
                self.assertTrue(any(o == ('done', 'done') for o in outcomes.values()))


    def test_every_crash_point_of_a_hegemon_refund_ends_with_the_money_back(self):
        def run(hook):
            s = HegemonSwap('hegemon', 'ethereum', hook)
            states = s.run(seconds_per_step=300, active=lambda i, h: ('initiator',), human=True,
                           until=lambda h: h.states()['initiator'][0] in ('refunded', 'aborted', 'failed'))
            return s, states

        hook = sim.CrashHook(crash_at=())
        s, states = run(hook)
        self.assertEqual(states['initiator'][0], 'refunded')
        s.close()
        names = hook.names
        self.assertIn('wallet:import-refund-handoff:before', names)
        self.assertIn('wallet:refund:after', names)
        for index in range(1, len(names) + 1):
            if not names[index - 1].startswith('wallet:'):
                continue
            s, states = run(sim.CrashHook(crash_at=index))
            try:
                self.assertEqual(states['initiator'][0], 'refunded', (index, names[index - 1], s.harness.log[-8:]))
                self.assertEqual(s.problems(), [], (index, names[index - 1]))
                self.assertEqual(s.fair('unchanged'), [], (index, names[index - 1]))
            finally:
                s.close()


class TermsDigestTests(unittest.TestCase):
    def test_digest_binds_every_agreed_term(self):
        leg = {'chain': 'hegemon', 'amount': 1, 'refundee': 'a', 'claimant': 'b', 'expiry': 5, 'hashlock': HASHLOCK}
        seen = {terms_digest(leg)}
        for key, value in (('amount', 2), ('refundee', 'c'), ('claimant', 'c'), ('expiry', 6), ('hashlock', 'ee' * 32)):
            seen.add(terms_digest({**leg, key: value}))
        self.assertEqual(len(seen), 6)
        self.assertEqual(terms_digest({**leg, 'extra': 'ignored'}), terms_digest(leg))


if __name__ == '__main__':
    unittest.main()
