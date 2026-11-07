import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from swap_engine import identity
from swap_engine.identity import IdentityError, verify_identity
from swap_engine.store import Store

VECTORS = json.loads((Path(__file__).resolve().parents[2] / 'config' / 'swap' / 'identity-vectors.json').read_text())
CASES = {c['name']: c for c in VECTORS['cases']}
PAIR = VECTORS['pairs'][0]


def verify(case, **override):
    expected = {**case['expected'], **override.pop('expected', {})}
    return verify_identity(override.pop('blob', case['blob']), expected, override.pop('now', case['now']), case.get('allow_local', False))


class IdentityVectorTests(unittest.TestCase):
    def test_every_independently_signed_vector_verifies(self):
        for case in VECTORS['cases']:
            with self.subTest(case['name']):
                result = verify(case)
                self.assertEqual(result['proven'], case['proven'])
                self.assertEqual(result['addresses'], case['addresses'])
                self.assertEqual(identity.statement_text(result['statement']), case['statement_text'])

    def test_official_bip322_vectors(self):
        for message, signature in VECTORS['bip322_official']['signatures'].items():
            self.assertEqual(identity._verify_bip322({'signature': signature}, message), VECTORS['bip322_official']['public_key'])
        with self.assertRaises(IdentityError):
            identity._verify_bip322({'signature': VECTORS['bip322_official']['signatures']['']}, 'Hello World')

    def test_hegemon_leg_is_never_proven(self):
        result = verify(CASES['owner-hegemon-pending-ada'])
        self.assertEqual(result['unverified'], ['give'])
        self.assertFalse(result['proven']['give'])

    def test_local_only_hegemon_address_is_refused_unless_allowed(self):
        case = CASES['owner-hegemon-local-ada']
        with self.assertRaisesRegex(IdentityError, 'local-only'):
            verify_identity(case['blob'], case['expected'], case['now'])
        result = verify(case)
        self.assertEqual((result['local_only'], result['unverified'], result['proven']['give']), (['give'], ['give'], False))
        self.assertEqual(verify(CASES['owner-hegemon-pending-ada'])['local_only'], [])
        value = json.loads(case['blob'])
        value['statement']['legs']['give']['refund'] = 'local:short'
        with self.assertRaises(IdentityError):
            verify(case, blob=json.dumps(value))

    def test_binding_failures(self):
        case = CASES['taker-btc-ada-cip8-enterprise']
        for override, text in (({'expected': {'give': {'chain': 'ethereum'}}}, 'give chain'), ({'expected': {'offer': 'ff' * 32}}, 'offer'),
                               ({'expected': {'inbox': 'ff' * 32}}, 'inbox'), ({'expected': {'reservation': 'ff' * 32}}, 'reservation'),
                               ({'expected': {'role': 'owner', 'reservation': ''}}, 'role'), ({'now': case['now'] + 7200}, 'expired'),
                               ({'now': case['now'] - 3600}, 'future')):
            with self.subTest(text), self.assertRaisesRegex(IdentityError, text):
                verify(case, **copy.deepcopy(override))

    def test_edited_statement_invalidates_proofs(self):
        for case in VECTORS['cases']:
            value = json.loads(case['blob'])
            value['statement']['nonce'] = '00' * 16
            with self.subTest(case['name']), self.assertRaises(IdentityError):
                verify(case, blob=json.dumps(value))

    def test_proof_rules(self):
        case = CASES['owner-btc-eth-eip191-bip322']
        value = json.loads(case['blob'])
        for mutate, text in ((lambda v: v.update(proofs=[]), 'no signature'), (lambda v: v.update(proofs=[v['proofs'][0]] * 2), 'Duplicate'),
                             (lambda v: v['proofs'][0].update(scheme='hmac'), 'Unsupported'), (lambda v: v.update(extra=1), 'Invalid identity')):
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.subTest(text), self.assertRaisesRegex(IdentityError, text):
                verify(case, blob=json.dumps(changed))
        with self.assertRaisesRegex(IdentityError, 'Invalid identity'):
            verify(case, blob='x' * 9000)


class AttachIdentitiesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.chmod(self.tmp.name, 0o700)
        self.store = Store(Path(self.tmp.name))
        self.owner = json.loads(PAIR['owner']['blob'])['statement']['legs']
        self.taker = json.loads(PAIR['taker']['blob'])['statement']['legs']

    def terms(self, **change):
        # Owner gives bitcoin (long), receives ethereum (short).
        legs = {'long': {'chain': 'bitcoin', 'amount': 1000, 'refundee': self.owner['give']['refund'], 'claimant': self.taker['give']['claim'], 'expiry': 900},
                'short': {'chain': 'ethereum', 'amount': 5, 'refundee': self.taker['receive']['refund'], 'claimant': self.owner['receive']['claim'], 'expiry': 800}}
        for path, value in change.items():
            name, field = path.split('__')
            legs[name][field] = value
        return {'version': 1, 'hashlock': hashlib.sha256(bytes(32)).hexdigest(), 'legs': legs}

    def create(self, terms):
        self.store.create('a' * 16, 'responder', terms, 1)
        return self.store.locked('a' * 16)

    def attach(self, swap, **override):
        owner = override.get('owner', PAIR['owner']['blob'])
        taker = override.get('taker', PAIR['taker']['blob'])
        return swap.attach_identities(owner, taker, PAIR['context'], override.get('give_leg', 'long'), PAIR['owner']['now'])

    def test_matching_terms_record_identities(self):
        with self.create(self.terms()) as swap:
            value = self.attach(swap)
            self.assertEqual(value['owner']['proven'], {'give': True, 'receive': False})
            self.assertEqual(value['taker']['proven'], {'give': True, 'receive': False})
            self.assertEqual(swap.record['identities'], value)
            self.assertEqual(self.attach(swap), value)
        with self.store.locked('a' * 16) as swap:
            self.assertEqual(swap.record['identities']['owner']['code'], value['owner']['code'])
            self.assertEqual(swap.record['history'][-1]['event'], 'identities_verified')

    def test_ethereum_comparison_ignores_case(self):
        with self.create(self.terms(short__claimant=self.owner['receive']['claim'].upper().replace('0X', '0x'))) as swap:
            self.attach(swap)

    def test_escrow_addresses_that_differ_from_the_identities_are_refused(self):
        other_key = '03' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        for field, value in (('long__claimant', other_key), ('long__refundee', other_key), ('short__claimant', '0x' + 'ee' * 20), ('short__refundee', '0x' + 'ee' * 20)):
            terms = self.terms(**{field: value})
            if os.path.exists(Path(self.tmp.name) / ('a' * 16)):
                import shutil
                shutil.rmtree(Path(self.tmp.name) / ('a' * 16))
            with self.subTest(field), self.create(terms) as swap, self.assertRaisesRegex(IdentityError, 'not the signed identity'):
                self.attach(swap)
            with self.store.locked('a' * 16) as swap:
                self.assertNotIn('identities', swap.record)

    def test_wrong_give_leg_and_other_identities_are_refused(self):
        with self.create(self.terms()) as swap:
            with self.assertRaisesRegex(IdentityError, 'different chain|different give chain|different receive chain'):
                self.attach(swap, give_leg='short')
            # A statement for another offer is refused outright.
            with self.assertRaises(IdentityError):
                self.attach(swap, owner=CASES['owner-hegemon-pending-ada']['blob'])
            self.attach(swap)
            # A different, equally valid statement does not replace the recorded one.
            with self.assertRaisesRegex(ValueError, 'already recorded'):
                self.attach(swap, owner=CASES['owner-btc-eth-eip191-bip322']['blob'])

    def test_local_hegemon_leg_must_name_the_local_identities(self):
        terms = self.terms()
        owner = verify_identity(PAIR['owner']['blob'], PAIR['owner']['expected'], PAIR['owner']['now'])
        taker = verify_identity(PAIR['taker']['blob'], PAIR['taker']['expected'], PAIR['taker']['now'])
        for who, side, address in ((owner, 'give', 'local:' + 'aa' * 16), (taker, 'give', 'local:' + 'bb' * 16)):
            who['statement']['legs'][side]['chain'] = 'hegemon'
            who['addresses'][side] = address
        for who in (owner, taker):
            who['statement']['legs']['receive']['chain'] = 'hegemon'
        owner['addresses']['receive'] = 'local:' + 'cc' * 16
        taker['addresses']['receive'] = 'local:' + 'dd' * 16
        for name in ('long', 'short'):
            terms['legs'][name]['chain'] = 'hegemon'
        # give leg (long): claimant is the taker's give address, refundee the owner's give address
        terms['legs']['long'].update(claimant='bb' * 16, refundee='aa' * 16)
        terms['legs']['short'].update(claimant='cc' * 16, refundee='dd' * 16)
        self.assertEqual(identity.check_terms(terms, owner, taker, 'long'), {'unverified': ['long', 'short'], 'local_only': ['long', 'short']})
        terms['legs']['short']['claimant'] = 'ee' * 16
        with self.assertRaisesRegex(IdentityError, 'local Hegemon identities'):
            identity.check_terms(terms, owner, taker, 'long')

    def test_hegemon_leg_is_reported_unverified(self):
        terms = self.terms()
        owner = verify_identity(PAIR['owner']['blob'], PAIR['owner']['expected'], PAIR['owner']['now'])
        taker = verify_identity(PAIR['taker']['blob'], PAIR['taker']['expected'], PAIR['taker']['now'])
        for side in ('give', 'receive'):
            owner['statement']['legs'][side]['chain'] = 'hegemon'
            taker['statement']['legs'][side]['chain'] = 'hegemon'
        for name in ('long', 'short'):
            terms['legs'][name]['chain'] = 'hegemon'
            terms['legs'][name]['claimant'] = 'anything'
            terms['legs'][name]['refundee'] = 'something'
        checked = identity.check_terms(terms, owner, taker, 'long')
        self.assertEqual((checked['unverified'], checked['local_only']), (['long', 'short'], []))


if __name__ == '__main__':
    unittest.main()
