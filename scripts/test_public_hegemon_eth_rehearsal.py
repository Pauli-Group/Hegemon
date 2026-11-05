import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import public_hegemon_eth_rehearsal as rehearsal
from test_public_hegemon_preimage_observer import action


class FakeRehearsal:
    """Offline fixtures; no node, wallet, provider or transaction is started."""
    def __init__(self, root):
        self.root = Path(root)
        self.work = self.root / 'hegemon-eth'
        self.secret = b'\x31' * 32
        self.chain = bytes.fromhex('21' * 32)
        self.actors = {'hgn_alice': 'alice-hgn', 'hgn_bob': 'bob-hgn',
                       'eth_alice': '0x' + '11' * 20, 'eth_bob': '0x' + '22' * 20}
        self.lock_attempt = 'aa' * 32
        self.claim_attempt = 'bb' * 32
        self.lock_id = '42' * 48
        self.claim_id = '43' * 48
        self.calls = []
        self.sends = []
        self.observed = 0
        self.invalid_note = False
        self.wrong_lock_block = False

    def status(self, name):
        phase = None
        if (self.work / 'state.json').exists():
            phase = json.loads((self.work / 'state.json').read_text())['phase']
        htlc = bool(phase and phase not in ('created', 'hgn_lock_prepare_inflight',
                         'hgn_lock_prepared', 'hgn_lock_export_inflight', 'hgn_lock_exported',
                         'hgn_lock_submit_inflight'))
        lines = ['ordinary position=5 value=500000' if name == 'alice'
                 else 'ordinary position=6 value=100000']
        if name == 'bob' and htlc:
            lines.append('htlc position=13 value=100000')
        if name == 'alice' and phase in ('refund_import_inflight', 'refund_ready', 'eth_lock_inflight',
                'eth_lock_submitted', 'both_verified', 'eth_claim_inflight', 'eth_claim_submitted',
                'hgn_claim_prepare_inflight', 'hgn_claim_prepared', 'hgn_claim_export_inflight',
                'hgn_claim_exported', 'hgn_claim_submit_inflight', 'hgn_claim_submitted', 'complete'):
            lines.append('htlc position=13 value=100000')
        if name == 'bob' and phase in ('hgn_claim_submitted', 'complete'):
            lines.append('ordinary position=30 value=100000')
        lines.append('balance synced_height=101 available_atoms=500000 available_notes=1 '
                     'reserved_atoms=0 reserved_notes=0 htlc_atoms=0 htlc_notes=0 watch_only=false')
        return '\n'.join(lines) + '\n'

    def wallet(self, root, binary, url, name, command, *, extra_prompts=()):
        operation = command[0]
        self.calls.append((name, operation))
        metrics = {'seconds': 3.5, 'peak_rss_kib': 1_000_000}
        if operation == 'address':
            return self.actors['hgn_' + name] + '\n', metrics
        if operation == 'status':
            return self.status(name), metrics
        if operation == 'lock':
            self.work.joinpath('refund.bin').write_bytes(b'encrypted-handoff')
            self.work.joinpath('refund.bin').chmod(0o600)
            return 'candidate ' + self.lock_attempt + '\n', metrics
        if operation == 'export':
            released = name == 'bob'
            raw = bytearray(action(self.secret, self.chain, released=released))
            raw[:48] = bytes.fromhex(self.claim_id if released else self.lock_id)
            path = Path(command[2])
            path.write_bytes(raw)
            path.chmod(0o600)
            return 'exported\n', metrics
        if operation == 'submit':
            return 'submitted ' + (self.lock_id if name == 'alice' else self.claim_id) + '\n', metrics
        if operation == 'verify-htlc':
            position = int(command[command.index('--locked') + 1])
            return json.dumps({'verified': not self.invalid_note, 'position': position,
                               'created_height': 100, 'confirmations': 2}) + '\n', metrics
        if operation == 'import-refund-handoff':
            return 'imported\n', metrics
        if operation == 'claim':
            assert bytes(extra_prompts[0][1]) == self.secret.hex().encode()
            return 'candidate ' + self.claim_attempt + '\n', metrics
        raise AssertionError(operation)

    def confirmed(self, url, status, attempt, path):
        is_lock = attempt == self.lock_attempt
        return {'action_id': self.lock_id if is_lock else self.claim_id,
                'block_height': 100 if is_lock else 102,
                'block_hash': '0x' + ('03' if self.wrong_lock_block and is_lock else '01') * 32,
                'confirmations': 2}

    def send(self, work, key, contract, value, data):
        self.sends.append((key.name, key.parent.name, contract, value))
        if contract is None:
            return {'txid': 'cc' * 32}
        return {'txid': 'dd' * 32}

    def observe(self, *args):
        self.observed += 1
        return bytearray(self.secret), {'confirmations': 2}

    def rpc(self, method, params):
        if method == 'eth_getBlockByNumber':
            return {'timestamp': hex(100_000), 'baseFeePerGas': '0x1'}
        if method == 'eth_maxPriorityFeePerGas':
            return '0x1'
        if method == 'eth_getBalance':
            return hex(10**18)
        raise AssertionError(method)

    def patches(self):
        node = {'height': 101, 'chain_id': '0x' + self.chain.hex()}
        return [patch.object(rehearsal, '_actors', return_value=self.actors),
                patch.object(rehearsal, '_wallet', side_effect=self.wallet),
                patch.object(rehearsal.hgn, 'ready', return_value=(node, {'matches': True})),
                patch.object(rehearsal.hgn, 'confirmed_action', side_effect=self.confirmed),
                patch.object(rehearsal, 'verify_network'),
                patch.object(rehearsal, 'ethereum_rpc', side_effect=self.rpc),
                patch.object(rehearsal, 'ethereum_send', side_effect=self.send),
                patch.object(rehearsal, 'verify_native', return_value={'confirmations': 2}),
                patch.object(rehearsal, '_receipt', return_value={'contractAddress': '0x' + '33' * 20}),
                patch.object(rehearsal, 'ethereum_claim', side_effect=self.observe),
                patch.object(rehearsal.secrets, 'token_bytes', return_value=self.secret)]


class PublicHegemonEthRehearsalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hegemon-eth-rehearsal-')
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.fake = FakeRehearsal(self.root)
        self.stack = []
        for item in self.fake.patches():
            item.start()
            self.stack.append(item)

    def tearDown(self):
        for item in reversed(self.stack):
            item.stop()
        self.temp.cleanup()

    def init(self):
        return rehearsal.initialize(self.root, '/fake/private-spend', 'http://127.0.0.1:9944')

    def advance(self):
        return rehearsal.advance(self.root, '/fake/private-spend', 'http://127.0.0.1:9944')

    def advance_until(self, phase):
        for _ in range(20):
            if self.advance()['phase'] == phase:
                return
        self.fail('phase not reached: ' + phase)

    def test_full_staged_rehearsal_uses_confirmed_ethereum_preimage(self):
        self.assertEqual(self.init()['phase'], 'created')
        phases = [self.advance()['phase'] for _ in range(12)]
        self.assertEqual(phases, ['hgn_lock_prepared', 'hgn_lock_exported', 'hgn_lock_submitted',
                         'hgn_lock_confirmed', 'refund_ready', 'eth_lock_submitted', 'both_verified',
                         'eth_claim_submitted', 'hgn_claim_prepared', 'hgn_claim_exported',
                         'hgn_claim_submitted', 'complete'])
        self.assertEqual(self.fake.observed, 2)
        self.assertEqual(self.fake.sends[0][1], 'bob')
        self.assertEqual(self.fake.sends[1][1], 'alice')
        self.assertEqual([call for call in self.fake.calls if call[1] == 'submit'],
                         [('alice', 'submit'), ('bob', 'submit')])
        state = json.loads((self.root / 'hegemon-eth/state.json').read_text())
        self.assertEqual(state['hashlock'], hashlib.sha256(self.fake.secret).hexdigest())
        self.assertNotIn(self.fake.secret.hex(), json.dumps(state))
        self.assertEqual((self.root / 'hegemon-eth/secret').stat().st_mode & 0o077, 0)
        self.assertEqual(state['proofs']['hgn_claim']['peak_rss_kib'], 1_000_000)

    def test_hgn_preparation_failure_is_never_automatically_retried(self):
        self.init()
        original = self.fake.wallet
        def fail_lock(*args, **kwargs):
            if args[4][0] == 'lock':
                raise TimeoutError('lost wallet result')
            return original(*args, **kwargs)
        with patch.object(rehearsal, '_wallet', side_effect=fail_lock):
            with self.assertRaises(TimeoutError):
                self.advance()
            with self.assertRaisesRegex(ValueError, 'Uncertain action'):
                self.advance()
        self.assertEqual(rehearsal._state(self.root / 'hegemon-eth')['phase'], 'hgn_lock_prepare_inflight')

    def test_lost_ethereum_submission_is_not_retried(self):
        self.init()
        self.advance_until('refund_ready')
        with patch.object(rehearsal, 'ethereum_send', side_effect=TimeoutError('lost')) as send:
            with self.assertRaises(TimeoutError):
                self.advance()
            with self.assertRaisesRegex(ValueError, 'Uncertain action'):
                self.advance()
            self.assertEqual(send.call_count, 1)

    def test_wrong_htlc_stops_before_ethereum_funding(self):
        self.init()
        self.advance_until('refund_ready')
        self.fake.invalid_note = True
        with self.assertRaisesRegex(ValueError, 'verification'):
            self.advance()
        self.assertEqual(self.fake.sends, [])
        self.assertEqual(rehearsal._state(self.root / 'hegemon-eth')['phase'], 'refund_ready')
        self.assertIn(('alice', 'import-refund-handoff'), self.fake.calls)

    def test_reorg_stops_before_ethereum_funding(self):
        self.init()
        self.advance_until('refund_ready')
        self.fake.wrong_lock_block = True
        with self.assertRaisesRegex(ValueError, 'canonical'):
            self.advance()
        self.assertEqual(self.fake.sends, [])

    def test_refund_handoff_is_imported_before_ethereum_lock(self):
        self.init()
        self.advance_until('eth_lock_submitted')
        self.assertIn(('alice', 'import-refund-handoff'), self.fake.calls)
        self.assertTrue((self.root / 'hegemon-eth/refund.bin').exists())

    def test_unconfirmed_ethereum_claim_does_not_start_hegemon_claim(self):
        self.init()
        self.advance_until('eth_claim_submitted')
        with patch.object(rehearsal, '_receipt', return_value=None):
            self.assertEqual(self.advance(), {'phase': 'eth_claim_submitted', 'pending': True})
        self.assertEqual(self.fake.observed, 0)
        self.assertNotIn(('bob', 'claim'), self.fake.calls)

    def test_wrong_ethereum_escrow_stops_before_secret_disclosure(self):
        self.init()
        self.advance_until('eth_lock_submitted')
        with patch.object(rehearsal, 'verify_native', side_effect=ValueError('wrong terms')):
            with self.assertRaisesRegex(ValueError, 'wrong terms'):
                self.advance()
        self.assertEqual(len(self.fake.sends), 1)
        self.assertEqual(rehearsal._state(self.root / 'hegemon-eth')['phase'], 'eth_lock_submitted')

    def test_ethereum_claim_is_rechecked_before_marking_swap_complete(self):
        self.init()
        self.advance_until('hgn_claim_submitted')
        with patch.object(rehearsal, '_receipt', return_value=None):
            with self.assertRaisesRegex(ValueError, 'no longer'):
                self.advance()
        self.assertEqual(rehearsal._state(self.root / 'hegemon-eth')['phase'], 'hgn_claim_submitted')

    def test_short_ethereum_deadline_stops_before_secret_disclosure(self):
        self.init()
        self.advance_until('both_verified')
        with patch.object(rehearsal, 'ethereum_rpc', return_value={'timestamp': hex(200_000)}):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                self.advance()
        self.assertEqual(len(self.fake.sends), 1)

    def test_reserved_or_undersized_fee_notes_are_rejected(self):
        status = ('ordinary position=1 value=1000\n'
                  'balance synced_height=100 available_atoms=1000 available_notes=1 '
                  'reserved_atoms=0 reserved_notes=0 htlc_atoms=0 htlc_notes=0 watch_only=false\n')
        self.assertEqual(rehearsal._single_note(status, 1000), 1)
        with self.assertRaisesRegex(ValueError, 'reserved'):
            rehearsal._single_note(status.replace('reserved_notes=0', 'reserved_notes=1'), 1000)
        with self.assertRaisesRegex(ValueError, 'funded'):
            rehearsal._single_note(status, 1001)

    def test_alice_lock_input_keeps_a_refund_fee_in_change(self):
        almost = rehearsal.HGN_AMOUNT + rehearsal.HGN_FEE
        status = (f'ordinary position=1 value={almost}\n'
                  f'balance synced_height=100 available_atoms={almost} available_notes=1 '
                  'reserved_atoms=0 reserved_notes=0 htlc_atoms=0 htlc_notes=0 watch_only=false\n')
        with self.assertRaisesRegex(ValueError, 'funded'):
            rehearsal._single_note(status, rehearsal.HGN_AMOUNT + 2 * rehearsal.HGN_FEE)

    def test_wrong_carrier_and_unexpected_secret_release_are_rejected(self):
        self.init()
        self.advance_until('hgn_lock_exported')
        work = self.root / 'hegemon-eth'
        state = rehearsal._state(work)
        original = (work / 'lock.action').read_bytes()
        wrong = bytearray(original)
        offset = wrong.index(b'HGPSLC02')
        wrong[offset + 24] ^= 1
        (work / 'lock.action').write_bytes(wrong)
        with self.assertRaisesRegex(ValueError, 'carrier'):
            rehearsal._validate_export(work, 'lock.action', state, releasing=False)
        wrong = bytearray(original)
        wrong[offset + 528:offset + 536] = (1).to_bytes(8, 'little')
        (work / 'lock.action').write_bytes(wrong)
        with self.assertRaisesRegex(ValueError, 'secret release'):
            rehearsal._validate_export(work, 'lock.action', state, releasing=False)


if __name__ == '__main__':
    unittest.main()
