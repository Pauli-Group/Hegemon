import contextlib
import hashlib
import io
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import public_hegemon_preimage_observer as observer
import watch_public_hegemon_preimage as watch
from check_native_asset_lifecycle import AcceptanceError
from hegemon_preimage_observer import IDENTITY
from unlock_swap_backup import unlock_backup


def compact(value):
    if value < 64:
        return bytes([value << 2])
    if value < 16384:
        return ((value << 2) | 1).to_bytes(2, 'little')
    return ((value << 2) | 2).to_bytes(4, 'little')


def action(secret, chain, *, released=True):
    carrier = bytearray(5788)
    carrier[:8] = b'HGPSLC02'
    carrier[8:24] = IDENTITY
    carrier[24:72] = bytes.fromhex(observer.RELATION[:96])
    carrier[72:104] = chain
    carrier[528:536] = int(released).to_bytes(8, 'little')
    if released:
        carrier[536:568] = secret
    carrier[5784:5788] = b'SMZL'
    header = bytearray(104)
    header[:48] = b'\x42' * 48
    for index, value in zip((48, 50, 52, 54), (12, 7, 1, 15)):
        header[index:index + 2] = value.to_bytes(2, 'little')
    vectors = compact(0) + compact(0) + compact(2) + bytes(96) + compact(2) + bytes(8)
    return bytes(header) + vectors + compact(len(carrier)) + bytes(carrier) + bytes(9)


class Clock:
    def __init__(self):
        self.value = 0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class PublicHegemonObserverTest(unittest.TestCase):
    def setUp(self):
        self.secret = b'\x31' * 32
        self.action_id = '42' * 48
        self.hashlock = hashlib.sha256(self.secret).hexdigest()
        self.chain = bytes.fromhex('21' * 32)
        self.node = {'height': 101, 'chain_id': '0x' + self.chain.hex(),
                     'peers': 8, 'syncing': False, 'private_spend_parameters_match': True,
                     'missing_wallet_methods': ['hegemon_submitAction']}
        self.reference = {'matches': True, 'reference_height': 101}
        self.clock = Clock()
        self.action = action(self.secret, self.chain)
        self.calls = []

    @staticmethod
    def hash_at(height):
        return '0x' + format(height, '064x')

    def rpc(self, url, method, params):
        self.assertEqual(method, 'chain_getBlockHash')
        self.calls.append(params[0])
        return self.hash_at(params[0])

    def body(self, url, block_hash):
        number = int(block_hash, 16)
        return ([self.action] if number == 100 else []), {'height': number}, b''

    def observe(self, **overrides):
        args = {'action_id': self.action_id, 'hashlock': self.hashlock,
                'start_height': 100, 'confirmations': 2,
                'timeout': 2, '_clock': self.clock.now, '_sleep': self.clock.sleep}
        args.update(overrides)
        return observer.observe_public_hegemon_preimage('http://127.0.0.1:9944', **args)

    def test_confirmed_hash_bound_release_from_read_only_node(self):
        with patch.object(observer, 'probe', return_value=self.node), \
             patch.object(observer, 'compare_public_tip', return_value=self.reference) as reference, \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body):
            secret, snapshot = self.observe()
        try:
            self.assertEqual(secret, self.secret)
            self.assertEqual(snapshot['block_height'], 100)
            self.assertEqual(snapshot['confirmations'], 2)
            self.assertEqual(reference.call_count, 2)
            self.assertNotIn(self.secret.hex(), json.dumps(snapshot))
        finally:
            secret[:] = b'\0' * len(secret)

    def test_hashlock_scan_returns_a_confirmed_release_and_none_when_absent(self):
        with patch.object(observer, 'probe', return_value=self.node), \
             patch.object(observer, 'compare_public_tip', return_value=self.reference), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body):
            secret, snapshot = observer.scan_public_hegemon_preimage(
                'http://127.0.0.1:9944', hashlock=self.hashlock, start_height=100,
                confirmations=2, timeout=2, _clock=self.clock.now, _sleep=self.clock.sleep)
        try:
            self.assertEqual(secret, self.secret)
            self.assertEqual(snapshot['block_height'], 100)
            self.assertEqual(snapshot['action_id'], self.action_id)
        finally:
            secret[:] = b'\0' * len(secret)
        self.clock = Clock()
        with patch.object(observer, '_snapshot',
                          return_value=(dict(self.node, height=100), self.reference)), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body):
            self.assertIsNone(observer.scan_public_hegemon_preimage(
                'http://127.0.0.1:9944', hashlock=self.hashlock, start_height=100,
                confirmations=2, timeout=0.05, _clock=self.clock.now, _sleep=self.clock.sleep))

    def test_unready_nodes_and_public_reference_are_rejected(self):
        for change in ({'syncing': True}, {'peers': 0}, {'peers': True},
                       {'private_spend_parameters_match': False},
                       {'missing_wallet_methods': ['chain_getBlockActionsChunk']}):
            with self.subTest(change=change), \
                 patch.object(observer, 'probe', return_value=dict(self.node, **change)), \
                 patch.object(observer, 'compare_public_tip') as reference:
                with self.assertRaisesRegex(ValueError, 'not ready'):
                    observer._snapshot('http://127.0.0.1:9944')
                reference.assert_not_called()
        with patch.object(observer, 'probe', return_value=self.node), \
             patch.object(observer, 'compare_public_tip', return_value={'matches': False}):
            with self.assertRaisesRegex(ValueError, 'reference did not match'):
                observer._snapshot('http://127.0.0.1:9944')
        with patch.object(observer, 'probe', return_value=self.node), \
             patch.object(observer, 'compare_public_tip', side_effect=ValueError('stale reference')):
            with self.assertRaisesRegex(ValueError, 'stale reference'):
                observer._snapshot('http://127.0.0.1:9944')

    def test_unconfirmed_or_nonmatching_claim_never_returns_secret(self):
        with patch.object(observer, '_snapshot',
                          return_value=(dict(self.node, height=100), self.reference)), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body) as body:
            with self.assertRaises(TimeoutError):
                self.observe()
            body.assert_not_called()
        self.clock = Clock()
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body):
            with self.assertRaisesRegex(ValueError, 'did not release the expected preimage'):
                self.observe(hashlock='00' * 32)

    def test_matching_preimage_in_a_different_action_is_not_observed(self):
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body), \
             patch.object(observer, 'released_preimage') as release:
            with self.assertRaises(TimeoutError):
                self.observe(action_id='ab' * 48)
            release.assert_not_called()

    def test_expected_action_without_release_is_rejected(self):
        self.action = action(self.secret, self.chain, released=False)
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body):
            with self.assertRaisesRegex(ValueError, 'did not release the expected preimage'):
                self.observe()

    def test_expected_action_with_wrong_family_is_rejected(self):
        wrong = bytearray(self.action)
        wrong[48:50] = (11).to_bytes(2, 'little')
        self.action = bytes(wrong)
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body):
            with self.assertRaisesRegex(ValueError, 'not a private spend'):
                self.observe()

    def test_scan_has_a_total_resource_bound(self):
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', return_value=([], {'height': 100}, b'x' * 9)), \
             patch.object(observer, 'MAX_SCAN_BYTES', 8):
            with self.assertRaisesRegex(ValueError, 'resource bound'):
                self.observe()

    def test_timeout_during_final_reference_check_clears_secret(self):
        candidate = bytearray(self.secret)
        count = 0
        def snapshots(_url):
            nonlocal count
            count += 1
            if count == 2:
                self.clock.value = 3
            return self.node, self.reference
        with patch.object(observer, '_snapshot', side_effect=snapshots), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body), \
             patch.object(observer, 'released_preimage', return_value=candidate):
            with self.assertRaises(TimeoutError):
                self.observe()
        self.assertEqual(candidate, bytearray(32))

    def test_timeout_during_final_block_checks_clears_secret(self):
        candidate = bytearray(self.secret)
        counts = {100: 0}
        def slow_rpc(url, method, params):
            if params[0] == 100:
                counts[100] += 1
                if counts[100] == 3:
                    self.clock.value = 3
            return self.hash_at(params[0])
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=slow_rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body), \
             patch.object(observer, 'released_preimage', return_value=candidate):
            with self.assertRaises(TimeoutError):
                self.observe()
        self.assertEqual(candidate, bytearray(32))

    def test_reorganization_clears_candidate_secret(self):
        candidate = bytearray(self.secret)
        calls = {100: 0}
        def changing_rpc(url, method, params):
            height = params[0]
            if height == 100:
                calls[100] += 1
                if calls[100] > 1:
                    return self.hash_at(999)
            return self.hash_at(height)
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=changing_rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body), \
             patch.object(observer, 'released_preimage', return_value=candidate):
            with self.assertRaisesRegex(ValueError, 'changed during observation'):
                self.observe()
        self.assertEqual(candidate, bytearray(32))

    def test_reorganization_of_scanned_checkpoint_is_rejected(self):
        self.action = action(self.secret, self.chain, released=False)
        seen = 0
        def changing_rpc(url, method, params):
            nonlocal seen
            if params[0] == 100:
                seen += 1
                if seen > 1:
                    return self.hash_at(999)
            return self.hash_at(params[0])
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=changing_rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body):
            with self.assertRaisesRegex(ValueError, 'reorganized'):
                self.observe(action_id='ab' * 48)

    def test_wrong_source_relation_and_malformed_action_are_rejected(self):
        wrong = bytearray(self.action)
        offset = wrong.index(b'HGPSLC02')
        wrong[offset + 24] ^= 1
        self.action = bytes(wrong)
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body):
            with self.assertRaisesRegex(ValueError, 'invalid private-spend carrier'):
                self.observe()
        self.action = self.action[:-1]
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body):
            with self.assertRaisesRegex(AcceptanceError, 'framing mismatch'):
                self.observe()

    def test_wrong_chain_carrier_is_rejected(self):
        self.action = action(self.secret, bytes.fromhex('22' * 32))
        with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)), \
             patch.object(observer, 'rpc', side_effect=self.rpc), \
             patch.object(observer, 'canonical_body', side_effect=self.body):
            with self.assertRaisesRegex(ValueError, 'invalid private-spend carrier'):
                self.observe()

    def test_invalid_inputs_are_rejected_before_network(self):
        for change in ({'action_id': 'x' * 96}, {'hashlock': 'x' * 64},
                       {'start_height': 0}, {'confirmations': 1},
                       {'timeout': float('nan')}, {'timeout': 3601}):
            with self.subTest(change=change), patch.object(observer, 'probe') as probe:
                with self.assertRaises(ValueError):
                    self.observe(**change)
                probe.assert_not_called()
        with self.assertRaises(ValueError):
            observer.observe_public_hegemon_preimage('http://example.com:9944',
                                                     action_id=self.action_id,
                                                     hashlock=self.hashlock, start_height=100)

    def test_real_loopback_rpc_and_canonical_action_framing(self):
        raw = self.action
        payload = compact(1) + compact(len(raw)) + raw
        block_hash = self.hash_at(100)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers['content-length'])))
                if data['method'] == 'chain_getBlockHash':
                    result = PublicHegemonObserverTest.hash_at(data['params'][0])
                elif data['method'] == 'chain_getBlockActionsChunk':
                    result = {'schema': 'hegemon.native.action-body-chunk-v1',
                              'height': 100, 'parent_hash': '0x' + '10' * 32,
                              'tx_count': 1, 'extrinsics_root': '0x' + '20' * 32,
                              'action_body_hash': '0x' + '30' * 32,
                              'action_body_len': len(payload), 'chunk_count': 1,
                              'chunk_index': 0, 'block_hash': block_hash,
                              'chunk': '0x' + payload.hex(), 'chunk_len': len(payload)}
                else:
                    raise AssertionError('unexpected method')
                body = json.dumps({'jsonrpc': '2.0', 'id': data['id'], 'result': result}).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(observer, '_snapshot', return_value=(self.node, self.reference)):
                secret, snapshot = observer.observe_public_hegemon_preimage(
                    f'http://127.0.0.1:{server.server_port}', action_id=self.action_id,
                    hashlock=self.hashlock,
                    start_height=100, confirmations=2, timeout=10)
            try:
                self.assertEqual(secret, self.secret)
                self.assertEqual(snapshot['block_hash'], block_hash)
            finally:
                secret[:] = b'\0' * len(secret)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_backup_cli_does_not_print_secret_and_clears_buffers(self):
        secret = bytearray(self.secret)
        captured = {}
        def save(directory, secret_arg, phrase_arg, label):
            captured['secret'] = secret_arg
            captured['phrase'] = phrase_arg
            return '/private/encrypted-backup.json'
        argv = ['watch', '--hegemon-rpc', 'http://127.0.0.1:9944',
                '--action-id', self.action_id, '--hashlock', self.hashlock,
                '--start-height', '100', '--output-dir', '/private']
        output = io.StringIO()
        with patch.object(sys, 'argv', argv), patch.object(watch.os, 'isatty', return_value=True), \
             patch.object(watch.os, 'umask'), \
             patch.object(watch, 'observe_public_hegemon_preimage',
                          return_value=(secret, {'block_height': 100})), \
             patch.object(watch.getpass, 'getpass', side_effect=['strong-passphrase', 'strong-passphrase']), \
             patch.object(watch, 'save_recovered_backup', side_effect=save), \
             contextlib.redirect_stdout(output):
            watch.main()
        self.assertNotIn(self.secret.hex(), output.getvalue())
        self.assertNotIn('strong-passphrase', output.getvalue())
        self.assertIn('does not establish that the action spent your intended HTLC', output.getvalue())
        self.assertEqual(captured['secret'], bytearray(32))
        self.assertEqual(captured['phrase'], bytearray(len('strong-passphrase')))

    def test_backup_cli_creates_a_private_recoverable_encrypted_backup(self):
        secret = bytearray(self.secret)
        with tempfile.TemporaryDirectory(prefix='hegemon-public-backup-') as directory:
            argv = ['watch', '--hegemon-rpc', 'http://127.0.0.1:9944',
                    '--action-id', self.action_id, '--hashlock', self.hashlock,
                    '--start-height', '100', '--output-dir', directory]
            output = io.StringIO()
            with patch.object(sys, 'argv', argv), patch.object(watch.os, 'isatty', return_value=True), \
                 patch.object(watch.os, 'umask'), \
                 patch.object(watch, 'observe_public_hegemon_preimage',
                              return_value=(secret, {'block_height': 100})), \
                 patch.object(watch.getpass, 'getpass', side_effect=['strong-passphrase', 'strong-passphrase']), \
                 contextlib.redirect_stdout(output):
                watch.main()
            result = json.loads(output.getvalue().splitlines()[-1])
            path = Path(result['saved'])
            self.assertEqual(path.parent, Path(directory))
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            self.assertNotIn(self.secret.hex(), path.read_text())
            recovered = unlock_backup(path, b'strong-passphrase')
            try:
                self.assertEqual(recovered, self.secret)
            finally:
                recovered[:] = b'\0' * len(recovered)
            self.assertEqual(secret, bytearray(32))

    def test_backup_cli_rejects_noninteractive_use_before_observation(self):
        argv = ['watch', '--hegemon-rpc', 'http://127.0.0.1:9944',
                '--action-id', self.action_id, '--hashlock', self.hashlock,
                '--start-height', '100', '--output-dir', '/private']
        with patch.object(sys, 'argv', argv), patch.object(watch.os, 'isatty', return_value=False), \
             patch.object(watch.os, 'umask'), \
             patch.object(watch, 'observe_public_hegemon_preimage') as observe, \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                watch.main()
            observe.assert_not_called()

    def test_backup_cli_rejects_mismatched_passphrases_and_clears_secret(self):
        secret = bytearray(self.secret)
        argv = ['watch', '--hegemon-rpc', 'http://127.0.0.1:9944',
                '--action-id', self.action_id, '--hashlock', self.hashlock,
                '--start-height', '100', '--output-dir', '/private']
        with patch.object(sys, 'argv', argv), patch.object(watch.os, 'isatty', return_value=True), \
             patch.object(watch.os, 'umask'), \
             patch.object(watch, 'observe_public_hegemon_preimage',
                          return_value=(secret, {'block_height': 100})), \
             patch.object(watch.getpass, 'getpass', side_effect=['strong-passphrase', 'different-passphrase']), \
             patch.object(watch, 'save_recovered_backup') as save, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'passphrases must match'):
                watch.main()
            save.assert_not_called()
        self.assertEqual(secret, bytearray(32))


if __name__ == '__main__':
    unittest.main()
