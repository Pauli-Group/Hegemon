import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import public_hegemon_wallet as wallet


class PublicHegemonWalletTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='hegemon-public-wallet-')
        self.root = Path(self.directory.name)
        os.chmod(self.root, 0o700)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, name, content, mode=0o600):
        path = self.root / name
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def test_private_files_must_be_owned_private_and_not_symlinks(self):
        path = self.write('pass', b'private phrase\n')
        self.assertEqual(wallet._private_read(path, 100), b'private phrase\n')
        value = wallet._password(path)
        self.assertEqual(value, b'private phrase')
        value[:] = b'\0' * len(value)
        link = self.root / 'link'
        link.symlink_to(path)
        with self.assertRaises(OSError):
            wallet._private_read(link, 100)
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'private'):
            wallet._private_read(path, 100)
        with self.assertRaisesRegex(ValueError, 'private'):
            wallet._check_private_wallet(path)

    def test_pinned_binary_and_loopback_node_are_checked_before_wallet_execution(self):
        binary = self.write('fake-wallet', b'not an official release', 0o700)
        store = self.write('alice.wallet', b'encrypted-wallet')
        phrase = self.write('alice.pass', b'test-passphrase\n')
        with patch.object(wallet, 'ready') as ready:
            with self.assertRaisesRegex(ValueError, 'pinned'):
                wallet.wallet(binary, store, phrase, 'http://127.0.0.1:9944', ['status'])
            ready.assert_not_called()
        for url in ('http://example.com:9944', 'http://127.0.0.1:9944/path'):
            with self.assertRaises(ValueError):
                wallet.ready(url)

    def test_wallet_uses_release_manifest_and_clears_passphrase(self):
        binary = self.write('wallet-bin', b'dummy', 0o700)
        store = self.write('alice.wallet', b'encrypted-wallet')
        phrase = self.write('alice.pass', b'test-passphrase\n')
        captured = {}
        def execute(path, args, prompts, *, timeout):
            captured.update(path=path, args=args, secret=prompts[0][1], timeout=timeout)
            return 'ordinary position=7 value=9\n', {'seconds': 1, 'peak_rss_kib': 100}
        with patch.object(wallet, 'check_binary', return_value=binary), \
             patch.object(wallet, 'ready', return_value=({'genesis': '0x' + '11' * 32}, {})), \
             patch.object(wallet, '_execute', side_effect=execute):
            out, metrics = wallet.wallet(binary, store, phrase, 'http://127.0.0.1:9944', ['status'])
        self.assertEqual(wallet.notes(out, 'ordinary'), [(7, 9)])
        self.assertEqual(captured['secret'], bytearray(len('test-passphrase')))
        self.assertIn(str(wallet.MANIFEST), captured['args'])
        self.assertNotIn('--development-local-candidate', captured['args'])
        self.assertGreater(metrics['peak_rss_kib'], 0)

    def make_prompt_executable(self):
        return self.write('prompt.py', b'''#!/usr/bin/env python3
import sys, time
print("Encrypted wallet passphrase: ", end="", flush=True)
first = sys.stdin.readline().rstrip("\\n")
print("Other secret: ", end="", flush=True)
second = sys.stdin.readline().rstrip("\\n")
if sys.argv[1] == "leak":
    print(first)
elif sys.argv[1] == "hang":
    time.sleep(20)
else:
    print("ordinary position=1 value=42")
''', 0o700)

    def test_private_pty_prompts_are_not_echoed_and_metrics_are_measured(self):
        program = self.make_prompt_executable()
        phrase = bytearray(b'wallet-secret-1234')
        other = bytearray(b'claim-secret-5678')
        output, metrics = wallet._execute(program, ['ok'], [(wallet.PASS_PROMPT, phrase),
                                                           (b'Other secret: ', other)], timeout=5)
        self.assertIn('ordinary position=1 value=42', output)
        self.assertNotIn(phrase.decode(), output)
        self.assertNotIn(other.decode(), output)
        self.assertGreater(metrics['peak_rss_kib'], 0)

    def test_private_pty_rejects_echo_and_kills_timed_out_process(self):
        program = self.make_prompt_executable()
        prompts = [(wallet.PASS_PROMPT, bytearray(b'wallet-secret-1234')),
                   (b'Other secret: ', bytearray(b'claim-secret-5678'))]
        with self.assertRaisesRegex(wallet.WalletCommandError, 'private input'):
            wallet._execute(program, ['leak'], prompts, timeout=5)
        with self.assertRaises(TimeoutError):
            wallet._execute(program, ['hang'], prompts, timeout=0.3)

    def test_unready_nodes_are_rejected(self):
        with patch.object(wallet, 'probe', return_value={'basic_wallet_checks_passed': False}), \
             patch.object(wallet, 'compare_public_tip') as compare:
            with self.assertRaisesRegex(ValueError, 'not ready'):
                wallet.ready('http://127.0.0.1:9944')
            compare.assert_not_called()
        with patch.object(wallet, 'probe', return_value={'basic_wallet_checks_passed': True}), \
             patch.object(wallet, 'compare_public_tip', return_value={'matches': False}):
            with self.assertRaisesRegex(ValueError, 'do not match'):
                wallet.ready('http://127.0.0.1:9944')

    def test_note_and_attempt_parsing_rejects_ambiguity(self):
        attempt = 'ab' * 32
        status = ('ordinary position=3 value=100\nhtlc position=8 value=10\n'
                  + attempt + ' Submitted([1]) mined=Some((100, [' + ', '.join(['1'] * 32) + ']))\n')
        self.assertEqual(wallet.notes(status, 'ordinary'), [(3, 100)])
        self.assertEqual(wallet.notes(status, 'htlc'), [(8, 10)])
        self.assertEqual(wallet.attempt_inclusion(status, attempt), (100, '0x' + '01' * 32))
        self.assertIsNone(wallet.attempt_inclusion(attempt + ' Ready mined=None\n', attempt))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            wallet.notes(status + 'ordinary position=3 value=101\n', 'ordinary')
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            wallet.attempt_inclusion(status + status, attempt)
        with self.assertRaisesRegex(ValueError, 'inclusion'):
            wallet.attempt_inclusion(attempt + ' Submitted mined=Some((100, [1, 2]))\n', attempt)

    def test_balance_reports_reservations_and_rejects_malformed_fields(self):
        line = ('balance synced_height=100 available_atoms=90 available_notes=1 '
                'reserved_atoms=10 reserved_notes=1 htlc_atoms=4 htlc_notes=1 watch_only=false\n')
        result = wallet.balance(line)
        self.assertEqual(result['reserved_notes'], 1)
        self.assertFalse(result['watch_only'])
        with self.assertRaises(ValueError):
            wallet.balance(line + line)
        with self.assertRaises(ValueError):
            wallet.balance(line.replace('reserved_notes=1', 'reserved_notes=-1'))
        with self.assertRaises(ValueError):
            wallet.balance(line.replace('watch_only=false', 'watch_only=yes'))

    def test_confirmed_action_checks_exact_bytes_and_canonical_anchors(self):
        action = b'\x42' * 48 + b'\x01' * 128
        path = self.write('lock.action', action)
        attempt = 'ab' * 32
        status = attempt + ' Submitted mined=Some((100, [' + ', '.join(['1'] * 32) + ']))\n'
        node = {'height': 101}
        expected = '0x' + '01' * 32
        anchor = '0x' + '02' * 32
        def rpc(url, method, params):
            self.assertEqual(method, 'chain_getBlockHash')
            return expected if params == [100] else anchor
        with patch.object(wallet, 'ready', return_value=(node, {})), \
             patch.object(wallet, 'rpc', side_effect=rpc), \
             patch.object(wallet, 'canonical_body', return_value=([action], {'height': 100}, b'')):
            result = wallet.confirmed_action('http://127.0.0.1:9944', status, attempt, path)
        self.assertEqual(result['action_id'], '42' * 48)
        self.assertEqual(result['confirmations'], 2)

        with patch.object(wallet, 'ready', return_value=(node, {})), \
             patch.object(wallet, 'rpc', side_effect=rpc), \
             patch.object(wallet, 'canonical_body', return_value=([action, action], {'height': 100}, b'')):
            with self.assertRaisesRegex(ValueError, 'duplicated'):
                wallet.confirmed_action('http://127.0.0.1:9944', status, attempt, path)

        calls = 0
        def reorganized(url, method, params):
            nonlocal calls
            if params == [100]:
                calls += 1
                return expected if calls == 1 else '0x' + '03' * 32
            return anchor
        with patch.object(wallet, 'ready', return_value=(node, {})), \
             patch.object(wallet, 'rpc', side_effect=reorganized), \
             patch.object(wallet, 'canonical_body', return_value=([action], {'height': 100}, b'')):
            with self.assertRaisesRegex(ValueError, 'changed'):
                wallet.confirmed_action('http://127.0.0.1:9944', status, attempt, path)

    def test_unconfirmed_action_does_not_fetch_or_return_action(self):
        action = self.write('lock.action', b'\x42' * 48 + b'\x01' * 128)
        attempt = 'ab' * 32
        with patch.object(wallet, 'ready') as ready:
            self.assertIsNone(wallet.confirmed_action('http://127.0.0.1:9944',
                              attempt + ' Ready mined=None\n', attempt, action))
            ready.assert_not_called()
        status = attempt + ' Submitted mined=Some((100, [' + ', '.join(['1'] * 32) + ']))\n'
        with patch.object(wallet, 'ready', return_value=({'height': 100}, {})), \
             patch.object(wallet, 'canonical_body') as body:
            self.assertIsNone(wallet.confirmed_action('http://127.0.0.1:9944', status, attempt, action))
            body.assert_not_called()


if __name__ == '__main__':
    unittest.main()
