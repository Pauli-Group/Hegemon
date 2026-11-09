import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from swap_engine import store as store_module
from swap_engine.store import Store, journal_ids, terms_digest, validate_terms

PREIMAGE = bytes(range(32))
HASHLOCK = hashlib.sha256(PREIMAGE).hexdigest()


def terms():
    return {'version': 1, 'hashlock': HASHLOCK, 'legs': {
        'long': {'chain': 'ethereum', 'amount': 5, 'refundee': 'a@eth', 'claimant': 'b@eth', 'expiry': 9000},
        'short': {'chain': 'cardano', 'amount': 7, 'refundee': 'b@ada', 'claimant': 'a@ada', 'expiry': 8000}}}


def private(path):
    os.chmod(path, 0o700)
    return Path(path)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = private(self.tmp.name)
        self.store = Store(self.root / 'swaps')

    def make(self, role='initiator'):
        self.store.create('0123456789abcdef', role, terms(), 100, PREIMAGE if role == 'initiator' else None)
        return '0123456789abcdef'

    def test_layout_and_modes(self):
        swap_id = self.make()
        directory = self.root / 'swaps' / swap_id
        self.assertEqual(oct(directory.stat().st_mode & 0o777), '0o700')
        for name in ('record.json', 'terms.json', 'secret'):
            self.assertEqual(oct((directory / name).stat().st_mode & 0o777), '0o600', name)
        self.assertEqual(oct((directory / 'journal').stat().st_mode & 0o777), '0o700')

    def test_preimage_never_in_record_or_terms(self):
        swap_id = self.make()
        with self.store.locked(swap_id) as swap:
            swap.log(1, 'note')
            swap.save()
        directory = self.root / 'swaps' / swap_id
        for name in ('record.json', 'terms.json'):
            text = (directory / name).read_text()
            self.assertNotIn(PREIMAGE.hex(), text)
        self.assertEqual((directory / 'secret').read_bytes(), PREIMAGE)

    def test_duplicate_id_and_bad_roles_refused(self):
        self.make()
        with self.assertRaises(FileExistsError):
            self.make()
        with self.assertRaisesRegex(ValueError, 'preimage'):
            self.store.create('1123456789abcdef', 'responder', terms(), 1, PREIMAGE)
        with self.assertRaisesRegex(ValueError, 'preimage'):
            self.store.create('2123456789abcdef', 'initiator', terms(), 1, None)
        with self.assertRaisesRegex(ValueError, 'hashlock'):
            self.store.create('3123456789abcdef', 'initiator', terms(), 1, bytes(32))

    def test_storage_must_be_private(self):
        loose = self.root / 'loose'
        loose.mkdir(mode=0o700)
        loose.chmod(0o755)  # Make the directory non-private regardless of the process umask.
        with self.assertRaisesRegex(ValueError, 'private'):
            Store(loose)
        real = self.root / 'real'
        real.mkdir(mode=0o700)
        link = self.root / 'link'
        link.symlink_to(real)
        with self.assertRaisesRegex(ValueError, 'private'):
            Store(link)

    def test_tampered_terms_are_detected(self):
        swap_id = self.make()
        path = self.root / 'swaps' / swap_id / 'terms.json'
        data = json.loads(path.read_text())
        data['legs']['long']['amount'] = 6
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'terms changed'):
            with self.store.locked(swap_id):
                pass

    def test_group_readable_secret_refused(self):
        swap_id = self.make()
        path = self.root / 'swaps' / swap_id / 'secret'
        os.chmod(path, 0o640)
        with self.store.locked(swap_id) as swap:
            with self.assertRaisesRegex(ValueError, 'private'):
                swap.read_secret('secret')

    def test_wrong_secret_content_refused_and_zeroed_on_success(self):
        swap_id = self.make()
        with self.store.locked(swap_id) as swap:
            secret = swap.read_secret('secret')
            self.assertEqual(bytes(secret), PREIMAGE)
            secret[:] = b'\0' * 32
            self.assertIsNone(swap.read_secret('learned-preimage'))
        path = self.root / 'swaps' / swap_id / 'secret'
        path.chmod(0o600)
        path.write_bytes(bytes(32))
        with self.store.locked(swap_id) as swap:
            with self.assertRaisesRegex(ValueError, 'hashlock'):
                swap.read_secret('secret')

    def test_lock_is_exclusive(self):
        swap_id = self.make()
        with self.store.locked(swap_id):
            with self.assertRaisesRegex(RuntimeError, 'Another process'):
                with self.store.locked(swap_id):
                    pass
        with self.store.locked(swap_id):
            pass

    def test_save_is_atomic_and_counts(self):
        swap_id = self.make()
        with self.store.locked(swap_id) as swap:
            swap.record['state'] = 'long_funded'
            swap.save()
            self.assertEqual(swap.record['seq'], 1)
        with self.store.locked(swap_id) as swap:
            self.assertEqual(swap.record['state'], 'long_funded')
        leftovers = [p.name for p in (self.root / 'swaps' / swap_id).iterdir() if p.name.endswith('.tmp')]
        self.assertEqual(leftovers, [])

    def test_history_is_bounded(self):
        swap_id = self.make()
        with self.store.locked(swap_id) as swap:
            for index in range(300):
                swap.log(index, 'note')
            swap.save()
            self.assertLessEqual(len(swap.record['history']), store_module.MAX_HISTORY)

    def test_terms_validation(self):
        bad = terms()
        bad['legs']['short']['amount'] = 0
        with self.assertRaisesRegex(ValueError, 'amount'):
            validate_terms(bad)
        bad = terms()
        bad['legs']['long']['claimant'] = bad['legs']['long']['refundee']
        with self.assertRaisesRegex(ValueError, 'different'):
            validate_terms(bad)
        same = terms()
        same['legs']['short']['chain'] = 'ethereum'
        with self.assertRaisesRegex(ValueError, 'cross'):
            validate_terms(same)
        same['legs']['short'].update(refundee='b@eth', claimant='a@eth')
        validate_terms(same)
        self.assertNotEqual(terms_digest(terms()), terms_digest(same))

    def test_journal_ids(self):
        directory = self.root / 'journal'
        directory.mkdir(mode=0o700)
        (directory / 'x-1.json').write_text(json.dumps({'chain': 'ethereum-sepolia', 'txid': 'aa', 'state': 'prepared_or_submitted'}))
        (directory / 'x-2.json').write_text(json.dumps({'chain': 'cardano-preview', 'txid': 'bb', 'state': 'prepared_or_submitted'}))
        (directory / 'x-1.signed').write_bytes(b'raw')
        self.assertEqual(journal_ids(directory), ['aa', 'bb'])
        self.assertEqual(journal_ids(directory, 'cardano-preview'), ['bb'])
        (directory / 'bad.json').write_text('{')
        with self.assertRaises(ValueError):
            journal_ids(directory)


if __name__ == '__main__':
    unittest.main()
