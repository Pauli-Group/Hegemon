import tempfile
import unittest
from pathlib import Path

import check_swap_secrets as scanner

HEX = 'a1b2c3d4e5f60718293a4b5c6d7e8f90' * 2
WIF = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k'


class SecretScannerTest(unittest.TestCase):
    def rules(self, name, text):
        return {rule for _, rule, _ in scanner.scan_text(name, text)}

    def test_detects_each_kind_of_secret(self):
        self.assertEqual(self.rules('scripts/x.py', '-----BEGIN EC PRIVATE KEY-----\nabc'), {'private-key-block'})
        self.assertEqual(self.rules('scripts/x.py', f'key = "{WIF}"'), {'wif-key'})
        self.assertEqual(self.rules('scripts/x.py', f'"preimage": "{HEX}"'), {'secret-hex'})
        self.assertEqual(self.rules('scripts/x.py', f'private_key = 0x{HEX}'), {'secret-hex'})
        self.assertEqual(self.rules('scripts/x.py', 'tx = "02000000' + 'ab' * 200 + '"'), {'signed-transaction-hex'})
        self.assertEqual(self.rules('scripts/x.py', 'passphrase = "correct-horse-battery"'), {'literal-passphrase'})
        self.assertEqual(self.rules('scripts/x.py', 'xprv' + '9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'), {'extended-private-key'})

    def test_ignores_public_data_and_patterns(self):
        self.assertEqual(self.rules('scripts/x.py', '"preimage": "' + 'cd' * 32 + '"'), set())
        self.assertEqual(self.rules('scripts/x.py', f'"hashlock": "{HEX}", "txid": "{HEX}"'), set())
        self.assertEqual(self.rules('scripts/x.py', 'getpass.getpass("passphrase: ")'), set())
        self.assertEqual(self.rules('docs/x.md', 'PASSWORD="<app-password>"'), set())
        self.assertEqual(self.rules('scripts/x.py', 'candidateArtifactReceiptWithoutDigitsInTheNameOfThisIdentifierAbc'), set())

    def test_allowlist_is_narrow(self):
        self.assertEqual(self.rules('scripts/make_identity_vectors.py', f'from_wif("{WIF}")'), set())
        self.assertEqual(self.rules('scripts/make_identity_vectors.py', f'"secret": "{HEX}"'), {'secret-hex'})
        self.assertEqual(self.rules('scripts/other.py', f'from_wif("{WIF}")'), {'wif-key'})

    def test_scan_reads_files_and_main_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            clean = Path(directory) / 'clean.txt'
            dirty = Path(directory) / 'dirty.txt'
            clean.write_text('nothing here\n')
            dirty.write_text('ok\n-----BEGIN PRIVATE KEY-----\n')
            self.assertEqual(scanner.main([str(clean)]), 0)
            self.assertEqual(scanner.main([str(dirty)]), 1)
            self.assertEqual(scanner.scan([str(dirty)])[0][1:3], (2, 'private-key-block'))

    def test_repository_swap_paths_are_clean(self):
        self.assertEqual(scanner.scan(), [])


if __name__ == '__main__':
    unittest.main()
