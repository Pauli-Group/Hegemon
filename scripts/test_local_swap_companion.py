import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from local_swap_companion import cardano_wire_terms, hegemon_wire_terms, private_token

class LocalCompanionTest(unittest.TestCase):
    def test_token_private_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);token=root/'token'
            first=private_token(token)
            self.assertEqual(len(first),64);self.assertEqual(private_token(token),first)
            self.assertEqual(token.stat().st_mode & 0o777,0o600)
            link=root/'link';link.symlink_to(token)
            with self.assertRaises(OSError):private_token(link)
            os.chmod(token,0o644)
            with self.assertRaises(ValueError):private_token(token)
    def test_cardano_decimal_values_are_exact_and_bounded(self):
        policy='a'*56
        terms={'expiry_ms':'1800000000000','expected_value':{'lovelace':'10000000',policy:{'00':'9007199254740993'}}}
        parsed=cardano_wire_terms(terms)
        self.assertEqual(parsed['expected_value'][policy]['00'],9007199254740993)
        for bad in ('1e6','01',str(2**63)):
            with self.assertRaises(ValueError):cardano_wire_terms({**terms,'expiry_ms':bad})
        with self.assertRaises(ValueError):cardano_wire_terms({**terms,'expiry_ms':9007199254740993})
    def test_hegemon_decimal_values_are_exact_and_bounded(self):
        data={'locked':'0','timeout':'9007199254740993','amount':'100','min_confirmations':'2',
              'min_remaining_blocks':'2','hashlock':'a'*64,'claim':'claim','refund':'refund'}
        with patch('local_swap_companion.public_v8_address_keys'):
            self.assertEqual(hegemon_wire_terms(data)['timeout'],'9007199254740993')
            with self.assertRaises(ValueError):hegemon_wire_terms({**data,'timeout':str(2**64)})
            with self.assertRaises(ValueError):hegemon_wire_terms({**data,'amount':'0'})
    def test_hegemon_companion_refuses_noninteractive_terminal(self):
        with tempfile.TemporaryDirectory() as d:
            process=subprocess.run([sys.executable,'scripts/local_swap_companion.py','--token-file',str(Path(d)/'token'),
                '--hegemon-wallet','/tmp/wallet','--hegemon-manifest','/tmp/manifest',
                '--hegemon-genesis','a'*64,'--hegemon-rpc','http://127.0.0.1:19944'],
                stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(process.returncode,0)
            self.assertIn('interactive local terminal',process.stderr)

if __name__=='__main__':unittest.main()
