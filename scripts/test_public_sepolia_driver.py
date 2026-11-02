import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from eth_account import Account
from public_sepolia_driver import send

class PublicSepoliaDriverTest(unittest.TestCase):
    def test_signs_locally_and_only_submits_signed_transaction(self):
        key=b'\x55'*32;sender=Account.from_key(key).address;calls=[]
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700);wallet=Path(d)/'wallet';wallet.write_text(sender+' 0x'+key.hex());os.chmod(wallet,0o600)
            def rpc(method,params):
                calls.append((method,params))
                return {'eth_getTransactionCount':'0x0','eth_getBlockByNumber':{'baseFeePerGas':'0x3b9aca00'},'eth_maxPriorityFeePerGas':'0x3b9aca00','eth_estimateGas':'0x5208','eth_getBalance':hex(10**18)}[method]
            def submit(directory,chain,raw):
                self.assertEqual(chain,'ethereum-sepolia');self.assertEqual(Account.recover_transaction(raw),sender)
                return {'chain':chain,'txid':'11'*32,'confirmed':False}
            with patch('public_sepolia_driver.verify_network'),patch('public_sepolia_driver.rpc',side_effect=rpc),patch('public_sepolia_driver.submit',side_effect=submit):
                result=send(d,wallet,'0x'+'22'*20,1,b'')
            self.assertFalse(result['confirmed']);self.assertNotIn(key.hex(),repr(calls))
    def test_refuses_nonprivate_wallet_file(self):
        key=b'\x55'*32;sender=Account.from_key(key).address
        with tempfile.TemporaryDirectory() as d:
            wallet=Path(d)/'wallet';wallet.write_text(sender+' 0x'+key.hex());os.chmod(wallet,0o644)
            with self.assertRaisesRegex(ValueError,'private'):send(d,wallet,'0x'+'22'*20,1,b'')

if __name__=='__main__':unittest.main()
