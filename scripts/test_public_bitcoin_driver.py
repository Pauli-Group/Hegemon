import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from embit import ec,transaction
from public_bitcoin_driver import fund,spend_contract

class PublicBitcoinDriverTest(unittest.TestCase):
    def test_funds_with_confirmed_utxo_and_local_key(self):
        claimant=ec.PrivateKey(b'\x11'*32).get_public_key().sec().hex();refund=ec.PrivateKey(b'\x22'*32)
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700);key=Path(d)/'key';key.write_text(refund.secret.hex());os.chmod(key,0o600)
            def broadcast(_dir,network,raw):
                tx=transaction.Transaction.parse(raw);self.assertEqual(network,'bitcoin-testnet4');self.assertEqual(tx.vout[0].value,30000);self.assertEqual(len(tx.vin[0].witness.items),2)
                return {'txid':tx.txid().hex(),'confirmed':False}
            with patch('public_bitcoin_driver.verify_network'),patch('public_bitcoin_driver.request',return_value=b'100'),patch('public_bitcoin_driver._fee',return_value=250),patch('public_bitcoin_driver.bitcoin_utxos',return_value=[{'txid':'33'*32,'vout':0,'amount_sats':50000}]),patch('public_bitcoin_driver.submit',side_effect=broadcast):
                self.assertFalse(fund(d,key,'44'*32,claimant,200,30000)['confirmed'])
    def test_refuses_early_refund_without_submission(self):
        alice=ec.PrivateKey(b'\x11'*32);bob=ec.PrivateKey(b'\x22'*32)
        with tempfile.TemporaryDirectory() as d:
            key=Path(d)/'key';key.write_text(bob.secret.hex());os.chmod(key,0o600)
            with patch('public_bitcoin_driver.verify_network'),patch('public_bitcoin_driver.request',return_value=b'100'),patch('public_bitcoin_driver.submit') as sent:
                with self.assertRaisesRegex(ValueError,'not yet eligible'):
                    spend_contract(d,key,'33'*32,0,30000,'44'*32,alice.get_public_key().sec().hex(),bob.get_public_key().sec().hex(),200)
                sent.assert_not_called()
    def test_refuses_funding_if_spend_would_be_dust(self):
        alice=ec.PrivateKey(b'\x11'*32);bob=ec.PrivateKey(b'\x22'*32)
        with tempfile.TemporaryDirectory() as d:
            key=Path(d)/'key';key.write_text(bob.secret.hex());os.chmod(key,0o600)
            with patch('public_bitcoin_driver.verify_network'),patch('public_bitcoin_driver.request',return_value=b'100'),patch('public_bitcoin_driver._fee',return_value=1000),patch('public_bitcoin_driver.submit') as sent:
                with self.assertRaisesRegex(ValueError,'dust'):fund(d,key,'44'*32,alice.get_public_key().sec().hex(),200,1500)
                sent.assert_not_called()

if __name__=='__main__':unittest.main()
