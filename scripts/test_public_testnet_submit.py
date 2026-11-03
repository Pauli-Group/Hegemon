import json
import os
import tempfile
import unittest
from unittest.mock import patch
from eth_account import Account
from public_ethereum_transactions import sign_transaction
from public_testnet_probe import BITCOIN_GENESIS, ETHEREUM_GENESIS
from public_testnet_submit import submit,verify_network

class PublicTestnetSubmitTest(unittest.TestCase):
    def test_bitcoin_service_is_selected_before_journal_and_broadcast_once(self):
        events=[];ident='a'*64
        with patch('public_testnet_submit.verify_network'),patch('public_testnet_submit.bitcoin_submission_url',side_effect=lambda:events.append('choose') or 'https://testnet.invalid/tx'),patch('public_testnet_submit.prepare',side_effect=lambda *_:events.append('journal') or {'txid':ident}),patch('public_testnet_submit._broadcast',side_effect=lambda *_:events.append('send') or ident.encode()):
            self.assertEqual(submit('/unused','bitcoin-testnet4',b'signed')['txid'],ident)
        self.assertEqual(events,['choose','journal','send'])
    def test_journal_exists_before_broadcast_and_no_retry_after_lost_response(self):
        key=b'\x66'*32;sender=Account.from_key(key).address
        raw,txid=sign_transaction(key,sender,nonce=0,to='0x'+'1'*40,value=1,data=b'',gas=21000,max_fee=100,priority_fee=1)
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700)
            def lost(_url,_raw,_content_type):
                self.assertTrue(os.path.exists(os.path.join(d,'ethereum-sepolia-'+txid[2:]+'.json')))
                raise TimeoutError('response lost')
            with patch('public_testnet_submit.verify_network'),patch('public_testnet_submit._broadcast',side_effect=lost) as sent:
                with self.assertRaises(TimeoutError):submit(d,'ethereum-sepolia',raw)
                with self.assertRaises(FileExistsError):submit(d,'ethereum-sepolia',raw)
                self.assertEqual(sent.call_count,1)
    def test_network_identity_rejected_before_journaling(self):
        with patch('public_testnet_submit.request',return_value=b'00'):
            with self.assertRaisesRegex(ValueError,'not testnet4'):verify_network('bitcoin-testnet4')
        with patch('public_testnet_submit.rpc',return_value='0x1'):
            with self.assertRaisesRegex(ValueError,'not Sepolia'):verify_network('ethereum-sepolia')
    def test_acceptance_is_not_confirmation(self):
        key=b'\x66'*32;sender=Account.from_key(key).address
        raw,txid=sign_transaction(key,sender,nonce=0,to='0x'+'1'*40,value=1,data=b'',gas=21000,max_fee=100,priority_fee=1)
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700)
            with patch('public_testnet_submit.verify_network'),patch('public_testnet_submit._broadcast',return_value=json.dumps({'id':1,'result':txid}).encode()):
                result=submit(d,'ethereum-sepolia',raw)
            self.assertEqual(result['txid'],txid[2:]);self.assertFalse(result['confirmed'])

if __name__=='__main__':unittest.main()
