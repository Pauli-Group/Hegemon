import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from public_sepolia_verifier_fixture import initialize,advance

class SepoliaFixtureTest(unittest.TestCase):
    def test_funds_waits_and_refunds_only_after_deadline(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700)
            def wallet(path):return None,('0x'+'1'*40 if 'alice' in str(path) else '0x'+'2'*40)
            def rpc(method,params):
                if method=='eth_getBlockByNumber':return {'timestamp':hex(1000)}
                if method=='eth_getBalance':return '0x0'
                raise AssertionError(method)
            with patch('public_sepolia_verifier_fixture.verify_network'),patch('public_sepolia_verifier_fixture.load_test_wallet',side_effect=wallet),patch('public_sepolia_verifier_fixture.rpc',side_effect=rpc),patch('public_sepolia_verifier_fixture.send',side_effect=[{'txid':'a'*64},{'txid':'b'*64}]) as send,patch('public_sepolia_verifier_fixture._receipt',return_value={'contractAddress':'0x'+'3'*40}),patch('public_sepolia_verifier_fixture.verify_native'):
                initialize(root);self.assertEqual(advance(root)['phase'],'deploy_submitted');self.assertEqual(advance(root)['phase'],'wait_refund');self.assertEqual(advance(root)['phase'],'wait_refund');self.assertEqual(send.call_count,1)
                with patch('public_sepolia_verifier_fixture.rpc',return_value={'timestamp':hex(2200)}):self.assertEqual(advance(root)['phase'],'refund_submitted')
                self.assertEqual(advance(root)['phase'],'complete');self.assertEqual(send.call_count,2)
                self.assertEqual(json.loads((root/'sepolia-ui-fixture/state.json').read_text())['refund'],'b'*64)

if __name__=='__main__':unittest.main()
