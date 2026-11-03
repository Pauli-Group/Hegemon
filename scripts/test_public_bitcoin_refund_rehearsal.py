import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from public_bitcoin_refund_rehearsal import initialize,advance
from test_public_btc_eth_rehearsal import wallets

class PublicBitcoinRefundTest(unittest.TestCase):
    def test_refund_waits_for_height(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700);wallets(root);height=[100]
            def request(url):return str(height[0]).encode()
            def spend(*args):
                if height[0]<106:raise ValueError('Bitcoin refund is not yet eligible')
                return {'txid':'22'*32}
            patches=[patch('public_bitcoin_refund_rehearsal.verify_network'),patch('public_bitcoin_refund_rehearsal.request',side_effect=request),patch('public_bitcoin_refund_rehearsal.fund',return_value={'txid':'11'*32}),patch('public_bitcoin_refund_rehearsal._bitcoin_lock',return_value=100),patch('public_bitcoin_refund_rehearsal.spend_contract',side_effect=spend)]
            for item in patches:item.start()
            try:
                initialize(root);self.assertEqual(advance(root)['phase'],'lock_submitted');self.assertEqual(advance(root)['phase'],'wait_refund');self.assertEqual(advance(root)['phase'],'wait_refund')
                s=json.loads((root/'bitcoin-refund/state.json').read_text());self.assertTrue(s['early_refund_rejected']);height[0]=106
                self.assertEqual(advance(root)['phase'],'refund_submitted')
            finally:
                for item in reversed(patches):item.stop()

if __name__=='__main__':unittest.main()
