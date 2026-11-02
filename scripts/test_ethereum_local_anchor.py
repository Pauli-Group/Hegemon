import unittest
from unittest.mock import patch
from ethereum_local_anchor import ethereum_local_head

class EthereumLocalAnchorTest(unittest.TestCase):
    def test_rejects_remote_endpoints_before_any_rpc(self):
        with patch('ethereum_local_anchor.rpc') as rpc:
            for url in ('https://example.com:443','http://example.com:8545','http://127.0.0.1:8545/path'):
                with self.assertRaises(ValueError):ethereum_local_head(url)
            rpc.assert_not_called()
    def test_rejects_forked_or_wrong_chain_metadata(self):
        for metadata in ({'chainId':31337,'clientVersion':'anvil/v1','forkedNetwork':{'chainId':1}},
                         {'chainId':1,'clientVersion':'anvil/v1','forkedNetwork':None},
                         {'chainId':31337,'clientVersion':'geth','forkedNetwork':None}):
            with patch('ethereum_local_anchor.rpc',side_effect=['0x7a69',metadata]):
                with self.assertRaises(ValueError):ethereum_local_head('http://127.0.0.1:8545')

if __name__=='__main__':unittest.main()
