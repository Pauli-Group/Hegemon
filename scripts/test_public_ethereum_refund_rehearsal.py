import json
import unittest
from unittest.mock import patch
from eth_abi import encode
from eth_utils import keccak
from public_ethereum_refund_rehearsal import _early_refund_rejected

class PublicEthereumRefundTest(unittest.TestCase):
    def test_early_refund_requires_exact_revert_reason(self):
        data='0x'+(keccak(text='Error(string)')[:4]+encode(['string'],['refund premature'])).hex()
        with patch('public_ethereum_refund_rehearsal.request',return_value=json.dumps({'id':1,'error':{'code':3,'data':data}}).encode()):_early_refund_rejected('0x'+'11'*20,'0x'+'22'*20)
        with patch('public_ethereum_refund_rehearsal.request',return_value=b'{"id":1,"error":{"code":3,"data":"0x"}}'):
            with self.assertRaisesRegex(ValueError,'expected contract rejection'):_early_refund_rejected('0x'+'11'*20,'0x'+'22'*20)

if __name__=='__main__':unittest.main()
