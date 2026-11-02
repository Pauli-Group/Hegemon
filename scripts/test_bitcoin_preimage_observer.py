import hashlib
import unittest
from bitcoin_preimage_observer import observe_bitcoin_preimage


class BitcoinObserverTest(unittest.TestCase):
    def test_only_confirmed_matching_outpoint_reveals_secret(self):
        secret=b'\x22'*32;digest=hashlib.sha256(secret).hexdigest();genesis='a'*64;funding='b'*64;block_hash='c'*64;spend='d'*64
        class Node:
            def __init__(self,changed=False):self.calls=0;self.changed=changed
            def call(self,method,*args):
                if method=='getblockchaininfo':return {'chain':'regtest'}
                if method=='getblockhash':return genesis if args[0]==0 else block_hash
                if method=='getconnectioncount':return 0
                if method=='getbestblockhash':
                    self.calls+=1;return 'e'*64 if self.changed and self.calls>1 else 'f'*64
                if method=='getblockcount':return 3
                if method=='getblock':return {'hash':block_hash,'height':2,'tx':[{'txid':spend,'vin':[{'txid':funding,'vout':1,'txinwitness':[secret.hex()]}]}]}
                raise AssertionError(method)
        terms={'genesis':genesis,'txid':funding,'vout':1,'hashlock':digest,'start_height':2,'confirmations':2}
        recovered,snapshot=observe_bitcoin_preimage(Node(),**terms);self.assertEqual(recovered,secret);self.assertEqual(snapshot['confirmations'],2);recovered[:]=b'\0'*len(recovered)
        with self.assertRaisesRegex(ValueError,'chain changed'):observe_bitcoin_preimage(Node(changed=True),**terms)
        with self.assertRaisesRegex(ValueError,'timed out'):observe_bitcoin_preimage(Node(),**{**terms,'vout':0},timeout=.001)

if __name__=='__main__':unittest.main()
