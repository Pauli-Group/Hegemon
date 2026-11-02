import hashlib
import json
import unittest
from unittest.mock import patch
from eth_utils import keccak
from public_testnet_observers import bitcoin_claim,ethereum_claim,cardano_claim
from public_testnet_probe import BITCOIN,CARDANO
from test_cardano_preimage_observer import fixture

class PublicTestnetObserversTest(unittest.TestCase):
    @patch('public_testnet_observers.verify_network')
    def test_bitcoin_confirmed_exact_outpoint_and_hash(self,_network):
        secret=b'\x11'*32;digest=hashlib.sha256(secret).hexdigest();claim='aa'*32;fund='bb'*32;block='cc'*32
        def get(url):
            if url==BITCOIN+'/tx/'+claim:return json.dumps({'txid':claim,'status':{'confirmed':True,'block_height':10,'block_hash':block},'vin':[{'txid':fund,'vout':1,'witness':[secret.hex()]}]}).encode()
            if url==BITCOIN+'/blocks/tip/height':return b'11'
            if url==BITCOIN+'/block-height/10':return block.encode()
            raise AssertionError(url)
        with patch('public_testnet_observers.request',side_effect=get):
            observed,snapshot=bitcoin_claim(claim,fund,1,digest);self.assertEqual(bytes(observed),secret);self.assertEqual(snapshot['confirmations'],2)
            with self.assertRaisesRegex(ValueError,'not found'):bitcoin_claim(claim,fund,2,digest)
    @patch('public_testnet_observers.verify_network')
    def test_ethereum_canonical_exact_contract_and_hash(self,_network):
        secret=b'\x11'*32;digest=hashlib.sha256(secret).hexdigest();ident='aa'*32;block='0x'+'bb'*32;contract='0x'+'cc'*20
        data='0x'+keccak(text='claim(bytes32)')[:4].hex()+secret.hex()
        def rpc(method,params):
            return {'eth_getTransactionReceipt':{'status':'0x1','transactionHash':'0x'+ident,'blockNumber':'0xa','blockHash':block},'eth_getTransactionByHash':{'hash':'0x'+ident,'to':contract,'input':data,'blockHash':block},'eth_blockNumber':'0xb','eth_getBlockByNumber':{'hash':block}}[method]
        with patch('public_testnet_observers.rpc',side_effect=rpc):
            observed,snapshot=ethereum_claim(ident,contract,digest);self.assertEqual(bytes(observed),secret);self.assertEqual(snapshot['confirmations'],2)
            with self.assertRaisesRegex(ValueError,'mismatch'):ethereum_claim(ident,'0x'+'dd'*20,digest)
    @patch('public_testnet_observers.verify_network')
    def test_cardano_cbor_binding_and_confirmations(self,_network):
        txid,raw,digest=fixture();outref='aa'*32+'#1';block='dd'*32
        def get(url,body):
            if url==CARDANO+'/tx_status':return json.dumps([{'tx_hash':txid,'num_confirmations':2}]).encode()
            if url==CARDANO+'/tx_cbor':return json.dumps([{'tx_hash':txid,'block_hash':block,'valid_contract':True,'cbor':raw}]).encode()
            raise AssertionError(url)
        with patch('public_testnet_observers.request',side_effect=get):
            observed,snapshot=cardano_claim(txid,outref,digest);self.assertEqual(hashlib.sha256(observed).hexdigest(),digest);self.assertEqual(snapshot['block_hash'],block)
            with self.assertRaisesRegex(ValueError,'not found'):cardano_claim(txid,'bb'*32+'#0',digest)

if __name__=='__main__':unittest.main()
