import json
import unittest
from unittest.mock import patch
from public_testnet_probe import probe, BITCOIN_GENESIS, ETHEREUM_GENESIS, BITCOIN, CARDANO

def actors():
    return {name:{'bitcoin_testnet4':'tb1q'+'a'*38,'ethereum_sepolia':'0x'+'1'*40,'cardano_preview':'addr_test1'+'q'*40} for name in ('alice','bob')}

def fake_request(url,body=None):
    if url==BITCOIN+'/block-height/0':return BITCOIN_GENESIS.encode()
    if url==BITCOIN+'/blocks/tip/height':return b'999'
    if url.startswith(BITCOIN+'/address/'):return json.dumps({'chain_stats':{'funded_txo_sum':100,'spent_txo_sum':5}}).encode()
    if url==CARDANO+'/genesis':return b'[{"networkmagic":"2","networkid":"Testnet","systemstart":1666656000}]'
    if url==CARDANO+'/tip':return b'[{"abs_slot":100,"block_no":20}]'
    if url==CARDANO+'/address_info':return b'[{"balance":"20"}]'
    raise AssertionError(url)

def fake_rpc(method,params):
    return {'eth_chainId':'0xaa36a7','eth_getBlockByNumber':{'hash':ETHEREUM_GENESIS},'eth_blockNumber':'0x10','eth_getBalance':'0x12'}[method]

class PublicTestnetProbeTest(unittest.TestCase):
    @patch('public_testnet_probe.rpc',side_effect=fake_rpc)
    @patch('public_testnet_probe.request',side_effect=fake_request)
    def test_checks_networks_and_reports_balances(self,_req,_rpc):
        result=probe(actors());self.assertEqual(result['actors']['alice'],{'bitcoin_confirmed_sats':95,'ethereum_wei':18,'cardano_lovelace':20})
    @patch('public_testnet_probe.rpc',side_effect=lambda m,p: '0x1')
    @patch('public_testnet_probe.request',side_effect=fake_request)
    def test_wrong_ethereum_network_is_rejected(self,_req,_rpc):
        with self.assertRaisesRegex(ValueError,'not Sepolia'):probe(actors())
    def test_rejects_urls_embedded_in_addresses(self):
        terms=actors();terms['alice']['bitcoin_testnet4']='../../elsewhere'
        with self.assertRaises(ValueError):probe(terms)

if __name__=='__main__':unittest.main()
