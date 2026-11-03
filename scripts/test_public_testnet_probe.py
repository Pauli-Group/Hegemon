import json
import unittest
import urllib.error
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
    def test_bitcoin_read_fallback_checks_genesis_and_never_retries_submission(self):
        import public_testnet_probe as probe_module
        error=urllib.error.HTTPError(BITCOIN+'/blocks/tip/height',429,'limited',{},None)
        class Response:
            def __init__(self,value):self.value=value
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,_limit):return self.value
        with patch.object(probe_module,'_bitcoin_fallback_until',0),patch.object(probe_module,'_bitcoin_fallback_verified_until',0),patch('public_testnet_probe.urllib.request.urlopen',side_effect=[error,Response(BITCOIN_GENESIS.encode()),Response(b'100')]) as opened:
            self.assertEqual(probe_module.request(BITCOIN+'/blocks/tip/height'),b'100');self.assertEqual(opened.call_count,3)
            self.assertTrue(opened.call_args_list[1].args[0].full_url.startswith(probe_module.BITCOIN_FALLBACK))
        with patch.object(probe_module,'_bitcoin_fallback_until',0),patch('public_testnet_probe.urllib.request.urlopen',side_effect=error) as opened:
            with self.assertRaises(urllib.error.HTTPError):probe_module.request(BITCOIN+'/tx',{'raw':'example'})
            self.assertEqual(opened.call_count,1)
    def test_bitcoin_fallback_rejects_wrong_genesis(self):
        import public_testnet_probe as probe_module
        error=urllib.error.HTTPError(BITCOIN+'/blocks/tip/height',429,'limited',{},None)
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,_limit):return b'wrong'
        with patch.object(probe_module,'_bitcoin_fallback_until',0),patch.object(probe_module,'_bitcoin_fallback_verified_until',0),patch('public_testnet_probe.urllib.request.urlopen',side_effect=[error,Response()]):
            with self.assertRaisesRegex(ValueError,'not testnet4'):probe_module.request(BITCOIN+'/blocks/tip/height')
    def test_submission_service_selected_before_send_and_rechecks_network(self):
        import public_testnet_probe as probe_module
        with patch.object(probe_module,'_bitcoin_fallback_until',float('inf')),patch.object(probe_module,'_fallback_read',return_value=BITCOIN_GENESIS.encode()):
            self.assertEqual(probe_module.bitcoin_submission_url(),probe_module.BITCOIN_FALLBACK+'/tx')
        with patch.object(probe_module,'_bitcoin_fallback_until',float('inf')),patch.object(probe_module,'_fallback_read',return_value=b'wrong'):
            with self.assertRaisesRegex(ValueError,'not testnet4'):probe_module.bitcoin_submission_url()
    def test_only_read_operations_retry_transient_http_errors(self):
        from public_testnet_probe import request,ETHEREUM
        error=urllib.error.HTTPError(ETHEREUM,503,'unavailable',{},None)
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,_limit):return b'{}'
        with patch('public_testnet_probe.time.sleep'),patch('public_testnet_probe.urllib.request.urlopen',side_effect=[error,Response()]) as opened:
            self.assertEqual(request(ETHEREUM,{'method':'eth_getBalance'}),b'{}');self.assertEqual(opened.call_count,2)
        with patch('public_testnet_probe.time.sleep'),patch('public_testnet_probe.urllib.request.urlopen',side_effect=error) as opened:
            with self.assertRaises(urllib.error.HTTPError):request(ETHEREUM,{'method':'eth_sendRawTransaction'})
            self.assertEqual(opened.call_count,1)
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
