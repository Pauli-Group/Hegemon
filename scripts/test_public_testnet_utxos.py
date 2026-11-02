import json
import unittest
from unittest.mock import patch
from embit import ec,networks,script
from public_testnet_probe import BITCOIN,CARDANO
from public_testnet_utxos import bitcoin_utxos,cardano_utxos

class PublicTestnetUtxosTest(unittest.TestCase):
    @patch('public_testnet_utxos.verify_network')
    def test_bitcoin_verifies_output_spend_and_block(self,_network):
        key=ec.PrivateKey(b'\x11'*32);spk=script.p2wpkh(key.get_public_key());address=spk.address(networks.NETWORKS['test']);txid='11'*32;block='22'*32
        def get(url,body=None):
            if url==BITCOIN+'/blocks/tip/height':return b'101'
            if url==BITCOIN+'/address/'+address+'/utxo':return json.dumps([{'txid':txid,'vout':0,'value':2000,'status':{'confirmed':True,'block_height':100,'block_hash':block}}]).encode()
            if url==BITCOIN+'/block-height/100':return block.encode()
            if url==BITCOIN+'/tx/'+txid:return json.dumps({'txid':txid,'status':{'block_hash':block},'vout':[{'value':2000,'scriptpubkey':spk.data.hex()}]}).encode()
            if url==BITCOIN+'/tx/'+txid+'/outspend/0':return b'{"spent":false}'
            raise AssertionError(url)
        with patch('public_testnet_utxos.request',side_effect=get):
            result=bitcoin_utxos(address);self.assertEqual(result[0]['amount_sats'],2000);self.assertEqual(result[0]['confirmations'],2)
    @patch('public_testnet_utxos.verify_network')
    def test_cardano_preserves_each_native_asset(self,_network):
        address='addr_test1'+'q'*40;policy='aa'*28;txid='bb'*32
        row={'tx_hash':txid,'tx_index':0,'address':address,'value':'10000000','asset_list':[{'policy_id':policy,'asset_name':'00','quantity':'9'}],'block_height':5}
        with patch('public_testnet_utxos.request',return_value=json.dumps([row]).encode()):
            self.assertEqual(cardano_utxos(address)[0]['assets'],{policy+'.00':9})
            row['asset_list'].append(row['asset_list'][0])
            with patch('public_testnet_utxos.request',return_value=json.dumps([row]).encode()):
                with self.assertRaisesRegex(ValueError,'asset'):cardano_utxos(address)

if __name__=='__main__':unittest.main()
