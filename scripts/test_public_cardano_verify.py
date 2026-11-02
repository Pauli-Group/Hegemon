import json
import unittest
from unittest.mock import patch
import cbor2
from public_cardano_verify import verify_preview
from public_testnet_probe import CARDANO

class PublicCardanoVerifyTest(unittest.TestCase):
    @patch('public_cardano_verify.verify_network')
    def test_exact_script_datum_asset_and_confirmation_checks(self,_network):
        txid='11'*32;outref=txid+'#0';hashlock='22'*32;claimant='33'*28;refundee='44'*28;expiry=(1666656000+1000)*1000;policy='55'*28
        value={'constructor':0,'fields':[{'bytes':hashlock},{'bytes':claimant},{'bytes':refundee},{'int':expiry}]}
        raw=cbor2.dumps(cbor2.CBORTag(121,[bytes.fromhex(hashlock),bytes.fromhex(claimant),bytes.fromhex(refundee),expiry])).hex()
        row={'outref':outref,'lovelace':5000000,'assets':{policy+'.00':5},'inline_datum':{'value':value,'bytes':raw},'block_height':100}
        def request(url,body=None):
            if url==CARDANO+'/tx_status':return json.dumps([{'tx_hash':txid,'num_confirmations':2}]).encode()
            if url==CARDANO+'/tip':return b'[{"abs_slot":100}]'
            raise AssertionError(url)
        args=('/workspace/chain-tools/htlc.plutus',outref,hashlock,claimant,refundee,expiry,5000000,{policy+'.00':5})
        with patch('public_cardano_verify.request',side_effect=request),patch('public_cardano_verify.cardano_utxos',return_value=[row]):
            self.assertEqual(verify_preview(*args)['confirmations'],2)
            changed=dict(row,assets={policy+'.00':6})
            with patch('public_cardano_verify.cardano_utxos',return_value=[changed]):
                with self.assertRaisesRegex(ValueError,'value mismatch'):verify_preview(*args)
            changed=dict(row,inline_datum={'value':value,'bytes':'01'})
            with patch('public_cardano_verify.cardano_utxos',return_value=[changed]):
                with self.assertRaisesRegex(ValueError,'datum bytes'):verify_preview(*args)

if __name__=='__main__':unittest.main()
