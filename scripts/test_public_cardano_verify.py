import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import cbor2
from public_cardano_verify import verify_preview
from public_testnet_probe import CARDANO
from public_cardano_verify import ROOT
from swap_engine.tools import skip_unless_tools, tool

# The policy's minimum remaining claim window is far longer than this fixture's deadline; the checks under test are the
# script, datum, value and confirmation checks, so the window is set explicitly.
SHORT={'minimum_remaining_ms':60000}


class PublicCardanoVerifyTest(unittest.TestCase):
    @skip_unless_tools('aiken', 'cardano-cli')
    @patch('public_cardano_verify.verify_network')
    def test_exact_script_datum_asset_and_confirmation_checks(self,_network):
        directory=tempfile.TemporaryDirectory(prefix='cardano-verify-script-');self.addCleanup(directory.cleanup)
        script=Path(directory.name)/'htlc.plutus'
        script.write_text(subprocess.check_output([str(tool('aiken')),'blueprint','convert',str(ROOT/'contracts/cardano')],text=True,timeout=60))
        txid='11'*32;outref=txid+'#0';hashlock='22'*32;claimant='33'*28;refundee='44'*28;expiry=(1666656000+1000)*1000;policy='55'*28
        value={'constructor':0,'fields':[{'bytes':hashlock},{'bytes':claimant},{'bytes':refundee},{'int':expiry}]}
        raw=cbor2.dumps(cbor2.CBORTag(121,[bytes.fromhex(hashlock),bytes.fromhex(claimant),bytes.fromhex(refundee),expiry])).hex()
        row={'outref':outref,'lovelace':5000000,'assets':{policy+'.00':5},'inline_datum':{'value':value,'bytes':raw},'block_height':100}
        def request(url,body=None):
            if url==CARDANO+'/tx_status':return json.dumps([{'tx_hash':txid,'num_confirmations':2}]).encode()
            if url==CARDANO+'/tip':return b'[{"abs_slot":100}]'
            raise AssertionError(url)
        args=(str(script),outref,hashlock,claimant,refundee,expiry,5000000,{policy+'.00':5})
        with patch('public_cardano_verify.request',side_effect=request),patch('public_cardano_verify.cardano_utxos',return_value=[row]):
            self.assertEqual(verify_preview(*args,**SHORT)['confirmations'],2)
            changed=dict(row,assets={policy+'.00':6})
            with patch('public_cardano_verify.cardano_utxos',return_value=[changed]):
                with self.assertRaisesRegex(ValueError,'value mismatch'):verify_preview(*args,**SHORT)
            changed=dict(row,inline_datum={'value':value,'bytes':'01'})
            with patch('public_cardano_verify.cardano_utxos',return_value=[changed]):
                with self.assertRaisesRegex(ValueError,'datum bytes'):verify_preview(*args,**SHORT)
            def expired(url,body=None):
                if url==CARDANO+'/tip':return b'[{"abs_slot":1001}]'
                return request(url,body)
            with patch('public_cardano_verify.request',side_effect=expired):
                with self.assertRaisesRegex(ValueError,'deadline'):verify_preview(*args,**SHORT)
                self.assertEqual(verify_preview(*args,**SHORT,allow_expired=True)['confirmations'],2)

if __name__=='__main__':unittest.main()
