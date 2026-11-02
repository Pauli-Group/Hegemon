import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from public_btc_cardano_rehearsal import initialize,advance

class PublicBtcCardanoRehearsalTest(unittest.TestCase):
    def test_stages_use_observed_cardano_secret_for_bitcoin_claim(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700);terms={'btc_refund':'02'+'11'*32,'btc_claimant':'03'+'22'*32,'ada_refundee':'33'*28,'ada_claimant':'44'*28,'ada_refund_address':'addr_test1'+'q'*40,'ada_claim_address':'addr_test1'+'p'*40}
            rows=[{'outref':'aa'*32+'#0','lovelace':20000000,'assets':{}},{'outref':'bb'*32+'#0','lovelace':20000000,'assets':{}}]
            def choose(items,minimum,excluded=()):return next(item for item in items if item['outref'] not in excluded)
            def build(**kwargs):kwargs['body'].write_text('{}');os.chmod(kwargs['body'],0o600);return 200000
            def ada_send(_work,body,_key):return {'txid':('cc' if 'lock' in body.name else 'dd')*32}
            def observed(*_args):return bytearray((root/'btc-cardano/secret').read_bytes()),{'confirmations':2}
            def compiled(cmd,**kwargs):return 'addr_test1'+'v'*40 if cmd[0].endswith('cardano-cli') else b'{}'
            patches=[patch('public_btc_cardano_rehearsal.verify_network'),patch('public_btc_cardano_rehearsal._actors',return_value=terms),patch('public_btc_cardano_rehearsal.cardano_utxos',return_value=rows),patch('public_btc_cardano_rehearsal._choose',side_effect=choose),patch('public_btc_cardano_rehearsal.request',return_value=b'100'),patch('public_btc_cardano_rehearsal.bitcoin_fund',return_value={'txid':'55'*32}),patch('public_btc_cardano_rehearsal._bitcoin_lock',return_value=100),patch('public_btc_cardano_rehearsal._tip',return_value=1000),patch('public_btc_cardano_rehearsal.preview_protocol_parameters',return_value={}),patch('public_btc_cardano_rehearsal.subprocess.check_output',side_effect=compiled),patch('public_btc_cardano_rehearsal.build_balanced',side_effect=build),patch('public_btc_cardano_rehearsal.actor',return_value={'skey':root/'dummy'}),patch('public_btc_cardano_rehearsal.sign_and_submit',side_effect=ada_send),patch('public_btc_cardano_rehearsal.status_confirmations',return_value=2),patch('public_btc_cardano_rehearsal._ada_verify'),patch('public_btc_cardano_rehearsal.cardano_claim',side_effect=observed),patch('public_btc_cardano_rehearsal.spend_contract',return_value={'txid':'66'*32}),patch('public_btc_cardano_rehearsal.bitcoin_claim',side_effect=observed)]
            for item in patches:item.start()
            try:
                initialize(root);phases=[advance(root)['phase'] for _ in range(7)]
            finally:
                for item in reversed(patches):item.stop()
            self.assertEqual(phases,['btc_lock_submitted','btc_lock_confirmed','ada_lock_submitted','both_verified','ada_claim_submitted','btc_claim_submitted','complete'])
            self.assertNotIn((root/'btc-cardano/secret').read_bytes().hex(),(root/'btc-cardano/state.json').read_text())

if __name__=='__main__':unittest.main()
