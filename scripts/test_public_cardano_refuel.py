import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from public_cardano_refuel import prepare,send,status

class PublicCardanoRefuelTest(unittest.TestCase):
    def test_preserves_input_assets_and_does_not_resubmit(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700);(root/'cardano-native-pair').mkdir();collateral='11'*32+'#0';asset='22'*28+'.00';txid='33'*32
            (root/'cardano-native-pair/state.json').write_text(json.dumps({'alice_collateral':collateral}))
            actors={'alice':{'address':'addr_test1'+'q'*40,'skey':root/'alice.key'},'bob':{'address':'addr_test1'+'p'*40,'skey':root/'bob.key'}}
            source={'outref':'44'*32+'#0','lovelace':100000000,'assets':{asset:7}}
            def row(ref,amount,assets):return {'outref':ref,'lovelace':amount,'assets':assets}
            def utxos(address):
                if not (root/'cardano-refuel/state.json').exists():return [source]
                return [row(txid+'#0',30000000,{}),row(txid+'#2',39800000,{asset:7})] if address==actors['alice']['address'] else [row(txid+'#1',30000000,{})]
            def build(**kwargs):self.assertEqual(kwargs['inputs'][0]['assets'],{asset:7});kwargs['body'].write_text('{}');os.chmod(kwargs['body'],0o600);return 200000
            patches=[patch('public_cardano_refuel.actor',side_effect=lambda _root,name:actors[name]),patch('public_cardano_refuel.cardano_utxos',side_effect=utxos),patch('public_cardano_refuel.status_confirmations',return_value=2),patch('public_cardano_refuel.preview_protocol_parameters',return_value={}),patch('public_cardano_refuel.build_balanced',side_effect=build),patch('public_cardano_refuel.sign_and_submit',return_value={'txid':txid})]
            for item in patches:item.start()
            try:
                self.assertEqual(prepare(root)['phase'],'prepared');self.assertEqual(send(root)['phase'],'submitted')
                with self.assertRaisesRegex(ValueError,'already attempted'):send(root)
                self.assertEqual(status(root)['phase'],'confirmed')
            finally:
                for item in reversed(patches):item.stop()

if __name__=='__main__':unittest.main()
