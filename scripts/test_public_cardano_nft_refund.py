import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from public_cardano_nft_refund import initialize,advance

class PublicCardanoNftRefundTest(unittest.TestCase):
    def test_funds_then_waits_and_returns_nft(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700)
            for name in ('eth-cardano-erc721-nft','cardano-native-pair'):(root/name).mkdir()
            asset='11'*28+'.4e4654';collateral='22'*32+'#0';lock='33'*32;refund='44'*32
            (root/'eth-cardano-erc721-nft/state.json').write_text(json.dumps({'phase':'complete','ada_asset':asset}));(root/'cardano-native-pair/state.json').write_text(json.dumps({'phase':'complete','bob_collateral':collateral}))
            alice={'address':'addr_test1'+'q'*40,'keyhash':'55'*28,'skey':root/'alice.key'};bob={'address':'addr_test1'+'p'*40,'keyhash':'66'*28,'skey':root/'bob.key'};now=[1000]
            def row(ref,amount,assets):return {'outref':ref,'lovelace':amount,'assets':assets}
            def outputs(address):
                p=root/'cardano-nft-refund/state.json';phase=json.loads(p.read_text())['phase'] if p.exists() else ''
                if address!=bob['address']:return []
                if phase in ('','lock'):return [row('aa'*32+'#0',4000000,{asset:1}),row('bb'*32+'#0',30000000,{}),row(collateral,20000000,{})]
                return [row(lock+'#1',29800000,{}),row(collateral,20000000,{}),row(refund+'#0',4000000,{asset:1})]
            def build(**kwargs):kwargs['body'].write_text('{}');os.chmod(kwargs['body'],0o600);return 200000
            def sign(_work,body,_key):return {'txid':lock if body.name=='lock.body' else refund}
            def command(cmd,**kwargs):return 'addr_test1'+'v'*40 if cmd[0].endswith('cardano-cli') else b'{}'
            patches=[patch('public_cardano_nft_refund.actor',side_effect=lambda _root,name:alice if name=='alice' else bob),patch('public_cardano_nft_refund.cardano_utxos',side_effect=outputs),patch('public_cardano_nft_refund.status_confirmations',return_value=2),patch('public_cardano_nft_refund.preview_protocol_parameters',return_value={}),patch('public_cardano_nft_refund.subprocess.check_output',side_effect=command),patch('public_cardano_nft_refund._tip',side_effect=lambda:now[0]),patch('public_cardano_nft_refund.build_balanced',side_effect=build),patch('public_cardano_nft_refund.sign_and_submit',side_effect=sign),patch('public_cardano_nft_refund.verify_preview')]
            for item in patches:item.start()
            try:
                initialize(root);self.assertEqual(advance(root)['phase'],'lock_submitted');self.assertEqual(advance(root)['phase'],'wait_refund');self.assertEqual(advance(root)['phase'],'wait_refund')
                now[0]=1300;self.assertEqual(advance(root)['phase'],'refund_submitted');self.assertEqual(advance(root)['phase'],'complete')
            finally:
                for item in reversed(patches):item.stop()

if __name__=='__main__':unittest.main()
