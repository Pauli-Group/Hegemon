import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from public_cardano_refund_rehearsal import initialize,advance

class PublicCardanoRefundTest(unittest.TestCase):
    def test_waits_for_expiry_and_checks_refund_output(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700);(root/'cardano-native-pair').mkdir();collateral='bb'*32+'#0'
            (root/'cardano-native-pair/state.json').write_text(json.dumps({'phase':'complete','bob_collateral':collateral}))
            alice={'address':'addr_test1'+'q'*40,'keyhash':'11'*28,'skey':root/'alice.key'};bob={'address':'addr_test1'+'p'*40,'keyhash':'22'*28,'skey':root/'bob.key'};lock='cc'*32;refund='dd'*32;now=[1000]
            def row(ref,amount):return {'outref':ref,'lovelace':amount,'assets':{}}
            def outputs(address):
                path=root/'cardano-refund/state.json';phase=json.loads(path.read_text())['phase'] if path.exists() else ''
                if address==bob['address']:
                    if phase in ('','lock'):return [row('aa'*32+'#0',18000000),row(collateral,20000000)]
                    return [row(lock+'#1',13800000),row(collateral,20000000),row(refund+'#0',4000000)]
                return [] if phase=='refund_submitted' else [row(lock+'#0',4000000)]
            def build(**kwargs):kwargs['body'].write_text('{}');os.chmod(kwargs['body'],0o600);return 200000
            def sign(_work,body,_key):return {'txid':lock if body.name=='lock.body' else refund}
            def command(cmd,**kwargs):return 'addr_test1'+'v'*40 if cmd[0].endswith('cardano-cli') else b'{}'
            patches=[patch('public_cardano_refund_rehearsal.actor',side_effect=lambda _root,name:alice if name=='alice' else bob),patch('public_cardano_refund_rehearsal.cardano_utxos',side_effect=outputs),patch('public_cardano_refund_rehearsal.status_confirmations',return_value=2),patch('public_cardano_refund_rehearsal.preview_protocol_parameters',return_value={}),patch('public_cardano_refund_rehearsal.subprocess.check_output',side_effect=command),patch('public_cardano_refund_rehearsal._tip',side_effect=lambda:now[0]),patch('public_cardano_refund_rehearsal.build_balanced',side_effect=build),patch('public_cardano_refund_rehearsal.sign_and_submit',side_effect=sign),patch('public_cardano_refund_rehearsal.verify_preview')]
            for item in patches:item.start()
            try:
                initialize(root);self.assertEqual(advance(root)['phase'],'lock_submitted');self.assertEqual(advance(root)['phase'],'wait_refund');self.assertEqual(advance(root)['phase'],'wait_refund')
                now[0]=1300;self.assertEqual(advance(root)['phase'],'refund_submitted');self.assertEqual(advance(root)['phase'],'complete')
            finally:
                for item in reversed(patches):item.stop()

if __name__=='__main__':unittest.main()
