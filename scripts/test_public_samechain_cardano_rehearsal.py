import itertools
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from public_samechain_cardano_rehearsal import initialize,advance,_choose_fee

class PublicSamechainCardanoTest(unittest.TestCase):
    @patch('public_samechain_cardano_rehearsal.status_confirmations',return_value=2)
    def test_selects_asset_bearing_fee_input_without_spending_collateral(self,_status):
        collateral='11'*32+'#0';asset_ref='22'*32+'#0';asset='33'*28+'.00'
        rows=[{'outref':collateral,'lovelace':20000000,'assets':{}},{'outref':asset_ref,'lovelace':30000000,'assets':{asset:990}}]
        selected=_choose_fee(rows,5000000,(collateral,));self.assertEqual(selected['outref'],asset_ref);self.assertEqual(selected['assets'][asset],990)
    def test_complete_stages_use_observed_secret_and_check_recipients(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700);setup=root/'cardano-setup';setup.mkdir(mode=0o700);policy='11'*28
            (setup/'state.json').write_text(json.dumps({'phase':'submitted','txid':'12'*32,'policy':policy}))
            actors={'alice':{'address':'addr_test1'+'q'*40,'keyhash':'22'*28,'skey':root/'alice.key'},'bob':{'address':'addr_test1'+'p'*40,'keyhash':'33'*28,'skey':root/'bob.key'}}
            ft=policy+'.46554e47';nft=policy+'.4e4654';distribution='aa'*32;lock1='bb'*32;lock2='cc'*32;claim1='dd'*32;claim2='ee'*32
            def row(ref,ada,assets):return {'outref':ref,'lovelace':ada,'assets':assets}
            def utxos(address):
                path=root/'cardano-native-pair/state.json';state=json.loads(path.read_text()) if path.exists() else {};phase=state.get('phase','init')
                if address==actors['alice']['address']:
                    if phase in ('init','distribute'):return [row('10'*32+'#0',5000000,{ft:1000,nft:1}),row('20'*32+'#0',1000000000,{})]
                    rows=[row(distribution+'#1',4000000,{ft:1000}),row(distribution+'#2',20000000,{}),row('20'*32+'#0',1000000000,{})]
                    if phase=='claim_long_submitted':rows.append(row(claim1+'#0',4000000,{nft:1}))
                    return rows
                rows=[row(distribution+'#0',4000000,{nft:1}),row('30'*32+'#0',20000000,{}),row('40'*32+'#0',18000000,{})]
                if phase=='claim_long_submitted':rows.append(row(claim2+'#0',4000000,{ft:10}))
                return rows
            def build(**kwargs):kwargs['body'].write_text('{}');os.chmod(kwargs['body'],0o600);return 200000
            ids=iter([distribution,lock1,lock2,claim1,claim2])
            def sign(*args):return {'txid':next(ids)}
            def observed(*args):return bytearray((root/'cardano-native-pair/secret').read_bytes()),{'confirmations':2}
            def command(cmd,**kwargs):return 'addr_test1'+'v'*40 if cmd[0].endswith('cardano-cli') else b'{}'
            patches=[patch('public_samechain_cardano_rehearsal.verify_network'),patch('public_samechain_cardano_rehearsal.status_confirmations',return_value=2),patch('public_samechain_cardano_rehearsal.actor',side_effect=lambda _root,name:actors[name]),patch('public_samechain_cardano_rehearsal.cardano_utxos',side_effect=utxos),patch('public_samechain_cardano_rehearsal.preview_protocol_parameters',return_value={}),patch('public_samechain_cardano_rehearsal.subprocess.check_output',side_effect=command),patch('public_samechain_cardano_rehearsal._tip',return_value=1000),patch('public_samechain_cardano_rehearsal.build_balanced',side_effect=build),patch('public_samechain_cardano_rehearsal.sign_and_submit',side_effect=sign),patch('public_samechain_cardano_rehearsal.verify_preview'),patch('public_samechain_cardano_rehearsal.cardano_claim',side_effect=observed)]
            for item in patches:item.start()
            try:
                initialize(root);phases=[advance(root)['phase'] for _ in range(9)]
            finally:
                for item in reversed(patches):item.stop()
            self.assertEqual(phases,['distribute_submitted','fund_long','fund_long_submitted','fund_short','fund_short_submitted','both_verified','claim_short_submitted','claim_long_submitted','complete'])

if __name__=='__main__':unittest.main()
