import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from public_eth_cardano_token_rehearsal import initialize,advance

class PublicEthCardanoTokenTest(unittest.TestCase):
    def test_token_swap_stages_preserve_recipient_checks(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700);(root/'ethereum-setup').mkdir(mode=0o700);(root/'cardano-setup').mkdir(mode=0o700);(root/'cardano-native-pair').mkdir(mode=0o700)
            policy='11'*28;asset=policy+'.46554e47';token='0x'+'22'*20;escrow='0x'+'33'*20
            (root/'cardano-setup/state.json').write_text(json.dumps({'policy':policy}));(root/'cardano-native-pair/state.json').write_text(json.dumps({'phase':'complete','alice_collateral':'44'*32+'#0','bob_collateral':'55'*32+'#0'}))
            actors={'eth_refundee':'0x'+'66'*20,'eth_claimant':'0x'+'77'*20,'ada_refundee':'88'*28,'ada_claimant':'99'*28,'ada_refund_address':'addr_test1'+'q'*40,'ada_claim_address':'addr_test1'+'p'*40}
            def holdings(_leg,address):
                path=root/'eth-cardano-erc20-fungible/state.json';phase=json.loads(path.read_text())['phase'] if path.exists() else ''
                return (990 if address==actors['eth_refundee'] else 10) if phase=='eth_claim_submitted' else (1000 if address==actors['eth_refundee'] else 0)
            def utxos(address):
                rows=[{'outref':'aa'*32+'#0','lovelace':10000000,'assets':{asset:1000}},{'outref':'bb'*32+'#0','lovelace':20000000,'assets':{}},{'outref':'55'*32+'#0','lovelace':20000000,'assets':{}}]
                if address==actors['ada_claim_address']:rows.append({'outref':'dd'*32+'#0','lovelace':4000000,'assets':{asset:7}})
                return rows
            def eth_send(_work,_wallet,to,_value,_data):return {'txid':('aa' if to is None else 'bb')*32}
            def build(**kwargs):kwargs['body'].write_text('{}');os.chmod(kwargs['body'],0o600);return 200000
            def ada_send(_work,body,_key):return {'txid':('cc' if 'lock' in body.name else 'dd')*32}
            def observed(*_args):return bytearray((root/'eth-cardano-erc20-fungible/secret').read_bytes()),{'confirmations':2}
            def compiled(cmd,**kwargs):return 'addr_test1'+'v'*40 if cmd[0].endswith('cardano-cli') else b'{}'
            def rpc(method,params):return {'eth_getBlockByNumber':{'timestamp':hex(1666657000)},'eth_getCode':'0x6000'}[method]
            patches=[patch('public_eth_cardano_token_rehearsal.verify_network'),patch('public_eth_cardano_token_rehearsal.eth_setup',return_value={'phase':'complete','contracts':{'erc20':{'address':token}}}),patch('public_eth_cardano_token_rehearsal._actors',return_value=actors),patch('public_eth_cardano_token_rehearsal._holding',side_effect=holdings),patch('public_eth_cardano_token_rehearsal.cardano_utxos',side_effect=utxos),patch('public_eth_cardano_token_rehearsal.status_confirmations',return_value=2),patch('public_eth_cardano_token_rehearsal.rpc',side_effect=rpc),patch('public_eth_cardano_token_rehearsal.send',side_effect=eth_send),patch('public_eth_cardano_token_rehearsal._receipt',return_value={'contractAddress':escrow}),patch('public_eth_cardano_token_rehearsal.expected_runtime',return_value='0x6000'),patch('public_eth_cardano_token_rehearsal._eth_verify'),patch('public_eth_cardano_token_rehearsal._ada_verify'),patch('public_eth_cardano_token_rehearsal._tip',return_value=1000),patch('public_eth_cardano_token_rehearsal._choose',return_value={'outref':'bb'*32+'#0','lovelace':20000000,'assets':{}}),patch('public_eth_cardano_token_rehearsal.preview_protocol_parameters',return_value={}),patch('public_eth_cardano_token_rehearsal.subprocess.check_output',side_effect=compiled),patch('public_eth_cardano_token_rehearsal.build_balanced',side_effect=build),patch('public_eth_cardano_token_rehearsal.actor',return_value={'skey':root/'dummy'}),patch('public_eth_cardano_token_rehearsal.sign_and_submit',side_effect=ada_send),patch('public_eth_cardano_token_rehearsal.cardano_claim',side_effect=observed),patch('public_eth_cardano_token_rehearsal.ethereum_claim',side_effect=observed)]
            for item in patches:item.start()
            try:
                initialize(root,'erc20-fungible');phases=[advance(root,'erc20-fungible')['phase'] for _ in range(11)]
            finally:
                for item in reversed(patches):item.stop()
            self.assertEqual(phases,['deploy_eth_submitted','approve_eth','approve_eth_submitted','fund_eth','fund_eth_submitted','eth_lock_confirmed','ada_lock_submitted','both_verified','ada_claim_submitted','eth_claim_submitted','complete'])

if __name__=='__main__':unittest.main()
