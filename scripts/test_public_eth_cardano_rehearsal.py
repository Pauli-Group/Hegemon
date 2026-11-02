import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from public_eth_cardano_rehearsal import initialize,advance

class PublicEthCardanoRehearsalTest(unittest.TestCase):
    def test_stages_claim_observed_cardano_secret_on_ethereum(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700)
            actors={'eth_refundee':'0x'+'11'*20,'eth_claimant':'0x'+'22'*20,'ada_refundee':'33'*28,'ada_claimant':'44'*28,'ada_refund_address':'addr_test1'+'q'*40,'ada_claim_address':'addr_test1'+'p'*40}
            (root/'addresses.json').write_text(json.dumps({'alice':{'cardano_preview':actors['ada_refund_address'],'ethereum_sepolia':actors['eth_refundee']},'bob':{'cardano_preview':actors['ada_claim_address'],'ethereum_sepolia':actors['eth_claimant']}}))
            utxo=[{'outref':'aa'*32+'#0','lovelace':20000000,'assets':{}},{'outref':'bb'*32+'#0','lovelace':20000000,'assets':{}}]
            def eth_send(_work,_wallet,to,_value,_data):return {'txid':('aa' if to is None else 'bb')*32}
            def build(**kwargs):kwargs['body'].write_text('{}');os.chmod(kwargs['body'],0o600);return 200000
            def ada_send(_work,body,_key):return {'txid':('cc' if 'lock' in body.name else 'dd')*32}
            def observed(*_args):return bytearray((root/'eth-cardano/secret').read_bytes()),{'confirmations':2}
            def compiled(cmd,**kwargs):return 'addr_test1'+'v'*40 if cmd[0].endswith('cardano-cli') else b'{}'
            patches=[patch('public_eth_cardano_rehearsal.verify_network'),patch('public_eth_cardano_rehearsal.setup_status',return_value={'phase':'confirmed'}),patch('public_eth_cardano_rehearsal._actors',return_value=actors),patch('public_eth_cardano_rehearsal._tip',return_value=1000),patch('public_eth_cardano_rehearsal.rpc',return_value={'timestamp':hex(1666657000)}),patch('public_eth_cardano_rehearsal.ethereum_send',side_effect=eth_send),patch('public_eth_cardano_rehearsal._receipt',return_value={'contractAddress':'0x'+'55'*20}),patch('public_eth_cardano_rehearsal.verify_native'),patch('public_eth_cardano_rehearsal._ada_verify'),patch('public_eth_cardano_rehearsal.cardano_utxos',return_value=utxo),patch('public_eth_cardano_rehearsal.status_confirmations',return_value=2),patch('public_eth_cardano_rehearsal.preview_protocol_parameters',return_value={}),patch('public_eth_cardano_rehearsal.subprocess.check_output',side_effect=compiled),patch('public_eth_cardano_rehearsal.build_balanced',side_effect=build),patch('public_eth_cardano_rehearsal.actor',return_value={'skey':root/'dummy'}),patch('public_eth_cardano_rehearsal.sign_and_submit',side_effect=ada_send),patch('public_eth_cardano_rehearsal.cardano_claim',side_effect=observed),patch('public_eth_cardano_rehearsal.ethereum_claim',side_effect=observed)]
            for item in patches:item.start()
            try:
                initialize(root);phases=[advance(root)['phase'] for _ in range(7)]
            finally:
                for item in reversed(patches):item.stop()
            self.assertEqual(phases,['eth_lock_submitted','eth_lock_confirmed','ada_lock_submitted','both_verified','ada_claim_submitted','eth_claim_submitted','complete'])
            self.assertNotIn((root/'eth-cardano/secret').read_bytes().hex(),(root/'eth-cardano/state.json').read_text())

if __name__=='__main__':unittest.main()
