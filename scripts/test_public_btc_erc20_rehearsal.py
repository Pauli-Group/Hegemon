import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from public_btc_erc20_rehearsal import initialize,advance

class PublicBtcErc20Test(unittest.TestCase):
    def test_uses_confirmed_ethereum_secret_and_checks_balances(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);os.chmod(root,0o700);(root/'ethereum-setup').mkdir(mode=0o700)
            terms={'btc_refund':'02'+'11'*32,'btc_claimant':'03'+'22'*32,'eth_refundee':'0x'+'33'*20,'eth_claimant':'0x'+'44'*20};token='0x'+'55'*20;escrow='0x'+'66'*20
            def holding(_leg,address):
                path=root/'btc-erc20/state.json';phase=json.loads(path.read_text())['phase'] if path.exists() else ''
                return (990 if address==terms['eth_refundee'] else 10) if phase=='btc_claim_submitted' else (1000 if address==terms['eth_refundee'] else 0)
            def rpc(method,params):return {'eth_getBlockByNumber':{'timestamp':hex(100000)},'eth_getCode':'0x6000'}[method]
            def observed(*args):return bytearray((root/'btc-erc20/secret').read_bytes()),{'confirmations':2}
            patches=[patch('public_btc_erc20_rehearsal.verify_network'),patch('public_btc_erc20_rehearsal._wallets',return_value=terms),patch('public_btc_erc20_rehearsal.fixture_state',return_value={'phase':'complete','contracts':{'erc20':{'address':token}}}),patch('public_btc_erc20_rehearsal._holding',side_effect=holding),patch('public_btc_erc20_rehearsal.request',return_value=b'100'),patch('public_btc_erc20_rehearsal.fund',return_value={'txid':'77'*32}),patch('public_btc_erc20_rehearsal._bitcoin_lock',return_value=100),patch('public_btc_erc20_rehearsal.rpc',side_effect=rpc),patch('public_btc_erc20_rehearsal.send',return_value={'txid':'88'*32}),patch('public_btc_erc20_rehearsal._receipt',return_value={'contractAddress':escrow}),patch('public_btc_erc20_rehearsal.expected_runtime',return_value='0x6000'),patch('public_btc_erc20_rehearsal._verify'),patch('public_btc_erc20_rehearsal.ethereum_claim',side_effect=observed),patch('public_btc_erc20_rehearsal.spend_contract',return_value={'txid':'99'*32}),patch('public_btc_erc20_rehearsal.bitcoin_claim',side_effect=observed)]
            for p in patches:p.start()
            try:
                initialize(root);phases=[advance(root)['phase'] for _ in range(11)]
            finally:
                for p in reversed(patches):p.stop()
            self.assertEqual(phases,['btc_lock_submitted','deploy_eth','deploy_eth_submitted','approve_eth','approve_eth_submitted','fund_eth','fund_eth_submitted','both_verified','eth_claim_submitted','btc_claim_submitted','complete'])

if __name__=='__main__':unittest.main()
